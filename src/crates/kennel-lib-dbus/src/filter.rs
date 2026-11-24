// SPDX-License-Identifier: Apache-2.0

//! The mechanical filter (§7.7.2a): decide a typed [`crate::wire::Call`] against the compiled
//! `[dbus]` table.
//!
//! kenneld compiles the policy into this table at construction and hands it to the `host-dbus`
//! delegate, which applies it per message — the delegate is a mechanical enforcer, not a second
//! author of policy (§7.7.2a). The table is matched on the typed header fields
//! (destination/interface/member), never on D-Bus wire (§7.7.3).
//!
//! # The delegate is the real boundary
//!
//! The facade also refuses the refuse-to-broker set (§7.7.5) as a backstop, but the facade runs
//! **in the kennel and is untrusted** — a compromised facade could forge a [`crate::wire::Call`]
//! to any destination. So the delegate, in the operator's trusted context, re-checks
//! refuse-to-broker *and* the full allowlist here. This filter — not the facade's backstop — is
//! what actually keeps a kennel off `org.freedesktop.secrets`.

use crate::wire::{Bus, Call};

/// The refuse-to-broker set (§7.7.5): destinations refused regardless of policy.
///
/// A bare entry matches that name and its `.`-separated children (`org.freedesktop.systemd1`
/// also covers `org.freedesktop.systemd1.Manager`).
pub const REFUSE_TO_BROKER: &[&str] = &[
    "org.freedesktop.secrets",
    "org.freedesktop.systemd1",
    "org.freedesktop.login1",
    "org.gnome.SessionManager",
    "org.kde.ksmserver",
];

/// Whether `name` is the refuse-to-broker set or a `.`-separated child of one of its entries.
#[must_use]
pub fn is_refused(name: &str) -> bool {
    REFUSE_TO_BROKER.iter().any(|&r| {
        name == r
            || name
                .strip_prefix(r)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// One bus's compiled rules — the allowlists and the explicit denies (§7.7.6). The `call`
/// entries are `destination=interface.member`; the rest are bare destination patterns.
#[derive(Debug, Clone, Default)]
pub struct BusRules {
    /// Destinations the kennel may call (and receive replies/signals from).
    pub talk: Vec<String>,
    /// Specific `destination=interface.member` calls (finer than `talk`).
    pub call: Vec<String>,
    /// Signals the kennel may receive (the match-rule allowlist, §7.7.4).
    pub broadcast: Vec<String>,
    /// Names the kennel may own (be addressable as, §7.7.4). Almost always empty.
    pub own: Vec<String>,
    /// Explicit denies layered over the allows (belt-and-braces, §7.7.6).
    pub deny_talk: Vec<String>,
}

/// The compiled `[dbus]` match table for a kennel: the per-bus rule sets that exist. A bus with
/// no rules (the policy did not enable it) is `None` and every call to it is denied.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// The session bus rules, present iff `[dbus.session].enabled`.
    pub session: Option<BusRules>,
    /// The system bus rules, present iff `[dbus.system].enabled`.
    pub system: Option<BusRules>,
}

/// The filter's verdict on a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The call passes — reconstruct and send it to the bus.
    Allow,
    /// The call is refused; the carried reason is the D-Bus error message returned to the
    /// workload as `org.freedesktop.DBus.Error.AccessDenied`.
    Deny(String),
}

impl Filter {
    /// Decide a typed call. Order: refuse-to-broker (the axiom carve-out, §7.7.5) → the bus is
    /// enabled at all → explicit deny → allow (`talk` or a matching `call`) → default-deny.
    #[must_use]
    pub fn decide(&self, call: &Call) -> Decision {
        if is_refused(&call.destination) {
            return Decision::Deny(format!(
                "{} is refused to brokering by Project Kennel",
                call.destination
            ));
        }
        let rules = match call.bus {
            Bus::Session => self.session.as_ref(),
            Bus::System => self.system.as_ref(),
        };
        let Some(rules) = rules else {
            return Decision::Deny(format!("the {} bus is not enabled", bus_name(call.bus)));
        };
        if rules
            .deny_talk
            .iter()
            .any(|p| pattern_admits(p, &call.destination))
        {
            return Decision::Deny(format!("{} is explicitly denied", call.destination));
        }
        if rules
            .talk
            .iter()
            .any(|p| pattern_admits(p, &call.destination))
            || call_admits(rules, call)
        {
            // The bus driver is not an ordinary destination: its methods act on the BUS — own a
            // name, activate a service, set the environment activated services start with,
            // become a monitor. A grant of the driver (which every client needs, for `AddMatch`)
            // admits only the methods a client needs, each checked against the policy.
            if call.destination == BUS_DRIVER {
                return driver_decision(rules, call);
            }
            return Decision::Allow;
        }
        Decision::Deny(format!(
            "{} is not on the {} bus allowlist",
            call.destination,
            bus_name(call.bus)
        ))
    }
}

/// The bus driver's well-known name.
pub const BUS_DRIVER: &str = "org.freedesktop.DBus";

/// Driver methods that only read bus state or manage the caller's own match rules.
const DRIVER_QUERIES: &[&str] = &[
    "Hello",
    "RemoveMatch",
    "GetNameOwner",
    "NameHasOwner",
    "ListNames",
    "ListActivatableNames",
    "ListQueuedOwners",
    "GetId",
    "GetConnectionUnixUser",
    "GetConnectionUnixProcessID",
    "GetConnectionCredentials",
];

/// Decide a call addressed to the bus driver, once the policy has granted the driver at all.
///
/// Default-deny by method. What is admitted:
///
/// - the read-only queries in [`DRIVER_QUERIES`], and `Peer`/`Introspectable`/`Properties.Get*`;
/// - `AddMatch`, unless the rule asks to eavesdrop;
/// - `RequestName` / `ReleaseName`, only for a name the policy's `own` admits;
/// - `StartServiceByName`, only for a destination the kennel may call anyway.
///
/// Everything else is refused — in particular `UpdateActivationEnvironment` (it sets the
/// environment of services the bus later starts, outside any kennel) and `BecomeMonitor`. A
/// method call may omit its interface, and the driver then resolves it by member alone, so an
/// empty interface is judged as the driver's own.
fn driver_decision(rules: &BusRules, call: &Call) -> Decision {
    let refuse = |why: &str| {
        Decision::Deny(format!(
            "bus driver method {}.{} is not brokered: {why}",
            call.interface, call.member
        ))
    };
    let member = call.member.as_str();
    match call.interface.as_str() {
        "" | BUS_DRIVER => {}
        "org.freedesktop.DBus.Peer" if matches!(member, "Ping" | "GetMachineId") => {
            return Decision::Allow;
        }
        "org.freedesktop.DBus.Introspectable" if member == "Introspect" => {
            return Decision::Allow;
        }
        "org.freedesktop.DBus.Properties" if matches!(member, "Get" | "GetAll") => {
            return Decision::Allow;
        }
        _ => return refuse("not a method a client needs"),
    }
    if DRIVER_QUERIES.contains(&member) {
        return Decision::Allow;
    }
    match member {
        "AddMatch" => match first_string_arg(call) {
            Some(rule) if !rule.contains("eavesdrop") => Decision::Allow,
            Some(_) => refuse("an eavesdropping match rule"),
            None => refuse("the match rule could not be read"),
        },
        "RequestName" | "ReleaseName" => match first_string_arg(call) {
            Some(name) if rules.own.iter().any(|p| pattern_admits(p, name)) => Decision::Allow,
            Some(name) => Decision::Deny(format!(
                "{name} is not a name this kennel may own (the policy's `own` list)"
            )),
            None => refuse("the name could not be read"),
        },
        "StartServiceByName" => match first_string_arg(call) {
            Some(name) if may_reach(rules, name) => Decision::Allow,
            Some(name) => Decision::Deny(format!(
                "{name} is not a destination this kennel may call, so it may not start it"
            )),
            None => refuse("the service name could not be read"),
        },
        _ => refuse("not a method a client needs"),
    }
}

/// Whether the kennel may address `name` at all: not refused to brokering, not explicitly
/// denied, and admitted by `talk` or by the destination half of a `call` entry.
fn may_reach(rules: &BusRules, name: &str) -> bool {
    !is_refused(name)
        && !rules.deny_talk.iter().any(|p| pattern_admits(p, name))
        && (rules.talk.iter().any(|p| pattern_admits(p, name))
            || rules.call.iter().any(|entry| {
                entry
                    .split_once('=')
                    .is_some_and(|(dest, _)| pattern_admits(dest, name))
            }))
}

/// The first argument of `call`, if it is a string: the body of a message whose signature
/// starts with `s` begins with a little-endian `u32` length, the bytes, and a NUL.
fn first_string_arg(call: &Call) -> Option<&str> {
    if !call.signature.starts_with('s') || call.body_endian != b'l' {
        return None;
    }
    let (len, rest) = call.body.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
    let text = rest.get(..len)?;
    if rest.get(len) != Some(&0) {
        return None;
    }
    std::str::from_utf8(text).ok()
}

/// Whether a `call` entry (`destination=interface.member`) admits this call: its destination
/// part admits the call's destination and its method part matches `interface.member`.
fn call_admits(rules: &BusRules, call: &Call) -> bool {
    let target = format!("{}.{}", call.interface, call.member);
    rules.call.iter().any(|entry| {
        let Some((dest, method)) = entry.split_once('=') else {
            return false;
        };
        pattern_admits(dest, &call.destination) && pattern_admits(method, &target)
    })
}

const fn bus_name(bus: Bus) -> &'static str {
    match bus {
        Bus::Session => "session",
        Bus::System => "system",
    }
}

/// Whether `pattern` admits `name`.
///
/// `*` matches anything; an exact string matches itself; a `prefix.*` matches `prefix` and any
/// `prefix.`-child. The semantics mirror `kennel_lib_compile::source::dbus_pattern_admits` —
/// the compile-time validator and this runtime matcher must agree, and are tested on the same
/// cases.
#[must_use]
pub fn pattern_admits(pattern: &str, name: &str) -> bool {
    if pattern == "*" || pattern == name {
        return true;
    }
    pattern
        .strip_suffix('*')
        .and_then(|p| p.strip_suffix('.'))
        .is_some_and(|prefix| {
            name == prefix
                || name
                    .strip_prefix(prefix)
                    .is_some_and(|r| r.starts_with('.'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(bus: Bus, dest: &str, iface: &str, member: &str) -> Call {
        Call {
            bus,
            serial: 1,
            no_reply: false,
            destination: dest.to_owned(),
            path: "/x".to_owned(),
            interface: iface.to_owned(),
            member: member.to_owned(),
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        }
    }

    fn notifications_filter() -> Filter {
        Filter {
            session: Some(BusRules {
                talk: vec!["org.freedesktop.Notifications".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        }
    }

    /// A call to the bus driver carrying one string argument.
    fn driver_call(iface: &str, member: &str, arg: Option<&str>) -> Call {
        let mut c = call(Bus::Session, BUS_DRIVER, iface, member);
        if let Some(arg) = arg {
            c.signature = "s".to_owned();
            c.body = u32::try_from(arg.len())
                .expect("short")
                .to_le_bytes()
                .into_iter()
                .chain(arg.bytes())
                .chain([0])
                .collect();
        }
        c
    }

    fn driver_filter() -> Filter {
        Filter {
            session: Some(BusRules {
                talk: vec![
                    BUS_DRIVER.to_owned(),
                    "org.freedesktop.Notifications".to_owned(),
                ],
                own: vec!["org.example.App".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        }
    }

    #[test]
    fn a_driver_grant_admits_what_a_client_needs() {
        let f = driver_filter();
        for (iface, member, arg) in [
            (BUS_DRIVER, "GetId", None),
            ("", "GetNameOwner", Some("org.freedesktop.Notifications")),
            (
                BUS_DRIVER,
                "AddMatch",
                Some("type='signal',interface='org.x.Y'"),
            ),
            (BUS_DRIVER, "RemoveMatch", Some("type='signal'")),
            (BUS_DRIVER, "ListNames", None),
            ("org.freedesktop.DBus.Peer", "Ping", None),
            ("org.freedesktop.DBus.Introspectable", "Introspect", None),
            (BUS_DRIVER, "RequestName", Some("org.example.App")),
            (
                BUS_DRIVER,
                "StartServiceByName",
                Some("org.freedesktop.Notifications"),
            ),
        ] {
            assert_eq!(
                f.decide(&driver_call(iface, member, arg)),
                Decision::Allow,
                "{iface}.{member}({arg:?})"
            );
        }
    }

    #[test]
    fn a_driver_grant_does_not_open_the_bus() {
        let f = driver_filter();
        for (iface, member, arg) in [
            // Sets the environment of services the bus activates later, outside any kennel.
            (BUS_DRIVER, "UpdateActivationEnvironment", None),
            ("", "UpdateActivationEnvironment", None),
            ("org.freedesktop.DBus.Monitoring", "BecomeMonitor", None),
            (BUS_DRIVER, "ReloadConfig", None),
            // A name outside `own`.
            (
                BUS_DRIVER,
                "RequestName",
                Some("org.freedesktop.Notifications"),
            ),
            ("", "RequestName", Some("org.freedesktop.secrets")),
            (BUS_DRIVER, "RequestName", None),
            // Activating something the kennel may not call — or that is never brokered.
            (BUS_DRIVER, "StartServiceByName", Some("org.gnome.Shell")),
            (
                BUS_DRIVER,
                "StartServiceByName",
                Some("org.freedesktop.systemd1"),
            ),
            // Eavesdropping.
            (
                BUS_DRIVER,
                "AddMatch",
                Some("eavesdrop=true,type='method_call'"),
            ),
            (BUS_DRIVER, "AddMatch", None),
            ("org.freedesktop.DBus.Properties", "Set", None),
            (BUS_DRIVER, "SomethingNew", None),
        ] {
            assert!(
                matches!(
                    f.decide(&driver_call(iface, member, arg)),
                    Decision::Deny(_)
                ),
                "{iface}.{member}({arg:?}) must be refused"
            );
        }
    }

    #[test]
    fn a_malformed_string_argument_is_not_read() {
        let mut c = driver_call(BUS_DRIVER, "RequestName", Some("org.example.App"));
        c.body.truncate(6);
        assert!(first_string_arg(&c).is_none(), "truncated");
        let mut c = driver_call(BUS_DRIVER, "RequestName", Some("org.example.App"));
        c.body_endian = b'B';
        assert!(
            first_string_arg(&c).is_none(),
            "big-endian bodies are not parsed"
        );
        let mut c = driver_call(BUS_DRIVER, "RequestName", Some("org.example.App"));
        c.signature = "u".to_owned();
        assert!(first_string_arg(&c).is_none(), "not a string");
    }

    #[test]
    fn allowed_talk_destination_passes() {
        let f = notifications_filter();
        assert_eq!(
            f.decide(&call(
                Bus::Session,
                "org.freedesktop.Notifications",
                "org.freedesktop.Notifications",
                "Notify"
            )),
            Decision::Allow
        );
    }

    #[test]
    fn default_deny_for_unlisted_destination() {
        let f = notifications_filter();
        let d = f.decide(&call(Bus::Session, "org.freedesktop.UDisks2", "x", "Mount"));
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn refuse_to_broker_overrides_even_an_allow() {
        // Even if a (mis)compiled table listed secrets in talk, the delegate refuses it.
        let f = Filter {
            session: Some(BusRules {
                talk: vec!["org.freedesktop.secrets".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        };
        let d = f.decide(&call(
            Bus::Session,
            "org.freedesktop.secrets",
            "org.freedesktop.Secret.Service",
            "OpenSession",
        ));
        assert!(matches!(d, Decision::Deny(m) if m.contains("refused to brokering")));
    }

    #[test]
    fn systemd1_child_is_refused() {
        let f = Filter {
            session: Some(BusRules {
                talk: vec!["*".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        };
        let d = f.decide(&call(
            Bus::Session,
            "org.freedesktop.systemd1.Manager",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
        ));
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[test]
    fn disabled_bus_denies_everything() {
        let f = notifications_filter(); // system is None
        let d = f.decide(&call(
            Bus::System,
            "org.freedesktop.Notifications",
            "x",
            "y",
        ));
        assert!(matches!(d, Decision::Deny(m) if m.contains("system bus is not enabled")));
    }

    #[test]
    fn explicit_deny_overrides_talk() {
        let f = Filter {
            session: Some(BusRules {
                talk: vec!["org.freedesktop.*".to_owned()],
                deny_talk: vec!["org.freedesktop.UDisks2".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        };
        assert!(matches!(
            f.decide(&call(Bus::Session, "org.freedesktop.UDisks2", "x", "y")),
            Decision::Deny(_)
        ));
        assert_eq!(
            f.decide(&call(
                Bus::Session,
                "org.freedesktop.Notifications",
                "x",
                "y"
            )),
            Decision::Allow
        );
    }

    #[test]
    fn call_entry_matches_destination_and_method() {
        let f = Filter {
            session: Some(BusRules {
                call: vec!["org.example.Service=org.example.Iface.DoThing".to_owned()],
                ..BusRules::default()
            }),
            system: None,
        };
        // The exact destination+interface.member passes; a different member does not.
        assert_eq!(
            f.decide(&call(
                Bus::Session,
                "org.example.Service",
                "org.example.Iface",
                "DoThing"
            )),
            Decision::Allow
        );
        assert!(matches!(
            f.decide(&call(
                Bus::Session,
                "org.example.Service",
                "org.example.Iface",
                "OtherThing"
            )),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn pattern_semantics_match_the_compiler() {
        // The same cases kennel_lib_compile::source::dbus_pattern_admits is tested on.
        assert!(pattern_admits("*", "anything.at.all"));
        assert!(pattern_admits(
            "org.freedesktop.Notifications",
            "org.freedesktop.Notifications"
        ));
        assert!(pattern_admits(
            "org.freedesktop.portal.*",
            "org.freedesktop.portal"
        ));
        assert!(pattern_admits(
            "org.freedesktop.portal.*",
            "org.freedesktop.portal.FileChooser"
        ));
        assert!(!pattern_admits(
            "org.freedesktop.portal.*",
            "org.freedesktop.portalX"
        ));
        assert!(!pattern_admits("org.a", "org.b"));
    }
}
