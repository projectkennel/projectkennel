//! `host-dbus`: the D-Bus mediation delegate (§7.7.2b).
//!
//! `kenneld` compiles the `[dbus]` policy into a match table, connects the operator's real bus,
//! and brokers the facade↔delegate conduit (`07-7-dbus.md` §7.7). This binary is what's left:
//! the bus-side I/O around the I/O-free `kennel_lib_dbus::delegate::Delegate` core. It binds one
//! owner-only `AF_UNIX` command socket; for each conduit fd `kenneld` sends over it, it connects
//! the bus, applies the compiled filter to each typed call, and demultiplexes replies/signals
//! back. No policy of its own — `kenneld` decided; this enforces the table it was handed.
//!
//! # Invocation
//!
//! `host-dbus <command-socket> <session|system> <bus-address> [--talk P]… [--call P]…
//! [--broadcast P]… [--deny-talk P]…`, spawned by `kenneld` in the operator's context. The
//! patterns are the compiled allow/deny lists; `<bus-address>` is the operator's
//! `DBUS_SESSION_BUS_ADDRESS` (or system equivalent).
//!
//! All the logic is in the library (`kennel_host_delegate::dbus`); `main` binds the socket,
//! builds the filter from the args, and serves.

#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;

use kennel_lib_dbus::filter::{BusRules, Filter};
use kennel_lib_dbus::wire::Bus;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("host-dbus: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let [socket, bus_arg, bus_address, rest @ ..] = args else {
        return Err(
            "usage: <command-socket> <session|system> <bus-address> [--talk P]… [--call P]… \
             [--broadcast P]… [--deny-talk P]…"
                .to_owned(),
        );
    };
    let bus = match bus_arg.as_str() {
        "session" => Bus::Session,
        "system" => Bus::System,
        other => return Err(format!("unknown bus {other:?} (expected session|system)")),
    };
    let rules = parse_rules(rest)?;
    let filter = match bus {
        Bus::Session => Filter {
            session: Some(rules),
            system: None,
        },
        Bus::System => Filter {
            session: None,
            system: Some(rules),
        },
    };

    let path = Path::new(socket);
    let _ = std::fs::remove_file(path); // clear a stale socket from a prior run
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {socket}: {e}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {socket}: {e}"))?;

    kennel_host_dbus::serve(&listener, bus, bus_address, &filter);
    Ok(())
}

/// Parse the `--talk`/`--call`/`--broadcast`/`--deny-talk` flag pairs into one bus's rules.
fn parse_rules(flags: &[String]) -> Result<BusRules, String> {
    let mut rules = BusRules::default();
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} expects a pattern argument"))?
            .clone();
        match flag.as_str() {
            "--talk" => rules.talk.push(value),
            "--call" => rules.call.push(value),
            "--broadcast" => rules.broadcast.push(value),
            "--own" => rules.own.push(value),
            "--deny-talk" => rules.deny_talk.push(value),
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    Ok(rules)
}
