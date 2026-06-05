//! Stable `MESSAGE_ID` UUIDs per event type, for the journald sink (`02-3`).
//!
//! journald's `MESSAGE_ID` lets `journalctl MESSAGE_ID=<uuid>` filter by event
//! kind without matching `MESSAGE` substrings. Each event type has one UUID,
//! assigned once and never changed or reused; a new event type adds a row. The
//! sink emits the dash-free 32-hex form journald expects.

/// `(event-type, RFC 4122 UUID)`. The source of truth for the registry.
const MESSAGE_IDS: &[(&str, &str)] = &[
    ("net.connect-allow", "f3f34d7d-9803-4f86-b0e0-6448ab9d2a46"),
    ("net.connect-deny", "272a449a-5530-4235-a25e-fe9db4efcf0e"),
    ("net.bind-allow", "7530d120-917e-4798-a401-04672c6e17bf"),
    ("net.bind-deny", "11ae7eb0-66e8-4172-b84d-4da9f95dc30f"),
    ("net.bind-rewrite", "e16826e6-6e04-4f1a-afaa-8747a1aaff27"),
    ("net.egress", "b9c1f4a2-3d6e-4c11-9a2f-7e0c5d8a1b34"),
    ("fs.access-deny", "31cdea3a-b4a3-4b28-a0a6-b701dc8bc9fe"),
    ("fs.scrub-hit", "43aaffc6-f93f-4444-a639-7ccf6ded44ac"),
    ("exec.allow", "0c7f429f-fd8c-45fe-85db-9d8f03b16bff"),
    ("exec.deny", "c5ea6b43-d002-4a9b-bac9-68f485dd0b4a"),
    ("unix.connect-allow", "77aa28e6-ad83-40a8-a7d0-c23aa3b7b95b"),
    ("unix.connect-deny", "990d921b-1bcf-4f80-8031-cd6a47663b7c"),
    ("dbus.call-allow", "96966399-d539-4baa-96b3-820beb95d03e"),
    ("dbus.call-deny", "c4499d84-b627-499a-9893-38580f563322"),
    ("priv.invoke", "76e3b05f-baf7-47f5-b5a9-b79c72645f4c"),
    ("priv.refuse", "1e8d2bd0-1455-4d0a-a6e0-560519bf188e"),
    (
        "lifecycle.kennel-start",
        "6a9570ea-637e-4afe-851a-797656ab5f3f",
    ),
    (
        "lifecycle.kennel-exit",
        "c251f7c2-2a1d-4b83-9eff-80e60ca5af4e",
    ),
    (
        "lifecycle.daemon-spawn",
        "401f4e9f-91d9-4564-8569-f704c2d69819",
    ),
    (
        "lifecycle.daemon-exit",
        "650d50d5-033c-463e-a197-55a9e6b8d489",
    ),
    (
        "lifecycle.daemon-giveup",
        "a25a7e30-c0b7-439b-8bb1-f3f3cc51fd27",
    ),
    (
        "lifecycle.workload-exit",
        "8bbe34b4-409d-4042-aaf1-47b4526876f8",
    ),
    (
        "lifecycle.kenneld-state-dump",
        "0c03a424-1d3c-4d09-8e0f-d402ea6b08be",
    ),
    (
        "lifecycle.audit-drop",
        "e27d4ef0-0cc1-4893-a0ad-79b243f55901",
    ),
    (
        "lifecycle.audit-truncate",
        "9bd3be2d-cdf5-447b-a783-7713fe211f4c",
    ),
];

/// The dash-free 32-hex `MESSAGE_ID` for an event type, or `None` if the type is
/// unregistered (then the sink omits `MESSAGE_ID`; `KENNEL_EVENT` still filters).
#[must_use]
pub fn for_event(event: &str) -> Option<String> {
    MESSAGE_IDS
        .iter()
        .find(|(name, _)| *name == event)
        .map(|(_, uuid)| uuid.replace('-', ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_event_yields_32_hex() {
        let id = for_event("net.connect-deny").expect("registered");
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!id.contains('-'));
    }

    #[test]
    fn unknown_event_is_none() {
        assert!(for_event("not.a-real-event").is_none());
    }

    #[test]
    fn ids_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for (name, uuid) in MESSAGE_IDS {
            assert_eq!(uuid.len(), 36, "{name} uuid not 36 chars");
            assert_eq!(uuid.matches('-').count(), 4, "{name} uuid not dashed");
            assert!(seen.insert(*uuid), "duplicate uuid for {name}");
        }
    }
}
