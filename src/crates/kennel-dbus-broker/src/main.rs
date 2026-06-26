//! `dbus-broker@v1`: the standing D-Bus mediation service kennel (§7.7).
//!
//! A single long-running service — the intended replacement for the per-consumer `host-dbus`
//! delegate — that receives per-consumer filter sets from `kenneld` over the `binder-connector`
//! mesh and mediates relayed D-Bus frames. Runs inside its own kennel, not on the host.
//!
//! **Status: the frame relay is not yet implemented.** The control channel (consumer
//! registration) and the mesh wiring are in place, but `handle_relay` is a stub — frames are
//! not parsed, filtered, or forwarded to the real bus. D-Bus mediation currently flows through
//! `kenneld`'s legacy `host-dbus` delegate; the broker is dormant unless a deployment selects it.
//!
//! **Control channel** (the `binder-connector` verb set):
//!
//! - `REGISTER_CONSUMER(ctx, bus, filter_set)` — `kenneld` pushes when a D-Bus consumer
//!   kennel is constructed. The broker stores the filter set keyed by `(ctx, bus)`.
//! - `UNREGISTER_CONSUMER(ctx, bus)` — `kenneld` pushes at consumer teardown. The broker
//!   drops the entry.
//! - `RELAY_FRAME(ctx, bus, frame)` — intended to apply the stored filter and forward approved
//!   frames to the real bus (currently stubbed; see Status above).
//!
//! **Architecture:**
//!
//! ```text
//! workload → facade-dbus → binder(node 0) → kenneld → RELAY_FRAME → dbus-broker → real bus
//!                                                        ↑
//!                                       kenneld pushes DbusBusRuntime
//!                                       via REGISTER_CONSUMER
//! ```

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::process::ExitCode;

use kennel_lib_binder::client::{Connection, Incoming};
use kennel_lib_binder::service::{broker, status};
use kennel_lib_dbus::filter::{BusRules, Filter};

/// The mesh binder device path — the `[[provides]]` endpoint, bind-mounted by `kenneld`.
const MESH_DEVICE: &str = "/dev/binderfs-mesh/binder";

/// The service name registered on the mesh bus via `ADD_SERVICE`.
const SERVICE_NAME: &str = "org.projectkennel.dbus-broker";

/// The mmap size for the broker's binder connection.
const MAP_SIZE: usize = 128 * 1024;

/// Poll timeout for the binder serve loop (milliseconds).
const POLL_MS: i32 = 5000;

/// Per-consumer state: the compiled filter for one (consumer, bus) pair.
#[derive(Debug)]
struct ConsumerEntry {
    filter: Filter,
}

/// The broker's in-memory state.
struct Broker {
    /// Per-consumer filter tables, keyed by `(consumer_id, bus)`.
    consumers: HashMap<(u16, u8), ConsumerEntry>,
}

impl Broker {
    fn new() -> Self {
        Self {
            consumers: HashMap::new(),
        }
    }

    fn handle(&mut self, incoming: &Incoming) -> Vec<u8> {
        match incoming.code {
            broker::REGISTER_CONSUMER => self.handle_register(incoming),
            broker::UNREGISTER_CONSUMER => self.handle_unregister(incoming),
            broker::RELAY_FRAME => self.handle_relay(incoming),
            _ => vec![status::BAD_REQUEST],
        }
    }

    fn handle_register(&mut self, incoming: &Incoming) -> Vec<u8> {
        let Some(reg) = broker::decode_register(&incoming.data) else {
            return vec![status::BAD_REQUEST];
        };
        // Build a per-bus Filter from the pushed rules. The bus byte selects which
        // slot (session/system) the rules populate.
        let rules = BusRules {
            talk: reg.talk,
            call: reg.call,
            broadcast: reg.broadcast,
            own: reg.own,
            deny_talk: reg.deny_talk,
        };
        let filter = if reg.bus == kennel_lib_binder::service::dbus::SESSION {
            Filter {
                session: Some(rules),
                system: None,
            }
        } else {
            Filter {
                session: None,
                system: Some(rules),
            }
        };
        self.consumers
            .insert((reg.consumer_id, reg.bus), ConsumerEntry { filter });
        eprintln!(
            "dbus-broker: registered consumer ctx={} bus={}",
            reg.consumer_id, reg.bus,
        );
        vec![status::OK]
    }

    fn handle_unregister(&mut self, incoming: &Incoming) -> Vec<u8> {
        let Some((consumer_id, bus)) = broker::decode_unregister(&incoming.data) else {
            return vec![status::BAD_REQUEST];
        };
        if self.consumers.remove(&(consumer_id, bus)).is_some() {
            eprintln!("dbus-broker: unregistered consumer ctx={consumer_id} bus={bus}");
            vec![status::OK]
        } else {
            vec![status::NOT_FOUND]
        }
    }

    fn handle_relay(&self, incoming: &Incoming) -> Vec<u8> {
        let Some((consumer_id, bus, frame)) = broker::decode_relay(&incoming.data) else {
            return vec![status::BAD_REQUEST];
        };
        let Some(consumer) = self.consumers.get(&(consumer_id, bus)) else {
            return vec![status::NOT_FOUND];
        };
        // Frame relay is not yet implemented: the consumer filter is registered and the wire
        // path is in place, but the frame is not parsed, run through `consumer.filter.decide()`,
        // or forwarded to the real D-Bus bus. D-Bus mediation flows through kenneld's legacy
        // host-dbus delegate until this is built; the broker is dormant unless selected.
        let _ = &consumer.filter;
        let _ = frame;
        vec![status::OK]
    }
}

fn run() -> io::Result<()> {
    eprintln!("dbus-broker: starting");

    // Open the mesh binder device (bind-mounted into our view by kenneld).
    let device_fd = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(MESH_DEVICE)?;

    // Become a binder client on the mesh bus.
    let conn = Connection::open(device_fd.into(), MAP_SIZE)?;

    // Register our control node via ADD_SERVICE on node 0 of the mesh bus.
    // transact_node sends our binder node alongside the name bytes; the context
    // manager (kenneld) acquires the translated handle.
    let name_bytes = kennel_lib_binder::service::mesh::encode_add_service(SERVICE_NAME);
    conn.transact_node(
        0, // node-0 of the mesh bus = kenneld
        kennel_lib_binder::service::verb::ADD_SERVICE,
        &name_bytes,
        1, // node_ptr: arbitrary non-zero local pointer for our service node
        0, // node_cookie
        0, // node_flags
    )?;
    eprintln!("dbus-broker: registered service `{SERVICE_NAME}` on mesh bus");

    // Enter the binder server loop: sleep for incoming transactions, wake, process.
    conn.enter_looper()?;
    let mut state = Broker::new();
    loop {
        if !conn.poll(POLL_MS)? {
            continue; // idle poll cycle — no work
        }
        for incoming in conn.recv()? {
            let reply_data = state.handle(&incoming);
            let _ = conn.reply_and_free(&incoming, &reply_data);
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dbus-broker: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broker_lifecycle() {
        let mut broker = Broker::new();

        // 1. REGISTER_CONSUMER
        let talk = vec!["org.freedesktop.DBus".to_owned()];
        let reg_data = kennel_lib_binder::service::broker::encode_register(
            42,                                        // consumer_id
            kennel_lib_binder::service::dbus::SESSION, // bus
            &talk,
            &[],
            &[],
            &[],
            &[],
        );
        let incoming_reg = Incoming {
            code: broker::REGISTER_CONSUMER,
            data: reg_data,
            fds: Vec::new(),
            sender_pid: 100,
            sender_euid: 1000,
            buffer: 0,
        };
        let reply_reg = broker.handle(&incoming_reg);
        assert_eq!(reply_reg, vec![status::OK]);

        // 2. RELAY_FRAME (registered consumer)
        let relay_data = kennel_lib_binder::service::broker::encode_relay(
            42,
            kennel_lib_binder::service::dbus::SESSION,
            &[0x01, 0x02, 0x03],
        );
        let incoming_relay = Incoming {
            code: broker::RELAY_FRAME,
            data: relay_data,
            fds: Vec::new(),
            sender_pid: 100,
            sender_euid: 1000,
            buffer: 0,
        };
        let reply_relay = broker.handle(&incoming_relay);
        assert_eq!(reply_relay, vec![status::OK]);

        // 3. UNREGISTER_CONSUMER
        let unreg_data = kennel_lib_binder::service::broker::encode_unregister(
            42,
            kennel_lib_binder::service::dbus::SESSION,
        );
        let incoming_unreg = Incoming {
            code: broker::UNREGISTER_CONSUMER,
            data: unreg_data,
            fds: Vec::new(),
            sender_pid: 100,
            sender_euid: 1000,
            buffer: 0,
        };
        let reply_unreg = broker.handle(&incoming_unreg);
        assert_eq!(reply_unreg, vec![status::OK]);

        // 4. RELAY_FRAME (unregistered consumer)
        let reply_relay_post = broker.handle(&incoming_relay);
        assert_eq!(reply_relay_post, vec![status::NOT_FOUND]);
    }
}
