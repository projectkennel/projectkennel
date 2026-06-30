//! `facade-spawn-probe` — the in-kennel `SPAWN` round-trip probe (`02-10` §7.12).
//!
//! The reference in-kennel `SPAWN` client and the workload of the `spawn-roundtrip` policy-suite
//! case. It opens the kennel's node 0, transacts [`verb::SPAWN`] for an operator-signed echo
//! template, receives the two channel ends the daemon mints (the bidirectional JSON-RPC socketpair
//! local end + the `stderr` pipe read end), and proves the channel reaches a *running sibling*: it
//! writes a probe to the socketpair and reads it back — the spawned tool (`/bin/cat`) echoes its
//! stdin to its stdout, which is the same socketpair end. Exit 0 iff the byte-exact round-trip holds.
//!
//! This is the workload-side half of dynamic spawn: a confined agent holds neither network nor a
//! second capability, but can ask `kenneld` to instantiate a scoped sibling and talk to it over the
//! returned fds. No host privilege, no JSON — `kenneld` brokers the fds and steps out of the byte path.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{spawn, status, verb};

/// The binder buffer mapping size for the probe's node-0 client.
const MAP_SIZE: usize = 128 * 1024;
/// The in-view binder device (the seal mounts the per-kennel binderfs here; §7.1).
const DEVICE: &str = "/dev/binderfs/binder";
/// The bytes round-tripped through the spawned tool.
const PROBE: &[u8] = b"kennel-spawn-roundtrip\n";

fn main() -> ExitCode {
    // `argv[1]` is the template to spawn (default `echo-tool`); the requester's `[spawn]` grant
    // must allow it, or `kenneld` denies the SPAWN.
    let template = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "echo-tool".to_owned());
    match round_trip(&template) {
        Ok(()) => {
            println!("facade-spawn-probe: SPAWN round-trip OK ({template})");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("facade-spawn-probe: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Spawn `template`, then write [`PROBE`] to the channel and read it back from the running sibling.
fn round_trip(template: &str) -> io::Result<()> {
    let request = spawn::encode_request(template, &[]);
    let fd = OpenOptions::new().read(true).write(true).open(DEVICE)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    let (reply, mut fds) = conn.transact_with_fds(CONTEXT_MANAGER_HANDLE, verb::SPAWN, &request)?;

    let code = reply
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("empty SPAWN reply"))?;
    if code != status::OK {
        return Err(io::Error::other(format!(
            "SPAWN refused: status {code} (grant/pin/eligibility/ceiling — see kenneld audit)"
        )));
    }
    // Two ends, in order: the socketpair local (the tool's stdin+stdout) and the stderr pipe read.
    if fds.len() != 2 {
        return Err(io::Error::other(format!(
            "expected 2 channel fds in the reply, got {}",
            fds.len()
        )));
    }
    let rpc = UnixStream::from(fds.swap_remove(0));

    // Write the probe and half-close: the spawned `cat` reads stdin to EOF, echoes it to stdout (the
    // same socketpair end), and exits — so the read below returns the echo then EOF.
    (&rpc).write_all(PROBE)?;
    rpc.shutdown(Shutdown::Write)?;
    let mut echoed = Vec::new();
    (&rpc).read_to_end(&mut echoed)?;
    if echoed != PROBE {
        return Err(io::Error::other(format!(
            "channel echo mismatch: wrote {} bytes, read back {} bytes",
            PROBE.len(),
            echoed.len()
        )));
    }
    Ok(())
}
