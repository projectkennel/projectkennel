//! The control socket: its location and how the daemon obtains the listener.
//!
//! kenneld is socket-activated (systemd passes the bound listener as fd 3), which
//! is what makes "start on first `kennel run`, persist for the session" work
//! without runtime shelling-out. When not socket-activated (development, or
//! systemd-less hosts) it binds its own socket at the same path, so it always
//! runs. The path is per-user under `$XDG_RUNTIME_DIR` (`/run/user/<uid>`), which
//! the session owns and the system clears at logout.

use std::io;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

/// kenneld's per-user runtime directory: `$XDG_RUNTIME_DIR/kennel`, falling back
/// to `/run/user/<uid>/kennel`. Holds the control socket and per-kennel proxy
/// configs.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/run/user/{}", kennel_syscall::unistd::real_uid())),
        PathBuf::from,
    );
    runtime.join("kennel")
}

/// The control socket's path: `<runtime_dir>/control.sock`.
#[must_use]
pub fn socket_path() -> PathBuf {
    runtime_dir().join("control.sock")
}

/// Obtain the control listener: the socket-activation fd if present, else a
/// freshly-bound socket at [`socket_path`].
///
/// # Errors
/// An OS error if creating the socket directory, removing a stale socket, or
/// binding fails.
pub fn listener() -> io::Result<UnixListener> {
    if let Some(fd) = kennel_syscall::listenfd::take_listener() {
        return Ok(UnixListener::from(fd));
    }
    bind(&socket_path())
}

/// Bind a fresh control socket at `path`, creating its parent directory and
/// removing any stale socket first.
fn bind(path: &std::path::Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A leftover socket from a previous run would make bind fail with EADDRINUSE.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    UnixListener::bind(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_is_under_the_runtime_dir() {
        let path = socket_path();
        assert!(
            path.ends_with("kennel/control.sock"),
            "got {}",
            path.display()
        );
    }

    #[test]
    fn bind_creates_and_replaces_the_socket() {
        let dir = std::env::temp_dir().join(format!("kenneld-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("kennel").join("control.sock");

        let first = bind(&path).expect("bind once");
        assert!(path.exists(), "the socket file should exist");
        drop(first);
        // Binding again over the stale socket succeeds (it is removed first).
        let _second = bind(&path).expect("re-bind over stale socket");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
