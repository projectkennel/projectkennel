// SPDX-License-Identifier: Apache-2.0

//! Readiness-atomic `AF_UNIX` listeners for the facades that serve a socket path inside the view
//! (`facade-dbus`, `facade-afunix`).
//!
//! # Purpose
//!
//! `kennel-bin-init` starts the workload only once every gated facade has signalled readiness
//! ([`signal_ready`], `kennel_lib_os::ready`). For that signal to mean "accepting connections", a
//! listener must be listening before it is visible: `UnixListener::bind` creates the node at
//! `bind(2)`, so a client finding the path in
//! the gap would get `ECONNREFUSED`. [`bind_ready`] binds and listens on a temporary name in the same
//! directory, then `rename(2)`s it onto the real path — the path appears already listening.

use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// Bind a listening `AF_UNIX` socket at `path` such that `path` only exists once it is already
/// accepting connections. A stale node at `path` is removed first; the parent directory is created.
///
/// # Errors
///
/// Returns the OS error if the parent cannot be created, or the bind/listen/rename fails.
pub fn bind_ready(path: &Path) -> io::Result<UnixListener> {
    let _ = std::fs::remove_file(path); // a stale node from a prior run
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let staging = staging_name(path);
    let _ = std::fs::remove_file(&staging);
    // `UnixListener::bind` is bind(2) + listen(2): the staging node is already listening when it
    // returns, so after the rename the real path is never visible un-listened.
    let listener = UnixListener::bind(&staging)?;
    std::fs::rename(&staging, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&staging);
    })?;
    Ok(listener)
}

/// Report readiness to `kennel-bin-init`.
///
/// If this facade is gated (`KENNEL_READY_FD` set by init), write one byte to the inherited
/// readiness fd. Call once, after every listener is bound. Ungated ⇒ a no-op.
/// (`kennel_lib_syscall::boot::signal_facade_ready` does the raw-fd write.)
///
/// # Errors
///
/// The OS error if the readiness fd is not the expected one, not open, or cannot be written.
pub fn signal_ready() -> io::Result<()> {
    kennel_lib_syscall::boot::signal_facade_ready(
        std::env::var(kennel_lib_syscall::ready::READY_ENV)
            .ok()
            .as_deref(),
    )
}

/// The temporary name [`bind_ready`] listens on before the rename: a sibling of `path`, so the
/// rename stays within one directory (atomic), and per-process unique.
fn staging_name(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".binding-{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kennel-facade-listen-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_path_appears_already_listening() {
        let dir = scratch("listening");
        let path = dir.join("nested").join("bus.sock");
        let listener = bind_ready(&path).expect("bind_ready creates the parent and binds");
        assert!(path.exists(), "the socket is at its final path");
        assert!(!staging_name(&path).exists(), "the staging name is gone");
        // Connect succeeds immediately — the node only ever existed listening.
        let client = UnixStream::connect(&path).expect("connect");
        let (_server, _) = listener.accept().expect("accept");
        drop(client);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_node_is_replaced() {
        let dir = scratch("stale");
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("bus.sock");
        std::fs::write(&path, b"stale").expect("stale file");
        let _listener = bind_ready(&path).expect("replaces the stale node");
        assert!(UnixStream::connect(&path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_staging_name_is_a_unique_sibling() {
        let p = Path::new("/home/kennel/.kennel-dbus/session");
        let s = staging_name(p);
        assert_eq!(s.parent(), p.parent());
        assert_ne!(s, p);
        assert!(s
            .to_string_lossy()
            .contains(&std::process::id().to_string()));
    }
}
