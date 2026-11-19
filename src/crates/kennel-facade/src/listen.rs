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
    let _ = path;
    todo!("facade readiness (D-Bus race)")
}

/// Report readiness to `kennel-bin-init`: if this facade is gated (`KENNEL_READY_FD` set by init),
/// write one byte to that fd. Call once, after every listener is bound. Ungated ⇒ a no-op.
///
/// # Errors
///
/// The OS error if the readiness fd cannot be written.
pub fn signal_ready() -> io::Result<()> {
    signal_ready_to(
        std::env::var(kennel_lib_syscall::ready::READY_ENV)
            .ok()
            .as_deref(),
    )
}

/// [`signal_ready`] with the environment value injected (testable). `fd` is the decimal fd
/// number; it is written through `/proc/self/fd/<n>` so this crate stays `unsafe`-free.
fn signal_ready_to(fd: Option<&str>) -> io::Result<()> {
    let _ = fd;
    todo!("facade readiness (D-Bus race)")
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
    fn signal_ready_writes_one_byte_to_the_named_fd() {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        let (r, w) = kennel_lib_syscall::ready::pipe().expect("pipe");
        signal_ready_to(Some(&w.as_raw_fd().to_string())).expect("signal");
        drop(w);
        let mut got = Vec::new();
        std::fs::File::from(r).read_to_end(&mut got).expect("read");
        assert_eq!(got, vec![1u8]);
    }

    #[test]
    fn signal_ready_is_a_no_op_when_ungated() {
        signal_ready_to(None).expect("no env ⇒ nothing to do");
    }

    #[test]
    fn signal_ready_refuses_a_malformed_fd() {
        assert!(signal_ready_to(Some("not-a-number")).is_err());
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
