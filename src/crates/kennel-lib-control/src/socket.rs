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
use std::path::{Component, Path, PathBuf};

/// kenneld's per-user runtime directory: `$XDG_RUNTIME_DIR/kennel`, falling back
/// to `/run/user/<uid>/kennel`. Holds the control socket and per-kennel proxy
/// configs.
#[must_use]
pub fn runtime_dir() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || {
            PathBuf::from(format!(
                "/run/user/{}",
                kennel_lib_syscall::unistd::real_uid()
            ))
        },
        PathBuf::from,
    );
    runtime.join("kennel")
}

/// The control socket's path: `<runtime_dir>/control.sock`.
#[must_use]
pub fn socket_path() -> PathBuf {
    runtime_dir().join("control.sock")
}

/// Lexically normalise `p` — fold `.`/`..`/redundant separators **without touching the filesystem**.
///
/// Works on a path that does not exist yet, and is not fooled by a `..` disguise (so a grant of
/// `…/kennel/../kennel/control.sock` normalises to the socket). Runtime symlink and mount resolution
/// is deliberately *not* done here — that is the construction-time guard's job, against the real
/// endpoint; here we catch the path-string disguises an install-time check can see.
#[must_use]
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Whether `candidate` names a kenneld **control socket** — the CLI→daemon trust boundary (§socket
/// docs), whose reachability from inside a kennel is privilege escalation.
///
/// A grant resolving here is refused **by rule**, not merely kept out by construction-by-absence
/// (W10): it joins the structurally-refused-regardless-of-policy set. The check compares the
/// *lexically-normalised* candidate (so a `..`-disguised path-string is caught, not just an exact
/// string) against this user's control socket, and against the structural
/// `/run/user/<uid>/kennel/control.sock` form so a policy authored under a different runtime dir is
/// caught too. Runtime symlink / cascade-mount disguises are the construction-time backstop's job.
#[must_use]
pub fn is_control_socket(candidate: &Path) -> bool {
    let norm = lexical_normalize(candidate);
    if norm == socket_path() {
        return true;
    }
    // Structural `/run/user/<digits>/kennel/control.sock` — a control socket for *any* uid (no
    // legitimate policy names one). Match on components, not a substring, so it cannot over- or
    // under-catch on a path that merely contains the text.
    let comps: Vec<Component<'_>> = norm.components().collect();
    if let [Component::RootDir, run, user, uid, kennel, sock] = comps.as_slice() {
        return run.as_os_str() == "run"
            && user.as_os_str() == "user"
            && uid
                .as_os_str()
                .to_str()
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            && kennel.as_os_str() == "kennel"
            && sock.as_os_str() == "control.sock";
    }
    false
}

/// Whether granting `candidate` as a filesystem bind would **expose** a control socket — i.e.
/// `candidate` is the socket itself or any ancestor directory that contains it.
///
/// [`is_control_socket`] guards the `[[unix.allow]]` path, which names the socket *leaf*. A
/// filesystem grant (`fs.read`/`fs.write`) instead names a *directory*, and binding a directory
/// exposes everything beneath it — so granting `/run/user/<uid>/kennel` (or `/run/user/<uid>`,
/// or `/run`) drags the control socket into the view even though none of those *is* the socket.
/// This is the ancestor-aware form the fs gate needs: the control socket is ungrantable by rule
/// (the CLI→daemon trust boundary, §socket docs / W10), so any grant that would expose it is
/// refused. Matches both this user's real socket (covering a non-standard `$XDG_RUNTIME_DIR`) and
/// the structural `/run/user/<digits>/kennel/control.sock` chain for any uid. Lexical only;
/// runtime symlink / cascade-mount disguises of a bind *source* are the construction-time guard's
/// job (the deferred anchored bind-source resolution).
#[must_use]
pub fn grant_exposes_control_socket(candidate: &Path) -> bool {
    // Structural chain for ANY uid: `norm`'s components must be a *prefix* of
    // `/run/user/<digits>/kennel/control.sock`, so every ancestor (`/run`, `/run/user`,
    // `/run/user/<n>`, `…/kennel`) and the socket itself are caught.
    const CHAIN: [&str; 5] = ["run", "user", "<uid>", "kennel", "control.sock"];
    let norm = lexical_normalize(candidate);
    // This user's real socket: `norm` is an ancestor-or-equal of it (component-wise `starts_with`).
    if socket_path().starts_with(&norm) {
        return true;
    }
    let mut comps = norm.components();
    if comps.next() != Some(Component::RootDir) {
        return false; // not absolute — cannot be an ancestor of the absolute socket path
    }
    for (depth, c) in comps.enumerate() {
        let Some(label) = CHAIN.get(depth) else {
            return false; // longer than the chain — not an ancestor
        };
        let seg = c.as_os_str();
        let ok = match *label {
            "<uid>" => seg
                .to_str()
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
            lit => seg == lit,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Obtain the control listener: the socket-activation fd if present, else a
/// freshly-bound socket at [`socket_path`].
///
/// # Errors
/// An OS error if creating the socket directory, removing a stale socket, or
/// binding fails.
pub fn listener() -> io::Result<UnixListener> {
    if let Some(fd) = kennel_lib_syscall::listenfd::take_listener() {
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
    fn is_control_socket_matches_the_structural_form_and_lexical_disguises() {
        // The structural `/run/user/<uid>/kennel/control.sock`, any uid.
        assert!(is_control_socket(Path::new(
            "/run/user/1000/kennel/control.sock"
        )));
        assert!(is_control_socket(Path::new(
            "/run/user/0/kennel/control.sock"
        )));
        // A `..`-disguised path-string normalises to the socket and is caught.
        assert!(is_control_socket(Path::new(
            "/run/user/1000/kennel/../kennel/control.sock"
        )));
        assert!(is_control_socket(Path::new(
            "/run/user/1000/./kennel/control.sock"
        )));
    }

    #[test]
    fn is_control_socket_does_not_overcatch() {
        // The kennel's own Node 0 is established by kenneld at construction, never a grant — it must
        // NOT be caught (a workload legitimately reaches Node 0).
        assert!(!is_control_socket(Path::new("/dev/binderfs/binder")));
        // A non-digit uid, a sibling socket, an extra component, a non-runtime parent: all distinct.
        assert!(!is_control_socket(Path::new(
            "/run/user/abc/kennel/control.sock"
        )));
        assert!(!is_control_socket(Path::new(
            "/run/user/1000/kennel/agent.sock"
        )));
        assert!(!is_control_socket(Path::new(
            "/run/user/1000/kennel/sub/control.sock"
        )));
        assert!(!is_control_socket(Path::new("/home/u/kennel/control.sock")));
        assert!(!is_control_socket(Path::new("/run/user/1000/control.sock")));
    }

    #[test]
    fn grant_exposing_the_control_socket_is_refused_at_every_ancestor() {
        // The socket itself, and every directory ancestor that would drag it into a view, are all
        // refused — this is the fs-grant gap the unix.allow leaf-check missed (W15 F1).
        for p in [
            "/run/user/1000/kennel/control.sock",
            "/run/user/1000/kennel",
            "/run/user/1000",
            "/run/user",
            "/run",
            "/",
            "/run/user/0/kennel",              // any uid, not just this one
            "/run/user/1000/kennel/../kennel", // `..`-disguised ancestor
        ] {
            assert!(
                grant_exposes_control_socket(Path::new(p)),
                "{p} should be refused — it exposes the control socket"
            );
        }
    }

    #[test]
    fn grant_does_not_overcatch_sibling_or_unrelated_paths() {
        // A sibling runtime subtree, a non-digit uid, a deeper non-socket path, an unrelated tree,
        // and a relative path must all pass — only paths that genuinely expose the socket are caught.
        for p in [
            "/run/systemd",
            "/run/user/abc/kennel",
            "/run/user/1000/kennel/agent.sock",
            "/run/user/1000/proxy",
            "/home/u/work",
            "/usr/share",
            "run/user/1000/kennel", // not absolute → not an ancestor of the absolute socket
        ] {
            assert!(
                !grant_exposes_control_socket(Path::new(p)),
                "{p} should pass — it does not expose the control socket"
            );
        }
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
