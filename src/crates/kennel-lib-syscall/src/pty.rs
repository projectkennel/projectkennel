//! PTY allocation and terminal control for interactive kennels.
//!
//! An interactive `kennel run` needs the workload on its **own** pseudo-terminal so
//! it can be a session leader with a controlling tty (job control: `^Z`/`fg`/`bg`).
//! The CLI allocates a pty pair, hands the **slave** to the workload as its stdio,
//! keeps the **master**, puts the real terminal into raw mode, and proxies bytes
//! between them. The workload side calls [`set_controlling_tty`] on the slave.
//!
//! `nix` owns the `unsafe`; the two raw `ioctl`s here (`TIOCGWINSZ`/`TIOCSWINSZ`,
//! `TIOCSCTTY`) have no `nix` wrapper in this version and are the minimal exceptions.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};

pub use nix::pty::Winsize;
pub use nix::sys::termios::Termios;
use nix::sys::termios::{self, SetArg};

/// An allocated pty pair: the master the CLI proxies through, and the slave the
/// workload uses as its controlling terminal.
pub struct Pty {
    /// The master end (CLI side).
    pub master: OwnedFd,
    /// The slave end (workload's stdio / controlling tty).
    pub slave: OwnedFd,
}

/// Allocate a pty pair, sizing the slave to `winsize` if given.
///
/// # Errors
/// The OS error if `openpty` fails.
pub fn open(winsize: Option<&Winsize>) -> io::Result<Pty> {
    let res = nix::pty::openpty(winsize, None).map_err(io::Error::from)?;
    Ok(Pty {
        master: res.master,
        slave: res.slave,
    })
}

/// Read a terminal's window size (`TIOCGWINSZ`).
///
/// # Errors
/// The OS error if the `ioctl` fails (e.g. the fd is not a terminal).
pub fn get_winsize(fd: BorrowedFd<'_>) -> io::Result<Winsize> {
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `ws` is a valid, sized-correctly out-param for TIOCGWINSZ on a fd we own.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &raw mut ws) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ws)
}

/// Set a terminal's window size (`TIOCSWINSZ`) and raise `SIGWINCH` on it.
///
/// # Errors
/// The OS error if the `ioctl` fails.
pub fn set_winsize(fd: BorrowedFd<'_>, ws: &Winsize) -> io::Result<()> {
    // SAFETY: `ws` is a valid TIOCSWINSZ in-param for a terminal fd we own.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, std::ptr::from_ref(ws)) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Put a terminal into raw mode, returning the previous settings for [`restore`].
///
/// Raw mode hands echo, signals, and line editing to the workload's shell rather than
/// this terminal's line discipline.
///
/// # Errors
/// The OS error if `tcgetattr`/`tcsetattr` fails.
pub fn make_raw(fd: BorrowedFd<'_>) -> io::Result<Termios> {
    let previous = termios::tcgetattr(fd).map_err(io::Error::from)?;
    let mut raw = previous.clone();
    termios::cfmakeraw(&mut raw);
    termios::tcsetattr(fd, SetArg::TCSANOW, &raw).map_err(io::Error::from)?;
    Ok(previous)
}

/// Restore a terminal to previously-saved settings (the inverse of [`make_raw`]).
///
/// # Errors
/// The OS error if `tcsetattr` fails.
pub fn restore(fd: BorrowedFd<'_>, previous: &Termios) -> io::Result<()> {
    termios::tcsetattr(fd, SetArg::TCSANOW, previous).map_err(io::Error::from)
}

/// Make the calling process a session leader and adopt `fd` as its controlling tty.
///
/// `setsid` + `TIOCSCTTY`, called on the workload side on the slave pty so its shell
/// gets job control. Safe on a fresh pty — it is no other session's controlling tty.
///
/// # Errors
/// The OS error if `setsid` or the `TIOCSCTTY` `ioctl` fails.
pub fn set_controlling_tty(fd: BorrowedFd<'_>) -> io::Result<()> {
    nix::unistd::setsid().map_err(io::Error::from)?;
    // SAFETY: TIOCSCTTY with arg 0 (do not steal another session's tty); `fd` is the
    // fresh slave pty and we are now a session leader after `setsid`.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSCTTY, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The fixed descriptor at which `kennel-bin-init` finds the interactive pty **return socket**.
///
/// `kennel-bin-init` is `fexecve`'d with empty argv, so it cannot be told a descriptor number on
/// the command line. For an interactive run the privhelper factory places the return socket
/// (over which the workload's pty master is sent back to the CLI) at this well-known fd before
/// the `fexecve`, and the seal passes it to [`setup_view_pty`] when the supervision-half says
/// the run is interactive (`07-2`/`07-9`). 0/1/2 are stdio; 3 is the first free slot.
pub const PTY_RETURN_FD: RawFd = 3;

/// Allocate a controlling pty from the current mount namespace's `/dev/ptmx`.
///
/// Makes its slave this process's controlling terminal and stdio, and hands the
/// master back to the caller's controller over `return_fd` (a connected socket).
/// This is the in-view counterpart of [`adopt_stdin_as_controlling_tty`]. Called
/// from the spawn seal *after* `pivot_root`, so `/dev/ptmx` resolves to the
/// kennel's own freshly-mounted, isolated `devpts` — the slave is therefore a node
/// that exists in the workload's view, so `ttyname(3)` (the `tty` command, and any
/// program that resolves the terminal's *path*) resolves it. A pty the controller
/// allocated on the host would not: its node lives in the host `devpts`, absent
/// from the view. The master travels back over `SCM_RIGHTS` so the controller can
/// proxy the user's terminal to it.
///
/// Sequence: `openpty` (view `devpts`) → `setsid` (best-effort) → `TIOCSCTTY` on
/// the slave → send the master over `return_fd` → `dup2` the slave onto fds 0/1/2.
///
/// # Errors
/// The OS error if `openpty`, `TIOCSCTTY`, the master hand-off, or `dup2` fails.
pub fn setup_view_pty(return_fd: RawFd) -> io::Result<()> {
    let p = open(None)?;
    // Become a session leader so we may claim a controlling terminal. Best-effort:
    // if we already lead a session `setsid` is EPERM, and `TIOCSCTTY` still works.
    let _ = nix::unistd::setsid();
    // SAFETY: TIOCSCTTY with arg 0 (never steal another session's tty); `p.slave` is
    // a fresh slave and we attempted to lead a session above.
    let rc = unsafe { libc::ioctl(p.slave.as_raw_fd(), libc::TIOCSCTTY, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // Hand the master back to the controller (the CLI), which proxies the real
    // terminal to it. One data byte is required by the SCM_RIGHTS contract.
    // SAFETY: `return_fd` is the connected socket the controller passed in; we only
    // borrow it for this send.
    let ret = unsafe { BorrowedFd::borrow_raw(return_fd) };
    crate::scm::send_with_fds(ret, &[0u8], &[p.master.as_fd()])?;
    // The slave becomes the workload's stdio. dup2 leaves fds 0/1/2 as independent
    // copies, so dropping `p` (master + the original slave fd) at end of scope keeps
    // them open.
    let slave = p.slave.as_fd();
    nix::unistd::dup2_stdin(slave).map_err(io::Error::from)?;
    nix::unistd::dup2_stdout(slave).map_err(io::Error::from)?;
    nix::unistd::dup2_stderr(slave).map_err(io::Error::from)?;
    Ok(())
}

/// Whether `fd` is a terminal (`isatty`).
#[must_use]
pub fn is_terminal(fd: BorrowedFd<'_>) -> bool {
    nix::unistd::isatty(fd).unwrap_or(false)
}

/// Block `SIGWINCH` in the calling thread so [`relay_winch`] can `sigwait` it.
///
/// Call once on the main thread before spawning the relay — threads spawned afterwards
/// inherit the block, and the default disposition will not fire.
///
/// # Errors
/// The OS error if the signal mask cannot be set.
pub fn block_winch() -> io::Result<()> {
    let mut set = nix::sys::signal::SigSet::empty();
    set.add(nix::sys::signal::Signal::SIGWINCH);
    set.thread_block().map_err(io::Error::from)
}

/// Relay terminal-resize events forever: `sigwait` `SIGWINCH`, copy `from`'s window
/// size onto `to`, repeat.
///
/// Run on a dedicated thread after [`block_winch`]. Takes owned fds for the thread's
/// `'static` bound (it borrows them each iteration); returns on a `sigwait` error.
#[allow(clippy::needless_pass_by_value)] // the spawned thread owns the fds for its lifetime
pub fn relay_winch(from: OwnedFd, to: OwnedFd) {
    let mut set = nix::sys::signal::SigSet::empty();
    set.add(nix::sys::signal::Signal::SIGWINCH);
    loop {
        if set.wait().is_err() {
            return;
        }
        if let Ok(ws) = get_winsize(from.as_fd()) {
            let _ = set_winsize(to.as_fd(), &ws);
        }
    }
}

/// If stdin (fd 0) is a terminal, adopt it as the controlling tty — best-effort.
///
/// Called from the spawn seal; lives here so the `unsafe` fd-0 borrow stays in this
/// crate, not the `unsafe`-free spawn crate.
pub fn adopt_stdin_as_controlling_tty() {
    // SAFETY: fd 0 is the workload's stdin, dup'd into place by std before the seal
    // runs; we only borrow it for the duration of these calls.
    let stdin = unsafe { BorrowedFd::borrow_raw(0) };
    if is_terminal(stdin) {
        let _ = set_controlling_tty(stdin);
    }
}
