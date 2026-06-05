# §7.5 Policy surface: D-Bus (proxied)

D-Bus is proxied, not granted directly. If a kennel needs D-Bus access, Project Kennel launches an `xdg-dbus-proxy` instance per kennel that enforces a per-method allowlist between the kennel and the real bus. The proxy's socket is shimmed into the kennel as the standard bus path. Without explicit policy enabling it, no bus socket exists in the kennel's view.

## 7.5.1 Direct D-Bus access

A bare socket grant for `$XDG_RUNTIME_DIR/bus` gives the kennel every D-Bus service the user's session offers. The default session bus has dozens of services connected: notification daemon, network manager, gnome-shell or kwin, file manager, screen lock, login manager, systemd user, secret service, evolution, tracker, packagekit, polkit agent. Each exposes methods that can:

- Read or write files via file-manager method calls.
- Spawn processes via `org.freedesktop.systemd1.Manager.StartTransientUnit`.
- Set environment variables in the user's session.
- Inhibit screen lock or trigger logout.
- Send notifications appearing to come from any application (phishing the user).
- Access secrets via `org.freedesktop.secrets`.
- Mount filesystems via `org.freedesktop.UDisks2`.
- Control NetworkManager (connect to attacker's wifi, configure DNS).

A kennel with `$XDG_RUNTIME_DIR/bus` access has essentially the same capability as the unconfined user session, by virtue of being able to ask the user's session to do things on its behalf. D-Bus is the largest single capability surface on a typical Linux desktop and direct grants are categorically wrong for kennels.

## 7.5.2 The proxy: xdg-dbus-proxy

`xdg-dbus-proxy` is the right tool, already exists, audited, and used at scale by Flatpak. It is a small daemon that:

- Accepts D-Bus client connections on a unix socket (the kennel's shim path).
- Maintains its own connection to the real bus.
- Filters every method call, signal, property access against a rules list.
- Translates between the client's view and the real bus.
- Can talk multiple bus connections at once (session, system, accessibility).

Rules are bus-name + path + interface + member granularity:

```
--talk=org.freedesktop.Notifications      # allow this service
--call=org.freedesktop.portal.*=*         # allow all calls to portal
--broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*
--own=net.example.MyApp                   # may own this name
```

Default deny. Anything not listed is rejected with `org.freedesktop.DBus.Error.AccessDenied`. Project Kennel configures the proxy from structured policy and reads the proxy's audit log.

## 7.5.3 How it slots in

Same architectural shape as the SOCKS5 proxy (§7.3). Per kennel:

```
Host view:
  /run/kennel/<ctx>/dbus-session.sock
       ← xdg-dbus-proxy listens here
         proxy connects to user's real $DBUS_SESSION_BUS_ADDRESS

Context view (via §7.4 shim):
  $XDG_RUNTIME_DIR/bus
       ← bind-mount from dbus-session.sock
         DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
```

The proxy process runs in the host mount namespace with the real `$DBUS_SESSION_BUS_ADDRESS`. The bind mount exposes its socket to the kennel as the standard path. Applications open `$XDG_RUNTIME_DIR/bus`, find the proxy, the proxy filters and forwards.

System bus gets a second proxy instance:

```
/run/kennel/<ctx>/dbus-system.sock
       ← second xdg-dbus-proxy, talks to /var/run/dbus/system_bus_socket
```

Shimmed to `/run/dbus/system_bus_socket` inside the kennel.

## 7.5.4 Policy primitives

```toml
[dbus]
session.enabled = true             # if false, no session bus at all (default)
system.enabled = false             # system bus rarely needed

[dbus.session.allow]
# Names the kennel may TALK to (call methods, receive responses)
talk = [
    "org.freedesktop.Notifications",
    "org.freedesktop.portal.*",   # the portal family (file picker, etc)
]
# Specific method calls (finer than talk)
call = []
# Broadcast signals the kennel may receive
broadcast = []
# Names the kennel may OWN (claim on the bus)
own = []                          # almost always empty for kennels

[dbus.session.deny]
# Belt and braces; rules above are already allowlists, but explicit deny
# protects against accidental overrides in user deltas.
talk = [
    "org.gnome.SessionManager",
    "org.freedesktop.login1",
    "org.freedesktop.systemd1",
    "org.freedesktop.secrets",
    "org.freedesktop.UDisks2",
    "org.freedesktop.NetworkManager",
]

[dbus.system.allow]
talk = []                         # default: nothing on system bus

[dbus.audit]
log_path = "~/.local/state/kennel/<kennel>/dbus.jsonl"
level = "summary"                 # "off" | "summary" | "full"
```

The user writes structured policy. Project Kennel emits the appropriate `--talk=`, `--call=`, `--broadcast=`, `--own=`, `--see=`, `--filter` flags to `xdg-dbus-proxy`. The user does not write proxy command lines directly.

## 7.5.5 The portal pattern

`org.freedesktop.portal.*` is worth special attention. Flatpak's portal system is the *intended* way for sandboxed applications to access user resources (files, screenshots, location, camera). Portals run in the user's session, present user-mediated dialogs, and return results to the sandboxed caller.

Templates that need file-open dialogs, screenshot capability, or camera access should allow the portal family rather than granting the underlying resources directly. The portal dialog is user-mediated: the user sees what's being accessed and approves it. This is meaningfully different from granting the resource itself.

Caveats:

- Portal implementation varies between desktop environments (GNOME, KDE, others). Some portals are missing on some DEs.
- Portal access from non-Flatpak kennels is supported but less battle-tested.
- The portal itself is on the session bus, so `dbus.session.enabled = true` is a prerequisite. This is the smallest legitimate D-Bus grant.

For kennels that need portals only and nothing else:

```toml
[dbus]
session.enabled = true
system.enabled = false

[dbus.session.allow]
talk = ["org.freedesktop.portal.*"]
own = []
```

This is approximately the Flatpak default and a reasonable starting point.

## 7.5.6 Notifications: a worked case

The kennel wants to show desktop notifications (build complete, test failed, AI agent finished). This is one of the simpler legitimate D-Bus grants:

```toml
[dbus]
session.enabled = true

[dbus.session.allow]
talk = ["org.freedesktop.Notifications"]
```

This allows method calls to `org.freedesktop.Notifications` only. The proxy will:

- Forward `Notify()` calls.
- Forward responses.
- Block `NotificationClosed` and `ActionInvoked` signals from other applications (the kennel only sees signals for its own notifications).
- Block any other service the kennel might try to reach.

The capability granted: the kennel can pop notifications. The capabilities not granted: anything else on the session bus.

Worth noting: the notification daemon itself may execute actions on user clicks ("open file", "reply"). The kennel's notification can specify actions; the user's click triggers them in the user's session, not the kennel's. This is a path by which the kennel could trick the user into running something — for instance, a notification action labelled "Click to fix" that actually opens a malicious URL. Templates should consider this carefully; it is not a flaw in the proxy design, it is the inherent property of a user-facing notification capability.

## 7.5.7 Template defaults

Most confined templates: `dbus.session.enabled = false`. The kennel has no bus socket; tools that try to connect fail at the shim layer (no socket file there).

Templates that need notifications: enable session bus, allow only Notifications.

Templates that need file dialogs or screenshots: enable session bus, allow only portals.

Templates that need a full desktop integration story (rare for kennels): document loudly that this approximates the unconfined session capability and that the threat model is correspondingly weakened.

No templates should grant `org.freedesktop.systemd1` or `org.gnome.SessionManager` to kennels. These are categorically too powerful.

## 7.5.8 Operational concerns

**The proxy is a daemon.** One per kennel (plus a system-bus proxy if enabled). On modern hardware these are inexpensive (~5 MB resident each) but they accumulate if kennel lifecycles are not managed. Framework supervises lifecycle.

**Bus reconnection.** If the host's dbus-daemon restarts, the proxy reconnects and continues serving the kennel. The kennel's bus connection survives the host bus restart because the kennel's connection terminates at the proxy.

**Audit volume.** D-Bus is chatty. Even a minimal session generates dozens of method calls per minute (status updates, property checks). `level = "summary"` logs first-and-last-of-kind events; `level = "full"` logs every call. Default to summary; full is for debugging.

**Activation services.** Some D-Bus services are activated on demand (`Type=Activation` units). The proxy must allow `org.freedesktop.DBus.StartServiceByName` for services the kennel is allowed to talk to. Project Kennel handles this automatically when emitting proxy config.

## 7.5.9 Failure modes

| Situation | Behaviour |
|---|---|
| Proxy crashes | Bus socket in the kennel becomes unresponsive; clients see connection errors. Project Kennel restarts proxy. |
| Real bus rejects proxy's connection | Proxy retries with backoff; logs warning. Context sees timeouts on bus operations. |
| Policy denies a method call | Client receives `org.freedesktop.DBus.Error.AccessDenied`. Audit logs the deny. |
| Context tries to own a name not in `own` list | `RequestName` returns DBUS_REQUEST_NAME_REPLY_NOT_ALLOWED. |
| `dbus.session.enabled = false` but client tries to connect | Connection to bus socket fails (no socket in shim). Standard "cannot connect to bus" error. |

## 7.5.10 Test plan

For each invariant, a regression test in `tests/dbus/`:

1. Context with `dbus.session.enabled = false`: `dbus-send --session --list-names` fails with "cannot autolaunch D-Bus".
2. Context with notifications allowed: `notify-send "test"` succeeds.
3. Same kennel: `dbus-send --session --dest=org.gnome.SessionManager ...` fails with AccessDenied.
4. Context with portal allowed: a portal call returns successfully via the proxy.
5. Context with portal allowed: a direct call to `org.freedesktop.secrets` is denied.
6. Audit log records the denied calls with full method name and timestamp.
7. Proxy survives a restart of the host dbus-daemon (kennel's bus client may briefly stall but eventually recovers).
8. `dbus.system.enabled = false`: any system-bus operation fails (no socket).
9. Context attempts to `RequestName` for a name not in `own`; returns NOT_ALLOWED.
10. Activation service in allowed `talk` list is autolaunched correctly via the proxy.

Approximately 15 cases in the full corpus.
