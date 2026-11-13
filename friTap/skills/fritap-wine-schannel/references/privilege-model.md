# Wine GDB route: privilege model

Source: `docs/platforms/wine.md` ("Who runs as whom under `sudo`"),
`friTap/legacy/ssl_logger_core.py` (`_wine_gdb_run_as`),
`agent_gdb/wine/wine_key_extract.py` (`unprivileged_gdb_blocker`).

## Three ways to run

| Goal | Command shape | Needs |
|------|---------------|-------|
| Keys only, no root | `fritap -s -k keys.log wine app.exe` | `ptrace_scope=0`, run as prefix owner |
| Keys + full capture | `sudo fritap -s -k keys.log -p cap.pcapng -f wine app.exe` | `sudo`; `ptrace_scope=0` optional |
| Keys + full capture, no sudo | `setcap` on a dedicated interpreter + `ptrace_scope=0` | see below |

```bash
fritap -s -k keys.log wine /path/to/app.exe
sudo fritap -s -k keys.log -p cap.pcapng -f wine /path/to/app.exe
```

## Under sudo

- Wine (spawn mode) runs as the invoking user from `SUDO_UID`/`SUDO_GID`,
  with that user's `HOME`, so `~/.wine` keeps working.
- The sniffer, the `/proc` scan, `SIGSTOP`/`SIGCONT` and teardown stay root.
- gdb parses untrusted target memory and runs Python, so friTap drops it to
  the invoking user when **all** of these hold:
  - `kernel.yama.ptrace_scope` is `0` or Yama is absent. With `1`
    (Ubuntu/Debian default) an unprivileged tracer may only attach to its own
    descendants, and Wine was started by friTap, not gdb. `2` allows root
    only, `3` nobody.
  - The target belongs to that user (always true in spawn mode; checked in
    attach mode).
  - The user can read friTap's gdb script directory (fails when friTap is
    installed under `/root`).
  - The user can write the keylog. A missing keylog is created owned by the
    user; an existing root-owned keylog blocks the drop.
- Log lines: `Running gdb as <user> (uid N); kernel.yama.ptrace_scope=0 allows
  an unprivileged attach.` or `Keeping gdb as root: <reason>`. Key extraction
  works in both cases.

## Root shell or su

There is no `SUDO_UID`, so Wine runs as root and needs a root-owned prefix:

```bash
WINEPREFIX=/root/.wine fritap -s -k keys.log wine /path/to/application.exe
```

Pass variables through sudo with options first: `sudo -E WINEPREFIX=… fritap …`.

## Non-root full capture (instead of sudo)

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
sudo sysctl -w kernel.yama.ptrace_scope=0
fritap -s -k keys.log -p cap.pcapng -f wine /path/to/app.exe
```

`setcap` grants raw-socket capabilities to every script that interpreter
runs. Prefer a dedicated virtualenv with its own copy of the interpreter
(`python -m venv --copies`) and `setcap` that copy; `setcap` needs a real file,
not a symlink. Get the user's consent first and remove the capability
afterwards (`sudo setcap -r <interpreter>`).
