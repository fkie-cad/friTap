# CLI Reference

The single, canonical reference for friTap's command-line interface. Every flag
below is verified against friTap's actual argument parser. Other documentation
pages link here rather than re-listing flags.

## Synopsis

```bash
fritap [OPTIONS] <executable/app name/pid>
```

Where `<executable/app name/pid>` is the capture target:

- Process name (e.g. `firefox`)
- Process ID (a numeric PID)
- Package name for mobile (e.g. `com.example.app`)
- Executable path, optionally with arguments (e.g. `"$(which curl) https://example.com"`)

friTap also has several **subcommands and alternate modes** (offline conversion,
analysis, replay, the interactive TUI, and backend installation). These are
described in [Subcommands and modes](#subcommands-and-modes).

!!! tip "Discoverability"
    `fritap --help` always prints the authoritative, version-specific flag list.
    This page documents the same flags with context, examples, and caveats.

---

## Flag reference

Flags are grouped logically. Each entry shows the long form, short form (if any),
the value placeholder, choices, default, and behavior.

### Targeting and spawning

#### `-m, --mobile [<device_id>]`
Attach to a process on Android or iOS. When multiple devices are connected, pass
the device id (e.g. `emulator-5554`). iOS targets require a jailbroken device.

```bash
fritap -m -k keys.log com.example.app
fritap -m emulator-5554 -k keys.log com.example.app
```

#### `-H, --host <ip:port>`
Attach to a process on a remote device through a remote Frida server.

```bash
fritap -H 192.168.1.100:27042 -m -k keys.log com.example.app
```

#### `-s, --spawn`
Spawn the executable/app instead of attaching to a running process. Use this to
capture activity that happens during startup/initialization.

```bash
fritap -s -k keys.log firefox
fritap -m -s -k keys.log com.example.app
```

#### `-env, --environment <env.json>`
Provide environment variables for spawning as a JSON file. Especially useful on
desktop. Example file:

```json
{ "ENV_VAR_NAME": "ENV_VAR_VALUE", "ANOTHER_VAR": "value" }
```

```bash
fritap -env env.json -s -k keys.log target
```

#### `-t, --timeout <seconds>`
Set a timeout in seconds. After the timeout the process is resumed automatically.
If not set, the process resumes immediately (relevant for spawned targets).

```bash
fritap -t 60 -k keys.log firefox
```

#### `--enable_spawn_gating`
Catch newly spawned processes matching the target app name (useful for Android
multi-process apps).

#### `--spawn_gating_all`
Catch **all** newly spawned processes without filtering by target name.

!!! warning "Use with caution"
    This hooks every newly spawned process on the system/device, which can add
    significant overhead and affect stability. Use only when necessary.

#### `--enable_child_gating`
Intercept child processes spawned by the target application (via fork/clone).

```bash
fritap --enable_spawn_gating --enable_child_gating -k keys.log target_app
```

#### `-ed, --enable_default_fd`
Activate the fallback socket information (`127.0.0.1:1234-127.0.0.1:2345`)
whenever the socket's file descriptor cannot be determined.

```bash
fritap -m -ed -k keys.log com.example.app
```

#### `-ar, --anti_root`
Activate anti-root hooks for Android.

```bash
fritap -m -ar -k keys.log com.example.app
```

#### `-nl, --no-lsass`
Windows only. By default friTap also hooks the LSASS process (the default TLS
provider on Windows via Schannel/SSPI). With this flag LSASS is **not** hooked.

!!! info "Windows TLS architecture"
    Windows uses **Schannel** (SSPI). Due to key isolation, TLS secrets live in
    `lsass.exe`. Hooking LSASS yields system-wide Schannel decryption (Edge, .NET,
    PowerShell, ...) but needs administrator privileges and can be blocked by PPL
    or antivirus. Use `--no-lsass` when analyzing non-Schannel apps (e.g. OpenSSL
    `curl.exe`).

```bash
fritap -nl -k keys.log curl.exe
```

---

### Output

#### `-k, --keylog <path>`
Log key material in the Wireshark-loadable format for the active protocol (NSS
`SSLKEYLOGFILE` for TLS, `SHARED_SECRET` for SSH). With `--protocol all`/`auto`
and multiple protocols emitting keys, the file is split per protocol as
`<stem>.<proto><ext>` (e.g. `keys.tls.log`, `keys.ssh.log`).

```bash
fritap -k keys.log firefox
```

#### `-p, --pcap <path>`
Name of the PCAP file to write (decrypted traffic).

```bash
fritap -k keys.log -p traffic.pcap firefox
```

#### `-f, --full_capture`
Do a full packet capture instead of logging only the decrypted TLS payload. Set
the PCAP name with `-p`.

```bash
fritap -f -k keys.log -p traffic.pcap target
```

#### `-j, --json <path>`
Save session metadata and analysis results in JSON format.

```bash
fritap -j session.json -k keys.log target
```

#### `-l, --live`
Create a named pipe `/tmp/sharkfin` that Wireshark can read during the capture.

```bash
fritap -l target
# then in Wireshark: File -> Open -> /tmp/sharkfin
```

#### `-sot, --socket_tracing [<path>]`
Trace all sockets of the target application and provide a prepared Wireshark
display filter. If a path is given, the socket trace is written to that file.

```bash
fritap -sot -k keys.log target
fritap -sot socket_trace.log -k keys.log target
```

#### Direct terminal output
With no output flag, friTap prints decrypted payload directly to the terminal.

```bash
fritap firefox
fritap -v firefox
```

---

### Key logging and payload

#### `--payload_modification`
Capability to alter the decrypted payload at runtime.

!!! warning "Use with caution"
    Modifying payloads in flight can crash the application.

When active, the agent listens for two Frida messages: `readmod` (modify incoming
`SSL_read` data) and `writemod` (modify outgoing `SSL_write` data). Drive it from
a companion script:

```python
import frida
new_payload = [0x48, 0x45, 0x4C, 0x4C, 0x4F]  # "HELLO"
session = frida.attach("target_app")
script = session.create_script("...")  # your agent script
script.load()
script.post({"type": "writemod", "payload": new_payload})
```

---

### Hooking and libraries

#### `-c, --custom_script <path>`
Path to a custom Frida hook script executed **before** friTap applies its own
hooks. Loaded as a plugin in the `BEFORE_MAIN` phase. See
[Plugins](../development/plugins.md).

```bash
fritap -c custom_hooks.js -k keys.log target
```

#### `--patterns <pattern.json>`
Provide custom byte patterns for module hooking (libraries without resolvable
symbols, e.g. stripped Cronet). Accepts a JSON file path or an inline JSON string.
Patterns deep-merge over the built-in defaults; an invalid file falls back to
defaults with a warning.

```bash
fritap --patterns pattern.json -k keys.log -s com.google.android.youtube
```

See [Pattern-based hooking](../advanced/patterns.md) for the correct schema
(`library -> arch -> function -> [hex strings]`), wildcard rules, and how to
generate patterns with BoringSecretHunter.

#### `--offsets <offsets.json>`
Provide custom offsets for hooked functions as a JSON file or inline JSON string
(`module -> function -> {address, absolute}`). A separate mechanism from
`--patterns`. See [Pattern-based hooking](../advanced/patterns.md).

```bash
fritap --offsets offsets.json -k keys.log target
```

#### `--library-scan, -ls`
Pre-scan for TLS libraries using **tlsLibHunter** before hooking. Discovers
renamed or statically linked libraries.

#### `-ll, --list-libraries`
List the loaded libraries (and TLS/SSL-related exports) to help debug hooking,
then exit **without** starting capture.

```bash
fritap -m --list-libraries com.example.app
```

#### `--extract-libraries <dir>`
Extract detected TLS libraries to the given directory, then exit.

```bash
fritap --extract-libraries ./libs com.example.app
```

#### `--force-scan <module>`
Force the BoringSSL pattern scan to run on the given module even if friTap thinks
it is covered by a sibling library (Cronet APEX split). Repeatable. Accepts a
regex when prefixed with `re:`, or a trailing `*` for prefix matching. Also
honored via the `FRITAP_FORCE_SCAN` env var (comma-separated).

```bash
fritap --force-scan libmainlinecronet.141.0.7340.3.so -m com.example.app
```

---

### QUIC

#### `--quic-capture-mode {stream,app-api}`
Select the QUIC plaintext capture boundary. **Default `stream`** uses the
lower-boundary stream-level hooks (`QuicStream`/`QuicStreamSequencer::Readv`).
`app-api` captures at the application-API Boundary-4 with decoded HTTP/3 headers
(Chrome/Android Google QUICHE only).

#### `--quic-egress-headers-layer {auto,quiche-internal,chrome-shim,session-level}`
Override which layer of the HTTP/3 egress-headers chain the agent attaches to.
**Default `auto`** keeps the winner-takes-all fallback chain (quiche-internal
preferred, chrome-shim fallback, session-level last resort). Force `chrome-shim`
or `session-level` to validate chain behavior on specific builds. Only effective
with `--quic-capture-mode app-api`.

#### `--quic-only`
Install **only** QUIC hooks; skip TLS-library hooks (BoringSSL, NSS, GnuTLS, ...),
OHTTP, the keylog scan-results pass, and (Android) the Java hooks. Much lighter
attach (no multi-MB pattern scans; on Android no Java VM safepoint sync) — helps
friTap attach to a target already in active QUIC traffic. Supported on Android and
Linux (arm64 + x86_64). Filter scope: Android = Google QUICHE (Cronet) only;
Linux = Cloudflare quiche, Google QUICHE (Cronet), Mozilla Neqo (Firefox).

---

### Protocol and backend

#### `--protocol {tls,ipsec,ssh,all,auto}`
Protocol to intercept. **Default `tls`**.

- `tls` covers the **TLS family** — TLS, QUIC, and **OHTTP**. There is no
  separate `--protocol ohttp` / `--ohttp` flag; OHTTP is on by default within
  `--protocol tls`. See [OHTTP](../protocols/ohttp.md).
- `ssh` and `ipsec` are exclusive (only their hooks install). `ssh` and `ipsec`
  auto-enable the modern agent path.
- `all` hooks every supported protocol and asks for confirmation (skip with
  `-y`/`--yes`).
- `auto` is a script-friendly alias for `all` that does **not** prompt.

!!! warning "IPsec is EXPERIMENTAL"
    `--protocol ipsec` is **detection-only**. IPsec/IKE detection works, but
    key extraction does not yet. See [IPsec](../protocols/ipsec.md).

```bash
fritap --protocol ssh -k keys.log sshd
fritap --protocol auto -k keys.log target
```

#### `-y, --yes`
Auto-confirm interactive prompts (e.g. the `--protocol all` warning).

#### `--backend {frida,gdb,lldb,ebpf}`
Instrumentation backend to use. **Default `frida`**.

!!! warning "Only frida is supported today"
    `frida` is the supported backend. **`gdb`, `lldb`, and `ebpf` are
    EXPERIMENTAL/future** — the CLI accepts the choices, but the configuration
    layer rejects the unsupported ones with a clear error.

---

### Scanning and analysis (live capture)

These flags run **passive** analysis over already-decrypted traffic during a live
capture. They never perform any active scanning of the target. For offline
analysis of an existing `.tap`, see the [`analyze` subcommand](#analyze-passive-tap-analysis)
and [Traffic analysis](../advanced/traffic-analysis.md).

#### `--scan [<analyzers>]`
Run passive analysis during capture. Optionally pass a comma-separated analyzer
list (e.g. `credentials,ioc`).

- **Absent: analysis is off** (default `None`).
- **Bare `--scan` (no value): runs all built-in analyzers** (`const="all"`).
- `--scan credentials,ioc`: runs just those analyzers.

Built-in analyzers: `credentials`, `ioc`, `privacy`, `protobuf`.

#### `--scan-report {json,csv,md,table}`
Format for the passive-analysis report printed at the end of capture (default: table).

#### `--scan-report-out <path>`
Write the passive-analysis report to this path instead of stdout.

#### `--scan-min-severity {critical,high,medium,low,info}`
Only report passive-analysis findings at or above this severity (default: info).

#### `--scan-min-confidence <float>`
Only report passive-analysis findings with confidence at or above this value
(default: 0.0).

#### `--scan-source <names>`
Comma-separated analyzer source names to include in the passive-analysis report
(default: all). Filters which findings **show**; use `--scan` to choose which
analyzers **run**.

#### `--scan-category <categories>`
Comma-separated finding categories to include (`secret,pii,network,protocol`;
default: all).

#### `--scan-show-pii`
Reveal PII/secret values in the passive-analysis report instead of redacting them
(default: redacted).

```bash
fritap --scan --scan-report md --scan-min-severity medium -k keys.log target
fritap --scan --scan-category pii --scan-min-confidence 0.8 -k keys.log target
```

---

### Filtering

#### `--filter <expression>`
Display filter using Wireshark-like syntax.

```bash
fritap --filter "http.response.code >= 400 and ip.dst == 10.0.0.1" target
```

#### `--hide-control-frames`
Hide HTTP/2 control frames (PING, SETTINGS, WINDOW_UPDATE, GOAWAY) in the flow
view.

#### `--no-filter-infrastructure`
Include frida/adb control traffic in captures. By default ports
`5037`/`5555`/`27042`/`27043` are dropped.

#### `--include-loopback`
Include loopback/localhost traffic (e.g. Firefox internal NSS IPC). By default
loopback traffic is filtered out to reduce noise.

#### `--proxy <host:port>`
Redirect connections to a proxy (e.g. mitmproxy) and bypass certificate pinning.
Requires the `fritap-proxy` package.

```bash
fritap --proxy 127.0.0.1:8080 -m com.example.app
```

---

### Debug

friTap has **three distinct** debug flags. Choose based on what you need:

#### `-d, --debug`
Full debug mode: debug output **plus** a listening Chrome Inspector server for
remote debugging of the agent (Chrome DevTools).

#### `-do, --debugoutput`
Debug output **only** (no Chrome Inspector server). Use this for verbose
diagnostics when you do not need a live debugger.

#### `--debug-log <path>`
Write the friTap debug log to `<path>` (default
`./fritap_debug_<ts>_<pid>.log`). Captures session-level errors, warnings, and
uncaught exceptions even in non-TUI mode. This is orthogonal to `-d`/`-do` — it
controls **where** the log goes, not the verbosity tier.

#### `-v, --verbose`
Show verbose output (not a debug flag; safe for everyday use).

```bash
fritap -do -v target 2>&1 | tee debug.log     # verbose diagnostics to a file
fritap -d -k keys.log target                   # attach Chrome DevTools
fritap --debug-log ./run.log -v target         # persist session-level log
```

---

### Miscellaneous and experimental

#### `--modern` (EXPERIMENTAL)
Opt into the modern (refactored) friTap agent code path. Unlocks the three-tier
BoringSSL keylog chain and improved Cronet hooks on Android/Windows.

!!! warning "Default is legacy"
    `--modern` is **opt-in**; the default agent path is **legacy** for TLS
    libraries. It is auto-enabled for `--protocol ssh` and `--protocol ipsec`.
    Known regressions vs. the legacy default: **iOS/macOS Cronet, Windows LSASS,
    IPsec**.

#### `-exp, --experimental`
Activate all existing experimental features. See the relevant feature docs.

#### `--version`
Print the program's version number and exit.

---

## Subcommands and modes

friTap dispatches several modes **before** the main capture argument parser, based
on the first argument (or the presence of `--from-pcap`). Each runs an independent
flow.

### `install-backend wireshark`
Install the friTap Wireshark extcap backend so friTap appears as a capture
interface inside Wireshark.

```bash
fritap install-backend wireshark
```

See the platform live-capture sections for usage.

### `--from-pcap` — offline pcap → .tap conversion
Reconstruct a friTap `.tap` from a captured pcap/pcapng — decrypting with tshark
when keys are available (`--keylog` or an embedded DSB), or ingesting an
already-plaintext capture directly. `--from-pcap` may appear anywhere in argv.

!!! info "Requires Wireshark/tshark >= 4.x"
    This pipeline shells out to `tshark`. If it is not on `PATH`, point friTap at
    it with `--tshark-path` or the `$FRITAP_TSHARK` env var (handy on macOS where
    tshark ships inside `Wireshark.app`).

Sub-flags (own parser): `--from-pcap <file>` (required), `--keylog <path>`,
`--tap <path>`, `--scan`, `--tls-port <n>` (repeatable), `--quic-port <n>`
(repeatable), `--decode-as <rule>` (repeatable), `--tls-heuristic`,
`--tshark-path <path>`. A sidecar manifest `<pcap>.fritap.json` supplies
defaults (CLI flags win). Exit codes: `0` success, `2` pcap not found, `3` tshark
missing, `4` ran but produced no decrypted packets (wrong keys/ports), `5` no
decryption keys (no keylog and no embedded DSB), `1` other failure.

```bash
fritap --from-pcap capture.pcapng --keylog keys.log --tap out.tap --scan
fritap --from-pcap cleartext.pcap --tap out.tap     # already-plaintext capture
fritap --from-pcap <file> --help                    # full offline option list
```

Full guide: [Offline pcap → tap](../advanced/offline-pcap-to-tap.md).

### `analyze` — passive .tap analysis
Run friTap's analyzers over an existing `.tap` file and render findings. Purely
offline; no network activity. Two equivalent entry forms:

- `fritap --analyze <file.tap>` — explicit, always analysis mode.
- `fritap analyze <file.tap>` — bare form, treated as analysis only when the next
  token looks like a `.tap` input (so a target literally named `analyze` is not
  hijacked).

Sub-flags (own parser, **distinct from the live `--scan*` family**):

| Flag | Description |
| --- | --- |
| `--scanners <names>` | Comma-separated analyzer names (default: all built-ins). Selects which analyzers **run**. |
| `--report {csv,json,md,table}` | Report output format (default: table). |
| `--report-out <path>` | Write the report to this path instead of stdout. |
| `--min-severity {critical,high,medium,low,info}` | Only report findings at or above this severity (default: info). |
| `--min-confidence <float>` | Only report findings with confidence at or above this value (0.0-1.0; default: 0.0). |
| `--source <names>` | Comma-separated analyzer source names to include in the report (e.g. `credentials,privacy`). Filters which findings **show**; use `--scanners` to choose which analyzers **run**. Default: all. |
| `--category <categories>` | Comma-separated finding categories to include (`secret,pii,network,protocol`). Default: all. |
| `--show-pii` | Reveal PII/secret values in the report instead of redacting them (default: redacted). |
| `--analyzer-path <module[:Class]>` | Load an external analyzer (`module` or `module:Class`). |
| `--include-private-ips` | Include private/reserved IP addresses in IOC findings. |
| `--protobuf-schema <path>` | Path to a protobuf schema for the protobuf analyzer. |

Built-in analyzers: `credentials`, `ioc`, `privacy`, `protobuf`.

A `<stem>.findings.json` sidecar is always written next to the `.tap`. Exit codes:
`0` success, `2` when any finding is at or above the gate severity (`medium`) — a
usable CI gate, `1` for usage/IO errors.

```bash
fritap analyze capture.tap --report md
fritap --analyze capture.tap --report md
fritap analyze capture.tap --category pii --show-pii          # reveal redacted PII
fritap analyze capture.tap --source credentials --min-confidence 0.8
```

Full guide: [Traffic analysis](../advanced/traffic-analysis.md).

### `-r, --replay` / bare `.tap` — interactive replay (TUI)
Browse the flows of an existing `.tap` capture in the interactive terminal UI.

```bash
fritap -r capture.tap        # explicit replay
fritap capture.tap           # a single trailing .tap path replays too
```

### Bare `fritap` — interactive TUI
Invoked with **no arguments**, friTap launches the interactive TUI for live
capture and flow browsing. Requires the `textual` dependency.

```bash
fritap
```

Full guide: [Interactive TUI](../getting-started/tui.md).

---

## Practical examples

### Basic

```bash
fritap -k keys.log firefox
fritap -p traffic.pcap "$(which curl) https://example.com"
fritap -m -k keys.log com.instagram.android
```

### Advanced

```bash
# Comprehensive: keys + pcap + verbose
fritap -k keys.log -p traffic.pcap -v firefox

# Pattern-based hooking for a stripped library
fritap --patterns flutter.json -k keys.log com.flutter.app

# Mobile with anti-root and spawn gating
fritap -m -s -ar --enable_spawn_gating -k keys.log com.example.app

# QUIC-only attach to a live Cronet target
fritap -m --quic-only --quic-capture-mode app-api com.example.app
```

### Real examples from `fritap --help`

```bash
fritap -m -p ssl.pcap com.example.app
fritap -m --pcap log.pcap --verbose com.example.app
fritap -m -k keys.log -v -s com.example.app
fritap -m -k keys.log -v -c <custom hook script> -s com.example.app
fritap -m --patterns pattern.json -k keys.log -s com.google.android.youtube
fritap --pcap log.pcap "$(which curl) https://www.google.com"
fritap -H 192.168.0.1:1234 --pcap log.pcap com.example.app
fritap -m -p log.pcap --enable_spawn_gating -v -do -sot --full_capture -k keys.log com.example.app
fritap -m -p log.pcap --enable_spawn_gating -v -do --anti_root --full_capture -k keys.log com.example.app
fritap -m -p log.pcap --enable_default_fd com.example.app
```

---

## Exit codes

| Mode | Codes |
|------|-------|
| Live capture | `0` success · `1` general error · `2` invalid arguments/configuration · additional Frida-specific codes |
| `analyze` / `--analyze` | `0` success · `2` finding at/above gate severity (medium) · `1` usage/IO error |
| `--from-pcap` | `0` success · `2` pcap not found · `3` tshark missing · `4` no decrypted packets · `5` no decryption keys · `1` other failure |

---

## Next steps

- **Python API**: [Python integration](python.md)
- **Patterns**: [Pattern-based hooking](../advanced/patterns.md)
- **Offline conversion**: [Offline pcap → tap](../advanced/offline-pcap-to-tap.md)
- **Traffic analysis**: [Traffic analysis](../advanced/traffic-analysis.md)
- **Interactive TUI**: [TUI](../getting-started/tui.md)
- **Examples**: [Usage examples](../examples/index.md)
- **Troubleshooting**: [Common issues](../troubleshooting/common-issues.md)
```
