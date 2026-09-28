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

!!! warning "`--full_capture` requires `-p`"
    `-f` on its own is rejected by the argument parser: friTap prints
    `Error: --full_capture requires -p to set the pcap name`, dumps the help
    text, and exits **without capturing anything**. Always pair `-f` with
    `-p <path>`.

!!! note "`-f` needs a host libpcap provider; `-k`/`-p` do not"
    Full raw capture sniffs the real interface, so it needs Npcap on Windows
    (see the [Windows guide](../platforms/windows.md#npcap-optional--only-for--f--full_capture);
    on ARM64 match the Python architecture) or libpcap + raw-socket privileges on
    Linux/macOS. Key extraction (`-k`) and decrypted-payload capture (`-p`) are
    written by friTap itself and need no capture driver.

#### `--owner-capture, -oc`
**Android/Linux, rooted.** Scope the full packet capture (`-f`) to **only** the
target app's traffic using its Linux UID, via the **AppTap** library. friTap picks
an in-kernel **NFLOG** pre-filter where the kernel supports it, otherwise a kernel
socket-table (**SOCK_DIAG**) filter — both app-precise and independent of the
Frida socket trace. Requires `-f` and root; falls back to the legacy whole-device
capture when AppTap or kernel support is unavailable.

`--owner-capture` **implies** `-f`: friTap enables full capture for you and logs
`--owner-capture implies a full capture; enabling -f/--full_capture.`

```bash
fritap -m -oc -p traffic.pcap -k keys.log com.example.app
```

#### `--owner-strict`
With `--owner-capture`: scope to the app's **base UID only** — exclude
isolated/WebView child UIDs *and* the DNS resolver UID.

#### `--owner-no-dns`
With `--owner-capture`: include isolated/WebView child UIDs but **not** the DNS
resolver UID.

#### `--nflog-group <N>`
With `--owner-capture`: NFLOG group used for the Tier-2 in-kernel capture.
**Default `30`.** Change it only if group 30 is already claimed on the device.

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

#### `--scan-keys-region <module|base,size|heap>`
Scan a memory region for cryptographic key material with the generic key-scan
engine and emit ranked, anonymous candidates to the keylog. **Requires `-k`.**
The value is one of:

| Value form | Meaning |
| --- | --- |
| `<module>` | A module name, e.g. `libfoo.so` |
| `0xADDR,SIZE` | An explicit region, e.g. `0x7f1234000,0x40000` |
| `heap` | All writable ranges |

```bash
fritap -m -k keys.log --scan-keys-region libfoo.so com.example.app
```

!!! note "This is a scan — expect a slower load"
    A key-region scan runs **inside** the agent's startup, so it extends
    `script.load()`. friTap automatically triples
    [`--script-load-timeout`](#-script-load-timeout-seconds) when this flag is
    active.

#### `-ms, --memory-scan [<pattern.json>]`
Recover TLS secrets by **scanning the target's heap memory** instead of hooking
the TLS library. This is a complementary, **independently-injected** Frida agent
(`friTap/fritap_memscan.js`) that periodically re-scans the process heap for
secret-carrying structures and writes what it finds as an NSS keylog. It works on
**both** the legacy (default) and `--modern` agent paths and on every OS Frida
supports; the scan engine is platform-generic, and the shipped default profile
targets **BoringSSL** (validated on Android/Chrome).

The optional value is a path to a custom pattern/profile JSON that
overrides/extends the shipped defaults (`friTap/memory_scanning/patterns.json`).
See [Memory-scan secret profiles](../advanced/patterns.md#memory-scan-secret-profiles).

Where recovered keys are written depends on the other flags:

| Command shape | Behavior |
| --- | --- |
| `-ms` **alone** | Only the memory-scan agent is loaded — the normal TLS-hooking agent is **skipped** — and keys are written to `<target>_memscan.keylog` in the current directory. |
| `-ms` with `-k <file>` | Recovered keys are written to a dedicated file **beside** it — `<stem>.memscan<ext>` (e.g. `keys.log` → `keys.memscan.log`) — never a second handle onto the `-k` file. |
| `-ms` with `-p`/`-c`/etc. | The memory-scan agent runs **alongside** the normal capture. |

```bash
fritap -ms -- com.android.chrome
fritap -ms -k keys.keylog -p out.pcap -- com.android.chrome
fritap -ms my_patterns.json com.android.chrome
```

!!! warning "Put the target after `--` (or after the pattern file)"
    Because the pattern file is optional (argparse `nargs='?'`), `fritap -ms com.app`
    wrongly consumes `com.app` as the pattern file. Either separate the target with
    `--` (`fritap -ms -- com.app`), or pass the pattern file explicitly **before**
    the target (`fritap -ms my_patterns.json com.app`). This mirrors the existing
    [`-sot`](#-sot-socket_tracing-path) behavior.

Verify the recovered keylog by decrypting a matching pcap:

```bash
tshark -r capture.pcap -o tls.keylog_file:keys.keylog \
  -o tls.ignore_ssl_mac_failed:FALSE -Y "http || http2"
```

#### `--memory-scan-interval <seconds>`
Poll cadence at which the memory-scan agent re-scans the heap. **Default `2.0`.**
Only effective together with `-ms`.

```bash
fritap -ms --memory-scan-interval 5 -- com.android.chrome
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

#### `--pairip-safe`
**Android only.** Minimal, scan-free capture mode for Google **PairIP**-protected
apps. Hooks only a curated TLS-library allowlist resolved without any
`Memory.scan`, and disables the loader hook, Java/ART hooks, the WebView/Cronet
pattern scan, OHTTP and the library scan — the broad footprint that trips
PairIP's integrity check and `SIGSEGV`s the app. Works with attach and `-s`
(spawn). Often combined with `--offsets` (e.g. for the System WebView login or a
Unity build). Full guide: [PairIP-Protected Apps](../advanced/pairip-safe.md).

```bash
fritap -m -k keys.log --pairip-safe -v com.example.app
```

#### `--no-loader-hook, -nlh`
**Android only.** Do **not** install the `android_dlopen_ext` loader hook. Avoids
PairIP / anti-tamper `SIGSEGV` crashes ([fkie-cad/friTap#64](https://github.com/fkie-cad/friTap/issues/64));
only already-loaded or explicitly selected (`--offsets`) TLS libraries are hooked.
Recommended together with **attach** mode (no `-s`).

friTap also **auto-skips** this hook in spawn mode when it detects a known
anti-tamper library such as Google PairIP (`libpairipcore.so`).

```bash
fritap -m -nlh -k keys.log com.example.app
```

#### `--experimental-stealth-loader`
**EXPERIMENTAL. Android, arm64.** Watch `android_dlopen_ext` via a **hardware
breakpoint** (CPU debug registers — no linker code patch) instead of the inline
trampoline, so late-loaded TLS libraries can still be hooked on PairIP-protected
apps without tripping the anti-tamper scan
([fkie-cad/friTap#64](https://github.com/fkie-cad/friTap/issues/64)).

!!! warning "Unvalidated on-device"
    Needs a root frida-server and may not catch loads on threads created after
    attach. Prefer `--no-loader-hook` or `--pairip-safe` unless you are
    specifically testing this path.

#### `-ll, --list-libraries`
List the loaded libraries (and TLS/SSL-related exports) to help debug hooking,
then exit **without** starting capture.

```bash
fritap -m --list-libraries com.example.app
```

Exits `0` once the listing is printed, or `2` if the inspection failed (look for
the `Error:` line). It scans every loaded module and prints nothing until that
finishes — a silent terminal here is the scan working, not a hang. On macOS that
is now ~1-2s; it stays proportional to module count and pattern set, so
`--scan-all-modules`, or an Android target with a few hundred modules, takes
correspondingly longer.

#### `--extract-libraries <dir>`
Extract detected TLS libraries to the given directory, then exit.

```bash
fritap --extract-libraries ./libs com.example.app
```

Exits `0` when libraries were written, `2` if the extraction failed. Same scan
cost as `-ll` above.

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

#### `--protocol <name>`
Protocol to intercept. **Default `tls`**.

The accepted values are **not a fixed list** — they are every *registered*
protocol name plus `all` and `auto`, so the set grows with the protocol registry
(and with installed protocol plugins). Run `fritap --help` for the exact set your
build accepts; at the time of writing it is
`{mtproto, signal, ssh, telegram, tls, all, auto}`.

- `tls` covers the **TLS family** — TLS, QUIC, and **OHTTP**. There is no
  separate `--protocol ohttp` / `--ohttp` flag; OHTTP is on by default within
  `--protocol tls`. See [OHTTP](../protocols/ohttp.md).
- `ssh` is exclusive (only its hooks install). No protocol
  auto-enables the modern agent path; every protocol runs on the default legacy
  path and on `--modern`.
- `all` hooks every supported protocol and asks for confirmation (skip with
  `-y`/`--yes`).
- `auto` is a script-friendly alias for `all` that does **not** prompt.
- `custom` selects every custom cipher (e.g. `rc4`) and combines with any
  protocol. With more than one protocol, `-k keys.log` is split into one file
  per protocol/cipher (`keys.tls.log`, `keys.rc4.log`, …); a single protocol
  (e.g. `--protocol rc4`) writes `keys.log` directly.

!!! warning "IPsec is EXPERIMENTAL and not selectable yet"
    `--protocol ipsec` is **not accepted yet** — the IPsec handler is not
    registered, so the CLI rejects it. The agent-side strongSwan hooks install
    (on both the legacy and `--modern` paths) only via `--protocol all`/`auto`,
    and are **detection-only**: IPsec/IKE detection works, key extraction does
    not yet. See [IPsec](../protocols/ipsec.md).

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
- **Bare `--scan` (no value): runs all available analyzers** (`const="all"`) —
  built-ins plus any auto-discovered external analyzers.
- `--scan credentials,ioc`: runs just those analyzers.

Built-in analyzers: `credentials`, `ioc`, `privacy`, `protobuf`. Externally
discovered analyzers (see `--analyzer-path` and `--list-analyzers`) are also
selectable by name.

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

#### `--analyzer-path <module[:Class]>`
Load an external analyzer for the live `--scan` (`module` to auto-discover
classes marked `is_fritap_analyzer = True`, or `module:Class`). **Repeatable** to
load several. Mirrors the offline `analyze --analyzer-path`. Analyzers placed in
the drop-in analyzers directory or exposed via the `fritap.analyzers` entry-point
group are discovered automatically and need no `--analyzer-path`.

#### `--list-analyzers`
Print all available analyzers — built-ins plus discovered externals (with their
source) — and exit. Needs no target. Also available as `fritap analyze --list-analyzers`.

```bash
fritap --scan --scan-report md --scan-min-severity medium -k keys.log target
fritap --scan --scan-category pii --scan-min-confidence 0.8 -k keys.log target
fritap --scan --analyzer-path my_pkg.scanner:JwtAnalyzer -k keys.log target
fritap --list-analyzers
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

#### `--loopback`
Also capture loopback/localhost traffic (`127.0.0.1`/`::1`, e.g. a client talking
to a local server, or Firefox internal NSS IPC). Off by default: loopback traffic
is filtered out to reduce noise, and a full capture (`-f`) does not sniff the
loopback adapter unless this flag is passed. On Windows this needs Npcap with
loopback support.

`--include-loopback` is the deprecated former name of this flag. It is still
accepted as an alias so existing scripts keep working, but it is hidden from
`--help`; use `--loopback` in new scripts.

#### `--proxy <host:port>`
Redirect connections to a proxy (e.g. mitmproxy) and bypass certificate pinning.
Requires the `fritap-proxy` package.

```bash
fritap --proxy 127.0.0.1:8080 -m com.example.app
```

---

### Diagnostics

Use these when friTap itself misbehaves — the target dies, or the agent never
finishes loading.

#### `--probe`
**Dry run.** Load the friTap agent, report which platform friTap detected and
which platform code path it selected, then **exit without installing any TLS
hooks**. No keys, pcap or plaintext are produced.

Its purpose is diagnosing targets that die during instrumentation
([fkie-cad/friTap#65](https://github.com/fkie-cad/friTap/issues/65)): **if the
target survives `--probe`, the agent loaded fine and the crash is in hook
installation** — not in agent bootstrap, the Frida attach, or the config
handshake.

```bash
fritap -m --probe com.example.app
fritap --probe -s firefox
```

friTap logs the agent's own answer, e.g.:

```
Agent platform report: android/arm64 (target=com.example.app, agent ABI 2)
Probe complete — no hooks were installed and no data was captured.
```

!!! danger "`--probe` exits with code `2` if the bundle does not acknowledge it"
    Probe mode is a property of the **agent bundle**, not just the CLI. An older
    bundle would silently ignore `probe` and instrument the target normally, so
    friTap refuses to let the diagnostic lie: if no platform report arrives, or
    the report does not have `probe` set, friTap logs

    ```
    --probe failed: the loaded agent bundle does not implement probe mode.
      -> Rebuild the agent bundle with ./dev/compile_agent.sh, then re-run --probe.
      Treat this run as a NORMAL instrumented run: hooks may well have been
      installed, so it proves nothing about probe mode.
    ```

    and exits **`2`**. See
    [I edited `agent/*.ts` and nothing changed](../troubleshooting/common-issues.md#i-edited-agentts-and-nothing-changed-the-rebuild-rule).

Combining `--probe` with a capture flag is a **warning**, not an error — the
capture flags are simply ignored:

```
--probe is a dry run: friTap installs no hooks, so these flags produce no data
and are ignored: -k/--keylog, -p/--pcap.
  -> Re-run the same command without --probe once the probe report looks healthy.
```

The flags that trigger that warning are `-k/--keylog`, `-p/--pcap`,
`-f/--full_capture`, `--live` and `-j/--json`.

!!! note "Probe mode means \"no *TLS* hooks\", not \"zero target mutation\""
    Two things still touch the target under `--probe`:

    - **`-c/--custom_script` hooks are still installed.** Custom scripts are
      loaded as a separate plugin script before the main agent, and probe mode
      does not gate them. Drop `-c` for a clean probe.
    - **On Android**, the bundle's `frida-java-bridge` initialises during
      `script.load()`, which installs a hook before `probe` is even read.

    So a target that dies under `--probe` has still not been cleared of
    friTap — it has been cleared of friTap's *TLS hook installation*.

#### `--script-load-timeout <seconds>`
Upper bound on loading the agent into the target — Frida's `script.load()`, which
blocks until the agent finishes its startup handshake. Exceeding it aborts with a
diagnostic instead of hanging forever. **Default `20.0`.**

- **Any non-positive value disables the bound** (`--script-load-timeout 0`).
- The value is automatically **tripled** when `--patterns`, `--library-scan` or
  `--scan-keys-region` is active, because those run memory scans *inside* the
  load.
- It is **not** applied to plugin scripts or `-c/--custom_script`; only the main
  agent load is bounded.

```bash
fritap --script-load-timeout 60 -m -k keys.log com.example.app
fritap --script-load-timeout 0  -m -k keys.log com.example.app   # no bound
```

!!! warning "This is a give-up, not a cancellation"
    Frida's `script.load()` **cannot be cancelled**. When the bound expires
    friTap abandons the load thread and reports the timeout — but the agent may
    still finish loading inside the target afterwards. Treat a timeout as
    "friTap stopped waiting", not "the agent was stopped".

---

### Debug

friTap has **three distinct** debug flags. Choose based on what you need:

#### `-d, --debug`
Full debug mode: debug output **plus** a listening Chrome Inspector server for
remote debugging of the agent (Chrome DevTools).

#### `-do, --debug-output`
Debug output **only** (no Chrome Inspector server). Use this for verbose
diagnostics when you do not need a live debugger.

!!! note "`-do` writes a log file into the current directory"
    Passing `-do` silently creates `./fritap_debug_<ts>_<pid>.log` in the CWD.
    Use `--debug-log <path>` to put it somewhere you choose (or set the
    `FRITAP_DEBUG_LOG` env var).

#### `--debug-log <path>`
Write the friTap debug log to `<path>` (default
`./fritap_debug_<ts>_<pid>.log`). Captures session-level errors, warnings, and
uncaught exceptions even in non-TUI mode. This is orthogonal to `-d`/`-do` — it
controls **where** the log goes, not the verbosity tier. Also honored via the
`FRITAP_DEBUG_LOG` env var.

#### `-v, --verbose`
Show verbose output (not a debug flag; safe for everyday use).

```bash
fritap -do -v --debug-log ./debug.log target    # verbose diagnostics to a file
fritap -d -k keys.log target                    # attach Chrome DevTools
fritap --debug-log ./run.log -v target          # persist session-level log
```

!!! tip "Prefer `--debug-log` over piping friTap into `head` or `grep`"
    friTap's output goes to **stderr**, so `fritap ... | grep ...` filters an
    empty stream unless you add `2>&1`. Use `--debug-log <path>` and grep the
    file afterwards — it is written by friTap itself and also captures the crash
    reports it collects.

---

### Miscellaneous and experimental

#### `--modern` (EXPERIMENTAL)
Opt into the modern (refactored) friTap agent code path. Unlocks the three-tier
BoringSSL keylog chain and improved Cronet hooks on Android/Windows.

!!! warning "Default is legacy"
    `--modern` is **opt-in**; the default agent path is **legacy** for TLS
    libraries and for every `--protocol`; no protocol auto-enables it.
    Every protocol works on both paths. For **iOS/macOS Cronet** and **Windows
    LSASS**, `--modern` runs the legacy hooks, since those have no native modern
    implementation yet.

#### `-exp, --experimental`
Activate all existing experimental features. See the relevant feature docs.

#### `--version`
Print the program's version number and exit.

---

## Platform caveats

The flags above are cross-platform, but three Apple-specific constraints change
what a given command can actually do.

### macOS: SIP normally has to be off

Attaching to *another* local process on macOS normally requires **System
Integrity Protection to be disabled** (`csrutil status` reports it). Without it,
Frida cannot get a task port for the target, so `fritap -k keys.log <app>` fails
at attach — regardless of `sudo`. Code signing matters too: a target with the
hardened runtime, library validation, or without
`com.apple.security.cs.get-task-allow` will refuse injection even with SIP off.

Full detail: [macOS platform guide](../platforms/macos.md).

### iOS: jailbreak required

Every `-m`/`-H` iOS flow needs a **jailbroken device** with a running
frida-server. There is no non-jailbroken path (and no `--anti_jailbreak` flag —
see [Common issues](../troubleshooting/common-issues.md)).

Full detail: [iOS platform guide](../platforms/ios.md).

### Apple BoringSSL: `-p/--pcap` produces an empty pcap

On **Apple BoringSSL** targets (macOS and iOS), friTap's capture is
**keys-only**: `-p/--pcap` writes a valid but **empty** pcap file, because no
plaintext read/write hooks are installed on that path. Use `-k/--keylog` and
decrypt an externally captured pcap (e.g. `tcpdump` + Wireshark, or
[`--from-pcap`](#-from-pcap-offline-pcap-tap-conversion)).

```bash
# Apple BoringSSL: keys only
fritap -k keys.log -s /Applications/Example.app/Contents/MacOS/Example
```

See [BoringSSL](../libraries/boringssl.md),
[macOS](../platforms/macos.md) and [iOS](../platforms/ios.md).

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
`--tshark-path <path>`, `--repair-keylog` (re-pair keylog secrets whose
client_random is not in the capture by trial decryption). A sidecar manifest `<pcap>.fritap.json` supplies
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
| `--probe` | `0` probe completed (agent loaded, no hooks installed) · `2` the loaded agent bundle does not implement probe mode |
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
