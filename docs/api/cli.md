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

The target is everything after friTap's own options, so a command with plain
arguments works as-is (`fritap -s -k keys.log wine app.exe`).

!!! note "Target arguments that start with `-` go after `--`"
    If the target has its own dash-arguments (e.g. curl's `-sk`), argparse would
    read them as friTap options (friTap has its own `-s`/`-k`). Put a `--` before
    the target; everything after it belongs to the target. `--` is not needed when
    the target has no dash-arguments. (This is separate from the
    [`-ms`/`-sot` `--` rule](#-ms-memory-scan-patternjsonengine).)

    ```bash
    fritap -s -k keys.log -- wine "$CURL" -sk https://web.de
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
Instrument the child processes of the target -- created with `fork()` or
`posix_spawn()` -- and, recursively, the children of every instrumented child.
Each instrumented child is also followed across `exec()` (see below), so the
typical "fork, then exec a helper that does the TLS" chain is captured:
`git clone https://...` runs `git-remote-https` (libcurl), a Python script runs
`curl` through `subprocess`.

```bash
fritap --enable_child_gating -s -k keys.log -- /opt/homebrew/bin/git ls-remote https://github.com/frida/frida.git
fritap --enable_spawn_gating --enable_child_gating -k keys.log target_app
```

Children are **opt-in**: every instrumented child costs an attach plus an agent
load (~0.3-1 s on macOS) before it may run, which fork-heavy targets (shells,
build tools, servers) cannot afford. Without this flag friTap gates children only
to follow the target's own `exec()`; fork/spawn children are resumed at once,
uninstrumented. On Android an app's other processes are started by zygote, not
forked by the app: use `--enable_spawn_gating` for those.

!!! note "Python `subprocess` children on macOS"
    Python's `subprocess` closes every inherited descriptor in the forked child
    (`close_fds=True`, the default), including Frida's. Frida 17 then stalls that
    child ~25 s in `exec()` and holds the new image without reporting it. friTap
    detects such a held image (its executable path changed, no exec reported)
    and instruments and resumes it, so the capture still works, ~25 s late per
    such child. `fork()`+`exec()` children that keep their descriptors (git,
    bash, `close_fds=False`) and `posix_spawn()` children are followed at once.

#### `--no-follow-exec`
friTap follows every process it instruments across `exec()` by default: the
spawned (`-s`) or attached target, and each child instrumented through
`--enable_child_gating`. A launcher that `exec()`s the real binary (e.g.
Homebrew's `/opt/homebrew/bin/python3`), or a running process that `exec()`s
`curl`, stays captured: the new image is held, instrumented, then resumed, so
its first TLS handshake is not missed, and the outputs (keylog, pcap, JSON)
never close. Following an `exec()` needs Frida child gating, which costs
~40-50 ms per `fork()` of a gated process and can slow fork-heavy apps (30
`subprocess.run()` calls: 0.24 s plain, 1.5 s gated); children friTap does not
instrument are always resumed right away. Where a session cannot gate, friTap
re-attaches to the new image after Frida's `process-replaced` detach (its first
instants then run uninstrumented).

`--no-follow-exec` turns this off: friTap captures only the original image, and
when the target `exec()`s the capture ends as "target detached" (exit 3).
`--enable_child_gating` still instruments children when given explicitly; their
`exec()`'d images are then resumed uninstrumented. Python API: `.follow_exec(False)`.

```bash
fritap -s --no-follow-exec -k keys.log ./fork_heavy_server
fritap --no-follow-exec -k keys.log 4242      # attach mode as well
```

#### `-ed, --enable_default_fd`
Activate the fallback socket information (`127.0.0.1:1234-127.0.0.1:2345`)
whenever the socket's file descriptor (FD) cannot be determined. The fallback
tuple is oriented: writes go `1234->2345`, reads `2345->1234`. Records whose
TLS client_random is known are instead emitted without addresses, so the host
assigns each connection its own synthetic tuple (see
[Connections without a socket: synthetic endpoints](#connections-without-a-socket-synthetic-endpoints)).

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
Name of the PCAP file to write (decrypted traffic). The container follows
`--pcap-format` (below): by default a `.pcapng` name writes pcapng, anything
else classic pcap.

```bash
fritap -k keys.log -p traffic.pcap firefox
```

#### `--pcap-format {auto,pcap,pcapng}`
Container of the `-p` file, for plaintext captures and `-f` full captures
alike. `pcapng` embeds the captured keys as a Decryption Secrets Block (DSB),
so Wireshark decrypts the file without a separate keylog. Default `auto`:
`.pcapng` extension → pcapng, any other extension → classic pcap. An explicit
format wins over the extension; a contradicting extension (`-p out.pcap
--pcap-format pcapng`) is written as requested with a warning. Requires `-p`.

```bash
fritap -k keys.log -p traffic.bin --pcap-format pcapng firefox   # pcapng
fritap -k keys.log -p traffic.pcapng firefox                      # pcapng (auto)
```

#### Connections without a socket: synthetic endpoints

Some TLS stacks (Chromium/Cronet memory BIOs and similar) hand friTap plaintext
records that have no socket fd, so there is no real IP/port tuple. Previously
these records were dropped, or with `-ed` merged onto the one shared fake tuple
`127.0.0.1:1234 <-> 127.0.0.1:2345`. Now, when such a record carries a TLS
client_random, friTap gives the connection its own stable **synthetic** TCP
tuple derived from `blake2s(client_random)`:

| Side | Address | Port |
|------|---------|------|
| client | `198.18.x.y` | `49152-65535` |
| server | `198.19.x.y` | `443` |

`198.18.0.0/15` is the RFC 2544 benchmarking range, so a synthetic address is
never a real host.

- **Pinned per connection.** The first tuple a connection (client_random) is
  seen with, real or synthetic, is used for all of its records, so one TLS
  connection is one TCP stream in the `-p` pcap and in the live sinks.
- **Rewrite at stop.** If a real tuple is learned later, the `-p` pcap is
  rewritten when the capture stops: each synthetic stream is switched to its
  real tuple only when that is safe, i.e. a real tuple was learned **and** no
  other stream in the file already uses that real 4-tuple (in either
  orientation). On a conflict, or when no real tuple was learned, the stream
  stays synthetic. Rewritten packets keep their timestamps, seq/ack and
  payload; an IPv6 real tuple becomes an IPv6 packet; checksums are
  recomputed. The rewrite is atomic (temp file + rename) and on any error the
  original pcap is kept. Classic pcap and pcapng `-p` output are both handled.
- **Manifest summary.** The outcome is recorded under the additive
  `synthetic_endpoints` key of the sidecar manifest `<pcap>.fritap.json` (see
  [Manifest sidecar](../advanced/offline-pcap-to-tap.md#manifest-sidecar-pcapfritapjson)).
  The key is written only when the capture had synthetic connections.
- **Live sinks** (live Wireshark `-l`, live auto-decrypt) keep showing the
  synthetic tuple. JSON/JSONL data records carry an additive
  `endpoints_synthetic: true`; `.tap` flows carry `endpoints_synthetic` and are
  upgraded to the real endpoints live once they are learned. Digests, HAR and
  IOC output skip synthetic addresses.
- **Requires a client_random.** Records without one (Go TLS, Windows
  SSPI/Schannel) keep the old behavior: dropped, or merged onto the `-ed`
  fallback tuple.

!!! tip "Wireshark: decode the synthetic port 443 as HTTP/2"
    Plaintext HTTP/2 on the synthetic server port 443 is not auto-detected.
    Use *Decode As* `tcp.port == 443` -> `HTTP2`, or with tshark:
    `tshark -r traffic.pcap -d tcp.port==443,http2`.

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
Save session metadata and analysis results in JSON format. A `*.jsonl` path
writes one event per line instead. `-j -` streams JSONL events to **stdout**
for scripts and AI agents (see [Unattended / automation](#unattended--automation)).

Every JSON output (`session.json`, `*.jsonl` and `-j -`) includes the decrypted
plaintext as `data` events, so `-j` on its own turns on the agent's plaintext
read/write hooks; `-p` or `--tap` are not needed for that. Each `data` event
carries `direction` `read` (received, e.g. a response) or `write` (sent).

**Key material is redacted by default** in every JSON output (`session.json`,
`*.jsonl` and `-j -`), because JSON is often handed to scripts, tickets and
AI agents/LLMs. Raw secrets (`key_data`, and the structured `payload` of a
keylog record) are written only when `-k` is given or with `--json-keys`.
Without either, each keylog record is kept so you still see that a key was
captured, but reduced to its `label` (plus the public `client_random` of NSS
lines) and marked `"redacted": true`:

```json
{"timestamp": 1730000000.0, "type": "key_extraction", "label": "CLIENT_RANDOM",
 "client_random": "aa…aa", "redacted": true}
```

```bash
fritap -j session.json -k keys.log target   # keys in keys.log and in session.json
fritap -j session.json target               # session.json: key records redacted
fritap -j session.json --json-keys target   # raw keys in session.json, no keylog file
fritap -j - --duration 30 target | jq -c 'select(.type=="data")'
```

!!! warning "Behaviour change"
    Before this change `-j file.json` / `-j file.jsonl` wrote the raw
    `key_data` of every key that reached them (for example the `-ms`
    memory-scan keys), even without `-k`. To restore the old output add
    `--json-keys` (or `-k <keylog>`, which also writes a keylog file). In the
    Python API use `.json_keys()`.

#### `--json-keys`
Write raw key material (`key_data` / `payload`) into the `-j` output (file or
stdout stream) even without `-k`. Like `-k`, it turns on key extraction in the
agent, so the hooked TLS keys reach the JSON without writing a keylog file.
Has no effect without `-j`.

#### `--tap <file.tap>`
Write the decrypted flows of the capture to a `.tap` file, the capture format
the TUI saves (open it with `fritap capture.tap`, `fritap analyze capture.tap`
or `fritap report capture.tap`). The file is finalized (flow index + footer) on
every stop: Ctrl+C, `--duration`, and the target exiting/detaching (exit `3`).

```bash
fritap --tap capture.tap --duration 60 target
```

#### `-l, --live`
Create a named pipe `<tempdir>/fritap_sharkfin.pcapng` that Wireshark can read
during the capture. `<tempdir>` is a fresh `mkdtemp()` directory, so it follows
`$TMPDIR` (on macOS it is under `/var/folders/...`, not `/tmp`). The exact path is
printed at start. Not supported on Windows.

```bash
fritap -l target
# friTap prints: Created named pipe: <tempdir>/fritap_sharkfin.pcapng
wireshark -k -i <tempdir>/fritap_sharkfin.pcapng
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

<a id="-ms-memory-scan-patternjson"></a>

#### `-ms, --memory-scan [<pattern.json|engine>]`
Recover TLS secrets by **scanning the target's heap memory** instead of hooking
the TLS library. This is a complementary, **independently-injected** Frida agent
(`friTap/fritap_memscan.js`) that periodically re-scans the process heap for
secret-carrying structures and writes what it finds as an NSS keylog. It works on
**both** the legacy (default) and `--modern` agent paths and on every OS Frida
supports. The scan engines are driven by profiles in one central database,
`friTap/memory_scanning/patterns.json`, which ships five profiles:

| Profile id | Engine | Platform | Protocol |
| --- | --- | --- | --- |
| `boringssl-2025-inplacevector-u8len` | boringssl | all | `tls` |
| `boringssl-signal-libsignal-scudo` | boringssl | android | `tls` |
| `rc4-memscan-generic` | rc4 | all | `rc4` |
| `schannel-win11-ncryptsslp` | schannel (read-only scan of `lsass.exe`) | windows | `tls` |
| `tgnet-android-arm64-2026` | mtproto | android | `mtproto` |

Without a value, a profile is used when its protocol is in the selected
[`--protocol`](#-protocol-name) set (`telegram` also selects `mtproto`) and its
platform matches the target. So the default `--protocol tls` scans BoringSSL on
every platform plus Schannel on Windows (skipped with `-nl`/`--no-lsass`);
`--protocol tls,rc4` adds RC4. The Schannel profile is calibrated for Windows 11
**arm64** only; **x64** ships uncalibrated and recovers nothing from the heap
(friTap's normal ncrypt/lsass hooks still run).

The optional value overrides that selection:

| Value | Effect |
| --- | --- |
| `boringssl` \| `schannel` \| `rc4` \| `mtproto` | Scan only that engine, regardless of `--protocol`. |
| `telegram` | Alias for `mtproto` (Telegram cloud + E2E keys, Android arm64). |
| `<profile-id>` | Scan only that profile (an id from the table above). |
| `<pattern.json>` | A custom pattern/profile file that overrides/extends the shipped database. |

See [Memory-scan secret profiles](../advanced/patterns.md#memory-scan-secret-profiles).

Where recovered keys are written depends on the other flags:

| Command shape | Behavior |
| --- | --- |
| `-ms` **alone** | Only the memory-scan agent is loaded — the normal TLS-hooking agent is **skipped** — and keys are written to `<target>_memscan.keylog` in the current directory. |
| `-ms` with `-k <file>` | Recovered keys are written to a dedicated file **beside** it — `<stem>.memscan<ext>` (e.g. `keys.log` → `keys.memscan.log`) — never a second handle onto the `-k` file. |
| `-ms` with `-p`/`-c`/etc. | The memory-scan agent runs **alongside** the normal capture. |

Protocol-specific findings go to sidecars next to that memory-scan keylog
(`<ms-stem>` is its path without the extension, e.g. `keys.memscan`). Each file is
created only when the engine emits that kind of finding:

| File | Contents |
| --- | --- |
| `<stem>.memscan<ext>` (or `<target>_memscan.keylog`) | Main NSS keylog lines (BoringSSL secrets, paired Schannel secrets). |
| `<ms-stem>.schannel.unpaired` | Windows `lsass` Schannel secrets with no memory-resident client random; pair them offline with `--schannel-unpaired`. |
| `<ms-stem>.rc4.keylog` | `RC4_KEY` lines from the RC4 engine. |
| `<ms-stem>.mtproto.keylog` | `MTPROTO_AUTH_KEY` / `MTPROTO_E2E_KEY` / `MTPROTO_OBF_KEY` lines from the MTProto engine. |
| `<ms-stem>.tls_midstream.secrets.jsonl` | BoringSSL mid-stream TLS 1.3 secret bundles (client/server traffic secrets, exporter) for connections whose handshake was missed. |

```bash
fritap -ms -- com.android.chrome
fritap -ms -k keys.keylog -p out.pcap -- com.android.chrome
fritap -ms my_patterns.json com.android.chrome
fritap -ms schannel -- app.exe
fritap -m -ms telegram -- org.telegram.messenger
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
symbols, e.g. stripped Cronet). Takes a path to a JSON file (inline JSON is
not accepted — unlike `--offsets`). Patterns deep-merge over the built-in
defaults; a missing or invalid file falls back to defaults with a warning.

```bash
fritap --patterns pattern.json -k keys.log -s com.google.android.youtube
```

See [Pattern-based hooking](../advanced/patterns.md) for the correct schema
(default engine: `modules -> module -> os -> arch -> function -> {primary, fallback}`;
`--modern`: `library -> os -> arch -> function -> [hex strings]`), wildcard rules,
and how to generate patterns with BoringSecretHunter.

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
`ipsec, mtproto, rc4, signal, ssh, telegram, tls, all, auto, custom`.

- `tls` covers the **TLS family** — TLS, QUIC, and **OHTTP**. There is no
  separate `--protocol ohttp` / `--ohttp` flag; OHTTP is on by default within
  `--protocol tls`. See [OHTTP](../protocols/ohttp.md).
- `ssh`, `ipsec` and `mtproto` are exclusive (only their hooks install; they
  cannot be combined with another protocol, e.g. `--protocol ipsec,tls` is an
  error; custom ciphers excepted). No protocol
  auto-enables the modern agent path; every protocol runs on the default legacy
  path and on `--modern`.
- `all` hooks every supported protocol and asks for confirmation (skip with
  `-y`/`--yes`).
- `auto` is a script-friendly alias for `all` that does **not** prompt.
- `custom` selects every custom cipher (e.g. `rc4`) and combines with any
  protocol. With more than one protocol, `-k keys.log` is split into one file
  per protocol/cipher (`keys.tls.log`, `keys.rc4.log`, …); a single protocol
  (e.g. `--protocol rc4`) writes `keys.log` directly.

!!! note "IPsec (strongSwan)"
    `--protocol ipsec` is a built-in, exclusive protocol. On Linux and Android
    the agent hooks strongSwan (`charon` / libcharon, on both the legacy and
    `--modern` paths) and extracts IKEv2 SA keys and ESP Child-SA keys; with
    `-k` friTap writes Wireshark `ikev2_decryption_table` and `esp_sa` tables
    next to the keylog. The strongSwan hooks also run under `--protocol all`/`auto`.
    See [IPsec](../protocols/ipsec.md).

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

#### `--wine [{auto,on,off}]`
Wine key extraction on Linux. **Default `auto`**: a Wine target (a `wine …`
command, or a Windows `.exe`/PE given directly) uses the GDB-based key extractor;
`on` forces it, `off` disables it (normal Frida flow). A bare `--wine` with no
value means `--wine auto`. See [Wine](../platforms/wine.md#key-extraction-via-gdb).

```bash
fritap -s -k keys.log --wine /path/to/app.exe
fritap -s -k keys.log --wine -- /path/to/curl.exe -sk https://example.com
```

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

### Security

#### `--isolate-decoders`
Decode compressed bodies (gzip/deflate, brotli, zstd), WebSocket
permessage-deflate messages and HTTP/3 QPACK header blocks in a separate,
restricted worker process instead of inside friTap. **Default off**: decoding stays
in-process exactly as before. `FRITAP_ISOLATE_DECODERS=1` does the same and also
covers the TUI, `--from-pcap` and replay, which take no capture flags.

Why: zlib, brotli and zstd are C decoders, and the bodies friTap decodes come
from the traffic it captures, e.g. a malware C2 response. One decoder memory bug
(such as the brotli heap overflow CVE-2026-111497) is enough to take over the
process that decodes. Without isolation that is the friTap process, which holds
the Frida session and the keys and often runs as root. With isolation it is a
throwaway worker.

```bash
sudo fritap --isolate-decoders -k keys.log -p capture.pcap com.example.app
FRITAP_ISOLATE_DECODERS=1 fritap      # TUI
```

How it works:

- **Worker.** One worker process, started on first use with the `multiprocessing`
  *spawn* method (never fork; friTap runs Frida threads). It loads only the
  stdlib, zlib/brotli/zstandard/pylsqpack, friTap's in-process decoder functions
  (`friTap/parsers/decompress.py`) and the QPACK wrapper
  (`friTap/decoder_isolation/qpack_kind.py`), both loaded by file path. It does
  not load Frida or the rest of friTap.
- **Stateful decoders.** Decoders that keep state between calls live in the
  worker as *contexts* (at most 4096 per worker): one zlib inflater per
  WebSocket direction (context takeover) and one pylsqpack decoder per QPACK
  dynamic table, plus the static-table decoders. They are created on first use,
  freed when the parser is flushed or garbage collected, and lost when the worker
  restarts. All limits stay in friTap: the per-message and per-connection
  WebSocket inflate budgets, the QPACK table-capacity and blocked-stream clamps,
  the header-block size bound and the header-list caps (512 fields / 256 KiB).
  Decoded header lists come back in a compact length-prefixed encoding that
  friTap checks strictly: lengths, field count, total size, no trailing bytes.
  A violation counts as an invalid reply. When a context is lost (crash,
  timeout, invalid reply, restart, context cap), the WebSocket direction stops
  decompressing with the error `permessage-deflate decoder context lost;
  decompression disabled`, because the compression history is gone. The QPACK
  context is treated like an encoder-stream error: its header blocks are
  raw-scanned for pseudo-headers, static-only blocks still decode, and new
  connections decode normally.
- **Protocol.** Length-prefixed binary frames: a fixed `struct` header (magic,
  version, op, status, flags, request id, handle, two integer args, text and
  data lengths) followed by raw bytes. friTap never unpickles or evaluates
  anything the worker sends. It checks every field: lengths against caps (data
  against the caller's `max_out`), status against the statuses allowed for the
  op, and the request id and op echo. Error text from the worker is length-capped,
  decoded with `errors="replace"`, and has control and bidi characters escaped.
- **Supervision.** Each request has a timeout of 10 s plus extra time that grows
  with input and output size (`FRITAP_DECODER_TIMEOUT` overrides the 10 s). A
  crash, timeout or invalid reply kills and reaps the worker, and the caller gets
  an ordinary decompress error. friTap logs the event as a **possible exploit
  attempt** and copies the input (up to 16 MiB) to
  `<user log dir>/friTap/decoder_crashes/` (at most 20 files; set
  `FRITAP_DECODER_QUARANTINE_DIR` to use another directory). The next request
  starts a new worker. After more than 5 failures within 60 s, decoding is turned
  off for 60 s ("decoder worker disabled after repeated crashes"). friTap never
  falls back to decoding in-process.
- **Hardening inside the worker** (best effort):

  | OS | What the worker gets |
  |----|----------------------|
  | all POSIX | inherited fds closed, stdin/stdout to `/dev/null`; as root: switches to `SUDO_UID`/`SUDO_GID`, or to `nobody` when those are unset; `RLIMIT_CORE=0`, `RLIMIT_NOFILE=64`, `RLIMIT_FSIZE=0`, `RLIMIT_NPROC=0` (when not root); `nice(10)` |
  | Linux | also `RLIMIT_AS=2 GiB`, `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG(SIGKILL)`, and an empty network namespace (`unshare(CLONE_NEWNET)`) when started as root |
  | macOS | also the built-in `pure-computation` sandbox (no file access, network or new processes). macOS does not enforce `RLIMIT_AS` |
  | Windows | process separation only |

- **Cost.** The worker starts in about 60 ms, once. Each call adds about 35 µs
  for small bodies and about 1.2 ms for a 1 MiB body (the data passes through a
  pipe). A 1 KiB WebSocket message goes from about 5 µs to about 55 µs, and a
  QPACK header block from about 7 µs to about 75 µs.

The brotli CVE guard still runs in friTap before anything reaches the worker,
and the worker runs it again.

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

### macOS: Apple platform binaries need root + a boot-arg, or `--macos-unsign-copy`

Apple's own binaries (`/usr/bin/curl`, ...) are arm64e platform binaries. Frida
can only inject into them as root with the boot-arg
`sudo nvram boot-args="-arm64e_preview_abi"` set (then reboot). Without that,
`fritap -s ... /usr/bin/curl` stops before spawning with exit code **1** and
lists the options.

| Flag | Description |
|---|---|
| `--macos-unsign-copy` | macOS, spawn mode (`-s`) only. If the target is an Apple platform binary, spawn an ad-hoc signed copy of it (copied to a temp dir, thinned to arm64e, `codesign -f -s -`) instead; no root, no reboot. The copy drops the original's entitlements and is deleted when friTap exits. No effect on other targets. |

```bash
fritap -s -k keys.log -p plain.pcap --macos-unsign-copy -- /usr/bin/curl -s https://example.com
```

Details: [macOS platform guide](../platforms/macos.md#apple-platform-binaries-usrbincurl-usrbinpython3).

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
client_random is not in the capture by trial decryption; writes
`<stem>.relabeled.keylog` and decrypts with it). A sidecar manifest `<pcap>.fritap.json` supplies
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

### `fritap q` — call an agent tool, get JSON
Runs one tool of the agent API (the same registry the MCP and REST servers
expose) and prints its JSON result on stdout. Meant for scripts and AI agents.

```bash
fritap q --list [--json] [--compact]          # tools: name, kind, summary (* = mutating)
fritap q get_digest --help-json               # spec + JSON-Schema of the parameters
fritap q get_digest --tap run.tap --budget 800
fritap q list_endpoints --json '{"tap": "run.tap", "limit": 20}' --compact
fritap q list_endpoints --params-file params.json   # '-' reads stdin
```

- **Parameters** come from `--params-file` < `--json` < generated flags (later
  wins). JSON input is capped at 1 MiB and 64 nesting levels (`bad_param`). Flags are generated from the tool's schema: strings/numbers
  `--name VALUE` (`--max-bytes` and `--max_bytes` both work), booleans
  `--name` / `--no-name`, enums take fixed choices, arrays take a comma list
  and/or a repeated flag (`--fields a,b --fields c`), objects take a JSON string.
  `fritap q <tool> --help` lists them.
- **Output**: pretty JSON by default, one line with `--compact`.
- **Errors**: printed as `{"error", "error_type", "hint"?, "exit_code"}` on
  **stdout**; the process exits with that `exit_code` (2 = usage/bad parameter,
  not found, forbidden; 1 = runtime error).
- **Sandbox**: `--root DIR` (default: cwd) bounds `.tap` paths and exports;
  `--allow-secrets` permits key material (keylog export); the keylog export
  call must still confirm it with its own `--confirm-secrets` parameter
  (`fritap q export --tap run.tap --format keylog --out k.log --allow-secrets
  --confirm-secrets`);
  `--max-response-bytes N` caps the response (default 65536).
- **Captures block**: a capture session lives in the `fritap q` process, so
  `fritap q start_capture ...` waits until the session ends (its `duration_s`
  elapsed or the target exited), polling `capture_status`, and prints the final
  status. Ctrl+C calls `stop_capture`. `--no-wait` returns immediately, but the
  capture then stops when the process exits.
- **One process per call**: the `session_id` of `fritap q start_capture` is not
  usable by a later `fritap q` call. Read the capture through the `tap` path in
  the printed status (`<root>/.fritap-sessions/<session_id>/capture.tap`);
  sessions persist across calls only inside `fritap mcp` / `fritap serve`.
- **Finding values**: `fritap q` always allows `show_values` (the local user
  owns the data); `fritap mcp` / `fritap serve` refuse it with `forbidden`
  unless started with `--allow-values`.

- **Leading options**: the q-level options `--root`, `--allow-secrets`,
  `--compact` and `--max-response-bytes` may also come *before* the tool name
  (`fritap q --root ./captures get_digest --tap run.tap`).
- **Unknown tools**: `fritap q get_digets` prints an `unknown_tool` error
  document with a did-you-mean hint and exits 2.

**Dispatch rule.** After skipping leading q-level options, `fritap q` is the
query CLI when

1. at least one q-level option was given (no capture flag has these names), or
2. the next token is `--list`, `-h` or `--help`, or
3. the next token is a registered tool name or a close misspelling of one
   (difflib ratio >= 0.75, `get_digets`); 2 and 3 then print `unknown_tool`
   for a non-tool.

Anything else falls through to capture mode with `q` as the target:
`fritap q -k keys.log`, `fritap q firefox` and `fritap q com.example.my_app`
still capture a process named `q`. Likewise `fritap mcp` / `fritap serve`
start the MCP / REST server only when every following token is one of their
own options, as defined by their argparse parsers (`fritap mcp --help` /
`fritap serve --help`); `fritap serve -m` captures a process named `serve`.

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

## Unattended / automation

Flags for running a capture from scripts, CI jobs or AI agents without a human
at the terminal. All are opt-in; without them friTap behaves exactly as before.

| Flag | Effect |
|------|--------|
| `--duration <seconds>` | Stop the capture cleanly after `<seconds>` (float). Uses the same teardown as Ctrl+C: pcap, keylog and JSON are flushed, the target is detached, exit code `0`. Not to be confused with `-t/--timeout`, which only delays resuming a spawned process. Ignored by `--probe`. |
| `-q, --quiet` | Suppress the banner and info messages on the console. Warnings and errors still go to stderr; a `--debug-log`/`-do` file keeps logging everything. |
| `--non-interactive` | Never prompt. Implies `-y/--yes`; the `-f` without `-k` confirmation only logs a warning and continues. That confirmation is also skipped automatically whenever stdin is not a TTY. (`--protocol all` without `-y` still fails fast on a non-TTY stdin; use `--protocol auto` or `-y`.) |

```bash
# 60-second unattended capture, quiet console, never blocks on a prompt
fritap --non-interactive -q --duration 60 -k keys.log -p traffic.pcap target
echo "friTap exited with $?"
```

### Machine-readable output

| Flag / command | Output |
|----------------|--------|
| `-j -` / `--json -` | JSONL event stream on stdout (details below). |
| `--tap <file.tap>` | `.tap` capture of the decrypted flows, finalized on every stop path. |
| `fritap devices [--json]` | Frida devices: `id`, `name`, `type`. |
| `fritap apps [-m [ID] \| --device ID \| -H HOST] [--running] [--json]` | Installed apps (`name`, `identifier`, `pid`; `pid` `0` = not running), running ones first. A device without an app list (desktop local device) lists its processes (`kind: "process"`, `identifier: null`). Default device: local. |

**`-j -` stream.** stdout carries nothing but JSONL: friTap reserves the real
stdout for the stream at startup and points file descriptor 1 at stderr, so the
banner, log lines, `-v` hexdumps and the output of a spawned target all go to
**stderr**. Every line is a JSON object with

- `"schema": "fritap.events/1"` (bumped on incompatible changes),
- `"type"`: `stream_start` (first line), `stream_end` (last line on every
  teardown, with the process's final `"exit_code"`; `null` if it is not known —
  plus `"ended_by"`: `duration`, `stopped`, `target_exited` or `error`, omitted
  when the reason is unknown),
  or the event kind — `keylog`, `data`, `session`, `library`,
  `console`, `error`, `detach`, `instrument`, `platform_report`, `script_loaded`,
  `socket_trace`, `ohttp`, `message`, … (`snake_case` of the event class),
- `"event"`: the event class name, `"event_type"` (present on every event
  record: the class name again, except `session` records where it is the
  session's own state such as `started`), `"timestamp"` (epoch seconds),
  `"protocol"`, and the event's fields. Envelope records (`stream_start`,
  `stream_end`, `usage_error`, the closing runtime `error`) carry neither
  `event` nor `event_type`. `bytes` values (the decrypted plaintext in `data`
  records) are hex-encoded.

**Key material** is in the stream only when it was explicitly requested with
`-k` or `--json-keys`. Otherwise a `keylog` record keeps only `label` (and the
public `client_random` of NSS lines) plus `"redacted": true`. `label` is
`unknown` when the line had no recognisable label and absent when the record
carried no keylog line at all (e.g. a payload-only SSH record);
`client_random` is `"???"` when the agent could not read it; `stream_start`
reports the policy as `"key_material": true|false`. The `-j file.json` /
`.jsonl` file outputs follow the same policy (see [`-j`](#-j-json-path)).

A usage error with `-j -` on the command line prints one
`{"type": "usage_error", "error": ..., "exit_code": 2}` record on stdout and the
help text on stderr.

A **runtime error** (spawn/attach failure, unknown app, missing executable,
agent script load failure, backend error, …) adds one record right before
`stream_end`, so a consumer learns the reason without parsing stderr:

```json
{"schema": "fritap.events/1", "type": "error", "timestamp": 1730000000.0,
 "error_type": "ExecutableNotFoundError",
 "message": "unable to find executable at '/nonexistent/binary'",
 "hint": "…optional next step…", "exit_code": 1}
{"schema": "fritap.events/1", "type": "stream_end", "timestamp": 1730000000.1, "exit_code": 1, "ended_by": "error"}
```

It is written when the stream closes, so its `exit_code` is the final one (for
example `3` when the target had already died before the error). `hint` is only
present when friTap has a concrete next step. Unlike agent-side `error` events,
this record has no `"event"` field. A target that simply exits (`exit_code` 3)
gets a `detach` record but no `error` record.

```bash
# 30 s capture: JSONL events on stdout, decrypted flows in a .tap, logs on stderr
fritap --non-interactive --duration 30 -j - --tap capture.tap -s -- /usr/local/bin/app \
    2> fritap.log | python3 -c 'import json,sys; [print(json.loads(l)["type"]) for l in sys.stdin]'

fritap devices --json
# {"schema": "fritap.devices/1", "devices": [{"id": "local", "name": "Local System", "type": "local"}, ...]}
fritap apps -m emulator-5554 --running --json
# {"schema": "fritap.apps/1", "device": {...}, "apps": [{"name": "Chrome", "identifier": "com.android.chrome", "pid": 4242, "kind": "app"}, ...]}
```

`apps` lists every app once: Frida can enumerate an app twice, so entries are
deduplicated by `identifier` (processes by `pid`), keeping the running entry.
`devices`/`apps` exit `0` on success, `1` on a Frida error (device not found,
frida-server not running, …) and `2` on bad arguments; with `--json` the error
is printed on stdout as `{"error": ..., "error_type": ..., "exit_code": ...}`,
otherwise on stderr. They are only treated as subcommands when **every**
following token is one of the options above, so a process literally named
`devices`/`apps` is still captured by adding any capture option
(`fritap apps -k keys.log`, `fritap -m apps`).

Live-capture exit codes (constants in `friTap/exit_codes.py`):

| Code | Constant | Meaning |
|------|----------|---------|
| `0` | `EXIT_OK` | Normal stop: Ctrl+C/SIGINT, `--duration` elapsed, or a clean return |
| `1` | `EXIT_RUNTIME_ERROR` | Runtime error: attach/spawn failure, agent script load failure, backend error |
| `2` | `EXIT_USAGE_ERROR` | Usage error: invalid arguments/configuration (argparse) |
| `3` | `EXIT_TARGET_DETACHED` | The target process died or detached before friTap was asked to stop (including a target that simply exited on its own) |

A termination signal other than SIGINT (e.g. SIGTERM) exits with `128 + signum`.

**The first non-zero status wins.** Whichever of target detach (`3`), runtime
error (`1`) or a non-SIGINT signal (`128 + signum`) happens first is the exit
code; later events never override it, and a clean stop (`0`) never overrides
an earlier failure. So Ctrl+C or SIGTERM after the target already detached
still exits `3`, and an error reported after the target died stays `3`.
There is no `--max-flows`: in a plain CLI capture friTap does not track flow
completion (flow events exist only with `--scan`), so a flow count could only
stop the capture in the middle of the Nth connection. Use `--duration` instead.

---

## Exit codes

| Mode | Codes |
|------|-------|
| Live capture | `0` success (incl. `--duration` elapsed) · `1` runtime error · `2` invalid arguments/configuration · `3` target died/detached unexpectedly · `128+signum` non-SIGINT signal (see [Unattended / automation](#unattended--automation)) |
| `--probe` | `0` probe completed (agent loaded, no hooks installed) · `2` the loaded agent bundle does not implement probe mode |
| `analyze` / `--analyze` | `0` success · `2` finding at/above gate severity (medium) · `1` usage/IO error |
| `devices` / `apps` | `0` success · `1` Frida error (device not found, server not running, …) · `2` invalid arguments |
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
