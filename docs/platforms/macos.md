# macOS Platform Guide

This guide covers macOS-specific setup, considerations, and best practices for using friTap on macOS systems.

!!! warning "What macOS support covers"
    macOS support is **per library**, not uniform:

    - **Apple's `/usr/lib/libboringssl.dylib`** (the TLS stack behind CFNetwork,
      URLSession and Network.framework) and **Cronet**: **TLS key extraction only**.
      The socket file descriptor cannot be recovered from an `SSL_read`/`SSL_write`
      on Apple platforms, so friTap installs no plaintext hooks for them — use the
      keylog with Wireshark.
    - **LibreSSL** (`/usr/lib/libssl.48.dylib`), **NSS** and **Python's bundled
      OpenSSL**: keys **and** decrypted plaintext (`SSL_read`/`SSL_write`).
    - Apple's legacy **SecureTransport / `libcoretls`** is not hooked at all.

## Prerequisites

### System Requirements

- **macOS** — friTap does not enforce a version floor. The keylog-offset table has
  named buckets down to **macOS 11 (Big Sur)**; anything reporting an older major
  version falls into an unmeasured catch-all (see
  [BoringSSL keylog offsets](#apple-boringssl-keylog-offsets)).
- **Administrator access** (required for most analysis)
- **Python 3.10+** (`setup.py` sets `python_requires=">=3.10"`)
- **Xcode Command Line Tools**
- **Apple silicon (arm64) or Intel** — with one real asymmetry: the run-time
  keylog-offset derivation decodes **arm64** instructions only. On an Intel Mac
  friTap silently falls back to the version table.

### Development Environment Setup

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (recommended package manager)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python (if not using system Python)
brew install python@3.12

# Install friTap
pip3 install fritap
```

## System Setup

### SIP (System Integrity Protection)

!!! warning "SIP normally has to be disabled"
    It is very likely that you have to deactivate System Integrity Protection to
    use friTap on macOS. Frida attaches to another local process via
    `task_for_pid`, which SIP blocks. Note that disabling SIP is **not** sufficient
    for Apple's own arm64e platform binaries (`/usr/bin/curl` & co.) — see
    [Apple platform binaries](#apple-platform-binaries-usrbincurl-usrbinpython3) for
    the boot-arg and the no-root `--macos-unsign-copy` workaround.

```bash
# Check SIP status
csrutil status
```

To disable SIP:

1. Boot into Recovery:
    - **Apple silicon**: shut down, then **press and hold the power button** until
      "Loading startup options" appears, then choose *Options → Continue*.
    - **Intel**: hold **Command+R** during boot.
2. Open *Terminal* from the *Utilities* menu.
3. Run `csrutil disable`.
4. Reboot normally.

Re-enable it with `csrutil enable` from Recovery when you are done.

### Frida Installation

```bash
# Install frida-tools
pip3 install frida-tools

# Verify installation
frida --version

# Test local device
frida-ps
```

!!! note "No frida-server on local macOS"
    Local macOS targets need **no frida-server** — Frida injects directly via
    `task_for_pid` (`friTap/server_manager/macos.py`). `pkill frida-server` and
    "check the frida-server status" are no-ops here. A frida-server is only
    involved for *remote* macOS targets reached with `-H <ip:port>`.

### BPF Devices (only for `-f/--full_capture`)

friTap's normal `--pcap` output is **synthesized from the decrypted payloads** — it
does not read from the network at all and needs no BPF access. Raw packet capture
is only used by `-f/--full_capture`, which drives scapy and therefore needs
**read/write** access to a `/dev/bpf*` node:

```bash
# Inspect the BPF nodes
ls -la /dev/bpf*

# The simplest correct answer: run the full capture as root
sudo fritap -f -p traffic.pcap -k keys.log -s "$(pwd)/my_client"
```

!!! warning "Do not `chmod 644 /dev/bpf*`"
    `644` grants others read-only access, while scapy opens the BPF node
    read/write — so it does not actually fix anything, and it loosens a
    security-relevant device permission for nothing. Use `sudo` instead.

## friTap Usage on macOS

### Spawn vs. attach: pass `-s` when you give a path or a command

`-s/--spawn` is **opt-in**. Without it friTap *attaches* to an already-running
process, and the positional argument is matched against running processes. If you
pass an executable path or a command with arguments, you must add `-s`, otherwise
friTap looks for a process that does not exist.

```bash
# Attach to a process that is already running (match by name or PID)
sudo fritap -k keys.log "Google Chrome"
sudo fritap -k keys.log 4711

# Spawn: any executable path, or a command with arguments
sudo fritap -s -k keys.log "$(pwd)/my_client"
sudo fritap -s -k keys.log curl https://httpbin.org/get
sudo fritap -s -k keys.log python3 my_script.py
```

!!! tip "Redirect to a file rather than piping friTap into `head` or `grep`"
    During a capture friTap writes everything to **stderr**, so a plain
    `fritap ... | grep` sees an empty stream — you need `2>&1` for a pipe to
    catch anything at all. Redirect
    to a file and grep the **file** instead: it keeps the whole session, and
    captures the crash reports friTap writes alongside it.

    ```bash
    sudo fritap -do -v -k keys.log my_client > fritap.log 2>&1
    grep -i boringssl fritap.log
    ```

### Native Apple-stack applications

Apple's Network.framework, CFNetwork and URLSession all run their TLS **on top of
`/usr/lib/libboringssl.dylib`**, which friTap hooks. A plain Swift `URLSession`
client is capturable: the verification rig in `dev/macos_verify/` drives exactly
that path and gets well-formed keys attributed to `libboringssl.dylib`.

!!! warning "Code signing, not the TLS stack, is what blocks Safari and Mail"
    Safari, Mail, Messages and the other Apple platform binaries cannot be
    instrumented because of **code signing**: hardened runtime, library validation,
    and the absence of the `com.apple.security.cs.get-task-allow` entitlement.
    friTap probes exactly these conditions and reports them
    (`friTap/backends/frida_backend.py`).

    Your own build, or a third-party app that is unsigned or adhoc-signed, **is**
    capturable even though it uses CFNetwork.

Check a target before you spend time on it:

```bash
# Is it signed with the hardened runtime / library validation?
codesign -d -vvv "/Applications/App.app" 2>&1

# Does it carry the debugging entitlement friTap needs?
codesign -d --entitlements - "/Applications/App.app" 2>&1 | grep -i get-task-allow

# Which TLS libraries does the binary link against?
otool -L "/Applications/App.app/Contents/MacOS/App" | grep -Ei "ssl|tls|boringssl|Network"
```

Only Apple's legacy **SecureTransport** (`libcoretls`, `SSLCreateContext`,
`CFStream`) has no friTap hooks at all.

### Apple platform binaries (`/usr/bin/curl`, `/usr/bin/python3`, ...)

On Apple silicon every binary in `/usr/bin`, `/bin`, `/usr/sbin` and
`/System` is an **arm64e platform binary** (`codesign -dv` prints
`Platform identifier=<n>`). Frida cannot inject into those as a normal user, and
disabling SIP alone is not enough: the kernel kills `frida-helper` and Frida
reports `PermissionDeniedError: oops, frida-helper appears to have crashed`.

friTap detects this before spawning and exits with code 1, listing three options:

| Option | Needs | Result |
|---|---|---|
| `fritap -s --macos-unsign-copy ... -- /usr/bin/curl ...` | nothing (no root, no reboot) | keys + plaintext from an ad-hoc signed **copy** |
| a Homebrew build, e.g. `$(brew --prefix curl)/bin/curl` | nothing | keys + plaintext from a different build |
| the original binary | SIP off, `sudo nvram boot-args="-arm64e_preview_abi"` (Frida also suggests adding `thid_should_crash=0 tss_should_crash=0`), a **reboot**, and running friTap with `sudo` | keys + plaintext from the real binary |

`--macos-unsign-copy` copies the target into a fresh temp directory, thins it to
its native slice (`lipo -thin arm64e`), ad-hoc signs it (`codesign -f -s -`) and
spawns that copy with your arguments. The copy is no longer a platform binary, so
Frida can inject; it still loads the system `libssl.48.dylib` /
`libboringssl.dylib`, so the normal hooks apply. The temp directory is deleted
when friTap exits.

!!! warning "It is a copy"
    The original's entitlements are dropped, so a binary that depends on them
    (keychain groups, sandbox, private Apple entitlements) may behave differently or
    refuse to start. App bundles (`*.app/Contents/...`) are not supported. The
    Rosetta route (`arch -x86_64 ...` or an x86_64 copy) does **not** work: Frida
    17 fails on translated processes ("unexpected error while probing dyld").

### Command-Line Applications

```bash
# Apple's curl (LibreSSL → keys *and* plaintext) via a signed copy, no root needed
fritap -s -k curl_keys.log -p curl.pcap --macos-unsign-copy -- /usr/bin/curl https://httpbin.org/get

# Or a Homebrew curl
fritap -s -k curl_keys.log -- "$(brew --prefix curl)/bin/curl" https://httpbin.org/get

# Python
sudo fritap -s -k python_keys.log python3 my_script.py

# Node.js
sudo fritap -s -k node_keys.log node app.js
```

### Application Bundle Analysis

```bash
# Find the executable inside the bundle
ls -la "/Applications/Some App.app/Contents/MacOS/"

# Spawn it by path
sudo fritap -s -k app_keys.log "/Applications/Some App.app/Contents/MacOS/Some App"

# Or attach to it once it is running
sudo fritap -k app_keys.log "Some App"
```

### SSH Targets

SSH hooks are registered under `protocol: "ssh"`, and registry entries are
protocol-gated. The default is `--protocol tls`, so an SSH capture **must** select
the protocol explicitly:

```bash
# OpenSSH client — SHARED_SECRET keylog
sudo fritap --protocol ssh -k ssh_keys.log -s ssh user@remote.host

# Both families in one session
sudo fritap --protocol all -k keys.log -s ssh user@remote.host
```

### Dry Run: `--probe`

`--probe` loads the agent, reports the detected platform and the platform code path
it selected, installs **no** hooks, and exits. It produces no keys, pcap or
plaintext, and exits non-zero if the bundle does not acknowledge probe mode — which
also makes it a quick check that the loaded bundle is current.

```bash
sudo fritap --probe -s "$(pwd)/my_client" > probe.log 2>&1
grep -i "platform" probe.log
```

### Bounding Agent Load: `--script-load-timeout`

`--script-load-timeout <seconds>` bounds Frida's `script.load()`, which blocks
until the agent finishes its startup, so a wedged load aborts with a diagnostic
instead of hanging forever.

- Default: **20 seconds**.
- **Any non-positive value disables** the bound (`--script-load-timeout 0`).
- The value is **tripled** when `--patterns`, `--library-scan` or
  `--scan-keys-region` is requested, because those scan inside the load.
- It is a *give-up*, not a cancellation: the load thread is abandoned, not killed.

```bash
# Large pattern scan on a slow target
sudo fritap --patterns macos_patterns.json --script-load-timeout 60 -k keys.log my_client

# Disable the bound entirely while debugging
sudo fritap --script-load-timeout 0 -do -k keys.log my_client > fritap.log 2>&1
```

## SSL/TLS Libraries on macOS

`agent/platforms/macos.ts` registers twelve entries for macOS:

| Library | Module pattern | Support | Notes |
|---------|----------------|---------|-------|
| **BoringSSL** (Apple) | `libboringssl.dylib` | Keys only | Apple's own `/usr/lib/libboringssl.dylib`. Backs CFNetwork / URLSession / Network.framework. See [the offset mechanism](#apple-boringssl-keylog-offsets). |
| **LibreSSL** | `libssl.<n>.dylib` at exactly `/usr/lib/` | Keys **+ plaintext** | macOS system SSL (`/usr/lib/libssl.48.dylib`). `SSL_get_fd` works here, so read/write hooks are enabled. Registered at `priority: 150`. The path filter is anchored, so an app vendoring its own `Contents/Frameworks/usr/lib/` sysroot is not mistaken for the system one. |
| **OpenSSL** | versioned `libssl.<n>[.<n>].dylib` **outside** `/usr/lib/` | Keys **+ plaintext** | Genuine OpenSSL wherever it comes from: Homebrew (`/opt/homebrew`, `/usr/local`), pyenv, MacPorts, conda, python.org and Xcode framework Pythons, app bundles. Formerly "Python OpenSSL" and restricted to paths containing `python`, which silently missed every Homebrew/pyenv interpreter. |
| **OpenSSL/BoringSSL** | `libssl*.dylib` that is **not** a versioned name | Keys | Generic fallback for bundled BoringSSL copies — `libssl.dylib`, `libssl_custom.dylib`. |
| **Cronet** | `*cronet*.dylib` | Keys only | Pattern-based; may require external patterns. |
| **NSS** | `libnss<n>.dylib` | Keys **+ plaintext** | Mozilla NSS. |
| **NSS HPKE (OHTTP)** | `libnss<n>.dylib` | Keys | Oblivious HTTP; gated under the TLS family. |
| **Cloudflare QUICHE** | `libquiche.dylib` | QUIC | Gated under the TLS family. |
| **Google QUICHE (Chrome)** | `Google Chrome Framework` | QUIC | QUIC only — this is **not** a TLS keylog hook. |
| **Mozilla Neqo** | `XUL` | QUIC | Firefox HTTP/3; the module is `XUL` inside `Firefox.app/Contents/MacOS/`. |
| **libssh** | `libssh.dylib`, `libssh2.dylib` | SSH | Needs `--protocol ssh`. |

!!! note "How the three `libssl*.dylib` entries divide the name space"
    friTap invokes **every** registry entry whose pattern matches a module, not
    just the first — so overlapping entries mean a library gets hooked twice by
    two different executors. The three entries above are therefore built as a
    strict partition, using the shared predicates in
    `agent/shared/darwin_library_patterns.ts`:

    * a **versioned** name (`libssl.3.dylib`, `libssl.1.1.dylib`,
      `libssl.48.dylib`) goes to LibreSSL *or* OpenSSL, decided purely by whether
      the path is exactly `/usr/lib/`;
    * any other `libssl*` name goes to the generic entry, whose `excludePattern`
      is the *same* versioned-name predicate;
    * so every libssl-shaped module resolves to exactly one hook.

    Picking the right executor matters: the generic entry runs the Apple
    BoringSSL path, which skips the read/write hooks and looks for a
    `bssl::ssl_log_secret` symbol that cannot exist in genuine OpenSSL. That is
    why versioned names route to the OpenSSL entry instead.
| **OpenSSH** | `ssh`, `sshd`, `sshd-session`, `scp`, `sftp-server` | SSH | Needs `--protocol ssh`. |

!!! warning "Chromium's own TLS is not covered on macOS"
    Chrome, Edge and Brave link BoringSSL **statically** into
    `Google Chrome Framework` / the equivalent Edge and Brave frameworks. No macOS
    registry pattern matches that: every BoringSSL/`libssl` entry requires a
    `libboringssl*.dylib` or `libssl*.dylib` filename, and the one
    `Google Chrome Framework` entry is the **QUIC** hook, not a TLS keylog hook.
    Chromium-based browsers are therefore among the *harder* macOS targets, not the
    easier ones. Try [pattern-based hooking](#pattern-based-hooking) against the
    framework binary if you need them.

### Apple BoringSSL keylog offsets

Apple does **not** export `SSL_CTX_set_keylog_callback` from
`/usr/lib/libboringssl.dylib`, so friTap cannot simply call it. Instead it:

1. hooks the **exported** `SSL_CTX_set_info_callback`, and
2. writes friTap's keylog callback pointer **directly into the live `SSL_CTX`
   struct** at a byte offset.

The offset is derived at run time from the target's own binary: friTap disassembles
the non-exported setter, whose whole body is `str x1, [x0, #imm]; ret`, and reads
`#imm`. This decoding is **arm64-only**. If it fails — or on Intel — friTap falls
back to a version table (`agent/legacy/tls/shared/apple_keylog_offset.ts`):

| macOS major | `SSL_CTX` keylog offset | Provenance |
|-------------|-------------------------|------------|
| ≥ 15 | `0x310` | inferred from the iOS twin; **confirmed live on macOS 26.3.1** |
| 14 (Sonoma) | `0x308` | inferred from the iOS 17 value |
| 13 (Ventura) | `0x300` | inferred from the iOS 16 bucket |
| 12 (Monterey) | `0x2F8` | inferred from the iOS 15 bucket |
| 11 (Big Sur) | `0x2B8` | inferred from the iOS 14 bucket |
| older | `0x2A8` | field-reported, never measured |

!!! warning "How much of this table is actually measured"
    macOS ships the same `libboringssl` revision as the iOS release of the same
    year, so every bucket ≥ 11 is *inferred from its iOS twin*. **macOS 26.3.1 is
    the only macOS version where the value has been confirmed live** — macOS 15
    (Sequoia) itself has never been measured, and the iOS reference numbers were
    measured from **iOS Simulator runtime** dylibs, not device builds.

    A wrong offset writes a function pointer into the wrong `SSL_CTX` field and
    kills the target. That is precisely the failure mode of
    [fkie-cad/friTap#65](https://github.com/fkie-cad/friTap/discussions/65).

Derive the ground truth for your own machine, or check the tables in CI:

```bash
# Print the offsets derived from the binaries on this machine
python dev/derive_boringssl_keylog_offset.py

# Compare the derived values against friTap's checked-in tables (exit 1 on conflict)
python dev/derive_boringssl_keylog_offset.py --check
```

### LibreSSL (best plaintext support on macOS)

`/usr/lib/libssl.48.dylib` is the one macOS library with full plaintext support:
unlike Apple's BoringSSL, its `SSL_get_fd` works, so `SSL_read`/`SSL_write` hooks
are enabled and you get decrypted payloads, not just keys.

```bash
# curl and many other CLI tools link against system LibreSSL
sudo fritap -s -k libressl_keys.log -p libressl.pcap curl https://httpbin.org/get
```

### Python Applications (Special Support)

```bash
# Python's bundled OpenSSL is matched by path and gets keylog + plaintext hooks
sudo fritap -s -k python_keys.log python3 script.py

sudo fritap -s -k python_keys.log python3 -c \
  "import urllib.request; urllib.request.urlopen('https://example.com')"
```

### Pattern-based Hooking

For statically-linked TLS (Chromium frameworks, Flutter, stripped binaries), supply
byte patterns:

```bash
sudo fritap --patterns macos_patterns.json -k keys.log -s "$(pwd)/my_client"
```

See [Pattern-Based Hooking](../advanced/patterns.md) for the file format.

### Library Detection Commands

```bash
# Which SSL/TLS libraries does a binary link against?
otool -L "/path/to/application" | grep -E "(ssl|tls|crypto|boringssl)"

# Framework dependencies
otool -L "/Applications/App.app/Contents/MacOS/App" | grep -Ei "security|network"

# Which modules friTap actually sees in the live process
sudo fritap -ll "Some App" > libs.log 2>&1
```

!!! note "Do not look for system dylibs on disk"
    `find /usr/lib /System/Library -name "*ssl*"` finds nothing on macOS 11+:
    the system dylibs live inside the **dyld shared cache** and have no
    on-disk files. Inspect the loaded modules in the live process instead.

## Apple Silicon Considerations

```bash
# Check the architectures in a binary
file "/Applications/App.app/Contents/MacOS/App"
lipo -info "/Applications/App.app/Contents/MacOS/App"
```

!!! note "arm64 vs. Rosetta"
    The keylog-offset derivation decodes arm64 instructions. Running the target
    under Rosetta 2 (`arch -x86_64 …`) means the x86_64 `libboringssl` slice is
    loaded and friTap falls back to the version table — so prefer the native
    arm64 slice when you have a choice.

## Rebuilding the Agent

friTap loads a **pre-compiled** agent bundle, `friTap/fritap_agent.js`. Nothing
compiles `agent/*.ts` at run time, so **editing the TypeScript changes nothing
until you rebuild**:

```bash
./dev/compile_agent.sh
```

!!! danger "Only the success line proves the bundle was rebuilt"
    The script runs under `set -euo pipefail` and writes `frida-compile -o`
    straight onto `friTap/fritap_agent.js` — no temp file, no backup. A failure
    therefore surfaces as `frida-compile`'s own error output and a non-zero exit,
    and **nothing guarantees what is left on disk**: the bundle may still be the
    previous one, or a partially written file. Either way a later run is not
    testing what you think it is. Always confirm the success line:

    ```
    [compile_agent.sh] done. Agent: <bytes> bytes
    ```

    `npx tsc --noEmit` is **not** a substitute; it has reported the tree clean
    while `frida-compile` rejected it.

To point friTap at a bundle somewhere else, set `FRITAP_AGENT_BUNDLE`. Resolution
order is:

1. `FRITAP_AGENT_BUNDLE` — an arbitrary bundle path, **not** ABI-filtered;
2. an ABI-matched `fritap.agent_bundle` entry point;
3. the shipped `friTap/fritap_agent.js`.

```bash
FRITAP_AGENT_BUNDLE=/path/to/fritap_agent.js sudo -E fritap -k keys.log my_client
```

## Verifying a macOS Build

`dev/macos_verify/verify.sh` is a device-free, end-to-end check of the Apple TLS
capture path. It builds a loopback HTTPS server plus a Swift URLSession client (so
it exercises CFNetwork → `libboringssl.dylib`, the exact path friTap hooks) and
drives friTap against them — no outbound network, nothing that expires.

```bash
./dev/macos_verify/verify.sh          # run every applicable check
./dev/macos_verify/verify.sh --list   # list the checks without running them
./dev/macos_verify/verify.sh --keep   # keep the work dir to inspect raw output
```

Nine checks: the Python unit suite, a deterministic `compile_agent.sh` build,
attach capture, spawn capture (without killing the target), both agent handshake
stages, `--script-load-timeout` firing and being disabled, `--probe` reporting
without installing hooks, and child gating instrumenting a second process. Exit
code is 0 only if every applicable check passed; inapplicable checks report `SKIP`.
See `dev/macos_verify/README.md` for what each check proves and how to drive the
rig by hand.

## Troubleshooting macOS Issues

### The Target Dies During Instrumentation

This is the failure mode `dev/macos_verify/` exists to regression-test, and the
symptom behind [fkie-cad/friTap#65](https://github.com/fkie-cad/friTap/discussions/65).
Work down this ladder:

```bash
# 1. Does the agent even load? --probe installs no hooks.
sudo fritap --probe -s "$(pwd)/my_client" > probe.log 2>&1
#    Survives --probe  → the agent is fine, the crash is in hook installation.
#    Dies under --probe → the problem is the load/bootstrap, not the hooks.

# 2. Attach instead of spawn — spawn-mode bootstrap is its own failure class.
sudo fritap -k keys.log my_client > fritap.log 2>&1

# 3. Try --modern, which does NOT write into SSL_CTX.
sudo fritap --modern -k keys.log my_client > modern.log 2>&1
#    Surviving under --modern points at a wrong keylog offset (see the table above).
#    Dying under --modern proves nothing — it installs its own additional hooks.

# 4. Collect the platform report for a bug report.
sudo fritap -do -v -k keys.log my_client > debug.log 2>&1
grep "Agent platform report" debug.log
```

Include that `Agent platform report: … (agent ABI N)` line, your `sw_vers`
output and `csrutil status` when you report the issue.

### Cannot Attach / Permission Denied

```bash
# SIP must normally be off for local attach
csrutil status

# Run as root
sudo fritap -k keys.log my_client

# Is the target signed in a way that forbids instrumentation?
codesign -d -vvv "/Applications/App.app" 2>&1
codesign -d --entitlements - "/Applications/App.app" 2>&1 | grep -i get-task-allow
```

Hardened runtime, library validation, or a missing
`com.apple.security.cs.get-task-allow` entitlement all block injection — friTap
probes for exactly these and says so. Apple's SIP-protected platform binaries stay
unattachable regardless.

### Application Won't Start

```bash
# Check the quarantine attribute
xattr -l "/Applications/App.app"

# Remove it
sudo xattr -rd com.apple.quarantine "/Applications/App.app"

# Verify the signature is intact
codesign -v "/Applications/App.app"
```

### No Keys Captured

```bash
# Confirm friTap hooked anything at all
sudo fritap -do -v -k keys.log my_client > fritap.log 2>&1
grep -Ei "hook|boringssl|libressl|keylog" fritap.log

# Verify the keylog lines are well formed (must print 0)
grep -cvE '^[A-Z_0-9]+ [0-9A-F]+ [0-9A-F]+$' keys.log
```

If the target is a Chromium-based browser, see the warning
[above](#ssltls-libraries-on-macos) — its statically-linked BoringSSL is not
matched by any macOS registry entry.

### Network Interface Issues

```bash
# List network interfaces
ifconfig

# Check raw capture works at all (only relevant for -f/--full_capture)
sudo tcpdump -i en0 -c 1
```

### System Log Monitoring

```bash
# Watch for SSL/TLS related system messages during a session
log stream --predicate 'eventMessage CONTAINS "SSL" OR eventMessage CONTAINS "TLS"'
```

Console.app lives at `/System/Applications/Utilities/Console.app` on modern macOS.

### Wireshark Integration

```bash
# Install Wireshark
brew install --cask wireshark

# Live analysis via the named pipe
sudo fritap -l -s "$(pwd)/my_client"

# Or decrypt an offline capture with the extracted keys
wireshark -o "tls.keylog_file:keys.log" traffic.pcap
```

## Best Practices for macOS

### 1. System Preparation

- Disable SIP on a **test** machine, not a production one, and re-enable it afterwards.
- Install the Xcode Command Line Tools.
- Rebuild the agent bundle after any `agent/*.ts` change (`./dev/compile_agent.sh`).

### 2. Application Analysis

```bash
# Start simple: keys only
sudo fritap -k keys.log my_client > fritap.log 2>&1

# Then add pcap and metadata
sudo fritap -k keys.log --pcap traffic.pcap -j metadata.json my_client > fritap.log 2>&1
```

`libraries_detected` is a **top-level** array and lists only libraries friTap
actually hooked — so a library missing from it was never instrumented, whatever
else the log said:

```bash
jq '.libraries_detected' metadata.json
```

!!! note "There is a second, nested shape in the source — it never runs"
    `friTap/legacy/ssl_logger_core.py` also builds a session dict with the array
    nested under `.statistics.libraries_detected`, but its file handle is never
    opened, so that writer is dead code and `jq '.statistics.libraries_detected'`
    returns `null`. Every real `-j` run goes through `JsonOutputHandler`, which
    writes the top-level shape shown above.

### 3. Security Considerations

- Use dedicated test systems and test accounts.
- Do not disable security features on production machines.
- Re-enable everything you turned off once the analysis is done.

### 4. Data Organization

```bash
# Create an analysis workspace
mkdir -p ~/Desktop/friTap_Analysis
cd ~/Desktop/friTap_Analysis

# Organize by date and application
mkdir "$(date +%Y%m%d)_ApplicationName"
cd "$(date +%Y%m%d)_ApplicationName"

# Run with organized output (stdout to a file, never a pipe)
sudo fritap -k keys.log --pcap traffic.pcap -j metadata.json my_client > fritap.log 2>&1
```

## Next Steps

- **iOS Analysis**: Check [iOS Platform Guide](ios.md) for mobile analysis
- **Windows Analysis**: See [Windows Platform Guide](windows.md)
- **Linux Analysis**: Review [Linux Platform Guide](linux.md)
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Check [Common Issues](../troubleshooting/common-issues.md)
