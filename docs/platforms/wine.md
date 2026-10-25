# Wine Platform Guide

This guide covers Wine-specific setup, considerations, and best practices for using friTap to analyze Windows applications running under Wine on Linux.

!!! warning "What is (and is not) experimental"
    **TLS key extraction for Wine targets is the default on Linux and needs no
    flag**: friTap routes Wine targets to its GDB-based key extractor
    automatically (see [Key Extraction via GDB](#key-extraction-via-gdb)).
    Full packet capture (`-p cap.pcapng -f`) works on that path too.

    Only the **Frida-based Wine agent** is still experimental. It is the route for
    decrypted *plaintext* pcaps (`-p` without `-f`), `--live` and payload
    modification, and must be selected explicitly with `--wine off --experimental`.
    It is still under development and may have stability issues. Please report
    any problems via GitHub issues.

## Overview

friTap's Wine support allows you to intercept TLS traffic from Windows applications running under Wine. This is achieved through a hybrid approach:

1. **Native Linux TLS Libraries** - Hooks Linux `.so` libraries that Wine applications may use
2. **Windows DLL Interception** - Hooks Windows TLS libraries (`.dll` files) bundled with applications

## Key Extraction via GDB (default on Linux) {#key-extraction-via-gdb}

When you point friTap at a Wine target on a Linux host, friTap now **automatically
routes TLS key extraction through a GDB-based extractor** (`agent_gdb/wine`) instead
of injecting Frida. gdb and Frida both rely on `ptrace`, so they cannot drive the
same process at once; the GDB path is the reliable one for Wine. No `--experimental`
flag is required for this.

```bash
# Spawn: friTap detects the Wine launcher, runs the GDB extractor, writes keys.
fritap -s -k keys.log wine /path/to/app.exe

# Or give the Windows binary directly — a .exe/PE on Linux is auto-detected as a
# Wine target and `wine` is prepended for you.
fritap -s -k keys.log /path/to/app.exe

# Attach to an already-running Wine app (no -s): by exe name ...
fritap -k keys.log app.exe

# ... or by PID (the PID is positional; -p is --pcap, not a PID option).
fritap -k keys.log "$(pgrep -f app.exe | head -1)"
```

!!! note "`-s` spawns, no `-s` attaches"
    With `-s`/`--spawn` friTap launches the app itself (launch +
    freeze-on-detect + attach, see below). **Without `-s`, friTap attaches to an
    already-running process.** This also applies to a launch-style command such as
    `fritap -k keys.log wine /path/to/app.exe`: friTap then looks for a running
    process that matches the exe path or its basename and attaches to it. If no
    such process is running, friTap tells you to add `-s`.

Control this with `--wine`:

- `--wine auto` (default): detect a Wine target (a `wine …` command, or a Windows
  `.exe`/PE given directly) and use the GDB extractor.
- `--wine on`: force the GDB Wine route on a local Linux target.
- `--wine off`: never use it — fall through to the normal Frida flow (e.g. the
  experimental Wine agent). An explicit `--backend frida` likewise keeps the Frida
  path for a Wine target.

!!! info "Keys + full packet capture; no decrypted plaintext on the GDB path"
    The GDB path extracts **TLS key material** (an NSS key log, directly loadable
    by Wireshark) and supports **full packet capture** (`-p cap.pcapng -f`, see
    [Full packet capture](#full-packet-capture) below).

    A decrypted-*plaintext* pcap (`-p` without `-f`), `--live` and payload
    modification depend on Frida's `SSL_read`/`SSL_write` hooks, which are not run
    on the GDB path. If you request them, friTap prints a notice and continues
    with key extraction. Use `-p … -f` instead, or select the experimental Frida
    agent with `--wine off --experimental`.

### Full packet capture (`-p … -f`) {#full-packet-capture}

friTap can record the raw traffic of the Wine app while the GDB extractor
collects the keys:

```bash
sudo fritap -s -k keys.log -p cap.pcapng -f wine /path/to/app.exe
```

- The packet sniffer needs root (or `CAP_NET_RAW`), hence `sudo`. Under `sudo`,
  spawn mode **launches Wine as the invoking user** (taken from
  `SUDO_UID`/`SUDO_GID`, with that user's `HOME`), so your normal `~/.wine`
  prefix keeps working. gdb also drops to your user when it can (see
  [Who runs as whom under `sudo`](#who-runs-as-whom-under-sudo)).
- With a **`.pcapng`** output, friTap embeds the captured keys as a Decryption
  Secrets Block (DSB), so the file decrypts directly:
  `fritap -r cap.pcapng` or open it in Wireshark. With a **`.pcap`** output,
  give Wireshark the key log (`keys.log`) yourself.
- The capture is finalized both when you press Ctrl-C and when the app exits on
  its own.

#### Who runs as whom under `sudo` {#who-runs-as-whom-under-sudo}

friTap keeps root only for the parts that need it:

| Component | Runs as |
|-----------|---------|
| Packet sniffer (`-f`) | root |
| `/proc` scan, `SIGSTOP`/`SIGCONT` freeze/resume, teardown | root |
| Wine (spawn mode) | your user |
| gdb (key extractor) | your user if the checks below pass, otherwise root |

gdb parses the memory of an untrusted target and runs Python scripts, so it is the
component that gains most from not being root. friTap runs it as your user when
**all** of these hold:

- `kernel.yama.ptrace_scope` is `0` (or Yama is absent). With `1` (the
  Ubuntu/Debian default) an unprivileged tracer may only attach to its own
  descendants; the Wine process was launched by friTap, not by gdb, so only a
  root gdb can attach. `2` allows root only, `3` nobody.
- The target process belongs to your user (always true in spawn mode; checked in
  attach mode).
- Your user can read friTap's gdb script directory (this fails e.g. when friTap
  is installed under `/root`).
- Your user can write the keylog. If it does not exist, friTap creates it owned by
  you; an existing root-owned keylog from an older `sudo` run blocks the drop
  (delete or `chown` it).

On success friTap logs
`Running gdb as <user> (uid N); kernel.yama.ptrace_scope=0 allows an unprivileged attach.`
Otherwise gdb stays root and friTap logs `Keeping gdb as root: <reason>`.
Key extraction works either way.

!!! note "`ptrace_scope=0` is your choice"
    `ptrace_scope=0` is a system-wide relaxation: any process can then attach to
    other processes of the same user. friTap never changes it; with the default
    `1` it simply keeps gdb as root.

**Non-root alternative.** Instead of `sudo` (not in addition to it), give the
Python interpreter the capture capabilities and lower `ptrace_scope`, then run
friTap without `sudo`. `setcap` is only needed for this route; key extraction
alone (`-k` without `-f`) needs neither `sudo` nor `setcap`, just
`ptrace_scope=0`:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
sudo sysctl -w kernel.yama.ptrace_scope=0
fritap -s -k keys.log -p cap.pcapng -f wine /path/to/app.exe
```

!!! warning "`setcap` applies to every script run by that interpreter"
    `setcap` on `python3` gives raw-socket capabilities to **every** program that
    interpreter runs, not just friTap. Prefer a dedicated virtualenv that holds
    its **own copy** of the interpreter. A venv's `python3` is often a symlink to
    the system binary, and `setcap` has to target a real file, so copy the binary
    into the venv first (or create the venv with `--copies`) and run `setcap` on
    that copy.

### Requirements for the GDB path

- `gdb` on `PATH`, **built with Python support** (`gdb -batch -ex "python print(1)"`).
  Works with older gdb too (tested on gdb 10.2): the extractor no longer requires
  `gdb.events.executable_changed` or `Breakpoint.locations` (both gdb ≥ 13).
- `wine` installed. friTap resolves the actual ELF loader automatically, handling
  both the classic layout (`wine-preloader`) and the newer *wow64* layout
  (a separate `wine64` loader, e.g. Wine 9.x on Ubuntu).
- `kernel.yama.ptrace_scope=0` for an unprivileged gdb: the GDB path attaches to
  the Wine process. Set it with `sudo sysctl -w kernel.yama.ptrace_scope=0`.
  Non-root runs need it. Under `sudo` it is optional: with it, gdb drops to your
  user; without it, gdb stays root, which needs no `ptrace_scope` change (see
  [Who runs as whom under `sudo`](#who-runs-as-whom-under-sudo)).

!!! note "How the `--spawn` path works (launch + freeze-on-detect + attach)"
    gdb-*spawning* Wine tracks the whole wow64 process tree (wineserver, services,
    …) and is too heavy — the app never reaches TLS. So friTap instead launches
    Wine **normally** (fast, untraced), **fast-polls `/proc`** for the process that
    maps the app's exe image, and **`SIGSTOP`s it the instant it appears** — before
    it reaches the TLS handshake. gdb then attaches to the frozen process, installs
    its hooks, and friTap resumes the app with `SIGCONT` while gdb stays attached
    (`set detach-on-fork on` so the app's vfork'd Wine helpers run free). This
    eliminates the attach race for short one-shots like `curl` (whole run ≈ 0.5 s,
    handshake ≈ 150 ms after the image maps). Needs `ptrace_scope=0` as above.

### Signatures and different Wine / library builds

The extractor locates the TLS keylog functions (GnuTLS, OpenSSL `SSL_log_secret`)
and the Wine loader entry points by **byte-signature scanning**. These signatures
are specific to a given Wine / TLS-library build, so friTap ships several and treats
extra ones as fallbacks: it scans every signature against the target's executable
memory, and a re-scan is triggered on each shared-object load. If your Wine or
GnuTLS/OpenSSL build differs from the shipped signatures, regenerate them:

- With Ghidra/PyGhidra: `python agent_gdb/wine/utils/wine_hunter.py -i <inputs> -j patterns.json`
  (see `agent_gdb/wine/utils/README.md`), then supply them via `--patterns patterns.json`
  to `agent_gdb/wine/wine_key_extract.py` (which loads them through the
  `FRITAP_PATTERNS` environment variable).
- Or add the new hex signatures directly to `DEFAULT_TLS_PATTERNS` /
  `DEFAULT_WINE_PATTERNS` in `agent_gdb/wine/gdb_script/gdb_wine_extract.py`.

!!! note "GnuTLS builds that inline `_gnutls_call_keylog_func`"
    On some distributions (e.g. Ubuntu's gnutls 3.8.x) `_gnutls_call_keylog_func`
    is inlined into the key-schedule code, so there is no standalone function to
    hook. For these, the extractor ships a fallback that hooks the registered NSS
    keylog **callback** instead (`GnuTLSNssKeylogFuncUnixBP`). gnutls invokes that
    callback for every secret of every handshake regardless of whether
    `SSLKEYLOGFILE` is set, so keys are still captured passively. Wine's Schannel
    uses the host's native `libgnutls`, so this covers Windows apps that use the
    OS TLS stack (WinHTTP/WinINet/Schannel). Windows apps that **bundle** their own
    TLS do not use gnutls:

    * A bundled **BoringSSL/OpenSSL** `libssl` needs the `SSL_log_secret`
      signature.
    * A bundled **LibreSSL** (e.g. a curl-for-win `curl.exe` statically linked
      against LibreSSL) has **no** `SSL_log_secret` and **never** invokes the
      keylog callback — its keys come from the KDF functions
      (`tls13_hkdf_expand_label_with_length` for TLS 1.3, `tls1_PRF` for TLS 1.2).
      friTap ships x86-64 signatures for these and reconstructs NSS keylog lines
      (handler `LibreSSLHkdfExpandLabelWinBP`). `client_random` is **not**
      reachable from any LibreSSL KDF frame, so friTap recovers it the same way
      the Windows Schannel path does — by parsing the plaintext ClientHello off
      the socket: it resolves `ws2_32!send` from the loaded PE export table and
      reads the 32-byte random (handler `Ws2SendClientHelloBP`). No struct
      offsets or `--patterns` are needed — the static curl-for-win case works out
      of the box. A dynamically linked LibreSSL `libssl-*.dll` / `libtls-*.dll`
      instead uses the exported `SSL_get_client_random`.

You can also run the extractor standalone, outside friTap:

```bash
python agent_gdb/wine/wine_key_extract.py --spawn /path/to/app.exe -k keys.log -- <args>
python agent_gdb/wine/wine_key_extract.py --attach <pid> -k keys.log
```

---

The remainder of this guide mostly covers the **experimental Frida-based** Wine
agent (`--wine off --experimental`), which is the path used for the hybrid
native/DLL hooking and is the only route that can produce decrypted plaintext
(`-p` without `-f`, `--live`, payload modification). Without `--wine off`, a Wine
target goes to the GDB extractor even if `--experimental` is given.

## Prerequisites

### System Requirements

- **Linux system** with Wine installed
- **Wine 5.0+** (recommended Wine 7.0+ for better compatibility)
- **Python 3.10+** with friTap installed (`setup.py` sets `python_requires=">=3.10"`)
- **Injection privileges (GDB and Frida).** Either run friTap as your *own*
  user with a lowered `kernel.yama.ptrace_scope`, or use `sudo` (needed anyway
  for full packet capture). A real root shell / `su` with a user-owned prefix is
  the most common source of failure for Wine targets (see "Common mistake"
  below). Lower `ptrace_scope` so gdb/Frida can attach as a non-root user:

  ```bash
  sudo sysctl kernel.yama.ptrace_scope=0   # one-time; survives until reboot
  ```

!!! danger "Common mistake: running Wine as root with a user-owned WINEPREFIX"
    Modern Wine (≥7) hard-aborts when the running uid does not match the
    WINEPREFIX directory's owner uid (it prints
    `wine: '/home/<you>/.wine' is not owned by you, refusing to create a
    configuration directory there` and exits within ~10–25 ms of starting).

    - **`sudo fritap -s … wine …` is handled for you**: in spawn mode friTap
      launches Wine as the invoking user (from `SUDO_UID`/`SUDO_GID`, with that
      user's `HOME`), so your own `~/.wine` is used. The sniffer stays root; gdb runs as you when
      it can (see [Who runs as whom under `sudo`](#who-runs-as-whom-under-sudo)).
    - **Pre-flight check.** Before launching Wine (spawn mode), both the GDB
      path and the Frida Wine agent check WINEPREFIX ownership. If the prefix owner differs
      from the uid Wine will run as, friTap aborts with a clear message that names
      the prefix and its owner, so the failure no longer looks like a hook crash.
    - **The remaining trap** is a real root shell or `su` (no `SUDO_UID`) with a
      user-owned prefix, e.g. `WINEPREFIX=/home/<you>/.wine` in a root shell.
      **Fix:** run friTap as your own user (with `ptrace_scope=0`), use `sudo`
      instead of a root shell, or point Wine at a root-owned prefix with
      `WINEPREFIX=/root/.wine`.


### Wine Installation

```bash
# Ubuntu/Debian
sudo apt install wine wine64

# Fedora
sudo dnf install wine

# Arch Linux
sudo pacman -S wine

# Verify installation
wine --version
```

### Frida Setup

```bash
# Install frida-tools
pip3 install frida-tools

# Verify Frida
frida --version
```

## Basic Usage

### Analyzing Wine Applications

Run friTap **as the owner of your WINEPREFIX** (normally your desktop user, with
`ptrace_scope=0`). No `--experimental` flag is needed: Wine targets go to the GDB
key extractor by default.

```bash
# Launch the app and extract its TLS keys (spawn mode)
fritap -s -k keys.log wine /path/to/application.exe

# Keys + full packet capture (the sniffer needs root; Wine still runs as you)
sudo fritap -s -k keys.log -p traffic.pcapng -f wine /path/to/application.exe

# Attach to an app that is already running
fritap -k keys.log application.exe
```

!!! note "Without `-s`, friTap attaches"
    `fritap -k keys.log wine /path/to/application.exe` (no `-s`) does **not**
    launch the app. friTap attaches to an already-running process that matches the
    exe path or basename. If none is running, it prints a hint to add `-s`.

For a decrypted *plaintext* pcap (`-p` without `-f`), use the experimental Frida
agent instead:

```bash
fritap --wine off --experimental -s -k keys.log --pcap plaintext.pcap \
    wine /path/to/application.exe
```

### Examples

```bash
# Analyze a Windows game
fritap -s -k game_keys.log wine ~/.wine/drive_c/Games/game.exe

# Analyze with verbose output
fritap -s -v -k keys.log wine /path/to/app.exe

# Debug mode for troubleshooting
fritap -s -do -v -k keys.log wine /path/to/app.exe

# Spawn target whose path contains spaces — quote it so the shell passes one
# token; friTap preserves the argv and spawns it intact (no space-splitting).
fritap -s -k keys.log wine "/home/u/.wine/drive_c/Program Files/App/app.exe"

# Full capture of the game's traffic, decryptable straight from the pcapng
sudo fritap -s -k game_keys.log -p game.pcapng -f wine ~/.wine/drive_c/Games/game.exe
fritap -r game.pcapng
```

### Attach-mode pattern (most robust for Wine spawn issues)

If spawn mode misbehaves for a specific target, start Wine yourself, then
attach friTap (no `-s`) by exe name or by PID. The target is positional; `-p` is
`--pcap`, not a PID option.

```bash
wine "/path/to/app.exe" &
sleep 2
fritap -k keys.log app.exe
# or by PID:
fritap -k keys.log "$(pgrep -f app.exe | head -1)"
```

Attaching only catches handshakes that happen *after* friTap attached.

### If you must run friTap as root

Plain `sudo fritap -s …` needs nothing extra: spawn mode launches Wine as the
invoking user, so your own prefix is used (see
[Full packet capture](#full-packet-capture)).

In a real root shell or after `su` (no `SUDO_UID`, so friTap has no user to
launch Wine as), Wine runs as root and needs a root-owned prefix:

```bash
# in a root shell
WINEPREFIX=/root/.wine fritap -s -k keys.log wine /path/to/application.exe
```

When passing variables through `sudo`, put `sudo` options such as `-E`
**before** any `VAR=value` assignment: `sudo -E WINEPREFIX=… fritap …`.
`sudo WINEPREFIX=… -E fritap …` is broken, because sudo stops parsing options
at the first `VAR=value` and tries to run a command named `-E`.

Do **not** point a root-running Wine at a user-owned `~/.wine`. friTap's
pre-flight check aborts with a message naming the prefix and its owner (Wine
would otherwise refuse the prefix and exit before anything can be hooked).

## Deployment Models

There are three ways to run friTap against a Wine target:

1. **GDB key extraction (the default on Linux).** Run friTap normally; a Wine
   target is routed to the GDB extractor automatically. It produces an NSS key
   log and supports full packet capture (`-p … -f`). See
   [Key Extraction via GDB](#key-extraction-via-gdb).

   ```bash
   fritap -s -k keys.log wine /path/to/application.exe
   ```

2. **Linux-host Frida agent (experimental, `--wine off --experimental`).**
   friTap injects native Frida into the Wine process. This gives full memory
   visibility (so schannel's underlying GnuTLS is reachable) and is the only
   route for decrypted plaintext (`-p` without `-f`), `--live` and payload
   modification. Because the host Frida sees the System V ABI, PE (Windows)
   code is read via the dual-ABI register technique described below.

   ```bash
   fritap --wine off --experimental -s -k keys.log --pcap plaintext.pcap \
       wine /path/to/application.exe
   ```

3. **Frida inside Wine (fallback).** Install friTap as a Windows process inside
   Wine and run it there (see `research/wine/tls_wine/Installing_fritap_wine.md`).
   Here `args[]` map to the Win64 ABI natively, but schannel memory is not always
   visible and packaging is more involved. Use only if neither host-side model
   works for your target.

## How Wine Support Works

### Detection Mechanism

friTap detects Wine processes using multiple indicators:

**Early Indicators** (available at spawn time):
- `wine64`
- `wine-preloader`
- `wine64-preloader`

**Late Indicators** (available after Wine initializes):
- `ntdll.dll.so`
- `ntdll.so`
- `kernelbase.dll.so`
- `kernel32.dll.so`

### Hybrid Hooking Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Wine Application                          │
│                    (Windows .exe)                            │
└───────────────┬─────────────────────────────┬───────────────┘
                │                             │
    ┌───────────▼───────────┐     ┌──────────▼──────────┐
    │  Linux TLS Libraries   │     │  Windows DLLs       │
    │  (.so files)           │     │  (via Wine)         │
    │                        │     │                     │
    │  • libssl.so           │     │  • libssl*.dll      │
    │  • libgnutls.so        │     │  • wolfssl*.dll     │
    │  • libnss3.so          │     │  • libgnutls*.dll   │
    │  • etc.                │     │  • etc.             │
    └───────────┬───────────┘     └──────────┬──────────┘
                │                             │
                └──────────┬──────────────────┘
                           │
                ┌──────────▼──────────┐
                │   friTap Agent      │
                │   (Wine mode)       │
                │                     │
                │   1. Linux agent    │
                │   2. LdrLoadDll     │
                │      hooking        │
                │   3. Dual-ABI key   │
                │      pattern scan   │
                └─────────────────────┘
```

### DLL Interception

Wine support intercepts Windows DLLs by hooking `LdrLoadDll` in Wine's `ntdll.dll.so`. When a matching DLL is loaded, friTap applies the appropriate hooks.

**Supported Windows DLL Patterns:**

| Library | DLL Pattern |
|---------|-------------|
| OpenSSL/BoringSSL | `libssl*.dll`, `libssl-*.dll` |
| WolfSSL | `*wolfssl*.dll` |
| GnuTLS | `libgnutls*.dll` |
| NSS | `nspr*.dll` |
| mbedTLS | `mbedTLS.dll` |
| Cronet | `*cronet*.dll` |

### Dual-ABI Keylog Pattern Scanning (Key Extraction)

The symbol/export-based DLL hooks above are not enough on their own under Wine,
for two reasons:

1. **Schannel.** Windows apps that use the native `schannel`/`secur32` API never
   expose a hookable TLS session — but under Wine, schannel delegates to GnuTLS.
2. **Mixed ABIs.** friTap injects *native* (Linux-host) Frida into the Wine
   process. On x86-64 a Wine process runs code in **two calling conventions at
   once**: Unix-side `.so` libraries use the **System V ABI** (args in
   `rdi, rsi, rdx, rcx`), while PE-side Windows DLLs use the **Win64 ABI** (args
   in `rcx, rdx, r8, r9`). Reading arguments through Frida's `args[]` abstraction
   silently mis-reads PE code. On AArch64 there is only one ABI (**AAPCS64**,
   args in `x0..x7`), but the internal function still needs locating in memory.

friTap combines three complementary mechanisms to solve both problems:

| Layer | What it does | Coverage |
|-------|--------------|----------|
| 1. **Symbol-based `gnutls_init` hook + injected callback** (`agent/legacy/tls/platforms/linux/gnutls_linux.ts`) | Hooks the exported `gnutls_init`, then on `onLeave` calls `gnutls_session_set_keylog_function(session, cb)`. Wine's schannel goes through this path on every fresh handshake — the callback fires with `(session, label, gnutls_datum_t)` in the normal gnutls contract. **Primary path** and works cross-arch. | Any target that goes through Wine's Unix-side `secur32.so`, including WinHTTP/schannel-via-gnutls |
| 2. **Dynamic pattern discovery** (see below) | Locates `_gnutls_call_keylog_func` in memory **without a hardcoded byte pattern** and prints a ready-to-paste `--patterns` override so you can pin it for offline reuse. Runs the first time layer 1 fires. | Any gnutls build on x86-64 / AArch64 |
| 3. **Byte-pattern scan of loaded modules** (`agent/shared/wine_keylog_pattern_hook.ts`) | Ships x86-64 signatures for `_gnutls_call_keylog_func` (SysV + Win64) and OpenSSL `SSL_log_secret` (Win64). Scans `r-x` and `rwx` ranges of every loaded module and re-scans on each `LdrLoadDll`. Fallback for cases where layer 1 didn't get to see the session's init (attach-after-handshake, resumed sessions). | x86-64 out of the box; AArch64/x86/ARM via `--patterns` overrides |

The scan runs over already-loaded modules at startup and re-runs on each
`LdrLoadDll` for freshly loaded DLLs. Extracted secrets flow through the
normal keylog pipeline, so `-k`/`--pcap` work unchanged. All three layers are
part of the Frida agent (`--wine off --experimental`) and work on both the legacy (default) and
`--modern` agent paths.

| Function (signature) | ABI | Bundled arch | Covers |
|----------------------|-----|--------------|--------|
| `_gnutls_call_keylog_func` | System V (`rdi,rsi,rdx,rcx`) | x86-64 | native `libgnutls.so` **and Windows schannel** (via Wine's GnuTLS) |
| `_gnutls_call_keylog_func` | Win64 (`rcx,rdx,r8,r9`) | x86-64 | PE-compiled `libgnutls-*.dll` bundled with an app |
| `SSL_log_secret` | Win64 | x86-64 | PE-compiled OpenSSL/**BoringSSL** `libssl` (NOT LibreSSL) |
| `tls13_hkdf_expand_label_with_length` (+ `ws2_32!send` for `client_random`) | Win64 | x86-64 | **LibreSSL** (PE `libssl-*.dll` or statically linked, e.g. curl-for-win); `client_random` parsed from the ClientHello on `send`, no offsets needed |
| `tls1_PRF` | Win64 | x86-64 | **LibreSSL** TLS 1.2 (experimental) |
| `_gnutls_call_keylog_func` | AAPCS64 (`x0,x1,x2,x3`) | *(none bundled — supply via `--patterns` or use layer 1/2)* | native ARM64 `libgnutls.so` |

#### Dynamic pattern discovery for GnuTLS *(new)*

Bundled byte signatures only match specific library builds and get stale as
distributions update. friTap now **discovers the address of `_gnutls_call_keylog_func`
at runtime** on any gnutls build. Mechanism (`agent/tls/libs/gnutls.ts`):

1. The exported `gnutls_init` hook injects friTap's own `NativeCallback` via
   `gnutls_session_set_keylog_function`.
2. friTap **also installs an `Interceptor.attach` on the callback's own
   address**. This provides a proper `InvocationContext` with `this.returnAddress`
   — something a bare `NativeCallback` body does *not* give you.
3. The first time gnutls invokes the callback, `this.returnAddress` points
   inside `_gnutls_call_keylog_func`. friTap walks backward using
   arch-specific prologue heuristics to find the function's entry:
   - **x86-64 / x86**: `endbr64` (Intel CET) first, else `push rbp ; mov rsp, rbp`;
     if `push rbp` is found and the preceding 4 bytes are `endbr64`, back up 4.
   - **AArch64**: `stp x29, x30, [sp, #-N]!` (bytes `FD 7B ?? A9`) with 4-byte
     strides; a preceding `paciasp` (`3F 23 03 D5`) or `bti c/j/jc` is
     detected and included so the captured pattern matches the on-disk binary.
     Handles ARMv8.3 PAC by stripping bits `[63:48]` from `returnAddress`.
   - **ARM (32-bit)**: `push {..., lr}` — best-effort.
4. friTap logs three lines you can act on:

    ```text
    [gnutls dyn] resolved _gnutls_call_keylog_func @ 0x780fa5c54e90
    [gnutls dyn] version-specific pattern (32 bytes): 55 48 89 E5 41 57 41 56 41 55 41 54 …
    [gnutls dyn] --patterns override:  { "modules": { "gnutls": { "wine": { "x64": {
                "gnutls_keylog_sysv": { "primary": "55 48 89 E5 41 57 …" } } } } } }
    ```

The last line is a **copy-paste ready** `pattern.json`. Save it as
`patterns/mybuild.json` and rerun with `--patterns patterns/mybuild.json`
for a stable byte-pattern hook that survives library rebuilds *of that exact
version*. On AArch64 the schema arch key becomes `arm64` and the sig id becomes
`gnutls_keylog_aarch64` — those are emitted automatically.

!!! tip "When does the discovery line print?"
    Only when gnutls actually fires the injected callback — i.e. when a fresh
    TLS handshake happens **after** friTap attached. If your target caches
    connections or uses session resumption, generate fresh handshakes by
    rotating hosts (see `dev/wine_e2e_test.sh` for a working recipe).

#### Custom / version-specific signatures via `--patterns`

If you already have a pattern (from a previous discovery run, from a research
build, or from a completely different Wine target), supply it with
`--patterns pattern.json` under the `wine.<arch>` key:

```json
{
  "modules": {
    "gnutls": {
      "wine": {
        "x64": {
          "gnutls_keylog_sysv":  { "primary": "F3 0F 1E FA ..." },
          "gnutls_keylog_win64": { "primary": "48 83 EC 38 ..." }
        },
        "arm64": {
          "gnutls_keylog_aarch64": { "primary": "3F 23 03 D5 FD 7B BF A9 ..." }
        }
      }
    },
    "openssl": {
      "wine": { "x64": { "openssl_log_secret_win64": { "primary": "41 57 41 56 ..." } } }
    }
  }
}
```

Arch keys are `x64` (Frida `Process.arch === "x64"`), `arm64`, `x86` (ia32),
`arm`. Each signature id accepts `primary`, `fallback`, and `second_fallback`
patterns. A user-supplied pattern overrides the bundled default for that id.
On non-x86-64 architectures where friTap ships no bundled bytes, the scan is
skipped unless you provide an override — the symbol-based gnutls hooks
(layer 1 above) still capture keys either way.

## Supported TLS Libraries

### Windows DLLs (via Wine)

| Library | Support | Notes |
|---------|---------|-------|
| OpenSSL/BoringSSL | Full | Key extraction + traffic; PE builds keyed via Win64 `SSL_log_secret` pattern |
| WolfSSL | Full | Key extraction + traffic |
| GnuTLS | Full | Key extraction + traffic; dual-ABI keylog pattern (System V + Win64) |
| Schannel | Keys | Key extraction via Wine's underlying GnuTLS (`_gnutls_call_keylog_func`) |
| NSS | Full | Key extraction + traffic |
| mbedTLS | R/W | Traffic hooks only |
| Cronet | Full | Pattern-based hooking |

### Native Linux Libraries

Wine applications can also use native Linux TLS libraries. All standard Linux library support applies:

| Library | Support | Notes |
|---------|---------|-------|
| OpenSSL/BoringSSL | Full | Key extraction + traffic |
| GnuTLS | Full | Key extraction + traffic |
| NSS | Full | Key extraction + traffic |
| WolfSSL | Full | Key extraction + traffic |
| Rustls | Keys | Key extraction only |
| Go TLS | Full | Go crypto/tls |
| S2N-TLS | Full | AWS TLS library |

## Technical Details

### Socket Handling

Wine applications use Linux sockets (via `libc`) rather than Windows sockets (`WS2_32.dll`). friTap's socket tracing works the same as native Linux applications.

Socket tracing is part of the Frida agent, so select it explicitly:

```bash
# Enable socket tracing for Wine apps (Frida agent)
fritap --wine off --experimental -s --socket_tracing -k keys.log wine /path/to/app.exe
```

### Process Timing

Wine module detection may not be immediately available at process spawn time. The agent handles this by:

1. Checking for early Wine indicators during spawn
2. Setting up delayed hooking for DLL loading via `LdrLoadDll`
3. Processing both pre-loaded and dynamically loaded DLLs

### End-to-end verification

`dev/wine_e2e_test.sh` is a self-contained script that proves the entire chain
works on your box:

* Launches `cscript.exe` under `wine64` via `setsid` (survives shell exit).
* Fires 120 HTTPS probes across 8 rotating hosts through Wine's
  WinHTTP → schannel → gnutls path — the rotation defeats TLS session
  resumption so every probe forces a fresh handshake.
* Attaches friTap with `--wine off --experimental` (the Frida agent — the
  GDB key extractor used by default does not do dynamic pattern discovery),
  monitors the keylog and the dynamic-discovery emissions in real time.
* Reports the number of captured `CLIENT_RANDOM` lines and the
  ready-to-paste `--patterns` override for the local gnutls build.

Run it as your desktop user (not root):

```bash
sysctl kernel.yama.ptrace_scope=0   # one-time, if not already 0
dev/wine_e2e_test.sh
```

The dynamic-discovery output tells you at a glance whether the byte pattern
scan can be pinned for this build:

```text
[gnutls dyn] resolved _gnutls_call_keylog_func @ 0x780fa5c54e90
[gnutls dyn] version-specific pattern (32 bytes): 55 48 89 E5 41 57 41 56 …
[gnutls dyn] --patterns override:  { "modules": { "gnutls": { "wine": { "x64": { … } } } } }
```


## Limitations

### Known Limitations

1. **Experimental Status (Frida agent)** - The Frida-based Wine agent is still under development and needs more testing
2. **Manual Flag Required (Frida agent)** - The Frida agent must be selected with `--wine off --experimental`; the GDB key extractor is the default and needs no flag
3. **Timing Sensitivity** - Some applications may load DLLs before hooks are installed
4. **DLL Path Parsing** - Complex Windows paths may occasionally cause issues
5. **Spawning issue (Frida agent)** - Spawning a Wine application with the Frida agent often results in Wine restarting without our hooks. The GDB path avoids this with launch + freeze-on-detect + attach
6. **No decrypted plaintext on the GDB path** - Plaintext pcaps (`-p` without `-f`), `--live` and payload modification need the Frida agent

### Unsupported Scenarios

- Windows-only TLS implementations without DLL exports
- Applications using custom/proprietary encryption
- Heavily obfuscated Windows executables
- Applications with anti-debugging/anti-hooking protections

## Troubleshooting

### Wine Not Detected

```bash
# Check if Wine process is recognized
fritap -s -do -v -k keys.log wine /path/to/app.exe 2>&1 | grep -i wine

# Verify Wine installation
wine --version
wine64 --version
```

### No Traffic Captured

```bash
# Enable debug output
fritap -s -do -v -k keys.log wine /path/to/app.exe

# Without -s friTap attaches instead of launching; if the app is not running yet
# it prints a hint to add -s. Make sure you are using the mode you intended.

# Check for DLL detection (Frida agent)
fritap --wine off --experimental -s -do wine /path/to/app.exe 2>&1 | grep -i "dll\|library"

# Try enabling default socket info (Frida agent)
fritap --wine off --experimental -s --enable_default_fd -k keys.log wine /path/to/app.exe
```

If friTap aborts before launching Wine with a message about WINEPREFIX
ownership, see "Common mistake" under [Prerequisites](#prerequisites).

### Application Crashes

```bash
# Try attach mode instead of spawn
# First start the application
wine /path/to/app.exe &

# Then attach to the running process (no -s), by name or by PID
fritap -k keys.log app.exe
fritap -k keys.log "$(pgrep -f app.exe | head -1)"
```

### DLL Not Hooked

```bash
# List loaded DLLs in the Wine process
cat "/proc/$(pgrep -f app.exe | head -1)/maps" | grep -i "\.dll"

# Check if the DLL matches supported patterns
# The DLL must match one of the supported patterns listed above
```

## Use Cases

### Game Analysis

```bash
# Analyze network traffic from Windows games: keys + full capture
sudo fritap -s -k game_keys.log -p game_traffic.pcapng -f \
    wine ~/.wine/drive_c/Games/SomeGame/game.exe

# Decrypted plaintext pcap instead (experimental Frida agent)
fritap --wine off --experimental -s -k game_keys.log --pcap game_plaintext.pcap \
    wine ~/.wine/drive_c/Games/SomeGame/game.exe
```

### Windows Application Testing

```bash
# Test Windows applications for TLS issues
fritap -s -v -k app_keys.log wine /path/to/app.exe
```


## Best Practices

### 1. Use Isolated Wine Prefixes

```bash
# Create isolated Wine prefix for analysis
export WINEPREFIX=~/.wine_analysis
wine winecfg  # Initialize prefix

# Run analysis in isolated prefix (as the prefix owner, no sudo)
WINEPREFIX=~/.wine_analysis fritap -s -k keys.log wine /path/to/app.exe
```

### 2. Enable Verbose Output Initially

```bash
# Start with verbose output to understand what's being hooked
fritap -s -v -do -k keys.log wine /path/to/app.exe
```

### 3. Use Spawn Mode for Initialization Capture

```bash
# Capture keys from application startup (GDB path: launch + freeze-on-detect + attach)
fritap -s -k keys.log wine /path/to/app.exe
```

Spawn mode with the Frida agent (`--wine off --experimental -s …`) is still in
a very early experimental state and can crash the target.

### 4. Document Working Configurations

- Note which Wine versions work with specific applications
- Record successful command-line combinations
- Report issues and working configurations to help improve Wine support

## Next Steps

- **[Linux Platform Guide](linux.md)** - Standard Linux application analysis
- **[Windows Platform Guide](windows.md)** - Native Windows analysis
- **[Pattern-Based Hooking](../advanced/patterns.md)** - Custom patterns for unsupported libraries
- **[Troubleshooting](../troubleshooting/common-issues.md)** - Common issues and solutions
