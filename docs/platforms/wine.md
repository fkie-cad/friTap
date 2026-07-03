# Wine Platform Guide (Experimental)

This guide covers Wine-specific setup, considerations, and best practices for using friTap to analyze Windows applications running under Wine on Linux.

!!! warning "Experimental Feature"
    Wine support is an **experimental feature** that requires the `--experimental` flag. It is still under development and may have stability issues. Please report any problems via GitHub issues.

## Overview

friTap's Wine support allows you to intercept TLS traffic from Windows applications running under Wine. This is achieved through a hybrid approach:

1. **Native Linux TLS Libraries** - Hooks Linux `.so` libraries that Wine applications may use
2. **Windows DLL Interception** - Hooks Windows TLS libraries (`.dll` files) bundled with applications

## Prerequisites

### System Requirements

- **Linux system** with Wine installed
- **Wine 5.0+** (recommended Wine 7.0+ for better compatibility)
- **Root/sudo access** (required for Frida injection)
- **Python 3.8+** with friTap installed
- **Frida injection privileges.** On a desktop Linux you almost always want to
  run friTap as your *own* user — `sudo` is the most common source of failure
  for Wine targets (see "Common mistake" below). Lower `kernel.yama.ptrace_scope`
  so Frida can attach as a non-root user:

  ```bash
  sudo sysctl kernel.yama.ptrace_scope=0   # one-time; survives until reboot
  ```

!!! danger "Common mistake: `sudo fritap … wine …` with a user-owned WINEPREFIX"
    Modern Wine (≥7) hard-aborts when the running uid does not match the
    WINEPREFIX directory's owner uid (it prints
    `wine: '/home/<you>/.wine' is not owned by you, refusing to create a
    configuration directory there` and exits within ~10–25 ms of starting).
    The most common trigger is `sudo fritap … -s wine …` while your `~/.wine`
    is owned by your desktop user. friTap's Wine agent now performs a
    pre-flight check for this exact mismatch and bails out clearly instead of
    looking like a hook crash. **Fix:** drop `sudo` (with `ptrace_scope=0`), or
    set `WINEPREFIX=/root/.wine` so Wine creates a fresh root-owned prefix.


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

Run friTap **as the owner of your WINEPREFIX** (normally your desktop user, not
root). Do not prefix with `sudo` unless you have explicitly set up a
root-owned WINEPREFIX.

```bash
# Basic Wine application analysis (requires --experimental flag)
fritap --experimental -k keys.log wine /path/to/application.exe

# With PCAP capture
fritap --experimental -k keys.log --pcap traffic.pcap wine /path/to/application.exe

# Spawn mode for capturing initialization
fritap --experimental -s -k keys.log wine /path/to/application.exe
```

### Examples

```bash
# Analyze a Windows game
sudo fritap --experimental -k game_keys.log wine ~/.wine/drive_c/Games/game.exe

# Analyze with verbose output
sudo fritap --experimental -v -k keys.log wine /path/to/app.exe

# Debug mode for troubleshooting
sudo fritap --experimental -do -v wine /path/to/app.exe

# Spawn target whose path contains spaces — quote it so the shell passes one
# token; friTap preserves the argv and spawns it intact (no space-splitting).
sudo fritap --experimental -s -k keys.log wine "/home/u/.wine/drive_c/Program Files/App/app.exe"
```

### Attach-mode pattern (most robust for Wine spawn issues)

If spawn mode misbehaves for a specific target, start Wine yourself, then
attach friTap by PID:

```bash
wine "/path/to/app.exe" &
sleep 2
fritap --experimental -k keys.log -p "$(pgrep -f app.exe | head -1)"
```

### If you must run friTap as root

If your workflow genuinely requires `sudo` (e.g. a packaged frida-server setup
that won't otherwise let you inject), give Wine a root-owned prefix:

```bash
sudo WINEPREFIX=/root/.wine -E fritap --experimental -k keys.log \
    -s wine /path/to/application.exe
```

Do **not** point a root-running Wine at a user-owned `~/.wine` — Wine will
refuse the prefix and exit before friTap can hook anything.

>>>>>>> a8fe099f667b13ffeb2ea4e67031af5ee8228355
## Deployment Models

There are two ways to run friTap against a Wine target:

1. **Linux-host Frida (recommended, the default).** Run friTap normally on Linux;
   it injects native Frida into the Wine process. This gives full memory
   visibility (so schannel's underlying GnuTLS is reachable) and is what every
   command in this guide uses. Because the host Frida sees the System V ABI, PE
   (Windows) code is read via the dual-ABI register technique described below.

   ```bash
   fritap --experimental -k keys.log wine /path/to/application.exe
   ```

2. **Frida inside Wine (fallback).** Install friTap as a Windows process inside
   Wine and run it there (see `research/wine/tls_wine/Installing_fritap_wine.md`).
   Here `args[]` map to the Win64 ABI natively, but schannel memory is not always
   visible and packaging is more involved. Use only if the host-side model does
   not work for your target.

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
gated behind `--experimental` and work on both the legacy (default) and
`--modern` agent paths.

| Function (signature) | ABI | Bundled arch | Covers |
|----------------------|-----|--------------|--------|
| `_gnutls_call_keylog_func` | System V (`rdi,rsi,rdx,rcx`) | x86-64 | native `libgnutls.so` **and Windows schannel** (via Wine's GnuTLS) |
| `_gnutls_call_keylog_func` | Win64 (`rcx,rdx,r8,r9`) | x86-64 | PE-compiled `libgnutls-*.dll` bundled with an app |
| `SSL_log_secret` | Win64 | x86-64 | PE-compiled OpenSSL/LibreSSL `libssl` |
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
>>>>>>> a8fe099f667b13ffeb2ea4e67031af5ee8228355

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

```bash
# Enable socket tracing for Wine apps
fritap --experimental --socket_tracing -k keys.log wine /path/to/app.exe
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
* Attaches friTap with `--experimental`, monitors the keylog and the
  dynamic-discovery emissions in real time.
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

1. **Experimental Status** - The feature is still under development and needs more testing
2. **Manual Flag Required** - Must explicitly enable with `--experimental`
3. **Timing Sensitivity** - Some applications may load DLLs before hooks are installed
4. **DLL Path Parsing** - Complex Windows paths may occasionally cause issues
5. **Spawning issue** - Spawning a wine application mostly result in restarting wine without our hooks

### Unsupported Scenarios

- Windows-only TLS implementations without DLL exports
- Applications using custom/proprietary encryption
- Heavily obfuscated Windows executables
- Applications with anti-debugging/anti-hooking protections

## Troubleshooting

### Wine Not Detected

```bash
# Check if Wine process is recognized
fritap --experimental -do -v wine /path/to/app.exe 2>&1 | grep -i wine

# Verify Wine installation
wine --version
wine64 --version
```

### No Traffic Captured

```bash
# Enable debug output
<<<<<<< HEAD
sudo fritap --experimental -do -v wine /path/to/app.exe

# Check for DLL detection
sudo fritap --experimental -do wine /path/to/app.exe 2>&1 | grep -i "dll\|library"

# Try enabling default socket info
fritap --experimental -do -v wine /path/to/app.exe

# Check for DLL detection
fritap --experimental -do wine /path/to/app.exe 2>&1 | grep -i "dll\|library"

# Try enabling default socket info
fritap --experimental --enable_default_fd -k keys.log wine /path/to/app.exe
```

### Application Crashes

```bash
# Try attach mode instead of spawn
# First start the application
wine /path/to/app.exe &

# Then attach to running process
fritap --experimental -k keys.log $(pgrep -f app.exe)
```

### DLL Not Hooked

```bash
# List loaded DLLs in the Wine process
cat /proc/$(pgrep -f app.exe)/maps | grep -i "\.dll"

# Check if the DLL matches supported patterns
# The DLL must match one of the supported patterns listed above
```

## Use Cases

### Game Analysis

```bash
# Analyze network traffic from Windows games
fritap --experimental -k game_keys.log --pcap game_traffic.pcap \
    wine ~/.wine/drive_c/Games/SomeGame/game.exe
```

### Windows Application Testing

```bash
# Test Windows applications for TLS issues
fritap --experimental -v -k app_keys.log wine /path/to/app.exe
```


## Best Practices

### 1. Use Isolated Wine Prefixes

```bash
# Create isolated Wine prefix for analysis
export WINEPREFIX=~/.wine_analysis
wine winecfg  # Initialize prefix

# Run analysis in isolated prefix
WINEPREFIX=~/.wine_analysis sudo -E fritap --experimental -k keys.log wine /path/to/app.exe
```

### 2. Enable Verbose Output Initially

```bash
# Start with verbose output to understand what's being hooked
fritap --experimental -v -do wine /path/to/app.exe
```

### 3. Use Spawn Mode for Initialization Capture

```bash
# Capture traffic from application startup (still in an very early experimental state; can result into crashes)
fritap --experimental -s -k keys.log wine /path/to/app.exe
```

### 4. Document Working Configurations

- Note which Wine versions work with specific applications
- Record successful command-line combinations
- Report issues and working configurations to help improve Wine support

## Next Steps

- **[Linux Platform Guide](linux.md)** - Standard Linux application analysis
- **[Windows Platform Guide](windows.md)** - Native Windows analysis
- **[Pattern-Based Hooking](../advanced/patterns.md)** - Custom patterns for unsupported libraries
- **[Troubleshooting](../troubleshooting/common-issues.md)** - Common issues and solutions
