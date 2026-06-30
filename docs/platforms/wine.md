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

```bash
# Basic Wine application analysis (requires --experimental flag)
sudo fritap --experimental -k keys.log wine /path/to/application.exe

# With PCAP capture
sudo fritap --experimental -k keys.log --pcap traffic.pcap wine /path/to/application.exe

# Spawn mode for capturing initialization
sudo fritap --experimental -s -k keys.log wine /path/to/application.exe
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

## Deployment Models

There are two ways to run friTap against a Wine target:

1. **Linux-host Frida (recommended, the default).** Run friTap normally on Linux;
   it injects native Frida into the Wine process. This gives full memory
   visibility (so schannel's underlying GnuTLS is reachable) and is what every
   command in this guide uses. Because the host Frida sees the System V ABI, PE
   (Windows) code is read via the dual-ABI register technique described below.

   ```bash
   sudo fritap --experimental -k keys.log wine /path/to/application.exe
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

!!! info "x86-64 only"
    This capability currently targets **x86-64** Wine targets.

The symbol/export-based DLL hooks above are not enough on their own under Wine,
for two reasons:

1. **Schannel.** Windows apps that use the native `schannel`/`secur32` API never
   expose a hookable TLS session — but under Wine, schannel delegates to GnuTLS.
2. **Mixed ABIs.** friTap injects *native* (Linux-host) Frida into the Wine
   process. On x86-64 a Wine process runs code in **two calling conventions at
   once**: Unix-side `.so` libraries use the **System V ABI** (args in
   `rdi, rsi, rdx, rcx`), while PE-side Windows DLLs use the **Win64 ABI** (args
   in `rcx, rdx, r8, r9`). Reading arguments through Frida's `args[]` abstraction
   silently mis-reads PE code.

To solve both, friTap scans loaded modules for the **byte signature of the
internal keylog/secret-logging function** and, at each match, reads the secret,
label and `client_random` straight from the CPU registers matching that
signature's ABI (the same register-reading technique friTap already uses for
Go's non-System-V ABI). This is adapted from the research proof-of-concept in
`research/wine/tls_wine/`.

| Function (signature) | ABI | Covers |
|----------------------|-----|--------|
| `_gnutls_call_keylog_func` | System V | native `libgnutls.so` **and Windows schannel** (via Wine's GnuTLS) |
| `_gnutls_call_keylog_func` | Win64 | PE-compiled `libgnutls-*.dll` bundled with an app |
| `SSL_log_secret` | Win64 | PE-compiled OpenSSL/LibreSSL `libssl` |

The scan runs over already-loaded modules at startup and re-runs on each
`LdrLoadDll` for freshly loaded DLLs. It is gated behind `--experimental` and
works on both the legacy (default) and `--modern` agent paths. Extracted secrets
flow through the normal keylog pipeline, so `-k`/`--pcap` work unchanged.

#### Custom / version-specific signatures via `--patterns`

The bundled signatures match specific library builds. If your target uses a
different GnuTLS/OpenSSL version, supply your own byte patterns with
`--patterns pattern.json` under a `wine` platform key:

```json
{
  "modules": {
    "gnutls": {
      "wine": {
        "x64": {
          "gnutls_keylog_sysv":  { "primary": "F3 0F 1E FA ..." },
          "gnutls_keylog_win64": { "primary": "48 83 EC 38 ..." }
        }
      }
    },
    "openssl": {
      "wine": { "x64": { "openssl_log_secret_win64": { "primary": "41 57 41 56 ..." } } }
    }
  }
}
```

Each signature id (`gnutls_keylog_sysv`, `gnutls_keylog_win64`,
`openssl_log_secret_win64`) accepts `primary`, `fallback`, and `second_fallback`
patterns. A user-supplied pattern overrides the bundled default for that id.

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
sudo fritap --experimental --socket_tracing -k keys.log wine /path/to/app.exe
```

### Process Timing

Wine module detection may not be immediately available at process spawn time. The agent handles this by:

1. Checking for early Wine indicators during spawn
2. Setting up delayed hooking for DLL loading via `LdrLoadDll`
3. Processing both pre-loaded and dynamically loaded DLLs

## Limitations

### Known Limitations

1. **Experimental Status** - The feature is still under development and needs more testing
2. **Manual Flag Required** - Must explicitly enable with `--experimental`
3. **Timing Sensitivity** - Some applications may load DLLs before hooks are installed
4. **DLL Path Parsing** - Complex Windows paths may occasionally cause issues

### Unsupported Scenarios

- Windows-only TLS implementations without DLL exports
- Applications using custom/proprietary encryption
- Heavily obfuscated Windows executables
- Applications with anti-debugging/anti-hooking protections

## Troubleshooting

### Wine Not Detected

```bash
# Check if Wine process is recognized
sudo fritap --experimental -do -v wine /path/to/app.exe 2>&1 | grep -i wine

# Verify Wine installation
wine --version
wine64 --version
```

### No Traffic Captured

```bash
# Enable debug output
sudo fritap --experimental -do -v wine /path/to/app.exe

# Check for DLL detection
sudo fritap --experimental -do wine /path/to/app.exe 2>&1 | grep -i "dll\|library"

# Try enabling default socket info
sudo fritap --experimental --enable_default_fd -k keys.log wine /path/to/app.exe
```

### Application Crashes

```bash
# Try attach mode instead of spawn
# First start the application
wine /path/to/app.exe &

# Then attach to running process
sudo fritap --experimental -k keys.log $(pgrep -f app.exe)
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
sudo fritap --experimental -k game_keys.log --pcap game_traffic.pcap \
    wine ~/.wine/drive_c/Games/SomeGame/game.exe
```

### Windows Application Testing

```bash
# Test Windows applications for TLS issues
sudo fritap --experimental -v -k app_keys.log wine /path/to/app.exe
```

### Security Research

```bash
# Analyze Windows malware samples in isolated Wine environment
sudo fritap --experimental -k malware_keys.log --pcap malware_traffic.pcap \
    --json malware_metadata.json wine /path/to/suspicious.exe
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
sudo fritap --experimental -v -do wine /path/to/app.exe
```

### 3. Use Spawn Mode for Initialization Capture

```bash
# Capture traffic from application startup
sudo fritap --experimental -s -k keys.log wine /path/to/app.exe
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
