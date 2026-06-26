# Android Platform Guide

This guide covers Android-specific setup, considerations, and best practices for using friTap on Android devices.

## Prerequisites

### Device Requirements

- **Rooted Android device** (required for friTap operation)
- **Android 7.0+** (minimum supported version)
- **ARM, ARM64, x86-64 or x86 architecture** support
- **USB Debugging enabled**
- **Developer Options enabled**

### Development Machine Setup

```bash
# Install ADB (Android Debug Bridge)
# Ubuntu/Debian
sudo apt install android-tools-adb

# macOS
brew install android-platform-tools

# Windows
# Download from https://developer.android.com/studio/releases/platform-tools
```

## Device Setup

### Enable Developer Options

1. Go to **Settings → About Phone**
2. Tap **Build Number** 7 times
3. Go back to **Settings → Developer Options**
4. Enable **USB Debugging**

### Root Access Verification

```bash
# Check device connection
adb devices

# Verify root access
adb shell su -c "id"

# Expected output:
# uid=0(root) gid=0(root) groups=0(root)
```

### frida-server Installation

**Step 1: Download frida-server**

```bash
# Check device architecture
adb shell getprop ro.product.cpu.abi

# Download matching frida-server from GitHub releases
# Example for ARM64:
wget https://github.com/frida/frida/releases/download/17.0.0/frida-server-17.0.0-android-arm64.xz
xz -d frida-server-17.0.0-android-arm64.xz
```

**Step 2: Install on Device**

```bash
# Push to device
adb push frida-server-17.0.0-android-arm64 /data/local/tmp/frida-server

# Set permissions
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server
adb shell su -c "/data/local/tmp/frida-server &"

# Verify it's running
adb shell ps | grep frida-server
```

## Basic Android Analysis

### Package Name Discovery

```bash
# List all installed packages
adb shell pm list packages

# Search for specific app
adb shell pm list packages | grep instagram

# Get package details
adb shell dumpsys package com.instagram.android | grep version
```

### Basic Analysis Commands

```bash
# Extract TLS keys from Android app
fritap -m -k instagram_keys.log com.instagram.android

# Capture decrypted traffic
fritap -m --pcap instagram_traffic.pcap com.instagram.android

# Spawn app from beginning
fritap -m -s -k keys.log com.example.app

# Verbose analysis with debug output
fritap -m -v -k keys.log -do com.example.app
```

## Android-Specific Features

### Anti-Root Detection Bypass

Many Android apps detect root access and refuse to run:

```bash
# Enable anti-root bypass
fritap -m --anti_root -k keys.log com.example.app

# Combined with spawn mode
fritap -m -s --anti_root -k keys.log com.example.app
```

### Spawn Gating

Capture child processes and services:

```bash
# Capture all spawned processes
fritap -m --enable_spawn_gating -k keys.log com.example.app

# Useful for apps that use services or multiple processes
```

### Default Socket Information

When socket information cannot be determined:

```bash
# Use fallback socket information (127.0.0.1:1234-127.0.0.1:2345)
fritap -m --enable_default_fd --pcap traffic.pcap com.example.app
```

### PairIP-Protected Apps (anti-tamper)

Apps hardened with Google **PairIP** (`libpairipcore.so`) crash with a `SIGSEGV`
under friTap's default inline hooks. Use the scan-free `--pairip-safe` mode:

```bash
fritap -m -k keys.log --pairip-safe -v com.example.app
```

See the dedicated guide: **[PairIP-Protected Apps](../advanced/pairip-safe.md)**.

## SSL/TLS Libraries on Android

### Supported Libraries

friTap has comprehensive support for Android TLS libraries, covering both system libraries and statically-linked implementations.

| Library | Apps Using It | friTap Support | Notes |
|---------|---------------|----------------|-------|
| **BoringSSL/OpenSSL** | Chrome, most Google apps | ✓ Full | Key extraction + traffic |
| **Conscrypt** | Android system, many apps | ✓ Full | Uses BoringSSL internally |
| **GnuTLS** | Some native apps | ✓ Full | Key extraction + traffic |
| **WolfSSL** | IoT/embedded apps | ✓ Full | Key extraction + traffic |
| **mbedTLS** | Embedded/IoT apps | R/W | Traffic hooks only |
| **NSS** | Firefox, Mozilla apps | ✓ Full | Key extraction + traffic |
| **Cronet** | Chrome-based networking | ✓ Full | Pattern-based hooking |
| **Flutter** | Flutter applications | ✓ Full | Built-in patterns |
| **S2N-TLS** | AWS SDK apps | ✓ Full | Key extraction + traffic |
| **Rustls** | Rust-based apps | Keys | Key extraction only |
| **Go TLS** | Go applications | ✓ Full | Runtime version detection |
| **BouncyCastle/Spongycastle** | Java crypto apps | ✓ Full | Java-level hooking |
| **Mono BTLS** | Xamarin/.NET apps | ✓ Full | Pattern-based hooking |
| **MetaRTC** | WebRTC applications | ✓ Full | Pattern-based hooking |
| **Java TLS** | Pure Java apps | ✓ Full | Java-level hooking |

**Legend:**
- ✓ **Full**: Key extraction + traffic decryption
- R/W: Read/Write hooks (traffic without keys)
- Keys: Key extraction only

!!! note "QUIC keys and OHTTP are captured alongside TLS"
    QUIC key material — **Google QUICHE** (Chrome/Cronet), **Cloudflare quiche**, and
    **Mozilla neqo** (Firefox) — is extracted on Android together with the TLS keylog;
    no separate flag is required. Likewise, **OHTTP** (Oblivious HTTP, NSS HPKE) is
    captured **within `--protocol tls`** — there is no separate `--protocol ohttp` or
    `--ohttp` flag, since `tls` covers the whole TLS family (TLS, QUIC, and OHTTP).

### Pattern-Based Hooking for Stripped Libraries

Many Android apps ship **stripped** or **statically-linked** TLS stacks where the
key-extraction symbols (`SSL_log_secret`, etc.) are not exported. friTap resolves
these byte-pattern first, falling back to its built-in pattern registry when no
symbol is available — no manual offsets required for the common cases.

```bash
# Use patterns for Flutter apps
fritap -m --patterns flutter_patterns.json -k keys.log com.flutter.app

# Generate custom patterns with BoringSecretHunter
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output boringsecrethunter
```

friTap includes built-in patterns for common libraries, but you may need to generate custom patterns for specific app versions.

#### Built-in pattern registry (Android)

The Android hook registry (`agent/platforms/android.ts`) ships matchers for the
stripped/statically-linked stacks below. These are matched by **library filename**,
so a stripped APK is hooked without any extra configuration:

| Library / stack | Matches (filename) | friTap registry entry |
|-----------------|--------------------|-----------------------|
| **libcronet** (GMS / mainline / APEX) | `libcronet*.so`, `libmainlinecronet.<ver>.so` | `Cronet`, `Cronet (mainline runtime)`, `Google QUICHE (Cronet)` |
| **libflutter** | `*flutter*.so` | `Flutter BoringSSL` |
| **libmonochrome** (Chrome / WebView) | `*monochrome*.so` | `Cronet (Monochrome)`, `Google QUICHE (Monochrome)` |
| **Signal / RingRTC** | `libsignal_jni*.so`, `libringrtc_rffi*.so` | `Cronet (Signal)`, `Cronet (RingRTC)` |
| **Cloudflare Warp** | `libwarp_mobile*.so` | `Cronet (Warp Mobile)` |

!!! note "Chrome / Cronet are BoringSSL underneath"
    The Chrome, Cronet, Signal, RingRTC and Warp matchers all route to the same
    BoringSSL key-extraction hook. Chrome-browser QUIC specifically lives in
    `libmonochrome*.so` (no resolvable symbols), which is why pattern-based hooking
    is mandatory there.

See [Pattern-based Hooking](../advanced/patterns.md) for the pattern-file schema, the
`--patterns`/`--offsets`/`--force-scan` flags, and how to author patterns with
BoringSecretHunter, r2 or Ghidra.

## QUIC / HTTP/3 on Android

Modern Android apps increasingly use QUIC (HTTP/3) through Chrome's network stack
(Cronet / `libmonochrome`). friTap extracts **QUIC keys alongside TLS** and can
capture decrypted QUIC/HTTP/3 plaintext. The QUIC stacks covered on Android are
Google QUICHE (Chrome/Cronet), Cloudflare quiche, and Mozilla neqo (Firefox); their
key material is dumped together with the TLS keylog — no separate flag is needed.

### `--quic-only` — QUIC-only hooking

Install **only** the QUIC hooks and skip the TLS-library hooks (BoringSSL, NSS,
GnuTLS, ...), OHTTP, the keylog scan pass, and the Android Java hooks:

```bash
# Attach with QUIC hooks only (lighter attach, no Java VM safepoint sync)
fritap -m --quic-only -k quic_keys.log com.android.chrome
```

This gives a dramatically lighter attach (no multi-MB pattern scans, and on Android
no Java VM safepoint synchronization), which helps friTap attach to a target that is
**already in active QUIC traffic**. On Android the filter scope is **Google QUICHE
(Cronet) only**.

### `--quic-capture-mode {stream,app-api}`

Select the QUIC plaintext capture boundary (default: `stream`):

```bash
# Default lower-boundary stream-level hooks
fritap -m --quic-capture-mode stream -k keys.log com.android.chrome

# Application-API boundary with decoded HTTP/3 headers (Chrome / Android Google QUICHE)
fritap -m --quic-capture-mode app-api -k keys.log com.android.chrome
```

- **`stream`** (default) — current lower-boundary stream-level hooks
  (`QuicStream` / `QuicStreamSequencer::Readv`).
- **`app-api`** — captures at the application-API "Boundary-4" with **decoded HTTP/3
  headers**. Only available for Chrome/Android Google QUICHE.

### `--quic-egress-headers-layer {auto,quiche-internal,chrome-shim,session-level}`

Override which layer of the HTTP/3 **egress**-headers chain the agent attaches to
(default: `auto`). This only takes effect with `--quic-capture-mode app-api`:

```bash
# Force the chrome-shim fallback layer (testing the egress chain)
fritap -m --quic-capture-mode app-api --quic-egress-headers-layer chrome-shim \
  -k keys.log com.android.chrome
```

`auto` keeps the winner-takes-all fallback chain (`quiche-internal` preferred,
`chrome-shim` as fallback, `session-level` as last resort). Set it explicitly to force
a particular layer when validating chain behavior on builds where the
`quiche-internal` path still resolves.

See the [QUIC protocol guide](../protocols/quic.md) for the full HTTP/3 capture model.

## Decrypted Plaintext Capture Stability

Recent Android work improved the reliability of **plaintext (decrypted)** capture for
apps whose TLS sockets are not directly reachable from the SSL object. Stacks that
wrap the socket in an in-memory BIO (or do async I/O) leave the SSL object **without a
usable socket file descriptor**, which previously produced flows with missing peer
addresses.

friTap now correlates each thread's most-recent stream-socket FD with the
`SSL_Read`/`SSL_Write` calls happening synchronously on that same thread, recovering
the peer endpoint for the connection. The tracker is armed lazily — only the first
time a socket-less SSL object is actually observed — so apps that always expose a
valid FD pay no overhead. Only TCP (SOCK_STREAM) sockets are eligible, so DNS/QUIC
datagram sockets are never mis-attributed as the peer of a TLS connection.

In practice this means more complete `--pcap` output (correct source/destination
addresses) for apps using BIO-wrapped or NIO/async networking, with no extra flags.

## `--modern` (EXPERIMENTAL agent path)

!!! warning "EXPERIMENTAL — default is the legacy path"
    `--modern` opts into the refactored ("modern") friTap agent code path. The
    **default is the stable legacy path** for TLS libraries. On Android/Windows the
    modern path unlocks the three-tier BoringSSL keylog chain and improved Cronet
    hooks, but it has **known regressions** versus legacy: **iOS/macOS Cronet, Windows
    LSASS, and IPsec**. Use it only when you specifically need the modern hooks.

```bash
# Opt into the modern agent path on Android
fritap -m --modern -k keys.log com.example.app
```

The modern path is **auto-enabled** when you select `--protocol ssh` or
`--protocol ipsec` (those agents live only in the modern path); you do not need to
pass `--modern` in that case.

## Application Categories

### Social Media Apps

```bash
# Instagram
fritap -m -k instagram_keys.log com.instagram.android

# Twitter
fritap -m --pcap twitter_traffic.pcap com.twitter.android

# TikTok
fritap -m -s -k tiktok_keys.log com.zhiliaoapp.musically
```

### Banking Applications

!!! warning "Use Test Accounts Only"
    Always use test accounts and isolated environments when analyzing banking applications.

```bash
# Generic banking app analysis
fritap -m --anti_root -k bank_keys.log com.example.bankapp

# Monitor authentication flows
fritap -m -s --pcap bank_auth.pcap com.example.bankapp
```

### Telegram (MTProto)

friTap can decrypt Telegram's MTProto 2.0 cloud-chat traffic on Android via
`--protocol mtproto` (tshark cannot — friTap ships its own decryptor):

```bash
# Live: decrypted MTProto straight into a .tap
fritap -m --protocol mtproto org.telegram.messenger

# Live full capture: pcap + MTProto keylog (for later offline re-analysis)
fritap -m --protocol mtproto -f -p tg.pcapng -k tg.keys org.telegram.messenger
```

To cover **both** Telegram encryption layers in one run, use the umbrella
`--protocol telegram`: cloud chats (MTProto **transport** — not end-to-end) plus
**secret chats** (MTProto 2.0 **end-to-end**). It writes one combined keylog
(`MTPROTO_AUTH_KEY` + `MTPROTO_E2E_KEY`) consumed offline via `--telegram-keylog`;
secret-chat plaintext can also be captured live with `-p`:

```bash
# Live full capture: pcap + combined (cloud + secret) Telegram keylog
fritap -m --protocol telegram -f -p tg.pcapng -k tg.keys org.telegram.messenger
```

See [Telegram (MTProto)](../protocols/telegram.md) for the keylog format, the
offline `--mtproto-keylog` / `--telegram-keylog` workflows, the crypto backend
(which ships in friTap's base install, no extra needed), and scope/limitations
(cloud-chat live plaintext is future work — use the keylog → offline path).



## Troubleshooting Android Issues

### Common Problems

**frida-server Not Starting:**
```bash
# Check if already running
adb shell ps | grep frida-server

# Kill existing process
adb shell su -c "killall frida-server"

# Restart with correct permissions
adb shell su -c "/data/local/tmp/frida-server &"
```

**App Crashes Immediately:**
```bash
# Use anti-root detection
fritap -m --anti_root -k keys.log com.example.app

# Avoid spawning mode
fritap -m -k keys.log com.example.app  # Attach to running process
```

**No SSL Library Detected:**
```bash
# Enable debug output
fritap -m -do -v com.example.app

# Try pattern matching
fritap -m --patterns android_patterns.json -k keys.log com.example.app
```

**No Traffic Captured:**
```bash
# Use default socket information
fritap -m --enable_default_fd --pcap traffic.pcap com.example.app

# Enable full capture
fritap -m --full_capture -k keys.log com.example.app
```

### Device-Specific Issues

**Samsung Knox:**
```bash
# Knox may interfere with root detection bypass
fritap -m --anti_root --enable_default_fd -k keys.log com.example.app
```

**MIUI (Xiaomi):**
```bash
# MIUI security features may require additional bypasses
fritap -m --anti_root -s -k keys.log com.example.app
```

**LineageOS/Custom ROMs:**
```bash
# Usually work well with standard commands
fritap -m -k keys.log com.example.app
```

## Advanced Android Techniques

### WebView Analysis

Many apps use WebViews for content:

```bash
# Capture WebView traffic
fritap -m --enable_spawn_gating -k webview_keys.log com.example.app

# Look for chromium-based WebView traffic
```


### Background Service Analysis

```bash
# Monitor background services
fritap -m --enable_spawn_gating -k service_keys.log com.example.app

# Target specific service
fritap -m -k keys.log com.example.app:service
```

### Storage Management

Whenever we do a full capture with friTap we don't remove the generated pcap files stored by default to `/data/local/tmp/`.
Therefore it might be helpful to delete them from time to time.

```bash
# Monitor storage usage
adb shell df /data

# Compress old captures
gzip old_traffic.pcap

# Clean up temporary files
adb shell su -c "rm -rf /data/local/tmp/frida-*"
```

## Security Considerations

### App Store Analysis

- Use isolated devices for unknown app analysis
- Create separate Android user profiles
- Monitor network traffic to external servers
- Document all analysis activities

### Malware Analysis

```bash
# Analyze suspicious APKs in isolated environment
fritap -m --anti_root --full_capture -k malware_keys.log com.suspicious.app

# Monitor for C&C communications
fritap -m --enable_spawn_gating --pcap malware_traffic.pcap com.suspicious.app
```

## Automation Scripts

### Batch Analysis Script

```bash
#!/bin/bash
# Android app batch analysis

DEVICE_ID="$1"
APP_LIST="$2"

while IFS= read -r app; do
    echo "Analyzing $app"
    timeout 300 fritap -m "$DEVICE_ID" -k "${app}_keys.log" \
                       --pcap "${app}_traffic.pcap" "$app"
done < "$APP_LIST"
```

### Continuous Monitoring

```bash
#!/bin/bash
# Continuous Android app monitoring

APP_PACKAGE="$1"
DURATION="${2:-300}"  # Default 5 minutes

while true; do
    timestamp=$(date +%Y%m%d_%H%M%S)
    timeout "$DURATION" fritap -m -k "keys_${timestamp}.log" \
                               --pcap "traffic_${timestamp}.pcap" \
                               "$APP_PACKAGE"
    sleep 10
done
```

## Integration with Other Tools

### Wireshark Integration

```bash
# Live analysis with Wireshark
fritap -m --live com.example.app

# Then in Wireshark: File → Open → /tmp/sharkfin
```

!!! tip "Capture live from inside Wireshark (extcap backend)"
    friTap ships a Wireshark **extcap** backend so you can start an Android capture
    directly from Wireshark's interface list. Install it once with:

    ```bash
    fritap install-backend wireshark
    ```

    After installing, friTap appears as a capture interface in Wireshark. See the
    [CLI reference](../api/cli.md) for `install-backend` and the live-capture mode in
    the [Terminal UI guide](../getting-started/tui.md).

### Burp Suite Integration

```bash
# Set up proxy on Android device
adb shell settings put global http_proxy 192.168.1.100:8080

# Capture and analyze with Burp
fritap -m --pcap api_traffic.pcap com.example.app
```

## Best Practices

### 1. Device Management

- Use dedicated test devices
- Maintain multiple Android versions
- Keep frida-server updated
- Regular device cleanup

### 2. Analysis Approach

- Start with basic key extraction
- Use spawn mode for initialization analysis
- Enable anti-root detection when needed
- Document app behavior patterns

### 3. Data Management

- Organize captures by app and date
- Compress old analysis data
- Maintain analysis notes
- Back up important findings

### 4. Security

- Use isolated networks
- Analyze unknown apps in containers
- Monitor for suspicious behavior
- Follow responsible disclosure

## Next Steps

- **iOS Analysis**: Check [iOS Platform Guide](ios.md)
- **Advanced Patterns**: Learn about [Pattern-Based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)
- **Examples**: See [Android Examples](../examples/android.md)