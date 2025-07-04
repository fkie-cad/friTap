# Android Platform Guide

This guide covers Android-specific setup, considerations, and best practices for using friTap on Android devices.

## Prerequisites

### Device Requirements

- **Rooted Android device** (required for friTap operation)
- **Android 7.0+** (minimum supported version)
- **ARM, ARM64, or x86 architecture** support
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

# Verbose analysis
fritap -m -v -k keys.log com.example.app
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

## SSL/TLS Libraries on Android

### Common Libraries

| Library | Apps Using It | friTap Support |
|---------|---------------|----------------|
| **BoringSSL** | Chrome, many Google apps | ✅ Full |
| **Conscrypt** | Android system, some apps | ✅ Full |
| **OpenSSL** | Older apps, native code | ✅ Full |
| **NSS** | Firefox, Mozilla apps | ⚠️ Limited |
| **OkHttp** | Many modern apps | ✅ Full (uses system SSL) |

### Pattern-Based Hooking

For apps with stripped or statically linked SSL libraries:

```bash
# Use patterns for Flutter apps
fritap -m --patterns flutter_patterns.json -k keys.log com.flutter.app

# Generate patterns with BoringSecretHunter
python BoringSecretHunter.py --target libflutter.so --arch arm64 --output patterns.json
```

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

### Gaming Applications

```bash
# Unity-based games
fritap -m --patterns unity_patterns.json -k game_keys.log com.unity.game

# Native games
fritap -m --enable_spawn_gating -k keys.log com.example.game
```

### E-commerce Applications

```bash
# Amazon Shopping
fritap -m -k amazon_keys.log com.amazon.mshop.android.shopping

# Monitor API calls
fritap -m --pcap ecommerce_api.pcap com.example.shopping
```

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

### Multi-User Analysis

```bash
# Switch to specific user (if multiple users)
adb shell am switch-user 10  # Switch to user 10

# Analyze app in specific user context
fritap -m -k keys.log --user 10 com.example.app
```

### Background Service Analysis

```bash
# Monitor background services
fritap -m --enable_spawn_gating -k service_keys.log com.example.app

# Target specific service
fritap -m -k keys.log com.example.app:service
```

## Performance Considerations

### Memory Usage

```bash
# Monitor memory usage during analysis
adb shell top -p $(adb shell pgrep frida-server)

# Optimize for low-memory devices
fritap -m --timeout 60 -k keys.log com.example.app
```

### Battery Impact

```bash
# Minimize battery drain
fritap -m --timeout 120 -k keys.log com.example.app

# Use targeted analysis
fritap -m -k keys.log com.example.app  # Don't spawn unnecessarily
```

### Storage Management

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