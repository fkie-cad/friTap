# Android Applications

This guide provides comprehensive examples for analyzing Android applications with friTap, covering various app types, SSL libraries, and advanced techniques.

## Prerequisites

### Device Setup

Ensure your Android device is properly configured:

```bash
# Check device connection
adb devices

# Verify root access
adb shell su -c "id"

# Check frida-server is running
adb shell ps | grep frida-server
```

### friTap Device Detection

```bash
# List available devices
fritap --list-devices

# List running processes
fritap -m --list-processes

# Check specific package
fritap -m --list-processes | grep com.example.app
```

## Basic Android Analysis

### Simple Social Media App

Let's start with a basic social media app analysis:

**Instagram Analysis:**
```bash
# Basic key extraction
fritap -m -k instagram_keys.log com.instagram.android

# Expected output:
# [*] Android agent loaded
# [*] BoringSSL found & will be hooked
# [*] Java SSL libraries detected
# [*] Logging TLS keys to instagram_keys.log
```

**Complete Traffic Analysis:**
```bash
# Capture both keys and decrypted traffic
fritap -m -k instagram_keys.log --pcap instagram_traffic.pcap com.instagram.android

# Now use Instagram app normally
# Press Ctrl+C to stop capture
```

### E-commerce Application

**Amazon Shopping App:**
```bash
# Comprehensive analysis
fritap -m -k amazon_keys.log --pcap amazon_traffic.pcap com.amazon.mshop.android.shopping

# Browse products, add to cart, etc.
# Monitor API calls in real-time
```

### Banking Application

**Banking App Analysis (be careful with production data):**
```bash
# Use on test accounts only
fritap -m -k bank_keys.log --pcap bank_traffic.pcap com.example.bankapp

# Monitor authentication flows
tcpdump -r bank_traffic.pcap 'port 443' -A | grep -i auth
```

## Advanced Android Analysis

### Spawn Mode Analysis

Start the app fresh under friTap control:

```bash
# Spawn app from the beginning
fritap -m -f -k keys.log --pcap traffic.pcap com.example.app

# This captures initialization traffic
# Including certificate pinning bypass attempts
```

### Pattern-Based Hooking

For apps with obfuscated or stripped SSL libraries:

```bash
# Create pattern file for specific app
fritap -m --patterns android_patterns.json -k keys.log com.example.app

# Debug pattern matching
fritap -m -do -v --patterns android_patterns.json com.example.app
```

### Anti-Root Detection Bypass

Many apps detect root and refuse to run:

```bash
# Enable anti-root detection bypass
fritap -m --enable-anti-root -k keys.log com.example.app

# Combined with other options
fritap -m -f --enable-anti-root -k keys.log --pcap traffic.pcap com.example.app
```

## App-Specific Examples

### Flutter Applications

Flutter apps often use BoringSSL statically linked:

**Basic Flutter Analysis:**
```bash
# Flutter apps may require pattern matching
fritap -m --patterns flutter_patterns.json -k flutter_keys.log com.example.flutter_app
```

**Advanced Flutter Analysis:**
```bash
# Debug Flutter SSL detection
fritap -m -do -v com.example.flutter_app

# Look for libflutter.so in output
# Use BoringSecretHunter for pattern generation
```

### React Native Applications

React Native apps use various SSL implementations:

**Basic React Native Analysis:**
```bash
# Standard analysis
fritap -m -k rn_keys.log --pcap rn_traffic.pcap com.example.reactnative

# Check for Metro bundler traffic
tcpdump -r rn_traffic.pcap 'port 8081'
```

### Xamarin Applications

Xamarin apps use Mono.Android SSL:

**Xamarin Analysis:**
```bash
# Mono.Android SSL libraries
fritap -m -k xamarin_keys.log com.example.xamarin

# Enable debug for Mono detection
fritap -m -do -v com.example.xamarin
```

### Unity Games

Unity games may use various SSL implementations:

**Unity Game Analysis:**
```bash
# Unity games with networking
fritap -m -k unity_keys.log --pcap unity_traffic.pcap com.example.unitygame

# Look for Unity-specific traffic
tcpdump -r unity_traffic.pcap -A | grep -i unity
```

## SSL Library Specific Examples

### OpenSSL/BoringSSL Applications

Most modern Android apps use BoringSSL:

```bash
# Standard BoringSSL analysis
fritap -m -k boringssl_keys.log com.example.app

# Debug BoringSSL detection
fritap -m -do -v com.example.app | grep -i boring
```

### Conscrypt Applications

Some apps use Google's Conscrypt:

```bash
# Conscrypt analysis
fritap -m -k conscrypt_keys.log com.example.app

# Verify Conscrypt detection
fritap -m -v com.example.app | grep -i conscrypt
```

### OkHttp Applications

Many apps use OkHttp for networking:

```bash
# OkHttp typically uses BoringSSL
fritap -m -k okhttp_keys.log com.example.app

# Monitor OkHttp connections
tcpdump -r traffic.pcap -A | grep -i okhttp
```

## Certificate Pinning Analysis

### Detecting Certificate Pinning

```bash
# App with certificate pinning
fritap -m -k pinned_keys.log com.example.pinned_app

# If no traffic is captured, pinning may be active
# Check debug output for SSL errors
fritap -m -do -v com.example.pinned_app
```

### Bypassing Certificate Pinning

```bash
# Use spawn mode to bypass pinning
fritap -m -f -k keys.log --pcap traffic.pcap com.example.pinned_app

# Enable default socket information
fritap -m --enable_default_fd -k keys.log com.example.pinned_app
```

## Advanced Analysis Techniques

### Multi-Process Analysis

Android apps often spawn multiple processes:

```bash
# Capture all processes
fritap -m --enable_spawn_gating -k all_keys.log --pcap all_traffic.pcap com.example.app

# Monitor WebView processes
fritap -m -k webview_keys.log com.example.app:webview
```

### WebView Analysis

Apps with embedded WebViews:

```bash
# Capture WebView traffic
fritap -m -k webview_keys.log --pcap webview_traffic.pcap com.example.app

# Filter for web traffic
tcpdump -r webview_traffic.pcap 'port 80 or port 443'
```

### Background Service Analysis

Analyze background services:

```bash
# Target specific service
fritap -m -k service_keys.log com.example.app:service

# Monitor scheduled tasks
fritap -m --enable_spawn_gating -k bg_keys.log com.example.app
```

## Real-World Analysis Scenarios

### API Security Testing

**REST API Analysis:**
```bash
# Capture API communications
fritap -m -k api_keys.log --pcap api_traffic.pcap com.example.api_app

# Extract API endpoints
tcpdump -r api_traffic.pcap -A | grep -E "(GET|POST|PUT|DELETE)" | head -20

# Analyze authentication tokens
tcpdump -r api_traffic.pcap -A | grep -i authorization
```

### Data Privacy Analysis

**Personal Data Transmission:**
```bash
# Monitor data transmission
fritap -m -k privacy_keys.log --pcap privacy_traffic.pcap com.example.app

# Search for personal data patterns
tcpdump -r privacy_traffic.pcap -A | grep -E "(email|phone|address)"
```

### Malware Analysis

**Suspicious App Analysis:**
```bash
# Analyze potentially malicious app
fritap -m -k malware_keys.log --pcap malware_traffic.pcap com.suspicious.app

# Look for C&C communications
tcpdump -r malware_traffic.pcap 'not port 443 and not port 80'

# Check for data exfiltration
tcpdump -r malware_traffic.pcap -A | grep -E "(password|token|key)"
```

## Troubleshooting Android Analysis

### Common Issues

**App Crashes on Analysis:**
```bash
# Use gentler approach
fritap -m --no-spawn -k keys.log com.example.app

# Enable anti-detection
fritap -m --enable-anti-root -k keys.log com.example.app
```

**No SSL Library Detected:**
```bash
# Debug library detection
fritap -m -do -v com.example.app | grep -i ssl

# List loaded libraries
fritap -m --list-libraries com.example.app
```

**No Traffic Captured:**
```bash
# Use default socket information
fritap -m --enable_default_fd --pcap traffic.pcap com.example.app

# Enable full capture mode
fritap -m --full_capture -k keys.log com.example.app
```

### Device-Specific Issues

**Samsung Knox Detection:**
```bash
# Samsung devices with Knox
fritap -m --enable-anti-root --no-spawn -k keys.log com.example.app
```

**MIUI Security:**
```bash
# Xiaomi devices with MIUI
fritap -m --enable-anti-root -k keys.log com.example.app
```

## Performance Optimization

### Memory Management

**Monitor Memory Usage:**
```bash
# Check memory usage during analysis
fritap -m -k keys.log com.example.app &
FRITAP_PID=$!
watch -n 1 "adb shell top -p \$(adb shell pgrep frida-server)"
```

### Battery Optimization

**Minimize Battery Impact:**
```bash
# Reduce analysis overhead
fritap -m --timeout 60 -k keys.log com.example.app

# Use targeted analysis
fritap -m --no-spawn -k keys.log com.example.app
```

## Automation Scripts

### Batch Analysis Script

```bash
#!/bin/bash
# Automated Android app analysis

PACKAGE_NAME="$1"
OUTPUT_DIR="android_analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "Starting analysis of $PACKAGE_NAME"

# Device information
adb shell getprop ro.build.version.release > device_info.txt
adb shell getprop ro.product.model >> device_info.txt

# App information
adb shell pm list packages | grep "$PACKAGE_NAME" > app_info.txt
adb shell dumpsys package "$PACKAGE_NAME" | grep version >> app_info.txt

# Start friTap analysis
fritap -m -k "${PACKAGE_NAME}_keys.log" \
       --pcap "${PACKAGE_NAME}_traffic.pcap" \
       -v "$PACKAGE_NAME" 2>&1 | tee "${PACKAGE_NAME}_analysis.log"

echo "Analysis complete. Results in $OUTPUT_DIR"
```

### Continuous Monitoring

```bash
#!/bin/bash
# Continuous Android app monitoring

PACKAGE_NAME="$1"
DURATION="$2"  # in seconds

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    timeout "$DURATION" fritap -m -k "keys_${TIMESTAMP}.log" \
                               --pcap "traffic_${TIMESTAMP}.pcap" \
                               "$PACKAGE_NAME"
    sleep 10
done
```

## Integration with Other Tools

### Wireshark Integration

```bash
# Real-time analysis
fritap -m -l com.example.app

# Open Wireshark and connect to named pipe
# File → Open → Select named pipe
```

### Burp Suite Integration

```bash
# Capture traffic for Burp analysis
fritap -m --pcap api_traffic.pcap com.example.app

# Import PCAP into Burp Suite
# Proxy → Options → Import CA Certificate
```

### Custom Analysis Tools

```bash
# Pipe to custom analyzer
fritap -m -v com.example.app | python android_analyzer.py

# Real-time processing
fritap -m -l com.example.app | python real_time_android_analysis.py
```

## Best Practices

### 1. Test Environment Setup

```bash
# Use dedicated test device
adb devices
adb shell su -c "id"

# Verify frida-server version
adb shell /data/local/tmp/frida-server --version
```

### 2. App State Management

```bash
# Clear app data before analysis
adb shell pm clear com.example.app

# Start fresh analysis
fritap -m -f -k keys.log com.example.app
```

### 3. Comprehensive Logging

```bash
# Enable all logging options
fritap -m -do -v -k keys.log --pcap traffic.pcap --json metadata.json com.example.app 2>&1 | tee full_analysis.log
```

### 4. Security Considerations

```bash
# Use test accounts only
# Analyze in isolated environment
# Document all actions for compliance
```

## Next Steps

- **iOS Analysis**: Check [iOS examples](ios.md)
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Platform Details**: See [Android Platform Guide](../platforms/android.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)