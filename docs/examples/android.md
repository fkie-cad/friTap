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

### Device and Process Detection

```bash
# List available devices
frida-ls-devices 
Id              Type    Name             OS
--------------  ------  ---------------  ------------
local           local   Local System     macOS 15.3.1
31041FDH2006EY  usb     Pixel 7          Android 13
barebone        remote  GDB Remote Stub
socket          remote  Local Socket

# List running processes
frida-ps

# Check specific package on a mobile device
frida-ps -Uai | grep com.example.app
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
# Capture keys, traffic (here full capture), and metadata
fritap -m -k instagram_keys.log --pcap instagram_traffic.pcap --full_capture --json instagram_metadata.json com.instagram.android

# Now use Instagram app normally
# Press Ctrl+C to stop capture

# Analyze session metadata
cat instagram_metadata.json | jq '.statistics, .session_info'
```

### E-commerce Application

**Amazon Shopping App:**
```bash
# Comprehensive analysis with metadata
fritap -m -k amazon_keys.log --pcap amazon_traffic.pcap --json amazon_analysis.json com.amazon.mshop.android.shopping

# Browse products, add to cart, etc.
# Monitor API calls in real-time

# Extract API endpoints from metadata
cat amazon_analysis.json | jq '.connections[] | select(.dst_port == 443) | .dst_addr' | sort | uniq
```

### Banking Application

**Banking App Analysis (be careful with production data):**
```bash
# Use on test accounts only - comprehensive logging
fritap -m -k bank_keys.log --pcap bank_traffic.pcap --json bank_analysis.json com.example.bankapp

# Monitor authentication flows
tcpdump -r bank_traffic.pcap 'port 443' -A | grep -i auth

# Analyze authentication patterns from JSON
cat bank_analysis.json | jq '.connections[] | select(.data_length > 100) | {timestamp, dst_addr, data_length}'
```

## Advanced Android Analysis

### Spawn Mode Analysis

Start the app fresh under friTap control:

```bash
# Spawn app from the beginning with full logging
fritap -m -s -k keys.log --pcap traffic.pcap --json spawn_analysis.json com.example.app

# This captures initialization traffic
# Including certificate pinning bypass attempts

# Analyze startup sequence
cat spawn_analysis.json | jq '.connections[] | select(.timestamp | . < (now - 10)) | {timestamp, dst_addr}'
```

### Pattern-Based Hooking

For apps with obfuscated or stripped SSL libraries:

```bash
# Create pattern file for specific app with metadata
fritap -m --patterns android_patterns.json -k keys.log --json pattern_analysis.json com.example.app

# Debug pattern matching
fritap -m -do -v --patterns android_patterns.json com.example.app

# Check detected libraries
cat pattern_analysis.json | jq '.statistics.libraries_detected'
```

### Anti-Root Detection Bypass

Many apps detect root and refuse to run:

```bash
# Enable anti-root detection bypass
fritap -m --enable-anti-root -k keys.log com.example.app

# Combined with other options (here we are doing a full packet capture)
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

Other frameworks such as Xamarin (Mono.Android SSL --> BoringSSL) or Unity games may use various SSL implementations.

## SSL Library Specific Examples

### OpenSSL/BoringSSL Applications

Most modern Android apps use BoringSSL:

```bash
# Standard BoringSSL analysis
fritap -m -k boringssl_keys.log com.example.app

# Debug BoringSSL detection
fritap -m -do -v com.example.app | grep -i boring
```


### OkHttp Applications

Many apps use OkHttp for networking:

```bash
# OkHttp typically uses BoringSSL
fritap -m -k okhttp_keys.log com.example.app

# Monitor OkHttp connections
tcpdump -r traffic.pcap -A | grep -i okhttp
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
# Capture API communications with metadata
fritap -m -k api_keys.log --pcap api_traffic.pcap --json api_analysis.json com.example.api_app

# Extract API endpoints
tcpdump -r api_traffic.pcap -A | grep -E "(GET|POST|PUT|DELETE)" | head -20

# Analyze authentication tokens
tcpdump -r api_traffic.pcap -A | grep -i authorization

# Get API statistics from JSON
cat api_analysis.json | jq '.statistics.total_connections, .connections | length'
```

### Malware Analysis

**Suspicious App Analysis:**
```bash
# Analyze potentially malicious app with full logging
fritap -m -k malware_keys.log --pcap malware_traffic.pcap --json malware_analysis.json com.suspicious.app

# Look for C&C communications
tcpdump -r malware_traffic.pcap 'not port 443 and not port 80'

# Check for data exfiltration
tcpdump -r malware_traffic.pcap -A | grep -E "(password|token|key)"

# Extract suspicious connection patterns
cat malware_analysis.json | jq '.connections[] | select(.dst_port != 443 and .dst_port != 80)'
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

# Start friTap analysis with comprehensive logging
fritap -m -k "${PACKAGE_NAME}_keys.log" \
       --pcap "${PACKAGE_NAME}_traffic.pcap" \
       --json "${PACKAGE_NAME}_metadata.json" \
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
                               --json "metadata_${TIMESTAMP}.json" \
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
# Enable all logging options with comprehensive output
fritap -m -do -v -k keys.log --pcap traffic.pcap --json metadata.json com.example.app 2>&1 | tee full_analysis.log

# Analyze comprehensive metadata
cat metadata.json | jq '.session_info, .statistics, .errors[] | select(.type == "frida_script_error")'
```

### 4. Security Considerations

```bash
# Use test accounts only
# Analyze in isolated environment
# Document all actions for compliance
```

## Next Steps

- **iOS Analysis**: Check [iOS Platform Guide](../platforms/ios.md)
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Platform Details**: See [Android Platform Guide](../platforms/android.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)