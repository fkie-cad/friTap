# iOS Platform Guide

This guide covers iOS-specific setup, considerations, and best practices for using friTap on iOS devices.

!!! warning "Limited iOS Support"
    iOS support is currently limited to **TLS key extraction only** (keylog). Full plaintext traffic interception is not yet implemented for iOS. Apple's native SecureTransport and Network.framework are **not supported**. Only BoringSSL-based applications (like Chrome) and Flutter apps can be analyzed.

## Prerequisites

### Device Requirements

- **Jailbroken iOS device** (required for friTap operation)
- **iOS 12.0+** (minimum supported version)
- **ARM64 architecture** (iPhone 5s and newer)
- **SSH access** or USB connection
- **Cydia/Sileo** package manager installed

### Development Machine Setup

```bash
# Install required tools
# macOS (recommended)
brew install usbmuxd
brew install libimobiledevice

# Linux
sudo apt install usbmuxd libimobiledevice-tools

# Install frida-tools
pip3 install frida-tools
```

## Device Setup

### Jailbreak Requirements

!!! warning "Jailbreak Requirement"
    friTap requires a jailbroken iOS device to function. Ensure your device is jailbroken with a compatible jailbreak tool.

**Supported Jailbreaks:**
- **checkra1n** (iOS 12.0-14.8.1)
- **unc0ver** (iOS 11.0-14.8)
- **Taurine** (iOS 14.0-14.3)
- **Odyssey** (iOS 13.0-13.7)

### Install Frida on iOS

```bash
# Method 1: Via Cydia/Sileo
# Add Frida repository: https://build.frida.re
# Install "Frida" package

# Method 2: Manual installation via SSH
ssh root@<device-ip>
apt update
apt install re.frida.server
```

### SSH Setup (Optional)

```bash
# Install OpenSSH via Cydia/Sileo
# Default credentials (CHANGE IMMEDIATELY):
# Username: root
# Password: alpine

# Connect to device
ssh root@<device-ip>

# Change default password
passwd root
```

### USB Connection Setup

```bash
# Forward port for USB connection
iproxy 27042 27042

# Verify connection
frida-ls-devices
# Should show your iOS device
```

## Frida Server Management

### Starting Frida Server

```bash
# Method 1: SSH connection
ssh root@<device-ip>
frida-server &

# Method 2: USB connection with iproxy
iproxy 27042 27042 &
frida-server &

# Method 3: Using frida-tools
frida-ls-devices  # Auto-starts server if needed
```

### Verify Server Status

```bash
# Check if frida-server is running
frida-ls-devices

# List running processes
frida-ps -U

# List installed applications
frida-ps -Ua
```

## friTap Usage on iOS

### Basic Analysis

```bash
# Extract TLS keys from iOS app
fritap -m -k keys.log com.example.app

# Capture decrypted traffic
fritap -m --pcap traffic.pcap --json metadata.json com.example.app

# Verbose analysis
fritap -m -v -do com.example.app
```

### App Identification

```bash
# List running apps
frida-ps -Ua

# Find specific app
frida-ps -Ua | grep -i instagram

# Use bundle identifier
fritap -m com.burbn.instagram
```

### Spawn Mode Analysis

```bash
# Start app fresh under friTap control
fritap -m -s -k keys.log --pcap traffic.pcap com.example.app

# This captures app initialization traffic
```

## iOS-Specific Considerations

### App Store Applications

```bash
# Most App Store apps use system SSL libraries
fritap -m -k keys.log com.apple.mobilesafari

# Some apps may use custom SSL implementations
fritap -m --patterns ios_patterns.json com.example.app
```

### System Applications

```bash
# Analyze Safari
fritap -m -k safari_keys.log com.apple.mobilesafari

# Analyze Mail app
fritap -m -k mail_keys.log com.apple.mobilemail

# Analyze Messages
fritap -m -k messages_keys.log com.apple.MobileSMS
```

### Third-Party Applications

```bash
# Social media apps
fritap -m -k instagram_keys.log com.burbn.instagram
fritap -m -k whatsapp_keys.log net.whatsapp.WhatsApp

# Banking apps (use test accounts only)
fritap -m -k banking_keys.log com.example.bankapp

# Enterprise apps
fritap -m -k enterprise_keys.log com.company.app
```

## SSL/TLS Libraries on iOS

### Supported iOS SSL Libraries

friTap's iOS support is limited to specific TLS libraries. Here's the current status:

| Library | Support | Notes |
|---------|---------|-------|
| **BoringSSL** | 🔑 Keylog | Key extraction via callback hooking |
| **Flutter** | 🔑 Keylog | Pattern-based key extraction |
| **Cronet** | 🧪 Experimental | Untested, may require patterns |
| **SecureTransport** | ❌ Not implemented | Apple's native TLS - no support |
| **Network.framework** | ❌ Not implemented | Modern Apple TLS - no support |

!!! note "Keylog Only"
    iOS support extracts TLS keys (keylog) but does **not** intercept plaintext traffic. Use the extracted keys with Wireshark to decrypt captured traffic.

**BoringSSL (Chrome, Google apps):**
```bash
# Extract keys from BoringSSL apps
fritap -m -k chrome_keys.log com.google.chrome.ios
```

**Flutter Applications:**
```bash
# Flutter apps with built-in BoringSSL patterns
fritap -m -k flutter_keys.log com.flutter.app
```

**Pattern-based Hooking:**
```bash
# Custom patterns for stripped libraries
fritap -m --patterns ios_patterns.json -k keys.log com.example.app
```

### Library Detection

```bash
# Debug library detection
fritap -m -do -v com.example.app

# Look for SSL-related output in logs
fritap -m -v com.example.app 2>&1 | grep -i ssl
```

### Limitations

- **No SecureTransport support** - Most native iOS apps using Apple's TLS cannot be analyzed
- **No plaintext interception** - Only keylog extraction is available
- **Socket FD unavailable** - Cannot extract socket information from SSL operations

## Certificate Pinning on iOS

### Detecting Certificate Pinning

```bash
# Standard analysis (may fail with pinning)
fritap -m -k keys.log com.example.pinned_app

# If no traffic captured, pinning may be active
fritap -m -do -v com.example.pinned_app
```

### Bypassing Certificate Pinning

```bash
# Use spawn mode for early hooking
fritap -m -s -k keys.log com.example.pinned_app

# Enable default socket information
fritap -m --enable_default_fd com.example.pinned_app

# Use SSL Kill Switch (install via Cydia)
# Then run normal analysis
fritap -m -k keys.log com.example.pinned_app
```

### Manual Pinning Bypass

```bash
# Install SSL Kill Switch 2 from Cydia
# Or use Frida scripts for pinning bypass

# Custom Frida script for pinning bypass
fritap -m --custom_script bypass_pinning.js com.example.app
```

## Troubleshooting iOS Issues

### Connection Problems

```bash
# Device not detected
frida-ls-devices

# Restart usbmuxd (macOS/Linux)
sudo pkill usbmuxd
sudo usbmuxd

# Restart frida-server on device
ssh root@<device-ip>
killall frida-server
frida-server &
```

### Frida Server Issues

```bash
# Check if frida-server is running
ssh root@<device-ip>
ps aux | grep frida-server

# Restart frida-server
killall frida-server
frida-server &

# Check for port conflicts
netstat -an | grep 27042
```

### App Analysis Issues

```bash
# App crashes on hook
fritap -m --no-spawn com.example.app

# Use gentler approach
fritap -m -k keys.log com.example.app

# Check app permissions
frida-ps -Ua | grep com.example.app
```

### Memory and Performance

```bash
# Monitor memory usage
ssh root@<device-ip>
top -u mobile

# Reduce analysis overhead
fritap -m --timeout 60 com.example.app

# Target specific functions only
fritap -m --offsets minimal_offsets.json com.example.app
```

## iOS-Specific Features

### Keychain Analysis

```bash
# Some apps store certificates in Keychain
# Use additional tools for Keychain analysis
fritap -m -k keys.log --json metadata.json com.example.app

# Check for Keychain-related SSL usage
cat metadata.json | jq '.libraries_detected[] | select(.name | contains("Security"))'
```

### Background App Analysis

```bash
# Analyze background app refresh
fritap -m --enable_spawn_gating com.example.app

# Monitor background network activity
fritap -m -k background_keys.log com.example.app &
# Switch app to background and monitor
```

### App Extensions Analysis

```bash
# Analyze app extensions (widgets, keyboards, etc.)
fritap -m com.example.app.extension

# Monitor extension communications
fritap -m --enable_spawn_gating com.example.app
```

## Advanced iOS Analysis

### Multi-App Analysis

```bash
# Analyze multiple apps simultaneously
fritap -m --enable_spawn_gating -k all_keys.log &

# Then launch various apps to capture their traffic
```

### System-Level Analysis

```bash
# Analyze system-wide SSL traffic (careful!)
fritap -m --enable_spawn_gating -k system_keys.log launchd

# Monitor specific system services
fritap -m com.apple.springboard
```

### Enterprise and MDM Analysis

```bash
# Analyze MDM communications
fritap -m -k mdm_keys.log com.apple.managedconfiguration

# Enterprise app analysis
fritap -m -k enterprise_keys.log --json enterprise_data.json com.company.app
```

## Security Considerations

### Device Security

- **Keep jailbreak tools updated**
- **Change default SSH passwords**
- **Use secure networks for analysis**
- **Disable unnecessary services**

### Analysis Safety

```bash
# Use test accounts for sensitive apps
# Avoid production banking/financial apps
# Document all analysis activities
# Maintain device backups
```

### Legal Considerations

- **Only analyze apps you own or have permission to test**
- **Respect app store terms of service**
- **Follow responsible disclosure for vulnerabilities**
- **Comply with local laws and regulations**

## Integration with Other Tools

### Wireshark Integration

```bash
# Real-time analysis with Wireshark
fritap -m -l com.example.app

# Open Wireshark and connect to named pipe
```

### Burp Suite Integration

```bash
# Capture traffic for Burp analysis
fritap -m --pcap api_traffic.pcap com.example.app

# Configure device proxy settings for Burp
```

### Custom Analysis Tools

```bash
# Export data for custom analysis
fritap -m --json analysis_data.json com.example.app

# Process with custom scripts
python analyze_ios_data.py analysis_data.json
```

## Best Practices for iOS Analysis

### 1. Device Preparation

```bash
# Always start with clean device state
# Remove previous analysis artifacts
# Ensure stable jailbreak environment
```

### 2. Analysis Methodology

```bash
# Start with basic analysis
fritap -m -k keys.log com.example.app

# Progress to comprehensive analysis
fritap -m -k keys.log --pcap traffic.pcap --json metadata.json com.example.app
```

### 3. Data Management

```bash
# Organize analysis data
mkdir ios_analysis_$(date +%Y%m%d)
cd ios_analysis_$(date +%Y%m%d)

# Run analysis with organized output
fritap -m -k app_keys.log --pcap app_traffic.pcap --json app_metadata.json com.example.app
```

### 4. Documentation

```bash
# Document device state
uname -a > device_info.txt
frida --version >> device_info.txt

# Document app version
frida-ps -Ua | grep com.example.app >> app_info.txt
```

## Common iOS App Categories

### Social Media Apps

```bash
# Instagram
fritap -m -k instagram_keys.log com.burbn.instagram

# Twitter
fritap -m -k twitter_keys.log com.atebits.Tweetie2

# TikTok
fritap -m -k tiktok_keys.log com.zhiliaoapp.musically
```

### Communication Apps

```bash
# WhatsApp
fritap -m -k whatsapp_keys.log net.whatsapp.WhatsApp

# Signal
fritap -m -k signal_keys.log org.whispersystems.signal

# Telegram
fritap -m -k telegram_keys.log ph.telegra.Telegraph
```

### Financial Apps

```bash
# Use test accounts only
fritap -m -k banking_keys.log com.example.bank

# PayPal (test environment)
fritap -m -k paypal_keys.log com.paypal.ppmobile
```

### Gaming Apps

```bash
# Mobile games with networking
fritap -m -k game_keys.log com.example.game

# Monitor game server communications
fritap -m --pcap game_traffic.pcap com.example.mmorpg
```

## Next Steps

- **Android Analysis**: Check [Android Platform Guide](android.md)
- **Desktop Analysis**: See [Linux](linux.md), [macOS](macos.md), [Windows](windows.md) guides
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)