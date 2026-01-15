# macOS Platform Guide

This guide covers macOS-specific setup, considerations, and best practices for using friTap on macOS systems.

!!! warning "Limited macOS Support"
    macOS support is currently limited to **TLS key extraction only** (keylog). Full plaintext traffic interception is not yet implemented for macOS. Apple's native **SecureTransport and Network.framework are not supported**. Only BoringSSL-based applications (like Chrome) and Python's OpenSSL can be analyzed.

## Prerequisites

### System Requirements

- **macOS 10.15+** (Catalina or newer)
- **Administrator access** (required for most analysis)
- **Python 3.8+** installed
- **Xcode Command Line Tools**
- **Intel or Apple Silicon (M1/M2) architecture**

### Development Environment Setup

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (recommended package manager)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python (if not using system Python)
brew install python@3.11

# Install friTap
pip3 install fritap
```

## System Setup

### SIP (System Integrity Protection) Considerations

```bash
# Check SIP status
csrutil status

# SIP affects debugging capabilities
# For full functionality, you may need to disable SIP
# (Not recommended for production systems)

# To disable SIP:
# 1. Boot into Recovery Mode (Command+R during boot)
# 2. Open Terminal from Utilities menu
# 3. Run: csrutil disable
# 4. Reboot normally
```

### BPF Device Permissions

```bash
# Check BPF device permissions
ls -la /dev/bpf*

# Grant access to BPF devices (required for packet capture)
sudo chmod 644 /dev/bpf*

# Make permanent by creating a script
sudo tee /Library/LaunchDaemons/com.fritap.bpf.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fritap.bpf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/chmod</string>
        <string>644</string>
        <string>/dev/bpf*</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# Load the launch daemon
sudo launchctl load /Library/LaunchDaemons/com.fritap.bpf.plist
```

### Frida Installation

```bash
# Install frida-tools
pip3 install frida-tools

# Verify installation
frida --version

# Test local device
frida-ps
```

## friTap Usage on macOS

### Native macOS Applications

```bash
# Analyze Safari
sudo fritap -k safari_keys.log --pcap safari_traffic.pcap Safari

# Analyze Mail app
sudo fritap -k mail_keys.log Mail

# Analyze system applications
sudo fritap -k system_keys.log /System/Applications/App\ Store.app/Contents/MacOS/App\ Store
```

### Third-Party Applications

```bash
# Analyze Chrome
sudo fritap -k chrome_keys.log --pcap chrome_traffic.pcap "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# Analyze Firefox
sudo fritap -k firefox_keys.log Firefox

# Analyze Electron apps
sudo fritap -k discord_keys.log --json discord_metadata.json Discord
```

### Command-Line Applications

```bash
# Analyze curl requests
sudo fritap -k curl_keys.log curl https://httpbin.org/get

# Python applications
sudo fritap -k python_keys.log python3 my_script.py

# Node.js applications
sudo fritap -k node_keys.log node app.js
```

### Application Bundle Analysis

```bash
# Find executable in application bundle
ls -la "/Applications/Some App.app/Contents/MacOS/"

# Analyze specific executable
sudo fritap -k app_keys.log "/Applications/Some App.app/Contents/MacOS/Some App"

# Use application name (if in PATH)
sudo fritap -k app_keys.log "Some App"
```

## macOS-Specific Features

### Keychain Integration

```bash
# Some applications use macOS Keychain for certificates
# Monitor Keychain-related SSL usage
sudo fritap -k keychain_keys.log --json keychain_metadata.json application

# Check for Keychain SSL usage in metadata
cat keychain_metadata.json | jq '.libraries_detected[] | select(.name | contains("Security"))'
```

### Network.framework Analysis

```bash
# Modern macOS apps often use Network.framework
sudo fritap -k network_keys.log --json network_metadata.json application

# Debug Network.framework detection
sudo fritap -do -v application | grep -i network
```

### App Store Applications

```bash
# Analyze Mac App Store applications
sudo fritap -k appstore_keys.log "/Applications/App Name.app/Contents/MacOS/App Name"

# Some App Store apps have restricted permissions
# Use spawn mode if attachment fails
sudo fritap -s -k keys.log application
```

### Sandbox Restrictions

```bash
# Check if application is sandboxed
codesign -d --entitlements - "/Applications/App.app"

# Sandboxed apps may have limited functionality
# Use spawn mode for better access
sudo fritap -s --enable_default_fd -k keys.log application
```

## SSL/TLS Libraries on macOS

### Supported macOS SSL Libraries

friTap's macOS support is limited to specific TLS libraries. Here's the current status:

| Library | Support | Notes |
|---------|---------|-------|
| **BoringSSL** | 🔑 Keylog | Key extraction via callback hooking (Chrome) |
| **Python OpenSSL** | 🔑 Keylog | Special handling for Python's bundled OpenSSL |
| **Cronet** | 🔑 Keylog | Pattern-based, requires external patterns |
| **SecureTransport** | ❌ Not implemented | Apple's native TLS - no support |
| **Network.framework** | ❌ Not implemented | Modern Apple TLS - no support |
| **LibreSSL** | ❌ Not implemented | System SSL - no support |

!!! note "Keylog Only"
    macOS support extracts TLS keys (keylog) but does **not** intercept plaintext traffic. Use the extracted keys with Wireshark to decrypt captured traffic.

**BoringSSL (Chrome and Chromium-based browsers):**
```bash
# Extract keys from Chrome
sudo fritap -k chrome_keys.log "Google Chrome"

# Debug BoringSSL detection
sudo fritap -do -v "Google Chrome" | grep -i boring
```

**Python Applications (Special Support):**
```bash
# Python applications using OpenSSL have special macOS support
sudo fritap -k python_keys.log python3 script.py

# Python's bundled OpenSSL keylog callbacks are intercepted
```

**Pattern-based Hooking:**
```bash
# Custom patterns for other libraries
sudo fritap --patterns macos_patterns.json -k keys.log application
```

### Unsupported Applications

!!! warning "Native macOS Apps Not Supported"
    The following applications use SecureTransport or Network.framework and **cannot** be analyzed with friTap:

    - Safari
    - Mail
    - Messages
    - Most native macOS applications
    - App Store applications using Apple TLS

### Library Detection Commands

```bash
# Check SSL libraries used by an application
otool -L "/path/to/application" | grep -E "(ssl|tls|crypto)"

# System-wide SSL library information
find /usr/lib /System/Library -name "*ssl*" -o -name "*tls*" 2>/dev/null

# Check framework dependencies
otool -L "/Applications/App.app/Contents/MacOS/App" | grep -i security
```

## Application Categories

### Supported Applications

!!! tip "Focus on BoringSSL-based Applications"
    friTap on macOS works best with Chromium-based browsers and Python applications. Native macOS apps using SecureTransport will not work.

**Chromium-based Browsers (Supported):**
```bash
# Chrome - uses BoringSSL
sudo fritap -k chrome_keys.log "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# Edge - uses BoringSSL
sudo fritap -k edge_keys.log "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"

# Brave - uses BoringSSL
sudo fritap -k brave_keys.log "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
```

**Python Applications (Supported):**
```bash
# Python scripts using requests/urllib
sudo fritap -k python_keys.log python3 script.py

# Python with specific SSL module
sudo fritap -k python_keys.log python3 -c "import ssl; import urllib.request; urllib.request.urlopen('https://example.com')"
```

### Unsupported Applications

!!! warning "These Will NOT Work"
    The following use SecureTransport/Network.framework and are not supported:

```bash
# Safari - uses SecureTransport (NOT SUPPORTED)
# sudo fritap -k safari_keys.log Safari  # Will not capture keys

# Messages - uses SecureTransport (NOT SUPPORTED)
# sudo fritap -k messages_keys.log Messages  # Will not capture keys

# FaceTime - uses SecureTransport (NOT SUPPORTED)
# sudo fritap -k facetime_keys.log FaceTime  # Will not capture keys

# Firefox - uses NSS (LIMITED SUPPORT on macOS)
# sudo fritap -k firefox_keys.log Firefox  # May have limited functionality
```

### Electron Applications (May Work)

Some Electron apps bundle Chromium and may work:
```bash
# Discord - Electron based
sudo fritap -k discord_keys.log Discord

# Slack - Electron based
sudo fritap -k slack_keys.log Slack

# VS Code - Electron based
sudo fritap -k vscode_keys.log "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"
```

### Development Tools

```bash
# Xcode
sudo fritap -k xcode_keys.log Xcode

# VS Code
sudo fritap -k vscode_keys.log "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"

# Terminal applications
sudo fritap -k terminal_keys.log -s ssh user@remote.host
```

### System Applications

```bash
# App Store
sudo fritap -k appstore_keys.log "/System/Applications/App Store.app/Contents/MacOS/App Store"

# Software Update
sudo fritap -k softwareupdate_keys.log softwareupdate -l

# System Preferences
sudo fritap -k sysprefs_keys.log "System Preferences"
```

## Advanced macOS Analysis

### Process Injection and Debugging

```bash
# Check process restrictions
ps aux | grep application
sudo dtruss -p PID 2>&1 | grep -i ssl

# Use LLDB for debugging (if needed)
lldb --attach-pid PID
```

### Kernel Extension Analysis

```bash
# Check loaded kernel extensions
kextstat | grep -i network

# Monitor system calls
sudo dtruss -f -p $(pgrep application) &
sudo fritap -k keys.log application
```

### launchd Service Analysis

```bash
# Analyze system services
sudo launchctl list | grep -i network

# Monitor launchd service SSL usage
sudo fritap -k service_keys.log launchd
```

### Code Signing Verification

```bash
# Check application code signing
codesign -v "/Applications/App.app"

# Display signing information
codesign -d -v "/Applications/App.app"

# Check entitlements
codesign -d --entitlements - "/Applications/App.app"
```

## Apple Silicon (M1/M2) Considerations

### Architecture-Specific Analysis

```bash
# Check application architecture
file "/Applications/App.app/Contents/MacOS/App"

# Universal binaries (x86_64 + arm64)
lipo -info "/Applications/App.app/Contents/MacOS/App"

# Run under Rosetta 2 (if needed)
arch -x86_64 fritap -k keys.log application
```

### Performance Optimization

```bash
# Native Apple Silicon performance
sudo fritap -k native_keys.log application

# Monitor memory usage on Apple Silicon
sudo memory_pressure &
sudo fritap -k keys.log application
```

### Rosetta 2 Compatibility

```bash
# Force x86_64 mode for compatibility
arch -x86_64 sudo fritap -k x86_keys.log application

# Check if application is running under Rosetta
ps aux | grep application
# Look for "translated" in process info
```

## Security and Privacy

### Privacy Permissions

```bash
# Grant Full Disk Access to Terminal (required for some analysis)
# System Preferences → Security & Privacy → Privacy → Full Disk Access

# Network access permissions
# Some applications may require network permission grants
```

### Gatekeeper and Notarization

```bash
# Check Gatekeeper status
spctl --status

# Check if application is notarized
spctl -a -t exec -vv "/Applications/App.app"

# Bypass Gatekeeper for analysis (temporarily)
sudo spctl --master-disable
```

### FileVault Considerations

```bash
# Check FileVault status
fdesetup status

# FileVault may affect some low-level analysis
# Consider running on non-encrypted volumes for testing
```

## Troubleshooting macOS Issues

### Permission Issues

```bash
# Run with sudo
sudo fritap -k keys.log application

# Check system permissions
ls -la /dev/bpf*

# Reset permissions
sudo chmod 644 /dev/bpf*
```

### Application Won't Start

```bash
# Check application quarantine
xattr -l "/Applications/App.app"

# Remove quarantine attribute
sudo xattr -rd com.apple.quarantine "/Applications/App.app"

# Check for damaged applications
codesign -v "/Applications/App.app"
```

### Network Interface Issues

```bash
# List network interfaces
ifconfig

# Check packet capture permissions
sudo tcpdump -i en0 -c 1

# Grant network access to Terminal
# System Preferences → Security & Privacy → Privacy → Network
```

### Frida Connection Issues

```bash
# Check Frida server status
frida-ps

# Restart Frida if needed
sudo pkill frida-server
frida --version

# Check for conflicting security software
ps aux | grep -E "(antivirus|security)"
```

## Integration with macOS Tools

### Instruments Integration

```bash
# Use Instruments for additional profiling
instruments -t "Network" -D network_trace.trace &
sudo fritap -k keys.log application

# Analyze Instruments trace
open network_trace.trace
```

### Console.app Integration

```bash
# Monitor system logs during analysis
open /Applications/Utilities/Console.app

# Filter for SSL/TLS related messages
log stream --predicate 'eventMessage CONTAINS "SSL" OR eventMessage CONTAINS "TLS"'
```

### Wireshark Integration

```bash
# Install Wireshark
brew install --cask wireshark

# Real-time analysis
sudo fritap -l application

# Open Wireshark and connect to named pipe
```

### Activity Monitor

```bash
# Monitor resource usage during analysis
open /Applications/Utilities/Activity\ Monitor.app

# Command line monitoring
top -pid $(pgrep fritap)
```

## Best Practices for macOS

### 1. System Preparation

```bash
# Disable SIP if necessary (not recommended for production)
# Grant required permissions to Terminal
# Install development tools
```

### 2. Application Analysis

```bash
# Always start with basic analysis
sudo fritap -k keys.log application

# Progress to comprehensive analysis
sudo fritap -k keys.log --pcap traffic.pcap --json metadata.json application
```

### 3. Security Considerations

```bash
# Use test systems for analysis
# Don't disable security features on production systems
# Re-enable security features after analysis
```

### 4. Data Organization

```bash
# Create analysis workspace
mkdir ~/Desktop/friTap_Analysis
cd ~/Desktop/friTap_Analysis

# Organize by date and application
mkdir "$(date +%Y%m%d)_ApplicationName"
cd "$(date +%Y%m%d)_ApplicationName"

# Run analysis with organized output
sudo fritap -k keys.log --pcap traffic.pcap --json metadata.json application
```

## Common macOS Applications

### Productivity Apps

```bash
# Microsoft Office
sudo fritap -k office_keys.log "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"

# Adobe Creative Suite
sudo fritap -k photoshop_keys.log "/Applications/Adobe Photoshop 2023/Adobe Photoshop 2023.app/Contents/MacOS/Adobe Photoshop 2023"

# Notion
sudo fritap -k notion_keys.log Notion
```

### Gaming Applications

```bash
# Steam
sudo fritap -k steam_keys.log Steam

# Epic Games Launcher
sudo fritap -k epic_keys.log "/Applications/Epic Games Launcher.app/Contents/MacOS/EpicGamesLauncher"

# Native Mac games
sudo fritap -k game_keys.log "Game Name"
```

### Financial Applications

```bash
# Banking apps (use test accounts only)
sudo fritap -k banking_keys.log "Bank App"

# Trading platforms
sudo fritap -k trading_keys.log "Trading Platform"

# Cryptocurrency wallets
sudo fritap -k wallet_keys.log "Crypto Wallet"
```

## Next Steps

- **iOS Analysis**: Check [iOS Platform Guide](ios.md) for mobile analysis
- **Windows Analysis**: See [Windows Platform Guide](windows.md)
- **Linux Analysis**: Review [Linux Platform Guide](linux.md)
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Check [Common Issues](../troubleshooting/common-issues.md)