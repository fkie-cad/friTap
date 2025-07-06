# Quick Start Guide

Get up and running with friTap in minutes! This guide covers the most common use cases and essential commands.

## Basic Usage Patterns

friTap operates in two main modes:

1. **Key Extraction Mode**: Extract TLS keys for offline analysis
2. **Live Decryption Mode**: Decrypt and capture traffic in real-time

## Desktop Applications

### Extract TLS Keys

```bash
# Extract keys from Firefox
sudo fritap -k firefox_keys.log firefox

# Extract keys from a specific process ID
sudo fritap -k keys.log --pid 1234
```

### Capture Decrypted Traffic

```bash
# Capture decrypted traffic as PCAP
sudo fritap --pcap decrypted.pcap firefox

# Combine key extraction and PCAP capture
sudo fritap -k keys.log --pcap traffic.pcap firefox
```

### Live Analysis

```bash
# Display decrypted traffic in terminal
sudo fritap firefox

# Verbose output with debugging
sudo fritap -v firefox
```

## Mobile Applications

### Android Analysis

```bash
# Extract keys from Android app
fritap -m -k keys.log com.example.app

# Capture decrypted traffic
fritap -m --pcap decrypted.pcap com.example.app

# Spawn app and analyze from start
fritap -m -f com.example.app
```

### iOS Analysis

```bash
# Extract keys from iOS app
fritap -m -k keys.log com.example.app

# Analyze running app
fritap -m --pcap decrypted.pcap com.example.app
```

## Common Command Patterns

### Process Selection

```bash
# By process name
fritap firefox

# By process ID
fritap --pid 1234

# By package name (mobile)
fritap -m com.example.app

# List running processes
fritap --list-processes
```

### Output Options

```bash
# Save keys to file
fritap -k output.log target

# Save PCAP to file
fritap --pcap output.pcap target

# Save session metadata as JSON
fritap --json metadata.json target

# Display output in terminal
fritap target

# Combine all output formats
fritap -k keys.log --pcap traffic.pcap --json metadata.json target
```

### Advanced Options

```bash
# Enable verbose logging
fritap -v target

# Debug output
fritap -do target

# Disable colors
fritap --no-color target

# Set custom timeout
fritap --timeout 30 target
```

## Practical Examples

### Example 1: Analyze Web Browser Traffic

```bash
# Start Firefox and capture comprehensive data
sudo fritap -k firefox_keys.log --pcap firefox_traffic.pcap --json firefox_metadata.json firefox

# Open Firefox, browse to websites
# Press Ctrl+C to stop capture

# Analyze results
wireshark firefox_traffic.pcap  # View decrypted traffic
cat firefox_metadata.json | jq '.statistics'  # View session statistics
```

### Example 2: Mobile App Analysis

```bash
# Connect Android device
adb devices

# Start frida-server on device
adb shell su -c "/data/local/tmp/frida-server &"

# Analyze Instagram app with comprehensive logging
fritap -m -k instagram_keys.log --json instagram_metadata.json com.instagram.android

# Open Instagram app and use it
# Keys will be saved to instagram_keys.log
# Session data will be saved to instagram_metadata.json

# Analyze the results
cat instagram_metadata.json | jq '.connections[] | {dst_addr, data_length}'
```

### Example 3: Malware Analysis

```bash
# Run malware sample in isolated environment with full logging
sudo fritap -k malware_keys.log --pcap malware_traffic.pcap --json malware_analysis.json ./malware_sample

# Analyze captured data
wireshark malware_traffic.pcap  # Visual analysis
cat malware_analysis.json | jq '.connections, .errors'  # Programmatic analysis
```

## Working with Output Files

### TLS Key Files

Key files use the NSS Key Log format:

```
# Example content of keys.log
CLIENT_RANDOM 52345678... ABCDEF123456...
CLIENT_RANDOM 87654321... FEDCBA654321...
```

**Usage with Wireshark:**
1. Open Wireshark
2. Go to Edit → Preferences
3. Navigate to Protocols → TLS
4. Set "Pre-Master-Secret log filename" to your key file
5. Load your network capture

### PCAP Files

PCAP files contain decrypted network traffic:

```bash
# View with tcpdump
tcpdump -r decrypted.pcap

# Analyze with Wireshark
wireshark decrypted.pcap

# Extract specific protocols
tcpdump -r decrypted.pcap 'port 443'
```

## Live Analysis with Wireshark

friTap supports live analysis with Wireshark through named pipes:

```bash
# Linux/macOS
fritap -l target

# Windows
fritap --live target

# Then open Wireshark:
# File → Open → Select the named pipe
```

## Common Scenarios

### Scenario 1: API Analysis

```bash
# Mobile app making API calls
fritap -m -k api_keys.log --json api_metadata.json com.example.app

# Desktop application with comprehensive logging
sudo fritap -k api_keys.log --pcap api_traffic.pcap --json api_analysis.json python api_client.py

# Analyze API endpoints
cat api_metadata.json | jq '.connections[] | .dst_addr' | sort | uniq
```

### Scenario 2: Certificate Pinning Bypass

```bash
# Analyze app with certificate pinning
fritap -m --enable_default_fd --pcap pinned_traffic.pcap --json pinning_analysis.json com.example.app

# Check for pinning bypass indicators
cat pinning_analysis.json | jq '.errors[] | select(.type == "ssl_error")'
```

### Scenario 3: Multi-Process Analysis

```bash
# Capture subprocess traffic with detailed logging
fritap --enable_spawn_gating --pcap all_traffic.pcap --json process_tree.json parent_process

# Analyze process spawn patterns
cat process_tree.json | jq '.connections[] | {timestamp, dst_addr}' | head -10
```

## Troubleshooting Quick Fixes

### No Traffic Captured

```bash
# Use default socket information
fritap --enable_default_fd target

# Enable spawn gating for subprocesses
fritap --enable_spawn_gating target

# Full packet capture mode
fritap --full_capture target
```

### Permission Issues

```bash
# Linux/macOS
sudo fritap [options] target

# Windows (run as Administrator)
fritap [options] target
```

### Mobile Connection Issues

```bash
# Check device connection
frida-ls-devices
Id              Type    Name             OS
--------------  ------  ---------------  ------------
local           local   Local System     macOS 15.3.1
09011FDD4007DJ  usb     Pixel 5          Android 14
barebone        remote  GDB Remote Stub
socket          remote  Local Socket

# Restart frida-server
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

## Best Practices

### 1. Start Simple

Begin with basic key extraction:
```bash
fritap -k keys.log target
```

### 2. Use Verbose Mode for Debugging

```bash
fritap -v -k keys.log target
```

### 3. Combine Multiple Outputs

```bash
fritap -k keys.log --pcap traffic.pcap --json metadata.json target
```

### 4. Save Debug Information

```bash
fritap -do -v --json debug_metadata.json target 2>&1 | tee debug.log
```

### 5. Test with Known Applications

Start with browsers or curl:
```bash
# Test with curl
sudo fritap --pcap curl_traffic.pcap curl https://httpbin.org/get

# Test with Firefox
sudo fritap -k firefox_keys.log firefox
```

## Next Steps

Once you're comfortable with basic usage:

1. **Explore [Advanced Features](../advanced/patterns.md)** for pattern-based hooking
2. **Read [Platform Guides](../platforms/android.md)** for detailed platform-specific instructions
3. **Check [Usage Examples](../examples/index.md)** for real-world scenarios
4. **Learn about [SSL/TLS Libraries](../libraries/index.md)** for library-specific tips

## Quick Reference

### Essential Commands

```bash
# Key extraction
fritap -k keys.log target

# PCAP capture
fritap --pcap traffic.pcap target

# JSON metadata
fritap --json metadata.json target

# Mobile analysis
fritap -m -k keys.log --json mobile_data.json com.example.app

# Live analysis
fritap -l target

# Comprehensive analysis
fritap -k keys.log --pcap traffic.pcap --json metadata.json target
```

### Common Options

| Option | Description |
|--------|-------------|
| `-k, --keylog` | Save TLS keys to file |
| `-p, --pcap` | Save decrypted traffic to PCAP |
| `-j, --json` | Save session metadata as JSON |
| `-m, --mobile` | Mobile application analysis |
| `-s, --spawn` | Spawn and analyze application |
| `-v, --verbose` | Verbose output |
| `-do, --debug-output` | Debug output |
| `-l, --live` | Live analysis with Wireshark |