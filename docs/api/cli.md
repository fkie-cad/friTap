# CLI Reference

Complete reference for friTap's command-line interface, based on the actual available options and features.

## Basic Syntax

```bash
fritap [OPTIONS] <executable/app name/pid>
```

Where `<executable/app name/pid>` can be:
- Process name (e.g., `firefox`)
- Process ID (e.g., with pid selection)
- Package name for mobile (e.g., `com.example.app`)
- Executable path (e.g., `./application`)

## Core Options

### Output Options

#### `-k, --keylog PATH`
Save TLS keys to file in NSS Key Log format.

```bash
# Basic key logging
fritap -k keys.log firefox

# Mobile key logging
fritap -m -k mobile_keys.log com.example.app
```

**Key Log Format (NSS Key Log Format):**
```
CLIENT_RANDOM 52345678... ABCDEF123456...
CLIENT_RANDOM 87654321... FEDCBA654321...
```

#### `-p, --pcap PATH`
Save decrypted traffic to PCAP file.

```bash
# Basic PCAP capture
fritap -p traffic.pcap firefox

# Combined with key logging
fritap -k keys.log -p traffic.pcap firefox
```

#### Direct Terminal Output
friTap can print the decrypted TLS payload directly to the terminal.

```bash
# Display decrypted content in terminal
fritap firefox

# Verbose terminal output
fritap -v firefox
```

### Process Control

#### `-m, --mobile [DEVICE_ID]`
Enable mobile application analysis mode.

```bash
# Android analysis
fritap -m -k keys.log com.example.app

# Specific device (if multiple connected)
fritap -m emulator-5554 -k keys.log com.example.app

# iOS analysis (requires jailbreak)
fritap -m -k keys.log com.example.app
```

#### `-s, --spawn`
Spawn target application under friTap control.

```bash
# Desktop application
fritap -s -k keys.log firefox

# Mobile application
fritap -m -s -k keys.log com.example.app
```

#### `-H, --host IP:PORT`
Connect to remote Frida server.

```bash
# Remote Frida server
fritap -H 192.168.1.100:27042 -m -k keys.log com.example.app

# Custom port
fritap -H 192.168.1.100:27043 -m -k keys.log com.example.app
```

### Advanced Hooking

#### `--patterns PATH`
Use pattern file for libraries without symbols.

```bash
# Basic pattern usage
fritap --patterns patterns.json -k keys.log target

# Debug pattern matching
fritap -do --patterns patterns.json -v target
```

**Pattern File Example:**
```json
{
  "version": "1.0",
  "patterns": {
    "SSL_Read": {
      "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9",
      "fallback": "1F 20 03 D5 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 01 A9"
    }
  }
}
```

!!! note "Pattern Generation"
    Use BoringSecretHunter to generate patterns for stripped libraries:
    ```bash
    python BoringSecretHunter.py --target libssl.so --output patterns.json
    fritap --patterns patterns.json -k keys.log target
    ```

#### `--offsets PATH`
Use offset file for known memory layouts.

```bash
# Offset-based hooking
fritap --offsets offsets.json -k keys.log target

# Combined with patterns
fritap --patterns patterns.json --offsets offsets.json -k keys.log target
```

**Offset File Example:**
```json
{
  "library": "libssl.so",
  "base_address": "0x7000000000",
  "functions": {
    "SSL_read": {
      "offset": "0x1234",
      "type": "relative"
    },
    "SSL_write": {
      "address": "0x7000001234",
      "type": "absolute"
    }
  }
}
```

#### `-c, --custom_script PATH`
Include custom Frida script.

```bash
# Use custom JavaScript
fritap -c custom_hooks.js -k keys.log target

# Multiple custom scripts
fritap -c script1.js -c script2.js -k keys.log target
```

### Process and Network Options

#### `--enable_spawn_gating`
Intercept and analyze child processes.

```bash
# Capture subprocess traffic
fritap --enable_spawn_gating -p all_traffic.pcap parent_app

# Mobile app with services
fritap -m --enable_spawn_gating -k keys.log com.example.app
```

#### `-ed, --enable_default_fd`
Use default socket information when FD lookup fails.

```bash
# Fallback socket info (127.0.0.1:1234-127.0.0.1:2345)
fritap -ed -p traffic.pcap target

# Mobile troubleshooting
fritap -m -ed -k keys.log com.example.app
```

#### `-f, --full_capture`
Enable full packet capture mode.

```bash
# Complete network capture (requires -p)
fritap -f -k keys.log -p traffic.pcap target

# For libraries with limited PCAP support
fritap -m -f -k keys.log com.example.app
```

### Debug and Verbosity

#### `-v, --verbose`
Enable verbose output.

```bash
# Verbose logging
fritap -v -k keys.log target

# Show library detection
fritap -v target | grep -i "found"
```

#### `-do, --debugoutput`
Enable debug output only (without Chrome Inspector).

```bash
# Maximum debugging
fritap -do -v target

# Save debug to file
fritap -do -v target 2>&1 | tee debug.log
```

#### `-d, --debug`
Enable full debug mode with Chrome Inspector.

```bash
# Full debug mode with Chrome Inspector
fritap -d -k keys.log target

# Access Chrome DevTools for script debugging
```

### Mobile-Specific Options

#### `-ar, --anti_root`
Enable anti-root detection bypass (Android).

```bash
# Bypass root detection
fritap -m -ar -k keys.log com.example.app

# Combined with spawn mode
fritap -m -s -ar -k keys.log com.example.app
```

### Live Analysis

#### `-l, --live`
Create named pipe for live analysis with Wireshark.

```bash
# Linux/macOS live analysis
fritap -l target

# Then open Wireshark:
# File → Open → /tmp/sharkfin
```

### Socket and Network Tracing

#### `-sot, --socket_tracing [PATH]`
Enable socket tracing.

```bash
# Basic socket tracing
fritap -sot -k keys.log target

# Save socket trace to file
fritap -sot socket_trace.log -k keys.log target
```

### Environment and Experimental

#### `-env, --environment PATH`
Provide environment variables for spawning.

```bash
# JSON environment file
fritap -env env.json -s -k keys.log target
```

**Environment File Example (env.json):**
```json
{
  "ENV_VAR_NAME": "ENV_VAR_VALUE",
  "ANOTHER_VAR": "value"
}
```

#### `-exp, --experimental`
Enable experimental features.

```bash
# Enable all experimental features
fritap -exp -k keys.log target
```

#### `--payload_modification`
Enable payload modification capabilities.

!!! warning "Use with Caution"
    This feature can crash applications.

```bash
# Enable payload modification
fritap --payload_modification -k keys.log target
```

## Practical Examples

### Basic Usage

```bash
# Simple key extraction
fritap -k keys.log firefox

# PCAP capture
fritap -p traffic.pcap curl https://example.com

# Mobile analysis
fritap -m -k keys.log com.instagram.android
```

### Advanced Usage

```bash
# Comprehensive analysis
fritap -k keys.log -p traffic.pcap -v firefox

# Pattern-based hooking
fritap --patterns flutter.json -k keys.log com.flutter.app

# Mobile with anti-root and spawn gating
fritap -m -s -ar --enable_spawn_gating -k keys.log com.example.app
```

### Troubleshooting

```bash
# Debug mode
fritap -do -v target

# Maximum verbosity with live analysis
fritap -do -v -l target

# Pattern debug
fritap -do -v --patterns patterns.json target
```

### Live Analysis Workflow

```bash
# Start live capture
fritap -l target &

# Open Wireshark in another terminal
wireshark /tmp/sharkfin

# Or combine with key logging
fritap -l -k keys.log target
```

### Mobile Analysis Workflow

```bash
# Check device connection
adb devices

# Start frida-server on device
adb shell su -c "/data/local/tmp/frida-server &"

# Basic mobile analysis
fritap -m -k keys.log com.example.app

# Advanced mobile analysis
fritap -m -s -ar --enable_spawn_gating --enable_default_fd \
       -k keys.log -p traffic.pcap com.example.app
```

## Exit Codes

friTap uses standard exit codes:

- `0`: Success
- `1`: General error
- `2`: Invalid arguments/configuration
- Additional codes for specific Frida errors

## Real CLI Examples from friTap Help

Based on the actual examples in friTap:

```bash
# Mobile examples
fritap -m -p ssl.pcap com.example.app
fritap -m --pcap log.pcap --verbose com.example.app
fritap -m -k keys.log -v -s com.example.app
fritap -m -k keys.log -v -c custom_script.js -s com.example.app
fritap -m --patterns pattern.json -k keys.log -s com.google.android.youtube

# Desktop examples  
fritap --pcap log.pcap "$(which curl) https://www.google.com"
fritap -H --pcap log.pcap 192.168.0.1:1234 com.example.app

# Advanced examples
fritap -m -p log.pcap --enable_spawn_gating -v -do -sot --full_capture -k keys.log com.example.app
fritap -m -p log.pcap --enable_spawn_gating -v -do --anti_root --full_capture -k keys.log com.example.app
fritap -m -p log.pcap --enable_default_fd com.example.app
```

## Best Practices

### 1. Start Simple

Begin with basic key extraction:
```bash
fritap -k keys.log target
```

### 2. Use Verbose Mode for Learning

```bash
fritap -v -k keys.log target
```

### 3. Debug When Needed

```bash
fritap -do -v target 2>&1 | tee debug.log
```

### 4. Combine Multiple Outputs

```bash
fritap -k keys.log -p traffic.pcap target
```

### 5. Mobile Best Practices

```bash
# Always check device connection first
adb devices

# Use anti-root when needed
fritap -m -ar -k keys.log com.example.app

# Use spawn mode for initialization analysis
fritap -m -s -k keys.log com.example.app
```

## Common Option Combinations

### Comprehensive Analysis

```bash
fritap -k keys.log -p traffic.pcap -v target
```

### Mobile Troubleshooting

```bash
fritap -m -ar -ed --enable_spawn_gating -do -v -k keys.log com.example.app
```

### Pattern-Based Analysis

```bash
fritap --patterns patterns.json -do -v -k keys.log target
```

### Live Monitoring

```bash
fritap -l -k keys.log target
```

## Integration Examples

### CI/CD Script

```bash
#!/bin/bash
set -e

# Run friTap analysis
timeout 60 fritap -k keys.log -p traffic.pcap ./app_under_test

# Validate results
if [ ! -s keys.log ]; then
    echo "ERROR: No TLS keys extracted"
    exit 1
fi

echo "Analysis complete: $(grep -c CLIENT_RANDOM keys.log) sessions captured"
```

### Batch Analysis

```bash
#!/bin/bash
for app in app1 app2 app3; do
    fritap -m -k "${app}_keys.log" -p "${app}_traffic.pcap" "$app"
done
```

## Next Steps

- **Python API**: Learn about [Python integration](python.md)
- **Examples**: Check [Usage Examples](../examples/index.md)
- **Patterns**: Learn about [Pattern-Based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)