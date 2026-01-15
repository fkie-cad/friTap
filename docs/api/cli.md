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
    Use BoringSecretHunter Docker to generate patterns for stripped libraries:
    ```bash
    # Setup directories
    mkdir -p binary results
    cp libssl.so binary/
    
    # Generate patterns with Docker (recommended)
    docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter
    
    # Use generated patterns
    fritap --patterns results/libssl.so_patterns.json -k keys.log target
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
Intercept and analyze child processes that match the target application name.

```bash
# Capture subprocess traffic
fritap --enable_spawn_gating -p all_traffic.pcap parent_app

# Mobile app with services
fritap -m --enable_spawn_gating -k keys.log com.example.app
```

#### `--spawn_gating_all`
Catch ALL newly spawned processes without filtering by target name.

!!! warning "Use with Caution"
    This option hooks every new process spawned on the system/device, which can cause significant overhead and may affect system stability. Use only when necessary.

```bash
# Hook all spawned processes (use carefully)
fritap --spawn_gating_all -k keys.log target_app

# Mobile - catch all spawned processes
fritap -m --spawn_gating_all -k keys.log com.example.app
```

#### `--enable_child_gating`
Intercept child processes spawned by the target application (via fork/clone).

```bash
# Capture forked child processes
fritap --enable_child_gating -k keys.log parent_app

# Combined with spawn gating for comprehensive coverage
fritap --enable_spawn_gating --enable_child_gating -k keys.log target_app

# Mobile with child gating
fritap -m --enable_child_gating -k keys.log com.example.app
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

### Library Analysis

#### `-ll, --list-libraries`
List loaded libraries to help debug hooking issues.

```bash
# List all loaded libraries and SSL-related exports
fritap --list-libraries target_app

# With spawning for new processes
fritap -s --list-libraries target_app

# Mobile applications  
fritap -m --list-libraries com.example.app
```

**Example Output:**
```
=== [ Loaded Libraries ] ===
- libc.so.6 @ 0x7ffff7c00000 (2097152 bytes)
- libssl.so.3 @ 0x7ffff7800000 (1048576 bytes)

=== [ Libraries with 'ssl' in their name ] ===
- libssl.so.3

=== [ Libraries with TLS/SSL-related exports ] ===
- libssl.so.3 (142 TLS/SSL exports)
  * SSL_read @ 0x7ffff7801234
  * SSL_write @ 0x7ffff7801567
  * SSL_get_session @ 0x7ffff7801890
  * BIO_get_fd @ 0x7ffff7801abc
  * SSL_new @ 0x7ffff7801def
  ... and 137 more

=== [ Known SSL/TLS Library Detection ] ===
✓ OpenSSL detected:
  - libssl.so.3 @ 0x7ffff7800000
  - libcrypto.so.3 @ 0x7ffff7900000
```

!!! tip "Debugging Workflow"
    Use `--list-libraries` to identify:
    
    1. **Available SSL libraries** in the target process
    2. **Export symbols** for manual pattern creation
    3. **Library versions** and implementations
    4. **Base addresses** for offset calculation

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
Provide environment variables for spawning. This is especially on desktop environments helpful.

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

!!! tip "How to Modify Payloads"
    When `--payload_modification` is active, friTap's agent listens for two specific Frida messages: `readmod` for modifying incoming data (from `SSL_read`) and `writemod` for modifying outgoing data (from `SSL_write`).

    You must use a separate script to send a message with a payload containing the new data as a byte array. For example, using Frida's Python bindings:
    ```python
    # script.py
    import frida

    new_payload = [0x48, 0x45, 0x4C, 0x4C, 0x4F] # "HELLO"

    session = frida.attach("target_app")
    script = session.create_script("...") # Your agent script
    script.load()

    # To modify the next SSL_write call's data
    script.post({'type': 'writemod', 'payload': new_payload})
    ```

#### `-t, --timeout SECONDS`
Set a timeout in seconds for the process. After the timeout, the process will be resumed automatically.

```bash
# Run analysis for 60 seconds
fritap -t 60 -k keys.log firefox

# Mobile analysis with timeout
fritap -m -t 120 -k keys.log com.example.app

# Batch analysis with timeout
fritap -t 300 -k keys.log -p traffic.pcap target
```

### Windows-Specific Options

#### `-nl, --no-lsass`
Skip LSASS (Local Security Authority Subsystem Service) hooking on Windows.

By default, friTap hooks lsass.exe to extract TLS keys from Windows' native Schannel TLS implementation. This provides system-wide Schannel traffic decryption but requires administrator privileges.

!!! info "Windows TLS Architecture"
    Windows uses **Schannel** (Secure Channel) as its native TLS library, which implements the **SSPI** (Security Support Provider Interface). Due to Windows' **key isolation** architecture, all TLS secrets are stored in **lsass.exe** and never leave that process. By hooking lsass.exe, friTap can extract keys for ALL applications using Schannel (Edge, .NET apps, PowerShell, etc.).

```bash
# Default behavior - hooks both target app and LSASS
fritap -k keys.log firefox.exe

# Disable LSASS hooking (only hook target application directly)
fritap --no-lsass -k keys.log firefox.exe

# Skip LSASS when analyzing apps using OpenSSL instead of Schannel
fritap -nl -k keys.log curl.exe
```

!!! warning "Requirements for LSASS Hooking"
    - Administrator privileges required
    - May not work with Protected Process Light (PPL) enabled
    - Antivirus software may interfere with LSASS access
    - Use `--no-lsass` if you only need to analyze non-Schannel traffic

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
# or frida-ls-devices as an alternative

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
# or frida-ls-devices as an alternative


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

If the integrated patterns of friTap not working try to provide your own patterns:

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