# Usage Examples

This section provides comprehensive, real-world examples of using friTap for various security analysis scenarios. Each example includes context, commands, expected output, and analysis techniques.

## Quick Reference

| Scenario | Command | Use Case |
|----------|---------|----------|
| **Web Browser** | `sudo fritap -k keys.log firefox` | Analyze web traffic |
| **Mobile App** | `fritap -m -k keys.log com.example.app` | Android/iOS analysis |
| **Malware** | `fritap -f -k malware.log --pcap traffic.pcap ./sample` | Malware communication with full capture |
| **Pattern Hook** | `fritap --patterns patterns.json -k keys.log target` | Stripped binaries |
| **Live Analysis** | `fritap -l target` | Real-time monitoring |

## Example Categories

### 🌐 [Desktop Applications](desktop.md)
- Web browsers (Firefox, Chrome, Safari)
- Email clients (Thunderbird, Outlook)
- Desktop applications (Slack, Discord)
- Command-line tools (curl, wget)

### 📱 [Android Applications](android.md)
- Social media apps (Instagram, Twitter)
- Banking applications
- E-commerce apps
- Custom applications

### 🍎 iOS Applications
- System applications
- Third-party apps
- Jailbreak considerations
- *See Platform Guides for iOS-specific examples*

### 🌍 Web Browsers
- Chrome/Chromium analysis
- Firefox analysis
- Safari analysis
- Edge analysis
- *See Desktop Applications examples for browser analysis*

### 🦠 [Malware Analysis](malware.md)
- C&C communication
- Data exfiltration
- Cryptocurrency miners
- APT analysis

### 🔴 Live Analysis
- Real-time monitoring
- Wireshark integration
- Continuous analysis
- Incident response
- *See CLI Reference for live analysis options*

## Common Workflow Patterns

### Pattern 1: Basic Analysis

```bash
# 1. Extract keys
fritap -k keys.log target

# 2. Analyze with Wireshark
wireshark -o tls.keylog_file:keys.log capture.pcap
```

### Pattern 2: Complete Analysis

```bash
# 1. Capture everything
fritap -k keys.log --pcap decrypted.pcap target

# 2. Analyze decrypted traffic
wireshark decrypted.pcap
```

### Pattern 3: Continuous Monitoring

```bash
# 1. Start live capture
fritap -l target &

# 2. Open Wireshark to live pipe
# File → Open → Select named pipe
```

### Pattern 4: Terminal Output Analysis

```bash
# 1. Capture to multiple formats
fritap -k keys.log --pcap traffic.pcap -v target | tee terminal_output.log

# 2. Analyze with different tools
wireshark traffic.pcap
grep -i "ssl\|tls" terminal_output.log
```

## Example Scenarios by Use Case

### Malware Analysis

**C&C Communication**
```bash
# Capture malware communications
fritap -k malware_keys.log --pcap malware_traffic.pcap ./malware_sample
```

**Data Exfiltration**
```bash
# Monitor data theft
fritap --full_capture -k keys.log --pcap exfil.pcap suspicious_app
```

### Application Security

**Mobile App Testing**
```bash
# Comprehensive mobile analysis with full network capture and keys to decrypt it later (e.g. in Wireshark)
fritap -m -f -k app_keys.log --pcap app_traffic.pcap com.example.app
```

**Web Application Testing**
```bash
# Browser-based testing
fritap -k browser_keys.log --pcap browser_traffic.pcap firefox
```

## Advanced Example Patterns

### Multi-Process Analysis

```bash
# Capture subprocess traffic
fritap --enable_spawn_gating --pcap all_processes.pcap parent_app
```

### Pattern-Based Hooking

```bash
# Hook stripped libraries
fritap --patterns custom_patterns.json --offsets custom_offsets.json -k keys.log target
```

### Custom Script Integration

```bash
# Use custom Frida script
fritap -c custom_hooks.js -k keys.log target
```

## Output Analysis Examples

### Key Log Analysis

```bash
# View extracted keys
cat keys.log

# Count unique sessions
grep "CLIENT_RANDOM" keys.log | wc -l

# Extract specific session
grep "52345678" keys.log
```

### PCAP Analysis

```bash
# Basic traffic analysis
tcpdump -r traffic.pcap

# HTTP analysis
tcpdump -r traffic.pcap 'port 80 or port 443'

# Extract specific connections
tcpdump -r traffic.pcap 'host example.com'
```

### Terminal Output Analysis

```bash
# Save terminal output
fritap -v target | tee analysis_output.log

# Extract specific information
grep -i "found" analysis_output.log
grep -i "hook" analysis_output.log

# Filter by criteria
grep "443" analysis_output.log
```

## Integration Examples

### Wireshark Integration

```bash
# Method 1: Key log file
fritap -k keys.log target
# Then in Wireshark: Edit → Preferences → Protocols → TLS → Pre-Master-Secret log filename

# Method 2: Live analysis
fritap -l target
# Then in Wireshark: File → Open → Select named pipe
```

### Burp Suite Integration

```bash
# Capture API traffic
fritap --pcap api.pcap target
# Import PCAP into Burp Suite for analysis
```

### Custom Tool Integration

```bash
# Pipe to custom analyzer
fritap -v target | python custom_analyzer.py

# Real-time processing
fritap -l target | tee live_analysis.pcap | python real_time_processor.py
```

## Error Handling Examples

### Common Issues and Solutions

**No Traffic Captured**
```bash
# Try default socket info
fritap --enable_default_fd --pcap traffic.pcap target

# Enable spawn gating
fritap --enable_spawn_gating --pcap traffic.pcap target
```

**Library Not Detected**
```bash
# Use pattern matching
fritap --patterns patterns.json -k keys.log target

# Enable debug output
fritap -do -v target
```

**Permission Issues**
```bash
# Linux/macOS
sudo fritap -k keys.log target

# Check device connection (mobile)
frida-ls-devices 
Id              Type    Name             OS
--------------  ------  ---------------  ------------
local           local   Local System     macOS 15.3.1
31041FDH2006EY  usb     Pixel 7          Android 13
barebone        remote  GDB Remote Stub
socket          remote  Local Socket
```

## Performance Optimization Examples

### Large-Scale Analysis

```bash
# Optimize for large captures
fritap --buffer-size 1MB --timeout 300 -k keys.log target
```

### Memory-Constrained Environments

```bash
# Minimize memory usage
fritap -k keys.log --no-pcap target
```

### High-Performance Capture

```bash
# Use minimal output
fritap --json --no-verbose target > analysis.json
```

## Automation Examples

### Batch Analysis

```bash
#!/bin/bash
for app in app1 app2 app3; do
    fritap -m -k "${app}_keys.log" --pcap "${app}_traffic.pcap" "$app"
done
```

### Continuous Monitoring

```bash
#!/bin/bash
while true; do
    fritap -k "keys_$(date +%Y%m%d_%H%M%S).log" target
    sleep 300
done
```

### Incident Response

```bash
#!/bin/bash
# Automated malware analysis
fritap -k "incident_keys.log" --pcap "incident_traffic.pcap" --json "incident_metadata.json" "$MALWARE_SAMPLE"
```

## Best Practices from Examples

### 1. Start Simple, Add Complexity

```bash
# Start with basic key extraction
fritap -k keys.log target

# Add traffic capture
fritap -k keys.log --pcap traffic.pcap target

# Add advanced features
fritap -k keys.log --pcap traffic.pcap --patterns patterns.json target
```

### 2. Use Appropriate Output Formats

```bash
# Keys for offline analysis
fritap -k keys.log target

# PCAP for comprehensive analysis
fritap --pcap traffic.pcap target

# JSON for programmatic processing
fritap --json metadata.json target
```

### 3. Combine with Other Tools

```bash
# friTap + Wireshark
fritap -k keys.log target &
wireshark -o tls.keylog_file:keys.log

# friTap + tcpdump
fritap --pcap decrypted.pcap target
tcpdump -r decrypted.pcap
```

### 4. Document Your Analysis

```bash
# Create analysis log
fritap -v target 2>&1 | tee analysis.log

# Save command history
history | grep fritap > fritap_commands.txt
```

## Next Steps

Choose the examples that match your use case:

- **New to friTap?** Start with [Desktop Applications](desktop.md)
- **Mobile Analysis?** Check [Android](android.md) examples or Platform Guides
- **Malware Research?** See [Malware Analysis](malware.md) examples
- **Need Real-time Analysis?** Check [CLI Reference](../api/cli.md) for live analysis options
- **Advanced Features?** Explore [Pattern-based Hooking](../advanced/patterns.md)