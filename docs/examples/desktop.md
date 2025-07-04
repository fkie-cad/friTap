# Desktop Applications

This guide provides comprehensive examples for analyzing desktop applications with friTap, covering web browsers, email clients, and other common desktop software.

## Web Browsers

### Firefox Analysis

Firefox is an excellent starting point for friTap analysis due to its widespread use and NSS library support.

**Basic Key Extraction:**
```bash
# Start Firefox and extract TLS keys
sudo fritap -k firefox_keys.log firefox

# Expected output:
# [*] NSS found & will be hooked
# [*] Logging TLS keys to firefox_keys.log
# [*] Press Ctrl+C to stop
```

**Complete Traffic Analysis:**
```bash
# Capture both keys and decrypted traffic
sudo fritap -k firefox_keys.log --pcap firefox_traffic.pcap firefox

# Browse to various websites
# Press Ctrl+C to stop capture
```

**Analysis with Wireshark:**
```bash
# Method 1: Use key log file
wireshark -o tls.keylog_file:firefox_keys.log network_capture.pcap

# Method 2: Open decrypted PCAP directly
wireshark firefox_traffic.pcap
```

### Chrome/Chromium Analysis

Chrome uses BoringSSL, which has excellent friTap support.

**Basic Analysis:**
```bash
# Extract keys from Chrome
sudo fritap -k chrome_keys.log google-chrome

# Or for Chromium
sudo fritap -k chromium_keys.log chromium-browser
```

**Advanced Analysis with Debugging:**
```bash
# Enable verbose output for troubleshooting
sudo fritap -v -k chrome_keys.log --pcap chrome_traffic.pcap google-chrome

# Expected output includes:
# [*] BoringSSL found & will be hooked
# [*] Hooking SSL_read, SSL_write functions
# [*] Logging TLS keys to chrome_keys.log
```

### Safari Analysis (macOS)

Safari analysis requires special considerations due to macOS security features.

**Basic Safari Analysis:**
```bash
# May require SIP disabled
sudo fritap -k safari_keys.log Safari

# Alternative: Use process ID
sudo fritap -k safari_keys.log --pid $(pgrep Safari)
```

**Troubleshooting Safari:**
```bash
# Enable debug output
sudo fritap -do -v Safari

# Check for library detection
sudo fritap --list-libraries Safari
```

## Email Clients

### Thunderbird Analysis

Thunderbird uses NSS for TLS operations, making it ideal for friTap analysis.

**IMAP/SMTP Analysis:**
```bash
# Capture email traffic
sudo fritap -k thunderbird_keys.log --pcap thunderbird_traffic.pcap thunderbird

# Monitor specific protocols
tcpdump -r thunderbird_traffic.pcap 'port 993 or port 465'
```

**Real-time Email Monitoring:**
```bash
# Live analysis
sudo fritap -l thunderbird

# Open Wireshark to view live traffic
# File → Open → Select named pipe
```

### Outlook Analysis (Windows)

Outlook on Windows uses the system's SSL implementation.

**Basic Outlook Analysis:**
```bash
# Run as Administrator
fritap -k outlook_keys.log outlook.exe

# Include debug information
fritap -do -v -k outlook_keys.log outlook.exe
```

## Messaging Applications

### Discord Analysis

Discord uses various SSL libraries depending on the platform.

**Desktop Discord:**
```bash
# Linux
sudo fritap -k discord_keys.log --pcap discord_traffic.pcap discord

# Windows
fritap -k discord_keys.log discord.exe

# macOS
sudo fritap -k discord_keys.log Discord
```

**Analysis Results:**
```bash
# View captured traffic
tcpdump -r discord_traffic.pcap

# Look for Discord API calls
tcpdump -r discord_traffic.pcap 'host discord.com'
```

### Slack Analysis

Slack desktop applications typically use Electron with system SSL libraries.

**Basic Slack Analysis:**
```bash
# Linux
sudo fritap -k slack_keys.log slack

# Windows
fritap -k slack_keys.log slack.exe

# macOS
sudo fritap -k slack_keys.log Slack
```

**API Traffic Analysis:**
```bash
# Capture Slack API communications
sudo fritap --pcap slack_api.pcap slack

# Extract API calls
tcpdump -r slack_api.pcap 'host slack.com' -A
```

## Development Tools

### curl Analysis

curl is excellent for testing friTap functionality and understanding SSL/TLS behavior.

**Basic curl Test:**
```bash
# Test with simple HTTPS request
sudo fritap -k curl_keys.log curl https://httpbin.org/get

# Expected output:
# [*] OpenSSL found & will be hooked
# [*] TLS key captured: CLIENT_RANDOM ...
```

**Multiple Request Analysis:**
```bash
# Capture multiple curl requests
sudo fritap -k curl_keys.log --pcap curl_traffic.pcap bash -c '
  curl https://httpbin.org/get
  curl https://httpbin.org/post -d "test=data"
  curl https://httpbin.org/headers
'
```

### wget Analysis

wget provides another good test case for OpenSSL hooking.

**Basic wget Test:**
```bash
# Download with key extraction
sudo fritap -k wget_keys.log wget https://example.com/file.zip

# Verbose wget analysis
sudo fritap -v -k wget_keys.log wget -v https://example.com/file.zip
```

## Custom Applications

### Python Applications

Python applications using the `requests` library or `urllib3`.

**requests Library:**
```bash
# Analyze Python script using requests
sudo fritap -k python_keys.log --pcap python_traffic.pcap python script.py

# Where script.py contains:
# import requests
# response = requests.get('https://httpbin.org/get')
```

**urllib3 Analysis:**
```bash
# For applications using urllib3 directly
sudo fritap -k urllib3_keys.log python -c "
import urllib3
http = urllib3.PoolManager()
resp = http.request('GET', 'https://httpbin.org/get')
"
```

### Java Applications

Java applications using various SSL providers.

**Basic Java Analysis:**
```bash
# Analyze Java application
sudo fritap -k java_keys.log java -jar application.jar

# For applications using specific SSL providers
sudo fritap -k java_keys.log java -Djavax.net.ssl.keyStore=keystore.jks MyApp
```

### .NET Applications

.NET applications on Linux (using Mono) or Windows.

**Mono Analysis (Linux):**
```bash
# Analyze Mono application
sudo fritap -k mono_keys.log mono application.exe
```

**Windows .NET Analysis:**
```bash
# Analyze .NET application
fritap -k dotnet_keys.log application.exe
```

## Troubleshooting Desktop Applications

### Common Issues

**No SSL Library Detected:**
```bash
# Enable debug output to see library detection
sudo fritap -do -v target_app

# Check loaded libraries
sudo fritap --list-libraries target_app
```

**No Traffic Captured:**
```bash
# Use default socket information
sudo fritap --enable_default_fd --pcap traffic.pcap target_app

# Enable spawn gating for child processes
sudo fritap --enable_spawn_gating --pcap traffic.pcap target_app
```

**Permission Issues:**
```bash
# Ensure proper permissions
sudo fritap -k keys.log target_app

# Check process ownership
ps aux | grep target_app
```

### Application-Specific Solutions

**Browser Sandboxing:**
```bash
# Disable browser security features for analysis
google-chrome --no-sandbox --disable-web-security --user-data-dir=/tmp/chrome_test
sudo fritap -k chrome_keys.log google-chrome
```

**Electron Applications:**
```bash
# Many desktop apps use Electron
sudo fritap -k electron_keys.log --pcap electron_traffic.pcap electron_app

# Enable additional debugging
sudo fritap -do -v electron_app
```

## Advanced Desktop Analysis

### Multi-Process Applications

Many desktop applications spawn multiple processes.

**Capture All Processes:**
```bash
# Enable spawn gating to capture child processes
sudo fritap --enable_spawn_gating -k all_keys.log --pcap all_traffic.pcap parent_app
```

### Pattern-Based Hooking

For applications with stripped SSL libraries.

**Using Pattern Files:**
```bash
# Create pattern file for specific application
sudo fritap --patterns app_patterns.json -k keys.log target_app
```

### Custom Scripts

Extend friTap with custom Frida scripts.

**Custom Hook Script:**
```bash
# Use custom JavaScript for specific analysis
sudo fritap -c custom_hooks.js -k keys.log target_app
```

## Analysis Workflows

### Comprehensive Analysis Workflow

```bash
# Step 1: Basic key extraction
sudo fritap -k app_keys.log target_app

# Step 2: Add traffic capture
sudo fritap -k app_keys.log --pcap app_traffic.pcap target_app

# Step 3: Analyze with Wireshark
wireshark -o tls.keylog_file:app_keys.log app_traffic.pcap

# Step 4: Extract specific protocols
tcpdump -r app_traffic.pcap 'port 443' -w https_traffic.pcap
```

### Automated Analysis

```bash
#!/bin/bash
# Automated desktop application analysis script

APP_NAME="$1"
OUTPUT_DIR="analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "Starting analysis of $APP_NAME"

# Start friTap with comprehensive logging
sudo fritap -k "${APP_NAME}_keys.log" \
           --pcap "${APP_NAME}_traffic.pcap" \
           --json "${APP_NAME}_metadata.json" \
           -v "$APP_NAME" 2>&1 | tee "${APP_NAME}_analysis.log"

echo "Analysis complete. Results in $OUTPUT_DIR"
```

## Performance Considerations

### Resource Usage

**Monitor friTap Performance:**
```bash
# Check memory usage
sudo fritap -k keys.log target_app &
FRITAP_PID=$!
watch -n 1 "ps -p $FRITAP_PID -o pid,ppid,cmd,%mem,%cpu"
```

**Optimize for Large Applications:**
```bash
# Reduce overhead for resource-intensive apps
sudo fritap --buffer-size 512KB --timeout 60 -k keys.log target_app
```

### Output Management

**Manage Large Captures:**
```bash
# Rotate capture files
sudo fritap -k keys.log --pcap traffic.pcap --max-size 100MB target_app

# Compress old captures
gzip old_traffic.pcap
```

## Best Practices

### 1. Test with Known Applications

Start with curl or wget to verify friTap is working:
```bash
sudo fritap -k test_keys.log curl https://httpbin.org/get
```

### 2. Use Appropriate Privileges

Most desktop applications require root/admin privileges:
```bash
# Linux/macOS
sudo fritap -k keys.log target_app

# Windows (run as Administrator)
fritap -k keys.log target_app
```

### 3. Enable Debugging for Troubleshooting

```bash
sudo fritap -do -v -k keys.log target_app 2>&1 | tee debug.log
```

### 4. Combine Multiple Analysis Methods

```bash
# Comprehensive analysis
sudo fritap -k keys.log --pcap traffic.pcap --json metadata.json target_app
```

### 5. Document Your Analysis

```bash
# Create analysis report
echo "Analysis of $APP_NAME on $(date)" > analysis_report.txt
echo "Command: fritap -k keys.log --pcap traffic.pcap $APP_NAME" >> analysis_report.txt
echo "Key count: $(grep -c CLIENT_RANDOM keys.log)" >> analysis_report.txt
echo "Traffic size: $(du -h traffic.pcap | cut -f1)" >> analysis_report.txt
```

## Next Steps

- **Mobile Analysis**: Check [Android](android.md) and [iOS](ios.md) examples
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: See [Common Issues](../troubleshooting/common-issues.md)
- **API Integration**: Explore [Python API](../api/python.md)