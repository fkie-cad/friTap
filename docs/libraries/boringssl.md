# BoringSSL Support

friTap provides comprehensive support for BoringSSL, Google's SSL/TLS implementation derived from OpenSSL. BoringSSL is commonly found in Chrome, Android applications, and is often statically linked into other libraries.

## Overview

BoringSSL is Google's fork of OpenSSL, designed for use in Google's various products. It's frequently encountered in:

- **Chrome browser** (desktop and mobile)
- **Android applications** using Cronet
- **Flutter applications** (statically linked)
- **Go applications** using crypto/tls
- **Various Google services** and products

## Supported Features

| Platform | Key Extraction | Traffic Capture | Notes |
|----------|---------------|-----------------|-------|
| Linux    | ✓ Full       | ✓ Full         | All versions |
| Windows  | ✓ Limited    | ✓ Full         | Read/Write hooks only |
| macOS    | KeyEo      | ✓ Full         | Key extraction only |
| Android  | ✓ Full       | ✓ Full         | All Android versions |
| iOS      | KeyEo      | ✓ Full         | Key extraction only |

**Legend:**
- **Full**: Complete key extraction and traffic capture
- **KeyEo**: Key extraction only
- **Limited**: Partial functionality

## Detection Methods

friTap uses multiple methods to detect and hook BoringSSL:

### 1. Symbol-Based Detection

When symbols are available:

```bash
# Standard symbol-based hooking
fritap -k keys.log target_app
```

### 2. Pattern-Based Detection

For stripped or statically-linked BoringSSL:

```bash
# Use built-in patterns
fritap -k keys.log target_app

# Use custom patterns
fritap --patterns boringssl_patterns.json -k keys.log target_app
```

### 3. Module-Based Detection

BoringSSL is often found in these modules:
- `libssl.so` (traditional)
- `libboringssl.so` (standalone)
- `libflutter.so` (Flutter apps)
- `libcronet.so` (Chrome/Android)

## Usage Examples

### Chrome Browser Analysis

```bash
# Desktop Chrome
fritap -k chrome_keys.log google-chrome

# Chrome with specific profile
fritap -k chrome_keys.log google-chrome --user-data-dir=/tmp/test-profile

# Debug mode for troubleshooting
fritap -do -k chrome_keys.log google-chrome
```

### Android Chrome/Cronet

```bash
# Chrome on Android
fritap -m -k android_chrome_keys.log com.android.chrome

# App using Cronet
fritap -m -k cronet_keys.log com.example.app

# With anti-root detection bypass
fritap -m -ar -k keys.log com.android.chrome
```

### Flutter Applications

Flutter apps commonly use statically-linked BoringSSL:

```bash
# Basic Flutter analysis
fritap -m -k flutter_keys.log com.example.flutter_app

# Generate patterns for stripped Flutter
mkdir -p binary results
cp /data/app/com.example.flutter_app/lib/arm64/libflutter.so binary/
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# Use generated patterns
fritap --patterns results/libflutter.so_patterns.json -m -k keys.log com.example.flutter_app
```

## Pattern-Based Hooking

For applications with stripped BoringSSL, use pattern-based hooking:

### Generating Patterns

Use BoringSecretHunter to automatically generate patterns:

```bash
# Setup directories
mkdir -p binary results

# Copy target libraries
cp libboringssl.so binary/
cp libflutter.so binary/

# Generate patterns with Docker (recommended)
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter

# Use generated patterns
fritap --patterns results/libboringssl.so_patterns.json -k keys.log target_app
```

### Example Pattern File

```json
{
  "version": "1.0",
  "architecture": "arm64",
  "platform": "android",
  "library": "libflutter.so",
  "patterns": {
    "SSL_Read": {
      "primary": "1F 20 03 D5 FD 7B BF A9 F4 4F 01 A9",
      "fallback": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9",
      "offset": 0,
      "description": "BoringSSL SSL_read in Flutter"
    },
    "SSL_Write": {
      "primary": "FF 83 00 D1 FD 7B 01 A9 F4 4F 02 A9",
      "fallback": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9",
      "offset": 0,
      "description": "BoringSSL SSL_write in Flutter"
    }
  }
}
```

## Advanced Usage

### Multiple Library Detection

BoringSSL can coexist with other SSL libraries:

```bash
# Enable verbose output to see all detected libraries
fritap -v -k keys.log target_app

# List all loaded libraries
fritap --list-libraries target_app
```

### Performance Considerations

BoringSSL applications may have high throughput:

```bash
# Use full capture mode for complete traffic
fritap -f -k keys.log -p traffic.pcap high_traffic_app

# Live analysis with Wireshark
fritap -l target_app
```

### Custom Scripts

For advanced BoringSSL analysis:

```bash
# Use custom JavaScript for specific BoringSSL functions
fritap -c custom_boringssl.js -k keys.log target_app
```

Example custom script (`custom_boringssl.js`):
```javascript
// Custom BoringSSL hooks
if (Process.platform === "linux") {
    const boringssl = Process.getModuleByName("libboringssl.so");
    if (boringssl) {
        console.log("BoringSSL base: " + boringssl.base);
        
        // Hook specific BoringSSL functions
        const ssl_get_version = boringssl.getExportByName("SSL_get_version");
        if (ssl_get_version) {
            Interceptor.attach(ssl_get_version, {
                onLeave: function(retval) {
                    const version = retval.readUtf8String();
                    console.log("SSL Version: " + version);
                }
            });
        }
    }
}
```

## Troubleshooting

### Common Issues

#### Library Not Detected

```bash
# Check if BoringSSL is loaded
fritap --list-libraries target_app | grep -i boring

# Enable debug output
fritap -do -v target_app

# Try pattern-based detection
fritap --patterns patterns.json -do target_app
```

#### No Keys Extracted

```bash
# Verify SSL traffic is occurring
fritap -p traffic.pcap target_app

# Check for statically linked BoringSSL
fritap --patterns auto -k keys.log target_app

# Try with spawn mode
fritap -s -k keys.log target_app
```

#### Pattern Matching Fails

```bash
# Generate new patterns
mkdir patterns && cp target_lib.so patterns/
docker run --rm -v "$(pwd)/patterns":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# Test with verbose output
fritap --patterns results/target_lib.so_patterns.json -do -v target_app
```

### Platform-Specific Issues

#### Android

```bash
# Check for anti-root detection
fritap -m -ar -k keys.log com.android.chrome

# Use spawn mode for app initialization
fritap -m -s -k keys.log com.example.app

# Enable default socket info if FD lookup fails
fritap -m -ed -k keys.log com.example.app
```

#### iOS

```bash
# iOS requires jailbroken device
fritap -m -k keys.log com.apple.mobilesafari

# Check for iOS-specific BoringSSL
fritap -m --list-libraries com.apple.mobilesafari
```

#### Windows

```bash
# Windows may require administrator privileges
fritap -k keys.log chrome.exe

# Check for Windows-specific modules
fritap --list-libraries chrome.exe | grep -i ssl
```

## Integration Examples

### Wireshark Integration

```bash
# Extract keys and capture traffic
fritap -k boringssl_keys.log -p boringssl_traffic.pcap target_app

# Open in Wireshark with keys
wireshark -o "tls.keylog_file:boringssl_keys.log" boringssl_traffic.pcap
```

### Automated Analysis

```bash
#!/bin/bash
# Automated BoringSSL analysis script

APP_NAME="$1"
OUTPUT_DIR="analysis_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"

# Run friTap analysis
fritap -k "$OUTPUT_DIR/keys.log" \
       -p "$OUTPUT_DIR/traffic.pcap" \
       -v "$APP_NAME" 2>&1 | tee "$OUTPUT_DIR/analysis.log"

# Generate report
echo "Analysis complete for $APP_NAME"
echo "Keys extracted: $(grep -c CLIENT_RANDOM "$OUTPUT_DIR/keys.log" 2>/dev/null || echo 0)"
echo "Traffic captured: $(ls -lh "$OUTPUT_DIR/traffic.pcap" 2>/dev/null || echo "No traffic file")"
```

## Version Compatibility

BoringSSL versions and compatibility:

| BoringSSL Version | Chrome Version | Status |
|-------------------|----------------|--------|
| Latest (main)     | Chrome 110+    | ✓ Supported |
| 2023 releases     | Chrome 100-109| ✓ Supported |
| 2022 releases     | Chrome 90-99   | ✓ Supported |
| 2021 releases     | Chrome 80-89   | ✓ Supported |
| Older versions    | Chrome <80     | Limited |

## Next Steps

- **Pattern Generation**: Learn more about [Pattern-Based Hooking](../advanced/patterns.md)
- **Android Analysis**: Check the [Android Platform Guide](../platforms/android.md)
- **Custom Scripts**: See [Advanced Usage Examples](../examples/index.md)
- **Troubleshooting**: Review [Common Issues](../troubleshooting/common-issues.md)

## Related Libraries

BoringSSL is related to these other SSL implementations:
- **[Other Libraries](others.md)**: OpenSSL and other SSL/TLS implementations
- **[Library Overview](index.md)**: Complete friTap library support matrix