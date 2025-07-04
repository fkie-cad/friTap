# Other SSL/TLS Libraries

This guide covers additional SSL/TLS libraries supported by friTap beyond the major ones (OpenSSL, BoringSSL, NSS, GnuTLS, WolfSSL). These libraries are often found in specialized applications, embedded systems, or platform-specific implementations.

## Platform-Native Libraries

### Schannel (Windows)

**Microsoft's SSL/TLS Implementation**

Schannel (Secure Channel) is Microsoft's native SSL/TLS implementation integrated into Windows. It's used by most Windows applications that don't bundle their own SSL library.

#### Key Features

- **Native Windows Integration**: Built into Windows OS
- **CryptoAPI Integration**: Works with Windows certificate stores
- **SSPI (Security Support Provider Interface)**: Unified authentication interface
- **Hardware Acceleration**: Supports hardware-based cryptography

#### Usage with friTap

```powershell
# Analyze application using Schannel
fritap -k schannel_keys.log --pcap schannel_traffic.pcap --json schannel_metadata.json application.exe

# Debug Schannel detection
fritap -do -v application.exe | Select-String "schannel"

# System applications (typically use Schannel)
fritap -k edge_keys.log msedge.exe
fritap -k outlook_keys.log OUTLOOK.EXE
```

#### Applications Using Schannel

```powershell
# Microsoft applications
fritap -k teams_keys.log Teams.exe
fritap -k ie_keys.log iexplore.exe

# .NET applications
fritap -k dotnet_keys.log dotnet_application.exe

# Windows Store applications
fritap -k store_app_keys.log --json store_metadata.json Microsoft.WindowsCalculator_8wekyb3d8bbwe
```

#### Technical Details

**Function Hooks:**
- `EncryptMessage()` - Encrypts outbound data
- `DecryptMessage()` - Decrypts inbound data
- `AcquireCredentialsHandle()` - Acquires SSL/TLS credentials
- `InitializeSecurityContext()` - Initializes SSL context

**Configuration Analysis:**
```powershell
# Check Schannel registry settings
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# View cipher suites
Get-TlsCipherSuite | Format-Table Name, Certificate, KeyExchange
```

### macOS SSL/TLS Libraries

**Apple Platform SSL Libraries**

macOS applications typically use system-provided SSL libraries, but friTap currently focuses on cross-platform libraries like OpenSSL and BoringSSL that are also available on macOS.

#### Key Libraries on macOS

- **OpenSSL/BoringSSL**: Many third-party applications bundle these libraries
- **LibreSSL**: Some applications use OpenBSD's SSL implementation
- **Custom implementations**: Enterprise applications may use proprietary SSL libraries

#### Usage with friTap

```bash
# Applications using bundled OpenSSL
sudo fritap -k app_keys.log --pcap app_traffic.pcap --json app_metadata.json "/Applications/App.app/Contents/MacOS/App"

# Chrome (uses BoringSSL)
sudo fritap -k chrome_keys.log "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# Debug SSL library detection
sudo fritap -do -v application | grep -i "ssl\|boring\|openssl"
```

#### Applications Analysis

```bash
# Third-party applications with bundled SSL
sudo fritap -k firefox_keys.log Firefox
sudo fritap -k discord_keys.log Discord

# Check what SSL libraries an application uses
otool -L "/Applications/App.app/Contents/MacOS/App" | grep -i ssl
```

#### Technical Considerations

**Library Detection:**
```bash
# Check for bundled SSL libraries
find "/Applications/App.app" -name "*ssl*" -o -name "*crypto*"

# Use pattern-based detection for stripped libraries
sudo fritap --patterns macos_patterns.json -k keys.log application
```

**Note**: Native macOS SSL frameworks (Secure Transport, Network.framework) are not currently supported by friTap. friTap focuses on applications that use portable SSL libraries like OpenSSL, BoringSSL, etc.

## Specialized Libraries

### Conscrypt (Android)

**Google's Java Security Provider**

Conscrypt is Google's Java Cryptography Architecture (JCA) provider that uses BoringSSL as the underlying implementation.

#### Key Features

- **Java Integration**: Seamless Java SSL/TLS support
- **BoringSSL Backend**: Uses Google's SSL library
- **Android System**: Default provider on Android
- **Performance Optimized**: Native implementation for speed

#### Usage with friTap

```bash
# Android applications using Conscrypt
fritap -m -k conscrypt_keys.log --pcap conscrypt_traffic.pcap --json conscrypt_metadata.json com.example.app

# Debug Conscrypt detection
fritap -m -do -v com.example.app | grep -i conscrypt

# Force Conscrypt detection
fritap -m --force-library conscrypt -k keys.log com.example.app
```

#### Applications Using Conscrypt

```bash
# Java/Android applications
fritap -m -k android_keys.log com.android.chrome
fritap -m -k gmail_keys.log com.google.android.gm

# Enterprise Android applications
fritap -m -k enterprise_keys.log com.company.android.app
```

### S2N-TLS (AWS)

**Amazon's Simple, Small, and Secure TLS**

S2N-TLS is Amazon's TLS implementation designed for high-performance server applications.

#### Key Features

- **Security Focus**: Minimal attack surface
- **Performance**: Optimized for AWS workloads
- **Simplicity**: Easy to audit and verify
- **Open Source**: Available for community use

#### Usage with friTap

```bash
# Applications using S2N-TLS
sudo fritap -k s2n_keys.log --pcap s2n_traffic.pcap --json s2n_metadata.json aws_application

# Pattern-based detection (if symbols stripped)
sudo fritap --patterns s2n_patterns.json -k keys.log target_app

# Debug S2N detection
sudo fritap -do -v aws_application | grep -i s2n
```

### RustTLS

**Memory-Safe TLS Implementation**

RustTLS is a TLS library written in Rust, providing memory safety and security.

#### Key Features

- **Memory Safety**: Written in Rust
- **Security Focus**: Eliminates common vulnerabilities
- **Performance**: Competitive with C implementations
- **Modern**: Supports latest TLS standards

#### Usage with friTap

```bash
# Rust applications using RustTLS
sudo fritap -k rusttls_keys.log --json rust_metadata.json rust_application

# Pattern-based hooking
sudo fritap --patterns rusttls_patterns.json -k keys.log target

# Debug RustTLS detection
sudo fritap -do -v rust_application | grep -i rust
```

## Embedded and IoT Libraries

### Mbed TLS (ARM)

**Lightweight SSL/TLS Library**

Mbed TLS is ARM's SSL/TLS library designed for embedded and IoT devices.

#### Key Features

- **Small Footprint**: Minimal memory usage
- **Modular Design**: Only include needed features
- **Hardware Support**: ARM hardware acceleration
- **Standards Compliance**: Full SSL/TLS implementation

#### Usage with friTap

```bash
# Embedded applications
sudo fritap -k mbedtls_keys.log --pcap mbedtls_traffic.pcap --json iot_metadata.json iot_application

# Mobile applications (Android/iOS)
fritap -m -k mbedtls_keys.log com.iot.mobileapp

# Pattern-based detection
fritap --patterns mbedtls_patterns.json -k keys.log embedded_device
```

#### Common Use Cases

```bash
# IoT devices
fritap -k iot_keys.log iot_firmware

# Mobile applications with embedded components
fritap -m -k mobile_iot_keys.log com.device.controller

# Embedded web servers
fritap -k webserver_keys.log --pcap web_traffic.pcap embedded_httpd
```

### Network.framework (Apple)

**Modern Apple Networking API**

Network.framework is Apple's modern replacement for traditional socket APIs, with built-in TLS support.

#### Key Features

- **Modern API**: Replaces legacy BSD sockets
- **Built-in Security**: TLS by default
- **Performance**: Optimized for Apple hardware
- **Privacy**: Enhanced privacy features

#### Usage with friTap

```bash
# macOS applications using Network.framework
sudo fritap -k network_keys.log --json network_metadata.json modern_macos_app

# iOS applications (requires jailbreak)
fritap -m -k network_keys.log com.modern.ios.app

# Debug Network.framework detection
sudo fritap -do -v modern_app | grep -i network
```

## Commercial and Proprietary Libraries

### MatrixSSL

**Commercial SSL/TLS Library**

MatrixSSL is a commercial SSL/TLS implementation often used in embedded and enterprise applications.

#### Usage with friTap

```bash
# Commercial applications using MatrixSSL
sudo fritap --patterns matrixssl_patterns.json -k keys.log commercial_app

# Debug detection
sudo fritap -do -v commercial_app | grep -i matrix
```

### Cryptlib

**Peter Gutmann's Cryptographic Library**

Cryptlib is a comprehensive cryptographic library that includes SSL/TLS support.

#### Usage with friTap

```bash
# Applications using Cryptlib
sudo fritap --patterns cryptlib_patterns.json -k keys.log application

# Debug Cryptlib detection
sudo fritap -do -v application | grep -i crypt
```

## Legacy Libraries

### SSLeay (Legacy)

**Historical SSL Implementation**

SSLeay is the predecessor to OpenSSL, still occasionally found in legacy applications.

#### Usage with friTap

```bash
# Legacy applications
sudo fritap --patterns ssleay_patterns.json -k keys.log legacy_app

# Use offset-based hooking if patterns fail
sudo fritap --offsets ssleay_offsets.json -k keys.log legacy_app
```

## Custom and Proprietary Implementations

### In-House SSL Libraries

Many organizations develop custom SSL/TLS implementations for specific requirements.

#### Analysis Approach

```bash
# Use pattern generation tools
python BoringSecretHunter.py --target custom_ssl.so --output custom_patterns.json

# Apply patterns with friTap
fritap --patterns custom_patterns.json -k keys.log custom_app

# Manual analysis
fritap -do -v custom_app | grep -E "(ssl|tls|encrypt|decrypt)"
```

#### Reverse Engineering Custom Libraries

```bash
# Analyze library structure
objdump -t custom_ssl.so | grep -E "(ssl|tls|encrypt)"

# Use IDA Pro or Ghidra for detailed analysis
# Generate patterns based on function signatures

# Test with friTap
fritap --patterns custom_patterns.json -k keys.log target
```

## Integration Patterns

### Java SSL/TLS (JSSE)

**Java Secure Socket Extension**

JSSE is Java's standard SSL/TLS implementation, often using native libraries underneath.

#### Usage with friTap

```bash
# Java applications
sudo fritap -k java_keys.log --json java_metadata.json java -jar application.jar

# Android applications (Java layer)
fritap -m -k jsse_keys.log com.java.android.app

# Debug Java SSL detection
sudo fritap -do -v java_app | grep -i java
```

### .NET SSL Classes

**Microsoft .NET SSL/TLS**

.NET provides SSL/TLS through System.Net.Security classes, typically using Schannel.

#### Usage with friTap

```powershell
# .NET applications
fritap -k dotnet_keys.log --json dotnet_metadata.json dotnet_application.exe

# ASP.NET applications
fritap -k aspnet_keys.log iisexpress.exe

# Debug .NET SSL detection
fritap -do -v dotnet_app | Select-String "System.Net"
```

## Advanced Detection Techniques

### Pattern Generation

For libraries without symbol information:

```bash
# Use BoringSecretHunter
python BoringSecretHunter.py --target unknown_ssl.so --output patterns.json

# Use Ghidra script for pattern generation
# Export function patterns from reverse engineering

# Test patterns
fritap --patterns patterns.json -k test.log target
```

### Offset-Based Hooking

For completely stripped libraries:

```bash
# Manual offset calculation
objdump -d stripped_ssl.so | grep -A 10 -B 10 "encrypt\|decrypt"

# Create offset configuration
echo '{"ssl_read": "0x1234", "ssl_write": "0x5678"}' > offsets.json

# Apply offsets
fritap --offsets offsets.json -k keys.log target
```

### Hybrid Approaches

Combine multiple detection methods:

```bash
# Use patterns with fallback to offsets
fritap --patterns primary.json --offsets fallback.json -k keys.log target

# Custom Frida script for complex detection
fritap --custom-script detection.js -k keys.log target
```

## Troubleshooting Other Libraries

### Library Not Detected

```bash
# Check library dependencies
ldd target_application | grep -E "(ssl|tls|crypto)"

# Analyze loaded modules
fritap --list-libraries target | grep -i ssl

# Use debug mode
fritap -do -v target 2>&1 | grep -i "library\|module\|detect"
```

### Partial Support

```bash
# Key extraction only
fritap -k keys.log target

# Traffic capture with external tools
tcpdump -i any -w network.pcap &
fritap --enable_default_fd target
```

### Version Compatibility

```bash
# Check library versions
strings target | grep -E "(version|ssl|tls)"

# Use version-specific patterns
fritap --patterns lib_v2.1.json -k keys.log target

# Compatibility mode
fritap --experimental -k keys.log target
```

## Contributing Library Support

### Adding New Library Support

1. **Library Analysis**:
   ```bash
   # Analyze library structure
   objdump -T new_library.so | grep -E "(ssl|tls|read|write)"
   
   # Function signature analysis
   readelf -s new_library.so | grep FUNC
   ```

2. **Pattern Generation**:
   ```bash
   # Use automated tools
   python BoringSecretHunter.py --target new_library.so --output new_patterns.json
   
   # Manual pattern creation
   # Analyze disassembly and create byte patterns
   ```

3. **Testing**:
   ```bash
   # Test with sample application
   fritap --patterns new_patterns.json -k test.log sample_app
   
   # Verify key extraction
   grep "CLIENT_RANDOM" test.log | wc -l
   ```

4. **Documentation**:
   - Create library-specific guide
   - Document usage examples
   - Submit pull request with patterns and documentation

### Pattern Contribution Guidelines

```bash
# Pattern format
{
  "library": "new_library.so",
  "patterns": {
    "SSL_Read": {
      "primary": "XX XX XX XX ?? ?? ?? ??",
      "secondary": "YY YY YY YY ?? ?? ?? ??"
    },
    "SSL_Write": {
      "primary": "ZZ ZZ ZZ ZZ ?? ?? ?? ??"
    }
  }
}

# Testing procedure
fritap --patterns new_patterns.json -k test.log target
cat test.log | wc -l  # Should contain extracted keys

# Submit via GitHub
git add new_patterns.json docs/libraries/new_library.md
git commit -m "Add support for NewLibrary SSL/TLS"
```

## Best Practices for Other Libraries

### 1. Library Identification

```bash
# Always identify library first
file target_application
ldd target_application | grep -E "(ssl|tls|crypto)"
strings target_application | grep -E "(ssl|tls|version)"
```

### 2. Progressive Analysis

```bash
# Start with automatic detection
fritap -k keys.log target

# Try pattern-based if automatic fails
fritap --patterns patterns.json -k keys.log target

# Use offsets as last resort
fritap --offsets offsets.json -k keys.log target
```

### 3. Documentation

- Document successful library configurations
- Share patterns with the community
- Report issues and improvements via GitHub

### 4. Testing Methodology

```bash
# Test with known working application first
fritap -k test.log curl https://httpbin.org/get

# Compare with target application
fritap -k target.log target_app

# Validate key extraction
openssl s_client -connect example.com:443 -keylogfile test.log
```

## Next Steps

- **[OpenSSL/BoringSSL Guide](openssl.md)**: Detailed OpenSSL family support
- **[NSS Guide](nss.md)**: Mozilla's Network Security Services
- **[GnuTLS Guide](gnutls.md)**: GNU TLS library support
- **[WolfSSL Guide](wolfssl.md)**: Embedded SSL library
- **[Pattern-Based Hooking](../advanced/patterns.md)**: Advanced pattern creation
- **[Troubleshooting](../troubleshooting/common-issues.md)**: Common library issues