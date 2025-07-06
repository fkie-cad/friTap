# SSL/TLS Libraries Overview

friTap supports a wide range of SSL/TLS libraries across different platforms. This section provides detailed information about library support, detection mechanisms, and specific considerations for each library.

## Supported Libraries Matrix

| Library | Linux | Windows | macOS | Android | iOS | Key Features |
|---------|-------|---------|-------|---------|-----|--------------|
| **OpenSSL** | ✅ Full | 🔄 R/W | 🚧 TBI | ✅ Full | 🚧 TBI | Most widely used |
| **BoringSSL** | ✅ Full | 🔄 R/W | 🔑 Keys | ✅ Full | 🔑 Keys | Google's OpenSSL fork |
| **NSS** | ✅ Full | 🔄 R/W | 🚧 TBI | 🚧 TBA | 🚧 TBI | Mozilla's library |
| **GnuTLS** | 🔄 R/W | 🔄 R/W | 🚧 TBI | ✅ Full | 🚧 TBI | GNU project library |
| **WolfSSL** | 🔄 R/W | 🔄 R/W | 🚧 TBI | ✅ Full | 🚧 TBI | Embedded/IoT focused |
| **mbedTLS** | 🔄 R/W | 🔄 R/W | 🚧 TBI | ✅ Full | 🚧 TBI | Lightweight library |
| **Schannel** | ❌ | ✅ Full | ❌ | ❌ | ❌ | Windows native SSL/TLS |
| **Conscrypt** | 🚧 TBA | 🚧 TBA | 🚧 TBA | ✅ Full | 🚧 TBA | Android system SSL |
| **S2N-TLS** | ✅ Full | ❌ | 🚧 TBA | ✅ Full | ❌ | AWS library |
| **RustTLS** | 🔑 Keys | 🚧 TBI | 🚧 TBI | 🔑 Keys | 🚧 TBI | Rust implementation |

**Legend:**
- ✅ **Full**: Complete support (keys + traffic decryption)
- 🔄 **R/W**: Read/Write hooks only (traffic without keys)
- 🔑 **Keys**: Key extraction only
- 🚧 **TBI**: To Be Implemented
- 🚧 **TBA**: To Be Analyzed
- ❌ **N/A**: Not applicable to platform

## Library Detection

friTap automatically detects SSL/TLS libraries using multiple methods:

### Detection Hierarchy

1. **Symbol-based Detection**: Look for known function exports
2. **Pattern-based Detection**: Use byte patterns for stripped libraries
3. **Library Name Matching**: Match against known library names
4. **Heuristic Analysis**: Analyze library behavior patterns

### Detection Process

```bash
# View library detection process
fritap -v target_app

# Debug library detection
fritap -do -v target_app | grep -i "library\|found\|detect"

# List loaded libraries
fritap --list-libraries target_app
```

## Library Categories

### System Libraries

**OpenSSL Family**
- **OpenSSL**: Traditional OpenSSL implementation
- **BoringSSL**: Google's maintained fork with additional features
- **LibreSSL**: OpenBSD's security-focused fork

**Platform-Specific**
- **Schannel**: Windows native SSL/TLS
- **Secure Transport**: macOS/iOS native implementation
- **NSS**: Mozilla's Network Security Services

### Embedded Libraries

**Resource-Constrained Environments**
- **mbedTLS**: ARM's lightweight implementation
- **WolfSSL**: Security-focused embedded library
- **s2n-tls**: AWS's simple, secure implementation

**Specialized Libraries**
- **RustTLS**: Memory-safe Rust implementation
- **Conscrypt**: Android's OpenSSL-based provider

## Platform-Specific Considerations

### Linux

**Standard System Libraries:**
```bash
# OpenSSL (most common)
fritap -k keys.log curl https://example.com

# NSS (Firefox and derivatives)
fritap -k keys.log firefox

# GnuTLS (some applications)
fritap -k keys.log wget https://example.com
```

### Windows

**Windows-Specific Libraries:**
```bash
# System SSL (Schannel)
fritap -k keys.log application.exe

# Bundled OpenSSL
fritap -k keys.log --patterns openssl_win.json application.exe
```

### Android

**Android SSL Ecosystem:**
```bash
# BoringSSL (most modern apps)
fritap -m -k keys.log com.example.app

# OkHttp (HTTP client library)
fritap -m -k keys.log com.okhttp.app
```

### iOS

**iOS SSL Libraries:**
```bash
# Secure Transport (system)
fritap -m -k keys.log com.example.app

# BoringSSL (some apps)
fritap -m --patterns ios_boring.json -k keys.log com.example.app
```

## Library-Specific Features

### OpenSSL/BoringSSL

**Key Extraction:**
- Full key material extraction
- Multiple cipher suite support
- Session resumption tracking

**Traffic Decryption:**
- Complete read/write hook coverage
- Socket information extraction
- Protocol version detection

```bash
# OpenSSL analysis
fritap -k openssl_keys.log curl https://httpbin.org/get

# BoringSSL with patterns
fritap --patterns boringssl.json -k keys.log chrome
```

### NSS (Network Security Services)

**Mozilla's Library:**
- Used by Firefox, Thunderbird
- Certificate store integration
- PKCS#11 support

```bash
# NSS analysis
fritap -k nss_keys.log firefox

# Debug NSS detection
fritap -do -v firefox | grep -i nss
```

### WolfSSL

**Embedded SSL Library:**
- Small footprint
- Extensive cipher support
- Real-time OS support

```bash
# WolfSSL analysis
fritap -k wolfssl_keys.log embedded_app

# Pattern-based for stripped versions
fritap --patterns wolfssl.json -k keys.log target
```

## Pattern-Based Library Support

For stripped or statically linked libraries, friTap supports pattern-based hooking:

### Creating Patterns

```bash
# Use BoringSecretHunter for BoringSSL
python BoringSecretHunter.py --target libssl.so --output patterns.json

# Use patterns with friTap
fritap --patterns patterns.json -k keys.log target
```

### Common Pattern Sources

**Flutter Applications:**
```json
{
  "library": "libflutter.so",
  "patterns": {
    "SSL_Read": {
      "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9"
    }
  }
}
```

**Cronet (Chrome Network Stack):**
```json
{
  "library": "libcronet.so", 
  "patterns": {
    "SSL_Write": {
      "primary": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9"
    }
  }
}
```

## Troubleshooting Library Issues

### Library Not Detected

```bash
# Check loaded modules
fritap --list-libraries target

# Enable debug output
fritap -do -v target | grep -i "library\|module"

# Try pattern matching
fritap --patterns custom.json -k keys.log target
```

### Partial Support

```bash
# Keys only (no traffic)
fritap -k keys.log target

# Traffic only (use with network capture)
fritap --pcap traffic.pcap target
tcpdump -i any -w network.pcap &
```

### Version Compatibility

```bash
# Check library versions
ldd target_app | grep ssl
strings target_app | grep -i "openssl\|version"

# Use version-specific patterns
fritap --patterns openssl_1.1.json -k keys.log target
```

## Best Practices

### 1. Library Identification

```bash
# Always identify library first
fritap -v target | head -20

# Check for multiple libraries
fritap --list-libraries target | wc -l
```

### 2. Appropriate Hook Strategy

```bash
# Symbol-based (preferred)
fritap -k keys.log target

# Pattern-based (when needed)
fritap --patterns patterns.json -k keys.log target

# Offset-based (last resort)
fritap --offsets offsets.json -k keys.log target
```

### 3. Testing Approach

```bash
# Test with known working app first
fritap -k test.log curl https://httpbin.org/get

# Then try target application
fritap -k keys.log target_app
```

### 4. Documentation

- Document which libraries work with which applications
- Keep patterns updated for new library versions
- Share successful configurations with the community

## Library-Specific Information

For detailed information about specific libraries, refer to the support matrix above and use the appropriate commands:

- **OpenSSL/BoringSSL**: Most comprehensive support - use standard friTap commands
- **NSS**: Mozilla's implementation - works well with Firefox and similar applications  
- **GnuTLS**: GNU TLS library - supported with read/write hooks
- **WolfSSL**: Embedded SSL solution - full support on Android, patterns needed elsewhere
- **Other Libraries**: See [Other Libraries](others.md) for additional implementations

## Contributing Library Support

### Adding New Library Support

1. **Analyze the library** structure and function exports
2. **Create detection patterns** using tools like BoringSecretHunter  
3. **Test with sample applications** using the library
4. **Submit pull request** with new library support
5. **Document usage** in library-specific guide

### Pattern Contribution

```bash
# Generate patterns
python BoringSecretHunter.py --target new_library.so --output new_patterns.json

# Test patterns
fritap --patterns new_patterns.json -k test.log target

# Submit via GitHub with documentation
```

## Future Library Support

**Planned Additions:**
- **Botan**: Crypto++ successor
- **LibreSSL**: OpenBSD SSL library
- **Cryptlib**: Peter Gutmann's library
- **MatrixSSL**: Commercial SSL library
- **JSSE**: Java Secure Socket Extension

**Community Requests:**
- Submit library support requests via GitHub issues
- Provide sample applications using the library
- Share analysis of library structure and functions

## Next Steps

- **Choose specific library guide** based on your target application
- **Learn [Pattern-Based Hooking](../advanced/patterns.md)** for unsupported libraries
- **Check [Platform Guides](../platforms/android.md)** for platform-specific library information
- **Review [Troubleshooting](../troubleshooting/common-issues.md)** for common library issues