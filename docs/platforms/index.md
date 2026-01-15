# Platform Guides

friTap supports multiple platforms and operating systems. This section provides detailed platform-specific guides covering setup, configuration, and best practices for each supported platform.

## Supported Platforms

### Desktop Platforms

| Platform | Status | Guide | Key Features |
|----------|--------|-------|--------------|
| **Linux** | ✅ Full Support | [Linux Guide](linux.md) | Native OpenSSL/GnuTLS, BPF capture, containers |
| **macOS** | 🔑 Partial Support | [macOS Guide](macos.md) | BoringSSL keylog extraction, Python OpenSSL |
| **Windows** | ✅ Full Support | [Windows Guide](windows.md) | Schannel (via LSASS), OpenSSL, bundled libraries |
| **Wine** | 🧪 Experimental | [Wine Guide](wine.md) | Windows apps on Linux, hybrid DLL/SO hooking |

### Mobile Platforms

| Platform | Status | Guide | Key Features |
|----------|--------|-------|--------------|
| **Android** | ✅ Full Support | [Android Guide](android.md) | BoringSSL, Conscrypt, Java SSL, root required |
| **iOS** | 🔑 Partial Support | [iOS Guide](ios.md) | BoringSSL keylog, Flutter, jailbreak required |

## Quick Platform Selection

### Choose Your Platform

**For Desktop Applications:**
- **Linux**: Best for server applications, command-line tools, and development environments
- **macOS**: Limited to BoringSSL-based applications (Chrome) and Python OpenSSL
- **Windows**: Perfect for Windows applications - comprehensive Schannel support via LSASS hooking
- **Wine**: Analyze Windows applications running under Wine on Linux (experimental)

**For Mobile Applications:**
- **Android**: Comprehensive Android app analysis with root access
- **iOS**: iOS app analysis requiring jailbroken devices

## Platform Comparison

### Feature Matrix

| Feature | Linux | macOS | Windows | Android | iOS | Wine |
|---------|-------|-------|---------|---------|-----|------|
| **Primary TLS Libraries** | OpenSSL, GnuTLS, NSS | BoringSSL (keylog) | Schannel (via LSASS) | BoringSSL, Conscrypt | BoringSSL (keylog) | Windows DLLs + Linux .so |
| **Full Key + Traffic** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Keylog Only** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Root/Admin Required** | Yes | Yes | Yes | Yes | Yes (Jailbreak) | Yes |
| **Pattern Hooking** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Live Analysis** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Spawn Mode** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Installation Complexity

| Platform | Complexity | Prerequisites | Notes |
|----------|------------|---------------|-------|
| **Linux** | Low | Python, pip | Most straightforward installation |
| **macOS** | Medium | Xcode tools, BPF permissions | SIP considerations |
| **Windows** | Medium | Visual Studio Build Tools | Antivirus considerations |
| **Android** | High | Root, frida-server, ADB | Device-specific setup |
| **iOS** | High | Jailbreak, SSH/USB setup | Limited to jailbroken devices |

## Getting Started by Platform

### Linux Quick Start

```bash
# Install dependencies
sudo apt update && sudo apt install python3 python3-pip

# Install friTap
pip3 install fritap

# Basic usage
sudo fritap -k keys.log --pcap traffic.pcap firefox
```

### macOS Quick Start

```bash
# Install Homebrew and dependencies
brew install python@3.11

# Install friTap
pip3 install fritap

# Configure BPF permissions
sudo chmod 644 /dev/bpf*

# Basic usage
sudo fritap -k keys.log --pcap traffic.pcap Safari
```

### Windows Quick Start

```powershell
# Install Python from python.org or Windows Store

# Install friTap
pip install fritap

# Run as Administrator
fritap -k keys.log --pcap traffic.pcap chrome.exe
```

### Android Quick Start

```bash
# Setup device with root and frida-server
adb devices
adb shell su -c "/data/local/tmp/frida-server &"

# Basic usage
fritap -m -k keys.log --pcap traffic.pcap com.example.app
```

### iOS Quick Start

```bash
# Setup jailbroken device with frida
# Install Frida via Cydia/Sileo

# Basic usage
fritap -m -k keys.log --pcap traffic.pcap com.example.app
```

## Platform-Specific Considerations

### Security Requirements

**Linux:**
- Root access for packet capture
- BPF permissions for full capture
- SELinux/AppArmor considerations

**macOS:**
- Administrator access
- BPF device permissions
- SIP (System Integrity Protection) considerations
- Gatekeeper and notarization

**Windows:**
- Administrator privileges
- UAC (User Account Control)
- Windows Defender/antivirus exclusions
- Windows Firewall configuration

**Android:**
- Root access required
- frida-server installation
- USB debugging enabled
- SELinux permissive mode (some cases)

**iOS:**
- Jailbreak required
- SSH or USB connection
- Frida installation via Cydia/Sileo
- Code signing restrictions

### Common SSL/TLS Libraries

**Linux:**
- OpenSSL (most common) - ✅ Full support
- GnuTLS - ✅ Full support
- NSS (Firefox) - ✅ Full support
- BoringSSL (Chrome) - ✅ Full support
- WolfSSL - ✅ Full support
- Rustls - 🔑 Keylog only
- Go TLS - ✅ Full support

**macOS:**
- BoringSSL (Chrome) - 🔑 Keylog only
- Python OpenSSL - 🔑 Keylog only
- Secure Transport - ❌ Not implemented
- Network.framework - ❌ Not implemented

**Windows:**
- Schannel (native via LSASS) - ✅ Full support
- OpenSSL/BoringSSL - ✅ Full support
- WolfSSL - ✅ Full support
- GnuTLS - ✅ Full support

**Android:**
- BoringSSL (most apps) - ✅ Full support
- Conscrypt - ✅ Full support
- Java SSL libraries - ✅ Full support
- GnuTLS - ✅ Full support
- WolfSSL - ✅ Full support
- Go TLS - ✅ Full support
- Flutter - ✅ Full support

**iOS:**
- BoringSSL - 🔑 Keylog only
- Flutter - 🔑 Keylog only
- Cronet - 🧪 Experimental
- Secure Transport - ❌ Not implemented
- Network.framework - ❌ Not implemented

## Architecture Support

### CPU Architectures

| Platform | x86_64 | ARM64 | x86 (32-bit) | ARM (32-bit) |
|----------|--------|-------|--------------|--------------|
| **Linux** | ✅ | ✅ | ✅ | ✅ |
| **macOS** | ✅ | ✅ (M1/M2) | ❌ | ❌ |
| **Windows** | ✅ | ✅ (ARM64) | ✅ | ❌ |
| **Android** | ✅ | ✅ | ✅ | ✅ |
| **iOS** | ❌ | ✅ | ❌ | ✅ (legacy) |

### Special Considerations

**Apple Silicon (M1/M2):**
- Native ARM64 support
- Rosetta 2 compatibility for x86_64 apps
- Performance optimizations for Apple Silicon

**Windows on ARM:**
- Native ARM64 support
- x86 emulation compatibility
- Performance considerations

**Android Architectures:**
- ARM64 (most modern devices)
- ARM32 (legacy devices)
- x86_64 (emulators, some tablets)
- x86 (legacy emulators)

## Best Practices by Platform

### Development Environment

**Linux:**
```bash
# Virtual environment setup
python3 -m venv fritap_env
source fritap_env/bin/activate
pip install fritap

# System-wide installation
sudo pip3 install fritap
```

**macOS:**
```bash
# Homebrew-managed Python
brew install python@3.11
pip3 install fritap

# pyenv for version management
brew install pyenv
pyenv install 3.11.0
pyenv global 3.11.0
```

**Windows:**
```powershell
# Virtual environment
python -m venv fritap_env
fritap_env\Scripts\activate
pip install fritap

# System-wide installation
pip install fritap
```

### Security Hardening

**All Platforms:**
- Use dedicated analysis systems
- Isolate from production networks
- Regular security updates
- Principle of least privilege

**Mobile Platforms:**
- Use test devices only
- Backup device before analysis
- Understand legal implications
- Document analysis procedures

## Troubleshooting by Platform

### Common Issues

**Permission Errors:**
- **Linux/macOS**: Use `sudo` for network operations
- **Windows**: Run as Administrator
- **Mobile**: Verify root/jailbreak status

**Library Detection Issues:**
- Check application architecture (32-bit vs 64-bit)
- Verify SSL library versions
- Use debug mode (`-do -v`) for diagnostics
- Consider pattern-based hooking

**Network Capture Problems:**
- Verify packet capture permissions
- Check firewall/antivirus settings
- Ensure proper network interface access
- Use full capture mode if needed

## Performance Considerations

### Resource Usage

| Platform | CPU Impact | Memory Usage | Disk I/O | Network Impact |
|----------|------------|--------------|----------|----------------|
| **Linux** | Low-Medium | Low | Medium | Low |
| **macOS** | Low-Medium | Low-Medium | Medium | Low |
| **Windows** | Medium | Medium | Medium-High | Low |
| **Android** | Medium-High | Medium | High | Medium |
| **iOS** | Medium-High | Medium | High | Medium |

### Optimization Tips

**All Platforms:**
- Use targeted analysis instead of system-wide
- Limit analysis duration
- Use appropriate output formats
- Monitor system resources

**Mobile Platforms:**
- Use spawn mode for initialization analysis
- Minimize background apps during analysis
- Monitor device temperature
- Use USB connection for stability

## Next Steps

Choose your platform and dive into the detailed guides:

1. **[Linux Platform Guide](linux.md)** - Comprehensive Linux analysis (full support)
2. **[macOS Platform Guide](macos.md)** - macOS analysis (keylog extraction only)
3. **[Windows Platform Guide](windows.md)** - Windows analysis with Schannel/LSASS support
4. **[Android Platform Guide](android.md)** - Mobile Android app analysis (full support)
5. **[iOS Platform Guide](ios.md)** - iOS app analysis (keylog extraction only)
6. **[Wine Platform Guide](wine.md)** - Windows apps on Linux (experimental)

For advanced features and cross-platform topics:
- **[Pattern-based Hooking](../advanced/patterns.md)** - Custom library detection
- **[Standalone Agent Usage](../advanced/standalone-agent.md)** - Using _ssl_log.js directly
- **[Common Issues](../troubleshooting/common-issues.md)** - Platform-agnostic troubleshooting
- **[Examples](../examples/index.md)** - Real-world analysis scenarios