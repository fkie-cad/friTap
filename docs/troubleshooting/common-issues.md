# Common Issues

This guide covers the most frequently encountered issues when using friTap and provides step-by-step solutions.

## Installation Issues

### friTap Installation Fails

**Issue**: `pip install fritap` fails with dependency errors.

**Solutions**:

```bash
# Update pip and setuptools
python -m pip install --upgrade pip setuptools

# Install with verbose output to see error details
pip install -v fritap

# Try installing dependencies separately
pip install frida frida-tools
pip install fritap
```

**Common Dependency Issues**:
```bash
# macOS: Install Xcode Command Line Tools
xcode-select --install

# Linux: Install development packages
sudo apt update && sudo apt install python3-dev build-essential

# Windows: Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
```

### Frida Version Conflicts

**Issue**: `frida version mismatch` errors.

**Solutions**:
```bash
# Check frida versions
pip list | grep frida
frida --version

# Reinstall frida with specific version
pip uninstall frida frida-tools
pip install frida==17.0.0 frida-tools==12.0.0

# Verify friTap compatibility
fritap --version
```

## Permission Issues

### Permission Denied (Desktop)

**Issue**: `Permission denied` when analyzing desktop applications.

**Solutions**:

=== "Linux"
    ```bash
    # Use sudo
    sudo fritap -k keys.log firefox
    
    # Add user to appropriate groups
    sudo usermod -a -G root $USER
    newgrp root
    
    # Check process ownership
    ps aux | grep firefox
    sudo fritap --pid $(pgrep firefox) -k keys.log
    ```

=== "macOS"
    ```bash
    # Use sudo
    sudo fritap -k keys.log Safari
    
    # Disable SIP (if necessary)
    # Boot into Recovery Mode (Cmd+R) and run:
    # csrutil disable
    
    # Grant Terminal full disk access
    # System Preferences → Security & Privacy → Full Disk Access
    ```

=== "Windows"
    ```cmd
    REM Run as Administrator
    fritap -k keys.log chrome.exe
    
    REM Check process privileges
    whoami /priv
    ```

### Mobile Device Access Issues

**Issue**: Cannot connect to Android/iOS device.

**Solutions**:

**Android**:
```bash
# Check device connection
adb devices

# Enable USB debugging
# Settings → Developer Options → USB Debugging

# Verify root access
adb shell su -c "id"

# Check frida-server
adb shell ps | grep frida-server

# Restart frida-server
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

**iOS**:
```bash
# Check SSH connection
ssh root@device-ip

# Verify frida installation
ssh root@device-ip "frida-ps"

# Restart frida-server
ssh root@device-ip "killall frida-server; frida-server &"
```

## Library Detection Issues

### No SSL Library Found

**Issue**: `No SSL library found` or `No hooks installed`.

**Diagnostic Steps**:
```bash
# Enable debug output
fritap -do -v target_app

# List loaded libraries
fritap --list-libraries target_app

# Check for SSL-related libraries
fritap --list-libraries target_app | grep -i ssl

# Enable verbose library detection
fritap -v target_app | grep -i "library\|found\|hook"
```

**Solutions**:

**Use Pattern-Based Hooking**:

By default, friTap uses Frida’s pattern‑based hooking to locate key functions like SSL_new, handling cases when symbols are stripped or missing. However, library updates may break these patterns—especially with stripped binaries. In those situations, you can provide your own byte-pattern definitions to restore functionality.

```bash
# For stripped libraries
fritap --patterns patterns.json -k keys.log target_app

# Generate patterns with BoringSecretHunter
python boring_secret_hunter.py --target libssl.so --output patterns.json
fritap --patterns patterns.json -k keys.log target_app
```

### Library Detected but No Hooks

**Issue**: Library detected but no function hooks installed.

**Solutions**:
```bash
# Check symbol availability
fritap -do -v target_app | grep -i symbol

# Use offset-based hooking
fritap --offsets offsets.json -k keys.log target_app

# Try manual function resolution
fritap -c custom_hooks.js -k keys.log target_app
```

## Traffic Capture Issues

### No Traffic Captured

**Issue**: friTap runs successfully but no traffic is captured.

**Common Causes and Solutions**:

**Socket Information Issues**:
```bash
# Use default socket information
fritap --enable_default_fd --pcap traffic.pcap target_app

# Enable full capture mode
fritap --full_capture -k keys.log target_app
```

**Child Process Issues**:
```bash
# Enable spawn gating for subprocesses
fritap --enable_spawn_gating --pcap traffic.pcap target_app

# Target specific child process
fritap --pid $(pgrep -f "child_process") -k keys.log
```

## Mobile-Specific Issues

### Android Analysis Problems

**frida-server Not Found**:
```bash
# Check frida-server location
adb shell find /data/local/tmp -name "*frida*"

# Download and install frida-server
# 1. Check device architecture
adb shell getprop ro.product.cpu.abi

# 2. Download matching frida-server from GitHub releases
# 3. Install frida-server
adb push frida-server-17.0.0-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"
```

**App Crashes on Hook**:
```bash
# Enable anti-root detection bypass
fritap -m --enable-anti-root -k keys.log com.example.app

# Run with debug output and try to figure out why it is 
fritap -m -v -do -k keys.log com.example.app
```

**Package Not Found**:
```bash
# List installed packages
frida-ps -Uai

# Check package name
adb shell pm list packages | grep example

# Use exact package name
fritap -m -k keys.log com.example.app.debug
```

### iOS Analysis Problems

**Jailbreak Detection**:

friTap doesn’t include built-in jailbreak-evasion mechanisms—but it allows you to inject your own custom hooks to bypass or disable jailbreak checks in target applications.

Simply write your custom hooking logic (e.g., intercepting calls like isJailbroken() or checking file paths under /private/var/) and pass it to friTap using the
-c
flag:

```bash
fritap \
  -c my_jailbreak_evasion.js \
  --patterns patterns.json \
  -k keys.log \
  target_app

```

!!! note "Why No `--anti_jailbreak` Flag?"
    Unlike the `--anti_root` flag for Android, friTap does not provide a generic jailbreak bypass. Jailbreak detection techniques on iOS are highly varied, often specific to the app and iOS version, making a universal bypass impractical. Instead, friTap provides the flexibility to use custom scripts (`-c`) tailored to the target application.

Your script might patch out jailbreak-check functions like so:
```javascript
// my_jailbreak_evasion.js
Interceptor.attach(Module.getExportByName(null, "isJailbroken"), {
  onEnter(args) {
    console.log("[*] Bypassing isJailbroken() → always returning false");
    this.replaceReturnValue = ptr("0");
  },
  onLeave(retval) {
    if (this.replaceReturnValue !== undefined) {
      retval.replace(this.replaceReturnValue);
    }
  }
});

```


**Code Signing Issues**:
```bash
# Use ldid to re-sign if needed
ldid -S frida-server
```

## Application-Specific Issues

### Browser Issues

**Chrome/Chromium Sandboxing**:
```bash
# Disable sandbox for analysis
google-chrome --no-sandbox --disable-web-security --user-data-dir=/tmp/chrome_test
fritap -k chrome_keys.log google-chrome
```

**Firefox Profile Issues**:
```bash
# Use temporary profile
firefox -profile /tmp/firefox_temp
fritap -k firefox_keys.log firefox
```

### Electron Apps

**Electron Detection Issues**:
```bash
# Target electron process directly
fritap --pid $(pgrep electron) -k keys.log

# Hook main process and renderers
fritap --enable_spawn_gating -k keys.log electron_app
```

### Flutter Applications

**No BoringSSL Detection**:
```bash
# Use Flutter-specific patterns
fritap --patterns flutter_patterns.json -k keys.log com.flutter.app

# build your BoringSecretHunter docker container
git clone https://github.com/monkeywave/BoringSecretHunter.git
cd BoringSecretHunter
docker build -t boringsecrethunter .
# Generate patterns with BoringSecretHunter
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter


Analyzing libflutter.so...
...
Byte pattern for frida (friTap): 3F 23 03 D5 FF C3 01 D1 FD ...

# use pattern
fritap --patterns flutter.json -k keys.log com.flutter.app
```

## Debugging Strategies

### Systematic Debugging Approach

**Step 1: Basic Functionality Test**:
```bash
# Test with known working application
fritap -k test_keys.log curl https://httpbin.org/get

# Verify friTap installation
fritap --version
fritap --help
```

**Step 2: Library Detection**:
```bash
# Check library detection
fritap -v target_app | grep -i "found\|library\|hook"

# List all libraries
fritap --list-libraries target_app
```

**Step 3: Hook Installation**:
```bash
# Enable debug mode
fritap -do -v target_app 2>&1 | tee debug.log

# Check for hook errors
grep -i "error\|fail\|exception" debug.log
```

**Step 4: Traffic Generation**:
```bash
# Verify network activity
netstat -an | grep :443
ss -tulpn | grep :443

# Test with minimal application
fritap -k keys.log wget https://example.com
```

### Debug Information Collection

**System Information**:
```bash
# Collect system info
uname -a > debug_info.txt
cat /etc/os-release >> debug_info.txt
python --version >> debug_info.txt
fritap --version >> debug_info.txt
```

**Process Information**:
```bash
# Target process details
ps aux | grep target_app >> debug_info.txt
lsof -p $(pgrep target_app) >> debug_info.txt
```

**Network Information**:
```bash
# Network connections
netstat -an >> debug_info.txt
ss -tulpn >> debug_info.txt
```

## Getting Help

### Information to Provide

When seeking help, include:

1. **System Information**:
   - Operating system and version
   - Python version
   - friTap version
   - Frida version

2. **Command Used**:
   ```bash
   fritap -do -v -k keys.log target_app 2>&1 | tee debug.log
   ```

3. **Target Application**:
   - Application name and version
   - SSL library used (if known)
   - Platform (desktop/mobile)

4. **Error Output**:
   - Complete error messages
   - Debug log file
   - Stack traces (if any)

### Diagnostic Commands

**Complete Diagnostic**:
```bash
#!/bin/bash
# Generate comprehensive diagnostic report

echo "=== friTap Diagnostic Report ===" > diagnostic.txt
echo "Date: $(date)" >> diagnostic.txt
echo "User: $(whoami)" >> diagnostic.txt

echo -e "\n=== System Information ===" >> diagnostic.txt
uname -a >> diagnostic.txt
cat /etc/os-release >> diagnostic.txt 2>/dev/null || sw_vers >> diagnostic.txt 2>/dev/null

echo -e "\n=== Python Environment ===" >> diagnostic.txt
python --version >> diagnostic.txt
pip list | grep -E "(fritap|frida)" >> diagnostic.txt

echo -e "\n=== Target Process ===" >> diagnostic.txt
TARGET="$1"
ps aux | grep "$TARGET" >> diagnostic.txt

echo -e "\n=== friTap Test ===" >> diagnostic.txt
fritap --version >> diagnostic.txt
frida-ls-devices >> diagnostic.txt 2>&1

echo -e "\n=== Network Status ===" >> diagnostic.txt
netstat -an | head -20 >> diagnostic.txt

echo "Diagnostic report saved to diagnostic.txt"
```

### Community Resources

- **GitHub Issues**: [https://github.com/fkie-cad/friTap/issues](https://github.com/fkie-cad/friTap/issues)
- **Discussions**: [https://github.com/fkie-cad/friTap/discussions](https://github.com/fkie-cad/friTap/discussions)
- **Email**: daniel.baier@fkie.fraunhofer.de

### Before Opening Issues

1. **Search existing issues** for similar problems
2. **Try troubleshooting steps** from this guide
3. **Collect diagnostic information** using commands above
4. **Provide minimal reproduction case** if possible
5. **Include all requested information** in issue template

## Next Steps

- **Advanced Debugging**: Use `-do -v` flags for detailed debugging output
- **Performance Tuning**: Use appropriate output formats and minimize unnecessary options
- **Platform Issues**: Review platform-specific guides
- **Feature Requests**: Visit [GitHub Discussions](https://github.com/fkie-cad/friTap/discussions)