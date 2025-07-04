# Installation

This guide will help you install and set up friTap for SSL/TLS traffic analysis.

## System Requirements

### Minimum Requirements

- **Python**: 3.7 or higher
- **Frida**: 16.0 or higher
- **Operating System**: Linux, Windows, macOS
- **Memory**: 512 MB RAM (minimum)
- **Storage**: 50 MB free disk space

### Recommended Requirements

- **Python**: 3.10 or higher
- **Frida**: 17.0 or higher
- **Memory**: 2 GB RAM or more
- **Storage**: 1 GB free disk space

## Installation Methods

### Method 1: PyPI Installation (Recommended)

The easiest way to install friTap is through PyPI:

```bash
pip install fritap
```

For the latest version:

```bash
pip install --upgrade fritap
```

### Method 2: Development Installation

If you want to modify friTap or contribute to its development:

```bash
# Clone the repository
git clone https://github.com/fkie-cad/friTap.git
cd friTap

# Install in development mode
pip install -e .

# Install with development dependencies
pip install -e .[dev]
```

### Method 3: Docker Installation

For isolated environments or specific use cases:

```bash
# Pull the Docker image
docker pull fkiecad/fritap

# Run friTap in Docker
docker run -it --rm fkiecad/fritap fritap --help
```

## Platform-Specific Setup

### Linux

1. **Install dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3-pip python3-dev build-essential

   # CentOS/RHEL/Fedora
   sudo yum install python3-pip python3-devel gcc
   ```

2. **Install friTap**:
   ```bash
   pip3 install fritap
   ```

3. **Set up permissions** (for desktop applications):
   ```bash
   # Add your user to the root group or use sudo
   sudo usermod -a -G root $USER
   ```

### Windows

1. **Install Python** from [python.org](https://python.org)
2. **Install Visual Studio Build Tools** (if needed)
3. **Install friTap**:
   ```cmd
   pip install fritap
   ```

4. **Run as Administrator** for desktop applications

### macOS

1. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install Python**:
   ```bash
   brew install python3
   ```

3. **Install friTap**:
   ```bash
   pip3 install fritap
   ```

4. **Disable SIP** (if analyzing system applications):
   ```bash
   # Boot into Recovery Mode and run:
   csrutil disable
   ```

## Mobile Platform Setup

### Android

1. **Enable Developer Options** on your Android device
2. **Enable USB Debugging**
3. **Install ADB** on your computer:
   ```bash
   # Linux/macOS
   sudo apt install android-tools-adb  # Ubuntu/Debian
   brew install android-platform-tools # macOS
   
   # Windows
   # Download from https://developer.android.com/studio/releases/platform-tools
   ```

4. **Install frida-server on Android**:
   ```bash
   # Download frida-server for your Android architecture
   # Extract and push to device
   adb push frida-server /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/frida-server
   
   # Run frida-server (requires root)
   adb shell su -c "/data/local/tmp/frida-server &"
   ```

### iOS

1. **Jailbreak your iOS device** (required for friTap)
2. **Install OpenSSH** and **Frida** from Cydia:
   ```bash
   # Add frida repository in Cydia
   # https://build.frida.re/
   ```

3. **Install frida-server**:
   ```bash
   # SSH into your device
   ssh root@your-device-ip
   
   # Install frida-server
   cydia://package/re.frida.server
   ```

## Verification

After installation, verify that friTap is working correctly:

```bash
# Check version
fritap --version

# Check help
fritap --help

# Test basic functionality
fritap --list-devices
```

### Expected Output

```
friTap 1.3.4.2
Usage: fritap [OPTIONS] TARGET

Options:
  -m, --mobile                    Mobile application analysis
  -k, --keylog PATH               Save TLS keys to file
  -p, --pcap PATH                 Save decrypted traffic to PCAP
  --help                          Show this message and exit
```

## Common Installation Issues

### Issue: Permission Denied

**Problem**: `Permission denied` when running friTap

**Solution**:
```bash
# Linux/macOS
sudo fritap [options] target

# Windows
# Run Command Prompt as Administrator
```

### Issue: Frida Not Found

**Problem**: `frida: command not found`

**Solution**:
```bash
# Install frida-tools
pip install frida-tools

# Verify installation
frida --version
```

### Issue: Python Version Compatibility

**Problem**: `friTap requires Python 3.7+`

**Solution**:
```bash
# Check Python version
python3 --version

# Install newer Python version
# Follow platform-specific Python installation guides
```

### Issue: ADB Not Found (Android)

**Problem**: `adb: command not found`

**Solution**:
```bash
# Linux
sudo apt install android-tools-adb

# macOS
brew install android-platform-tools

# Windows
# Download Android SDK Platform Tools
# Add to system PATH
```

## Next Steps

Once friTap is installed, you can:

1. **Read the [Quick Start Guide](quick-start.md)** for basic usage
2. **Explore [Usage Examples](../examples/index.md)** for specific scenarios
3. **Check [Platform Guides](../platforms/android.md)** for detailed setup instructions
4. **Review [Troubleshooting](../troubleshooting/common-issues.md)** if you encounter issues

## Dependencies

friTap automatically installs the following dependencies:

- **frida** (>= 16.0.0): Core instrumentation framework
- **frida-tools** (>= 11.0.0): Frida command-line tools
- **scapy**: Network packet manipulation
- **AndroidFridaManager**: Android device management
- **rich** (>= 13.0.0): Terminal output formatting
- **click**: Command-line interface
- **hexdump**: Binary data display
- **watchdog**: File system monitoring
- **psutil**: System and process utilities

## Optional Dependencies

For enhanced functionality:

```bash
# Wireshark for live analysis
sudo apt install wireshark

# tcpdump for packet capture
sudo apt install tcpdump

# Development tools
pip install pytest ruff mypy
```