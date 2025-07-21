# Linux Platform Guide

This guide covers Linux-specific setup, considerations, and best practices for using friTap on Linux systems.

## Prerequisites

### System Requirements

- **Linux distribution** (Ubuntu 18.04+, CentOS 7+, Fedora 30+, etc.)
- **Root access** (required for most analysis)
- **Python 3.8+** installed
- **x86_64 or ARM64 architecture**

### Package Installation

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-dev
sudo apt install build-essential libssl-dev libffi-dev

# CentOS/RHEL/Fedora
sudo yum install python3 python3-pip python3-devel
sudo yum install gcc openssl-devel libffi-devel

# Arch Linux
sudo pacman -S python python-pip base-devel openssl libffi

# Install friTap
pip3 install fritap
```

## System Setup

### Frida Installation

```bash
# Install frida-tools
pip3 install frida-tools

# Verify installation
frida --version

# Test local device
frida-ps
```

### Permission Configuration

```bash
# Add user to required groups (optional)
sudo usermod -a -G dialout $USER

# For some distributions, add to additional groups
sudo usermod -a -G plugdev $USER

# Logout and login again for group changes to take effect
```

### BPF Permissions (for full capture)

```bash
# Check current BPF settings
sysctl net.core.bpf_jit_enable

# Enable BPF JIT (if needed)
sudo sysctl net.core.bpf_jit_enable=1

# Make permanent
echo 'net.core.bpf_jit_enable=1' | sudo tee -a /etc/sysctl.conf
```

## friTap Usage on Linux

### Desktop Applications

```bash
# Extract TLS keys from Firefox
sudo fritap -k firefox_keys.log firefox

# Analyze Chrome/Chromium
sudo fritap -k chrome_keys.log google-chrome

# Comprehensive analysis with all outputs
sudo fritap -k keys.log --pcap traffic.pcap --json metadata.json firefox
```

### Command-Line Tools

```bash
# Analyze curl requests
sudo fritap -k curl_keys.log --pcap curl_traffic.pcap curl https://httpbin.org/get

# Monitor wget downloads
sudo fritap -k wget_keys.log wget https://example.com/file.zip

# Python applications
sudo fritap -k python_keys.log python3 my_script.py
```

### Server Applications

```bash
# Web servers
sudo fritap -k nginx_keys.log nginx

# Application servers
sudo fritap -k apache_keys.log apache2

# Database connections
sudo fritap -k mysql_keys.log mysql
```

### Process Targeting

```bash
# By process name
sudo fritap -k keys.log firefox

# By process ID
sudo fritap -k keys.log --pid 1234

# By executable path
sudo -E fritap -k keys.log /usr/bin/curl https://example.com

# List running processes
frida-ps
```

## SSL/TLS Libraries on Linux

### Common Linux SSL Libraries

**OpenSSL:**
```bash
# Most common SSL library on Linux
sudo fritap -k openssl_keys.log firefox

# Debug OpenSSL detection
sudo fritap -do -v firefox | grep -i openssl
```

**GnuTLS:**
```bash
# Used by some applications
sudo fritap -k gnutls_keys.log application_using_gnutls

# Check for GnuTLS usage
ldd /usr/bin/application | grep gnutls
```

**BoringSSL/LibreSSL:**
```bash
# Used by Chrome and some modern applications
sudo fritap -k boringssl_keys.log google-chrome

# Check SSL library version
openssl version
```

**NSS (Network Security Services):**
```bash
# Used by Firefox and Mozilla applications
sudo fritap -k nss_keys.log firefox

# Check NSS usage
ldd /usr/bin/firefox | grep nss
```

### Library Detection

```bash
# Debug library detection
sudo fritap -do -v application_name

# Check which SSL libraries an application uses
ldd /path/to/application | grep -E "(ssl|tls|crypto)"

# System-wide SSL library information
ldconfig -p | grep -E "(ssl|tls|crypto)"
```

## Linux-Specific Features

### Full Packet Capture

```bash
# Capture all network traffic (requires root)
sudo fritap --full_capture -k keys.log --pcap full_traffic.pcap firefox

# Monitor specific interface
sudo tcpdump -i eth0 -w network.pcap &
sudo fritap -k keys.log firefox
```

### Process Monitoring

```bash
# Monitor subprocess spawning
sudo fritap --enable_spawn_gating -k keys.log --pcap traffic.pcap parent_process

# Analyze process tree
pstree -p $(pgrep firefox)
sudo fritap -k keys.log firefox
```

### Container Analysis

```bash
# Docker container analysis
docker run -it --name test-container ubuntu:20.04
docker exec -it test-container bash

# Install friTap in container
pip3 install fritap

# Analyze applications in container
fritap -k container_keys.log application
```

### Systemd Service Analysis

```bash
# Analyze systemd services
sudo fritap -k service_keys.log systemctl status service_name

# Monitor service SSL communications
sudo systemctl start service_name &
sudo fritap -k service_keys.log service_name
```

## Application Categories

### Web Browsers

```bash
# Firefox
sudo fritap -k firefox_keys.log --pcap firefox_traffic.pcap firefox

# Chrome/Chromium
sudo fritap -k chrome_keys.log google-chrome

# Edge
sudo fritap -k edge_keys.log microsoft-edge

# Opera
sudo fritap -k opera_keys.log opera
```

### Development Tools

```bash
# Node.js applications
sudo fritap -k node_keys.log node app.js

# Python HTTPS requests
sudo fritap -k python_keys.log python3 -c "import requests; requests.get('https://httpbin.org/get')"

# Go applications
sudo fritap -k go_keys.log ./my_go_app

# Java applications
sudo fritap -k java_keys.log java -jar app.jar
```

### System Applications

```bash
# Package managers
sudo fritap -k apt_keys.log apt update

# System update tools
sudo fritap -k dnf_keys.log dnf update

# Network tools
sudo fritap -k ssh_keys.log ssh user@remote.host
```

### Communication Tools

```bash
# Email clients
sudo fritap -k thunderbird_keys.log thunderbird

# Chat applications
sudo fritap -k discord_keys.log discord
sudo fritap -k slack_keys.log slack

# VoIP applications
sudo fritap -k skype_keys.log skypeforlinux
```

## Advanced Linux Analysis

### Kernel-Level Analysis

```bash
# Monitor system calls
sudo strace -f -e trace=network -p $(pgrep firefox) &
sudo fritap -k firefox_keys.log firefox

# Monitor file descriptor usage
sudo lsof -p $(pgrep firefox) | grep -E "(TCP|UDP)"
```

### Network Namespace Analysis

```bash
# Create network namespace
sudo ip netns add test-ns

# Run application in namespace
sudo ip netns exec test-ns fritap -k ns_keys.log application

# Monitor namespace traffic
sudo ip netns exec test-ns tcpdump -i any -w ns_traffic.pcap
```

### eBPF Integration

```bash
# Advanced network monitoring with eBPF
# Install BCC tools
sudo apt install bpfcc-tools

# Monitor SSL connections
sudo opensnoop-bpfcc &
sudo fritap -k ssl_keys.log application
```

### Performance Analysis

```bash
# Monitor CPU usage during analysis
top -p $(pgrep fritap) &
sudo fritap -k keys.log application

# Memory usage monitoring
sudo smem -P fritap

# I/O monitoring
sudo iotop -p $(pgrep fritap)
```

## Security Considerations

### SELinux/AppArmor

```bash
# Check SELinux status
sestatus

# Temporarily disable SELinux (if needed)
sudo setenforce 0

# AppArmor profile management
sudo aa-status
sudo aa-disable /path/to/profile
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw status
sudo ufw allow from 127.0.0.1

# iptables
sudo iptables -L
sudo iptables -A INPUT -i lo -j ACCEPT

# firewalld (CentOS/Fedora)
sudo firewall-cmd --state
sudo firewall-cmd --add-interface=lo --zone=trusted
```

### Capabilities and Permissions

```bash
# Check required capabilities
getcap /usr/bin/fritap

# Run with minimal privileges
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/fritap

# Use sudo for network access only
sudo fritap -k keys.log application
```

## Troubleshooting Linux Issues

### Permission Denied Errors

```bash
# Run with sudo
sudo fritap -k keys.log application

# Check file permissions
ls -la /tmp/fritap*

# Fix permissions
sudo chown $USER:$USER output_files
```

### Library Loading Issues

```bash
# Check library paths
echo $LD_LIBRARY_PATH

# Update library cache
sudo ldconfig

# Debug library loading
LD_DEBUG=libs fritap -k keys.log application 2>&1 | grep -i ssl
```

### Network Interface Issues

```bash
# List network interfaces
ip link show

# Check interface permissions
ls -la /dev/net/tun

# Verify packet capture permissions
sudo tcpdump -i any -c 1
```

### Process Attachment Issues

```bash
# Check ptrace permissions
cat /proc/sys/kernel/yama/ptrace_scope

# Temporarily allow ptrace (if needed)
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Check process status
ps aux | grep target_process
```

## Distribution-Specific Notes

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt install python3-dev libssl-dev

# AppArmor considerations
sudo aa-disable /usr/bin/fritap

# Snap package considerations
fritap --help  # If installed via snap
```

### CentOS/RHEL/Fedora

```bash
# SELinux considerations
sudo setsebool -P domain_can_mmap_files 1

# Firewalld configuration
sudo firewall-cmd --add-port=27042/tcp --permanent

# Package installation
sudo dnf install python3-devel openssl-devel
```

### Arch Linux

```bash
# AUR installation
yay -S fritap

# Systemd service analysis
sudo systemctl --user enable fritap.service

# Custom kernel considerations
uname -r
```

### Alpine Linux

```bash
# Musl libc considerations
apk add python3-dev libffi-dev

# Lightweight container analysis
fritap -k keys.log --json metadata.json application
```

## Integration Examples

### CI/CD Pipelines

```bash
#!/bin/bash
# Jenkins/GitLab CI integration
set -e

# Install friTap
pip3 install fritap

# Run security analysis
sudo fritap -k app_keys.log --pcap app_traffic.pcap --json security_report.json ./test_app

# Process results
python3 analyze_security_report.py security_report.json
```

### Automated Testing

```bash
#!/bin/bash
# Automated SSL/TLS testing script

APPS=("firefox" "chrome" "curl")

for app in "${APPS[@]}"; do
    echo "Testing $app..."
    sudo fritap -k "${app}_keys.log" --json "${app}_report.json" "$app" --version
    
    # Validate output
    if [ -f "${app}_keys.log" ]; then
        echo "$app: TLS keys captured successfully"
    else
        echo "$app: Failed to capture TLS keys"
    fi
done
```

### Log Aggregation

```bash
# ELK Stack integration
sudo fritap --json elasticsearch_data.json application

# Send to Elasticsearch
curl -X POST "localhost:9200/fritap-logs/_doc" \
     -H "Content-Type: application/json" \
     -d @elasticsearch_data.json

# Splunk integration
sudo fritap --json splunk_data.json application
/opt/splunk/bin/splunk add oneshot splunk_data.json
```

## Best Practices for Linux

### 1. System Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Install development tools
sudo apt install build-essential

# Configure system limits
ulimit -c unlimited
```

### 2. Analysis Environment

```bash
# Create dedicated analysis directory
mkdir ~/fritap_analysis
cd ~/fritap_analysis

# Set up virtual environment
python3 -m venv fritap_env
source fritap_env/bin/activate
pip install fritap
```

### 3. Data Management

```bash
# Organize output files
mkdir -p analysis_$(date +%Y%m%d)/{keys,pcaps,json,logs}

# Run with organized output
sudo fritap -k analysis_$(date +%Y%m%d)/keys/app_keys.log \
            --pcap analysis_$(date +%Y%m%d)/pcaps/app_traffic.pcap \
            --json analysis_$(date +%Y%m%d)/json/app_metadata.json \
            application 2>&1 | tee analysis_$(date +%Y%m%d)/logs/analysis.log
```

### 4. Security Measures

```bash
# Use minimal privileges
sudo fritap --no-root-check -k keys.log application

# Sandbox analysis
firejail --net=none fritap -k keys.log application

# Clean up after analysis
sudo rm -f /tmp/fritap_*
```

## Next Steps

- **Windows Analysis**: See [Windows Platform Guide](windows.md)
- **macOS Analysis**: Check [macOS Platform Guide](macos.md)
- **Mobile Analysis**: Review [Android](android.md) and [iOS](ios.md) guides
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Check [Common Issues](../troubleshooting/common-issues.md)