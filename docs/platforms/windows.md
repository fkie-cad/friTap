# Windows Platform Guide

This guide covers Windows-specific setup, considerations, and best practices for using friTap on Windows systems.

## Prerequisites

### System Requirements

- **Windows 10 or Windows 11** (64-bit recommended)
- **Administrator privileges** (required for most analysis)
- **Python 3.8+** installed
- **Visual Studio Build Tools** (for some dependencies)
- **Windows Subsystem for Linux (WSL)** (optional but recommended)

### Development Environment Setup

```powershell
# Install Python (if not already installed)
# Download from https://python.org or use Windows Store

# Install Python package manager
python -m pip install --upgrade pip

# Install Visual Studio Build Tools (required for some dependencies)
# Download from https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Install friTap
pip install fritap
```

### Alternative: WSL Setup

```bash
# Install WSL2 (recommended for Linux-like environment)
wsl --install -d Ubuntu

# In WSL2 terminal:
sudo apt update
sudo apt install python3 python3-pip
pip3 install fritap
```

## System Setup

### Windows Defender and Antivirus

```powershell
# Temporarily disable Windows Defender (if needed)
# Run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true

# Add exclusions for friTap directory
Add-MpPreference -ExclusionPath "C:\path\to\fritap"

# Re-enable after analysis
Set-MpPreference -DisableRealtimeMonitoring $false
```

### User Account Control (UAC)

```powershell
# Check UAC status
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA

# friTap requires administrator privileges
# Always run PowerShell/Command Prompt as Administrator
```

### WinPcap/Npcap Installation

```powershell
# Download and install Npcap (recommended over WinPcap)
# https://nmap.org/npcap/

# Verify installation
Get-Service | Where-Object {$_.Name -like "*npcap*"}

# Check network adapters
Get-NetAdapter
```

### Frida Installation

```powershell
# Install frida-tools
pip install frida-tools

# Verify installation
frida --version

# Test local device
frida-ps
```

## friTap Usage on Windows

### Native Windows Applications

```powershell
# Analyze Internet Explorer/Edge
fritap -k edge_keys.log msedge.exe

# Analyze Chrome
fritap -k chrome_keys.log "C:\Program Files\Google\Chrome\Application\chrome.exe"

# Analyze Firefox
fritap -k firefox_keys.log firefox.exe

# Use process name (if in PATH)
fritap -k app_keys.log application.exe
```

### Windows Store Applications

```powershell
# List Windows Store app packages
Get-AppxPackage | Select Name, PackageFullName

# Analyze Windows Store apps (requires special handling)
fritap -k store_app_keys.log -p <PackageFullName>

# Example: Microsoft Edge (Store version)
fritap -k edge_store_keys.log Microsoft.MicrosoftEdge_44.19041.1266.0_neutral__8wekyb3d8bbwe
```

### System Applications

```powershell
# Analyze Windows system applications
fritap -k system_keys.log --json system_metadata.json svchost.exe

# Analyze Windows Update
fritap -k update_keys.log wuauclt.exe

# Analyze Windows Security
fritap -k security_keys.log SecurityHealthSystray.exe
```

### Command-Line Applications

```powershell
# Analyze PowerShell
fritap -k powershell_keys.log powershell.exe

# Analyze curl (Windows 10+)
fritap -k curl_keys.log curl.exe https://httpbin.org/get

# Python applications
fritap -k python_keys.log python.exe my_script.py
```

## Windows-Specific Features

### Windows API SSL Libraries

**Schannel (Windows native SSL/TLS):**
```powershell
# Most Windows applications use Schannel
fritap -k schannel_keys.log application.exe

# Debug Schannel detection
fritap -do -v application.exe | Select-String "schannel"
```

**CryptoAPI Integration:**
```powershell
# Applications using Windows CryptoAPI
fritap -k cryptoapi_keys.log --json crypto_metadata.json application.exe

# Check for CryptoAPI usage in metadata
Get-Content crypto_metadata.json | ConvertFrom-Json | Select-Object -ExpandProperty libraries_detected
```

### .NET Framework Applications

```powershell
# Analyze .NET applications
fritap -k dotnet_keys.log application.exe

# .NET applications often use System.Net.Security
fritap -do -v dotnet_application.exe | Select-String "System.Net"

# Check .NET version
Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\" -Name Release
```

### Universal Windows Platform (UWP) Apps

```powershell
# List UWP applications
Get-AppxPackage | Where-Object {$_.IsFramework -eq $false}

# Analyze UWP application
fritap -k uwp_keys.log --json uwp_metadata.json <PackageFamilyName>

# Example: Calculator app
fritap -k calc_keys.log Microsoft.WindowsCalculator_8wekyb3d8bbwe
```

## SSL/TLS Libraries on Windows

### Common Windows SSL Libraries

**Schannel:**
```powershell
# Native Windows SSL/TLS provider
fritap -k schannel_keys.log application.exe

# Check Schannel configuration
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
```

**OpenSSL (third-party applications):**
```powershell
# Applications that bundle OpenSSL
fritap -k openssl_keys.log application.exe

# Check for OpenSSL DLLs
Get-ChildItem -Path "C:\Program Files" -Recurse -Name "*ssl*.dll" -ErrorAction SilentlyContinue
```

**BoringSSL (Chrome and others):**
```powershell
# Chrome uses BoringSSL
fritap -k boringssl_keys.log chrome.exe

# Debug BoringSSL detection
fritap -do -v chrome.exe | Select-String "boring"
```

**Custom SSL Libraries:**
```powershell
# Check DLL dependencies
dumpbin /dependents "C:\path\to\application.exe" | Select-String -Pattern "ssl|tls|crypto"

# Use pattern-based hooking for custom libraries
fritap --patterns windows_patterns.json -k keys.log application.exe
```

## Application Categories

### Web Browsers

```powershell
# Microsoft Edge
fritap -k edge_keys.log --pcap edge_traffic.pcap msedge.exe

# Google Chrome
fritap -k chrome_keys.log chrome.exe

# Mozilla Firefox
fritap -k firefox_keys.log firefox.exe

# Internet Explorer
fritap -k ie_keys.log iexplore.exe
```

### Communication Applications

```powershell
# Microsoft Teams
fritap -k teams_keys.log Teams.exe

# Skype
fritap -k skype_keys.log Skype.exe

# Discord
fritap -k discord_keys.log Discord.exe

# Zoom
fritap -k zoom_keys.log Zoom.exe

# Slack
fritap -k slack_keys.log slack.exe
```

### Development Tools

```powershell
# Visual Studio
fritap -k vs_keys.log devenv.exe

# Visual Studio Code
fritap -k vscode_keys.log Code.exe

# Git
fritap -k git_keys.log git.exe

# Node.js
fritap -k node_keys.log node.exe
```

### Gaming Platforms

```powershell
# Steam
fritap -k steam_keys.log steam.exe

# Epic Games Launcher
fritap -k epic_keys.log EpicGamesLauncher.exe

# Battle.net
fritap -k battlenet_keys.log Battle.net.exe

# Origin
fritap -k origin_keys.log Origin.exe
```

### Business Applications

```powershell
# Microsoft Office
fritap -k word_keys.log WINWORD.EXE
fritap -k excel_keys.log EXCEL.EXE
fritap -k outlook_keys.log OUTLOOK.EXE

# Adobe Applications
fritap -k acrobat_keys.log AcroRd32.exe

# Enterprise applications
fritap -k enterprise_keys.log enterprise_app.exe
```

## Advanced Windows Analysis

### Process Monitoring

```powershell
# Monitor process creation
Get-WmiObject Win32_Process | Where-Object {$_.ProcessName -eq "application.exe"}

# Real-time process monitoring
Get-Process | Where-Object {$_.ProcessName -like "*app*"} | Format-Table -AutoSize

# Process tree analysis
Get-Process | Where-Object {$_.ProcessName -eq "parent"} | Select-Object -ExpandProperty Id | ForEach-Object {Get-WmiObject Win32_Process | Where-Object {$_.ParentProcessId -eq $_}}
```

### Windows Services Analysis

```powershell
# List Windows services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Analyze specific service
fritap -k service_keys.log svchost.exe

# Monitor service SSL communications
Get-Service | Where-Object {$_.Name -like "*network*"}
fritap -k network_service_keys.log svchost.exe
```

### Registry and System Analysis

```powershell
# Check SSL/TLS registry settings
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Monitor registry changes during analysis
# Use Process Monitor (ProcMon) from Sysinternals

# System SSL certificate stores
Get-ChildItem Cert:\LocalMachine\Root
Get-ChildItem Cert:\CurrentUser\My
```

### Event Log Analysis

```powershell
# Monitor security events during analysis
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -First 10

# SSL/TLS related events
Get-WinEvent -LogName System | Where-Object {$_.LevelDisplayName -eq "Error" -and $_.Message -like "*SSL*"}

# Application-specific events
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq "ApplicationName"}
```

## Windows-Specific Troubleshooting

### Permission Issues

```powershell
# Always run as Administrator
# Check if running as admin
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Grant SeDebugPrivilege if needed
# Use Local Security Policy (secpol.msc)
# User Rights Assignment → Debug programs
```

### Antivirus Interference

```powershell
# Check running antivirus
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

# Add fritap to antivirus exclusions
# Windows Defender example:
Add-MpPreference -ExclusionPath "C:\Users\$env:USERNAME\AppData\Local\Programs\Python"
Add-MpPreference -ExclusionProcess "fritap.exe"
```

### Windows Firewall

```powershell
# Check firewall status
Get-NetFirewallProfile

# Allow fritap through firewall
New-NetFirewallRule -DisplayName "friTap" -Direction Inbound -Protocol TCP -LocalPort 27042 -Action Allow

# Temporarily disable firewall (not recommended)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

### DLL Loading Issues

```powershell
# Check DLL dependencies
dumpbin /dependents fritap.exe

# Debug DLL loading
# Use Dependency Walker or Process Monitor

# Check PATH environment variable
$env:PATH -split ";"
```

### Process Attachment Issues

```powershell
# Check if process is running
Get-Process -Name "application" -ErrorAction SilentlyContinue

# Check process architecture (32-bit vs 64-bit)
Get-Process | Select-Object ProcessName, @{Name="Architecture";Expression={$_.StartInfo.EnvironmentVariables["PROCESSOR_ARCHITECTURE"]}}

# Use appropriate bitness
# For 32-bit processes on 64-bit Windows, use 32-bit Python/friTap
```

## PowerShell Integration

### Automated Analysis Scripts

```powershell
# PowerShell script for automated analysis
param(
    [Parameter(Mandatory=$true)]
    [string]$ApplicationPath,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputDirectory
)

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDirectory

# Run friTap analysis
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$keyFile = Join-Path $OutputDirectory "$timestamp_keys.log"
$pcapFile = Join-Path $OutputDirectory "$timestamp_traffic.pcap"
$jsonFile = Join-Path $OutputDirectory "$timestamp_metadata.json"

fritap -k $keyFile --pcap $pcapFile --json $jsonFile $ApplicationPath

# Generate report
$report = @{
    Timestamp = $timestamp
    Application = $ApplicationPath
    KeyFile = $keyFile
    PcapFile = $pcapFile
    JsonFile = $jsonFile
}

$report | ConvertTo-Json | Out-File (Join-Path $OutputDirectory "analysis_report.json")
```

### Batch Processing

```powershell
# Analyze multiple applications
$applications = @(
    "chrome.exe",
    "firefox.exe",
    "msedge.exe"
)

foreach ($app in $applications) {
    Write-Host "Analyzing $app..."
    
    $outputDir = "analysis_$app_$(Get-Date -Format 'yyyyMMdd')"
    New-Item -ItemType Directory -Force -Path $outputDir
    
    fritap -k "$outputDir\$app_keys.log" --json "$outputDir\$app_metadata.json" $app
    
    Write-Host "Analysis of $app completed. Output in $outputDir"
}
```

### Event Monitoring Integration

```powershell
# Monitor events during friTap analysis
$job = Start-Job -ScriptBlock {
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" | Select-Object TimeCreated, Id, LevelDisplayName, Message
}

# Run friTap analysis
fritap -k keys.log --pcap traffic.pcap application.exe

# Get events that occurred during analysis
$events = Receive-Job $job
Remove-Job $job

# Process events
$events | Export-Csv "security_events.csv" -NoTypeInformation
```

## Best Practices for Windows

### 1. System Preparation

```powershell
# Run as Administrator
# Disable antivirus temporarily
# Configure Windows Firewall exceptions
# Install required dependencies
```

### 2. Application Analysis

```powershell
# Always start with basic analysis
fritap -k keys.log application.exe

# Progress to comprehensive analysis
fritap -k keys.log --pcap traffic.pcap --json metadata.json application.exe
```

### 3. Security Considerations

```powershell
# Use test systems for analysis
# Re-enable security features after analysis
# Monitor system changes during analysis
```

### 4. Data Organization

```powershell
# Create analysis workspace
$workspace = "C:\friTap_Analysis"
New-Item -ItemType Directory -Force -Path $workspace
Set-Location $workspace

# Organize by date and application
$analysisDir = "$(Get-Date -Format 'yyyyMMdd')_ApplicationName"
New-Item -ItemType Directory -Force -Path $analysisDir
Set-Location $analysisDir

# Run analysis with organized output
fritap -k keys.log --pcap traffic.pcap --json metadata.json application.exe
```

## Windows-Specific Tools Integration

### Sysinternals Tools

```powershell
# Process Monitor (monitor file/registry/network activity)
procmon.exe /AcceptEula /BackingFile analysis.pml

# Process Explorer (detailed process information)
procexp.exe /AcceptEula

# TCPView (network connections)
tcpview.exe /AcceptEula
```

### Windows Performance Toolkit

```powershell
# Windows Performance Recorder
wpr.exe -start network -filemode

# Run friTap analysis
fritap -k keys.log application.exe

# Stop recording
wpr.exe -stop analysis.etl

# Analyze with Windows Performance Analyzer
wpa.exe analysis.etl
```

### Wireshark Integration

```powershell
# Install Wireshark for Windows
# Download from https://www.wireshark.org/

# Real-time analysis with Wireshark
fritap -l application.exe

# Open Wireshark and connect to named pipe
```

## Common Windows Applications

### Microsoft Applications

```powershell
# Office Suite
fritap -k word_keys.log WINWORD.EXE
fritap -k excel_keys.log EXCEL.EXE
fritap -k powerpoint_keys.log POWERPNT.EXE

# Windows Mail
fritap -k mail_keys.log HxMail.exe

# Windows Photos
fritap -k photos_keys.log Microsoft.Photos.exe
```

### Third-Party Applications

```powershell
# Adobe Reader
fritap -k acrobat_keys.log AcroRd32.exe

# 7-Zip
fritap -k 7zip_keys.log 7zFM.exe

# VLC Media Player
fritap -k vlc_keys.log vlc.exe

# Notepad++
fritap -k notepadpp_keys.log notepad++.exe
```

### Enterprise Software

```powershell
# VPN Clients
fritap -k vpn_keys.log vpnclient.exe

# Remote Desktop
fritap -k rdp_keys.log mstsc.exe

# Citrix Receiver
fritap -k citrix_keys.log receiver.exe

# VMware Tools
fritap -k vmware_keys.log vmtoolsd.exe
```

## Next Steps

- **Linux Analysis**: See [Linux Platform Guide](linux.md)
- **macOS Analysis**: Check [macOS Platform Guide](macos.md)
- **Mobile Analysis**: Review [Android](android.md) and [iOS](ios.md) guides
- **Advanced Features**: Learn about [Pattern-based Hooking](../advanced/patterns.md)
- **Troubleshooting**: Check [Common Issues](../troubleshooting/common-issues.md)