# Pattern-Based Hooking

Pattern-based hooking is one of friTap's most powerful features, allowing you to analyze applications with stripped SSL libraries or statically linked implementations where traditional symbol-based hooking fails.

## Overview

When SSL/TLS libraries are stripped of symbols or statically linked into applications, friTap cannot use traditional function name resolution. Pattern-based hooking solves this by matching byte patterns in memory to identify and hook the required functions. By default friTap has already some patterns included for well-known libaries but due to compilation and library updates it might be the case that these patterns needs to be updated.

### When to Use Pattern-Based Hooking

- **Stripped libraries**: No symbol information available
- **Statically linked SSL**: BoringSSL embedded in Chrome, libflutter.so
- **Obfuscated binaries**: Anti-analysis protections
- **Custom SSL implementations**: Modified or proprietary libraries
- **Mobile applications**: Flutter, React Native, Unity apps

## Pattern File Format

Pattern files use JSON format to define byte patterns for different hooking categories:

```json
{
  "version": "1.0",
  "architecture": "arm64",
  "platform": "android",
  "library": "libflutter.so",
  "patterns": {
    "SSL_Read": {
      "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9",
      "fallback": "1F 20 03 D5 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 01 A9",
      "offset": 0,
      "description": "SSL_read function pattern"
    },
    "SSL_Write": {
      "primary": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9",
      "fallback": "FF 83 00 D1 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 02 A9",
      "offset": 0,
      "description": "SSL_write function pattern"
    }
  }
}
```

### Pattern Categories

friTap supports five main hooking categories:

1. **Dump-Keys**: Extract encryption keys *right now we support only this feature*
2. **Install-Key-Log-Callback**: Install key logging callbacks
3. **KeyLogCallback-Function**: Key callback function hooks
4. **SSL_Read**: Hook SSL read operations
5. **SSL_Write**: Hook SSL write operations

## Creating Pattern Files

### Manual Pattern Creation

**Step 1: Identify Target Functions**

Use tools like Ghidra, IDA Pro, or Radare2 to analyze the binary:

```bash
# Use radare2 to analyze library
r2 -A libflutter.so
[0x00000000]> afl | grep -i ssl
[0x00000000]> pdf @ sym.SSL_read
```

**Step 2: Extract Byte Patterns**

```bash
# Extract bytes around function prologue
[0x00000000]> px 32 @ sym.SSL_read
0x12345678  1f2003d5 12345678 f44f01a9 87654321  .....O......
```

**Step 3: Create Pattern with Wildcards**

Replace variable bytes with `??`:
```
1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9
```

### Automated Pattern Generation

**Using BoringSecretHunter to Generate Patterns:**

For applications with stripped libraries, we recommend using the external tool [BoringSecretHunter](https://github.com/monkeywave/BoringSecretHunter) to automatically generate pattern files. This is a manual process, and the generated JSON file can then be supplied to friTap. **Use the Docker approach for best results:**

```bash
# Create directories for BoringSecretHunter
mkdir -p binary results

# Copy target libraries to analyze
cp libflutter.so binary/
cp libssl.so binary/

# Run BoringSecretHunter with Docker (recommended)
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter

# Generated patterns will be in results/ directory
ls results/
# Output: libflutter.so_patterns.json, libssl.so_patterns.json

# Use generated patterns with friTap
fritap --patterns results/libflutter.so_patterns.json -k keys.log com.example.flutter_app
```

!!! tip "Why Docker?"
    The Docker approach provides a pre-configured environment with Ghidra, eliminating setup complexity and ensuring consistent results across platforms.

## Using Pattern Files

### Basic Pattern Usage

```bash
# Use pattern file for analysis
fritap --patterns patterns.json -k keys.log target_app

# Combine with other options
fritap --patterns patterns.json --pcap traffic.pcap -k keys.log target_app

# Mobile application with patterns
fritap -m --patterns android_patterns.json -k keys.log com.example.app
```

### Debug Pattern Matching

```bash
# Enable debug output to see pattern matching
fritap -do --patterns patterns.json -v target_app

# Expected output:
# [*] Pattern matching enabled
# [*] Loading patterns from patterns.json
# [*] Searching for SSL_Read pattern in libssl.so
# [*] Pattern match found at offset 0x12345678
# [*] Hooking SSL_read at 0x12345678
```

### Platform-Specific Patterns

**Android Patterns:**
```bash
# ARM64 Android patterns
fritap -m --patterns android_arm64_patterns.json -k keys.log com.example.app

# x86_64 Android patterns (emulator)
fritap -m --patterns android_x64_patterns.json -k keys.log com.example.app
```

**iOS Patterns:**
```bash
# ARM64 iOS patterns
fritap -m --patterns ios_arm64_patterns.json -k keys.log com.example.app
```

## Advanced Pattern Techniques

### Multi-Architecture Support

Create patterns for multiple architectures:

```json
{
  "version": "1.0",
  "patterns": {
    "arm64": {
      "SSL_Read": {
        "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9"
      }
    },
    "x86_64": {
      "SSL_Read": {
        "primary": "55 48 89 E5 ?? ?? ?? ?? 48 83 EC ??"
      }
    },
    "armv7": {
      "SSL_Read": {
        "primary": "?? ?? 2D E9 ?? ?? ?? ?? ?? ?? ?? ??"
      }
    }
  }
}
```

### Conditional Patterns

Use conditional logic for pattern matching:

```json
{
  "patterns": {
    "SSL_Read": {
      "conditions": [
        {
          "if": "library_name == 'libflutter.so'",
          "pattern": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9"
        },
        {
          "if": "library_name == 'libssl.so'",
          "pattern": "55 48 89 E5 ?? ?? ?? ?? 48 83 EC ??"
        }
      ]
    }
  }
}
```

### Offset-Based Adjustments

Adjust hook points with offsets:

```json
{
  "patterns": {
    "SSL_Read": {
      "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9",
      "offset": 4,
      "description": "Hook 4 bytes into function"
    }
  }
}
```

## Real-World Examples

### Flutter Applications

Flutter apps often have statically linked BoringSSL:

**Flutter Pattern File (flutter_patterns.json):**
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
    },
    "Dump-Keys": {
      "primary": "FF 83 00 D1 FD 7B 01 A9 ?? ?? ?? ?? F4 4F 03 A9",
      "fallback": "FF 83 00 D1 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 03 A9",
      "offset": 0,
      "description": "Key extraction point"
    }
  }
}
```

**Usage:**
```bash
fritap -m --patterns flutter_patterns.json -k flutter_keys.log com.example.flutter_app
```

### Cronet Applications

Chrome's Cronet library with embedded BoringSSL:

**Cronet Pattern File (cronet_patterns.json):**
```json
{
  "version": "1.0",
  "architecture": "arm64",
  "platform": "android",
  "library": "libcronet.so",
  "patterns": {
    "SSL_Read": {
      "primary": "FF 83 00 D1 FD 7B 01 A9 F4 4F 02 A9 F6 57 03 A9",
      "fallback": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9",
      "offset": 0,
      "description": "Cronet BoringSSL SSL_read"
    },
    "SSL_Write": {
      "primary": "FF 83 00 D1 FD 7B 01 A9 F4 4F 02 A9 F6 57 03 A9",
      "fallback": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9",
      "offset": 0,
      "description": "Cronet BoringSSL SSL_write"
    }
  }
}
```

**Usage:**
```bash
fritap -m --patterns cronet_patterns.json -k cronet_keys.log com.google.android.gms
```

### Unity Games

Unity games with networking capabilities:

**Unity Pattern File (unity_patterns.json):**
```json
{
  "version": "1.0",
  "architecture": "arm64",
  "platform": "android",
  "library": "libil2cpp.so",
  "patterns": {
    "SSL_Read": {
      "primary": "1F 20 03 D5 FD 7B BF A9 ?? ?? ?? ?? F4 4F 01 A9",
      "fallback": "1F 20 03 D5 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 01 A9",
      "offset": 0,
      "description": "Unity il2cpp SSL operations"
    }
  }
}
```

## Pattern Development Workflow

### Step-by-Step Pattern Creation

**1. Analyze Target Application:**
```bash
# Extract APK and analyze libraries
apktool d target_app.apk
cd target_app/lib/arm64-v8a/
file *.so | grep -v stripped
```

**2. Use Static Analysis:**
```bash
# Analyze with radare2
r2 -A libssl.so
[0x00000000]> afl | grep -i ssl_read
[0x00000000]> pdf @ sym.SSL_read
```

**3. Extract and Test Patterns:**
```bash
# Test pattern matching
fritap --patterns test_patterns.json -do -v target_app

# Check debug output for pattern matches
grep -i "pattern" debug_output.log
```

**4. Refine Patterns:**
```bash
# Adjust patterns based on results
# Test with different app versions
# Add fallback patterns
```

### Pattern Validation

**Test Pattern Reliability:**
```bash
#!/bin/bash
# Test pattern across multiple app versions

PATTERN_FILE="$1"
APP_PACKAGE="$2"

for version in v1.0 v1.1 v1.2; do
    echo "Testing $APP_PACKAGE $version"
    fritap -m --patterns "$PATTERN_FILE" -k "test_${version}.log" "$APP_PACKAGE"
    
    if [ -s "test_${version}.log" ]; then
        echo "✓ $version: Pattern worked"
    else
        echo "✗ $version: Pattern failed"
    fi
done
```

## Troubleshooting Patterns

### Common Issues

**Pattern Not Found:**
```bash
# Enable debug output
fritap -do --patterns patterns.json -v target_app

# Check library loading
fritap --list-libraries target_app

# Verify pattern syntax
python -m json.tool patterns.json
```

**False Positives:**
```bash
# Make patterns more specific
# Add additional context bytes
# Use multiple validation patterns
```

**Performance Issues:**
```bash
# Optimize pattern length
# Use specific library targeting
# Implement pattern caching
```

### Debug Techniques

**Pattern Matching Debug:**
```bash
# Enable maximum verbosity
fritap -do -v --patterns patterns.json target_app 2>&1 | tee pattern_debug.log

# Analyze pattern matching process
grep -E "(Pattern|Match|Hook)" pattern_debug.log
```

**Memory Analysis:**
```bash
# Dump memory regions for analysis
fritap -c memory_dump.js --patterns patterns.json target_app

# Where memory_dump.js contains:
# Memory.scan(ptr("0x7000000000"), 0x10000000, "1F 20 03 D5", {
#     onMatch: function(address, size) {
#         console.log("Match at: " + address);
#     }
# });
```

## Best Practices

### 1. Pattern Design

- **Use sufficient context**: Include enough bytes to avoid false positives
- **Implement fallbacks**: Provide alternative patterns for robustness
- **Document patterns**: Include descriptions and version information
- **Test thoroughly**: Validate across different versions and devices

### 2. Maintenance

- **Version control**: Track pattern changes over time
- **Automated testing**: Validate patterns against known samples
- **Community sharing**: Contribute patterns to friTap community
- **Regular updates**: Update patterns for new library versions

### 3. Performance

- **Optimize pattern length**: Balance specificity with performance
- **Target specific libraries**: Avoid scanning unnecessary memory regions
- **Use caching**: Cache successful pattern matches
- **Parallel scanning**: Use multiple patterns simultaneously

## Integration with Other Tools

### BoringSecretHunter (Docker)

```bash
# Prepare binaries for analysis
mkdir -p binary results
cp libflutter.so binary/

# Generate patterns using Docker
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  boringsecrethunter

# Use generated patterns with friTap
fritap --patterns results/libflutter.so_patterns.json -k keys.log com.flutter.app
```

### Ghidra Scripts

```python
# Ghidra script to extract patterns
from ghidra.program.model.symbol import SymbolType

def extract_patterns():
    for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
        if "SSL_" in symbol.getName():
            addr = symbol.getAddress()
            bytes_data = getBytes(addr, 16)
            pattern = " ".join(["%02X" % (b & 0xFF) for b in bytes_data])
            print(f"{symbol.getName()}: {pattern}")

extract_patterns()
```

### Custom Pattern Generators

```python
#!/usr/bin/env python3
# Custom pattern generator

import json
import argparse
from capstone import *

def generate_patterns(binary_path, arch):
    """Generate patterns from binary analysis"""
    patterns = {
        "version": "1.0",
        "architecture": arch,
        "patterns": {}
    }
    
    # Analyze binary and extract patterns
    # Implementation depends on analysis framework
    
    return patterns

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--arch", default="arm64")
    parser.add_argument("--output", required=True)
    
    args = parser.parse_args()
    
    patterns = generate_patterns(args.binary, args.arch)
    
    with open(args.output, 'w') as f:
        json.dump(patterns, f, indent=2)
```

## Next Steps

- **Combine with offset-based hooking** using `--offsets` parameter for comprehensive analysis
- **Learn about custom Frida scripts** using `-c` parameter for advanced hooking
- **Explore anti-detection techniques** in specialized security analysis scenarios
- **Check platform-specific guides** for pattern examples