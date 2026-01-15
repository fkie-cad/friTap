# Pattern-Based Hooking

Pattern-based hooking is one of friTap's most powerful features, allowing you to analyze applications with stripped SSL libraries or statically linked implementations where traditional symbol-based hooking fails.

## Overview

When SSL/TLS libraries are stripped of symbols or statically linked into applications, friTap cannot use traditional function name resolution. Pattern-based hooking solves this by matching byte patterns in memory to identify and hook the required functions. By default friTap has already some patterns included for well-known libaries but due to compilation and library updates it might be the case that these patterns needs to be updated.

### When to Use Pattern-Based Hooking

Pattern-based hooking works by searching for unique byte sequences (patterns) that identify specific functions in memory. This technique is essential for:

- **Stripped libraries**: No symbol information available
- **Statically linked SSL**: BoringSSL embedded in Chrome, libflutter.so
- **Obfuscated binaries**: Anti-analysis protections
- **Custom SSL implementations**: Modified or proprietary libraries
- **Mobile applications**: Flutter, React Native, Unity apps

## Pattern File Format

Pattern files use a nested JSON structure organized by module, platform, and architecture:

```json
{
  "modules": {
    "libflutter.so": {
      "android": {
        "arm64": {
          "Dump-Keys": {
            "primary": "FF 83 01 D1 F6 1B 00 F9 F5 53 04 A9 F3 7B 05 A9...",
            "fallback": "FF 43 02 D1 FD 7B 05 A9 F7 33 00 F9..."
          }
        },
        "arm": {
          "Dump-Keys": {
            "primary": "2D E9 F0 4F 85 B0 04 46 0D 46...",
            "fallback": "2D E9 F0 47 87 B0 04 46 0D 46..."
          }
        },
        "x86_64": {
          "Dump-Keys": {
            "primary": "55 48 89 E5 41 57 41 56 41 55 41 54...",
            "fallback": "55 48 89 E5 41 57 41 56 53 48 83 EC..."
          }
        },
        "x86": {
          "Dump-Keys": {
            "primary": "55 89 E5 57 56 53 81 EC...",
            "fallback": "55 89 E5 57 56 53 83 EC..."
          }
        }
      }
    },
    "libsignal_jni.so": {
      "android": {
        "arm64": {
          "Dump-Keys": {
            "primary": "FF 43 02 D1 FD 7B 05 A9 F7 33 00 F9...",
            "fallback": "FF 83 01 D1 FD 7B 03 A9 F6 57 04 A9..."
          }
        }
      }
    }
  }
}
```

### JSON Structure Hierarchy

```
modules/
├── <module_name>/           # e.g., "libflutter.so"
│   └── <platform>/          # "android", "ios", "linux", "windows"
│       └── <architecture>/  # "arm64", "arm", "x86_64", "x86"
│           └── <action>/    # "Dump-Keys", "SSL_Read", etc.
│               ├── primary  # Primary pattern (tried first)
│               └── fallback # Fallback pattern (if primary fails)
```

### Pattern Categories

friTap supports five main hooking categories:

| Category | Description | Status |
|----------|-------------|--------|
| **Dump-Keys** | Extract TLS encryption keys via `ssl_log_secret()` | Fully supported |
| **Install-Key-Log-Callback** | Install key logging callbacks | Implemented |
| **KeyLogCallback-Function** | Key callback function hooks | Implemented |
| **SSL_Read** | Hook SSL read operations | Implemented |
| **SSL_Write** | Hook SSL write operations | Implemented |

!!! note "Current Focus"
    The `Dump-Keys` category is the primary use case for pattern-based hooking, especially for apps using statically-linked BoringSSL where symbols are stripped.

## Creating Pattern Files

### Manual Pattern Creation

**Step 1: Identify Target Functions**

Use tools like Ghidra, IDA Pro, or Radare2 to analyze the binary code of target functions:

```bash
# Use radare2 to analyze library
r2 -A libflutter.so
[0x00000000]> afl | grep -i ssl
[0x00000000]> pdf @ sym.ssl_log_secret
```

**Step 2: Extract Byte Patterns**

```bash
# Extract bytes around function prologue
# example pattern 1
[0x00000000]> px 32 @ sym.ssl_log_secret
0x12345678  1f2003d5 12345678 f44f01a9 87654321  .....O......
```

In other tools, retrieving the function’s bytes often requires an even more manual process:

```assembly
; Example ssl_log_secret function prologue
; example pattern 2
push rbp           ; 55
mov rbp, rsp       ; 48 89 E5
sub rsp, 0x20      ; 48 83 EC 20
mov [rbp-8], rdi   ; 48 89 7D F8
```

This translates to the pattern: `55 48 89 E5 48 83 EC 20 48 89 7D F8`

**Step 3: Create Pattern with Wildcards**

Replace variable bytes with `?` or `??`:
```
; example pattern 1
1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9
; example pattern 2
55 48 89 E? ?? 83 EC 20 ?8 89 ?? F8
;  
```
Wildcards (`?` or `??`) are used for:
- Register variations
- Immediate value variations
- Padding bytes
- Compiler-specific differences

### Automated Pattern Generation with BoringSecretHunter

[BoringSecretHunter](https://github.com/monkeywave/BoringSecretHunter) is a Ghidra-based tool that automates byte pattern extraction from stripped TLS libraries, particularly BoringSSL and rustls. It's the recommended approach for generating `Dump-Keys` patterns.

#### What BoringSecretHunter Does

- **Identifies TLS libraries** by scanning for characteristic strings (`CLIENT_RANDOM`, `EXPORTER_SECRET`)
- **Locates `ssl_log_secret()`** - the function responsible for TLS key logging
- **Generates byte patterns** from function prologues (32-48 bytes)
- **Supports multiple architectures** (ARM64, ARM, x86_64, x86)
- **Provides primary and fallback patterns** for robustness

#### Installation

```bash
# Clone the repository
git clone https://github.com/monkeywave/BoringSecretHunter.git
cd BoringSecretHunter

# Build the Docker container
docker build -t boringsecrethunter .
```

#### Complete Workflow

**Step 1: Discover TLS Libraries on Android Device**

Use the included helper script to find and download target libraries:

```bash
# List all app-specific libraries
python3 findBoringSSLLibsOnAndroid.py --package org.thoughtcrime.securesms -L

# Download libraries to local dumps/ directory
python3 findBoringSSLLibsOnAndroid.py --package org.thoughtcrime.securesms -L -D
```

**Step 2: Prepare and Analyze Libraries**

```bash
# Create working directories
mkdir -p binary results

# Copy target libraries
cp dumps/libsignal_jni.so binary/

# Run BoringSecretHunter analysis
docker run --rm \
  -v "$(pwd)/binary":/usr/local/src/binaries \
  -v "$(pwd)/results":/host_output \
  -e DEBUG_RUN=true \
  boringsecrethunter
```

**Example Output:**

```
[*] Start analyzing binary libsignal_jni.so (CPU Architecture: AARCH64)...

[*] Target function identified (ssl_log_secret):

Function label: FUN_00493BB0
Function offset: 00493BB0 (0X493BB0)
Byte pattern for frida (friTap): 3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4
```

**Step 3: Create Pattern File**

Convert the analysis output to friTap's JSON format:

```json
{
  "modules": {
    "libsignal_jni.so": {
      "android": {
        "arm64": {
          "Dump-Keys": {
            "primary": "3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4",
            "fallback": "FF 43 02 D1 FD 7B 05 A9 F7 33 00 F9 F5 53 04 A9 F3 7B 05 A9"
          }
        }
      }
    }
  }
}
```

**Step 4: Use with friTap**

```bash
# Deploy patterns for TLS key extraction
fritap -m -v -k signal_keys.log \
  --patterns signal_pattern.json \
  org.thoughtcrime.securesms
```

**Expected Output:**

```
[*] Pattern found at (primary_pattern) address: 0x6d82648b0c on libsignal_jni.so
[*] Pattern-based hooks installed.
[*] CLIENT_HANDSHAKE_TRAFFIC_SECRET 65042333... F2E8000B...
[*] SERVER_HANDSHAKE_TRAFFIC_SECRET 65042333... 4501F2E4...
[*] CLIENT_TRAFFIC_SECRET_0 65042333... 77597112...
```

#### Why BoringSecretHunter Works

The `ssl_log_secret()` function in BoringSSL is **always called** during TLS handshakes, regardless of whether key logging is enabled. This makes it a reliable hook target even in production builds where logging is disabled.

!!! tip "Why Docker?"
    The Docker approach provides a pre-configured Ghidra environment, eliminating setup complexity and ensuring consistent results across platforms.

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
    "Dump-Keys": {
      "primary": "FF 83 00 D1 FD 7B 01 A9 ?? ?? ?? ?? F4 4F 03 A9",
      "fallback": "FF 83 00 D1 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 03 A9"
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


## How Pattern-Based Hooking Works

### 1. Pattern Generation

Patterns are generated by analyzing the binary code of target functions:

```assembly
; Example SSL_read function prologue
push rbp           ; 55
mov rbp, rsp       ; 48 89 E5
sub rsp, 0x20      ; 48 83 EC 20
mov [rbp-8], rdi   ; 48 89 7D F8
```

This translates to the pattern: `55 48 89 E5 48 83 EC 20 48 89 7D F8`

### 2. Pattern Matching

friTap searches for these patterns in the target process memory:

```typescript
function find_pattern_in_module(module_name: string, pattern: string): NativePointer[] {
    const module = Process.getModuleByName(module_name);
    const pattern_bytes = pattern_to_bytes(pattern);
    
    return Memory.scan(module.base, module.size, pattern_bytes, {
        onMatch: function(address, size) {
            return address;
        },
        onError: function(reason) {
            devlog_error(`Pattern scan failed: ${reason}`);
        }
    });
}
```

### 3. Hook Installation

Once patterns are found, hooks are installed at the matching addresses:

```typescript
function hook_by_pattern(
    module_name: string,
    pattern: string,
    function_name: string,
    hook_callback: Function
): boolean {
    const addresses = find_pattern_in_module(module_name, pattern);
    
    if (addresses.length === 0) {
        devlog_error(`Pattern not found: ${pattern}`);
        return false;
    }
    
    if (addresses.length > 1) {
        devlog_error(`Multiple matches for pattern: ${pattern}`);
        return false;
    }
    
    Interceptor.attach(addresses[0], hook_callback);
    return true;
}
```

## Summary

Pattern-based hooking is a powerful technique that extends friTap's capabilities to handle stripped binaries and complex scenarios. By understanding the principles, implementing proper validation, and following best practices, you can create robust pattern-based hooks that work reliably across different environments and library versions.

The key to successful pattern-based hooking is careful pattern selection, thorough testing, and robust error handling. Combined with friTap's other hooking methods, it provides comprehensive coverage for SSL/TLS traffic analysis in any scenario.

## Next Steps
- **Learn about custom Frida scripts** using `-c` parameter for advanced hooking
- **Explore anti-detection techniques** in specialized security analysis scenarios
- **Check platform-specific guides** for pattern examples