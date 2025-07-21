# Adding Features to friTap

This guide covers how to add new features to friTap, including SSL/TLS library support, platform support, and analysis capabilities.

## Overview

friTap's architecture is designed to be extensible:

- **Python Host**: CLI interface, process management, output formatting
- **TypeScript Agent**: SSL library hooking, cross-platform compatibility
- **Plugin System**: Modular SSL library implementations
- **Platform Abstraction**: OS-specific code organization


## Architecture Overview

friTap is built on a multi-component architecture that combines Python orchestration with frida's dynamic instrumentation:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Python CLI    │    │  Frida Engine   │    │ Target Process  │
│   (friTap.py)   │────│   (Runtime)     │────│   (Hooked)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
    ┌─────────┐            ┌─────────────┐        ┌─────────────┐
    │SSL Logic│            │TypeScript   │        │SSL Libraries│
    │& PCAP   │            │Agent        │        │(OpenSSL,    │
    │Gen      │            │(_ssl_log.js)│        │BoringSSL,   │
    └─────────┘            └─────────────┘        │NSS, etc.)   │
                                                  └─────────────┘
```

### Components

1. **Python CLI** (`friTap.py`): Main orchestration layer
2. **SSL Logger** (`ssl_logger.py`): Core logging and processing engine
3. **PCAP Generator** (`pcap.py`): Network packet creation and manipulation
4. **Frida Agent** (`agent/ssl_log.ts`): TypeScript-based instrumentation agent (this is build via `frida-compile` from the TypeScript code in the agent/ folder)
5. **Platform Agents**: Platform-specific SSL library hooks


## Adding SSL/TLS Library Support

Adding support for a new SSL/TLS library involves both TypeScript agent code and Python integration.

### Step 1: Research the Library

Before implementation, thoroughly analyze the target library:

```bash
# Analyze library structure
objdump -T new_library.so | grep -E "(ssl|tls|read|write)"

# Study function signatures
readelf -s new_library.so | grep FUNC

# Check for debug symbols
file new_library.so
objdump -h new_library.so | grep debug

# Analyze with Ghidra/IDA Pro for patterns
# Document function calling conventions
# Identify key structures and data types
```

### Step 2: Create TypeScript Implementation

Create the main library implementation in `agent/ssl_lib/`:

```typescript
// agent/ssl_lib/new_library.ts
import { log, devlog, devlog_error } from "../util/log.js";
import { SharedStructures } from "../shared/shared_structures.js";

export class NewLibraryHooks {
    private moduleName: string;
    private baseAddress: NativePointer;
    private addresses: { [key: string]: NativePointer } = {};
    
    constructor(moduleName: string) {
        this.moduleName = moduleName;
        this.baseAddress = Module.getBaseAddress(moduleName);
        this.addresses = this.getAddresses();
    }
    
    /**
     * Get function addresses for the new library.
     * Try symbol-based detection first, then patterns.
     */
    private getAddresses(): { [key: string]: NativePointer } {
        const addresses: { [key: string]: NativePointer } = {};
        
        try {
            // Symbol-based detection (preferred)
            addresses["NewSSL_Read"] = Module.getExportByName(this.moduleName, "NewSSL_Read");
            addresses["NewSSL_Write"] = Module.getExportByName(this.moduleName, "NewSSL_Write");
            addresses["NewSSL_GetKeys"] = Module.getExportByName(this.moduleName, "NewSSL_GetKeys");
            
            devlog(`[${this.moduleName}] Found functions via symbols`);
            
        } catch (error) {
            devlog_error(`Symbol-based detection failed for ${this.moduleName}: ${error}`);
            
            // Fall back to pattern-based detection
            this.findFunctionsByPatterns(addresses);
        }
        
        return addresses;
    }
    
    /**
     * Find functions using byte patterns when symbols are not available.
     */
    private findFunctionsByPatterns(addresses: { [key: string]: NativePointer }): void {
        const module = Process.getModuleByName(this.moduleName);
        
        // Define patterns for different architectures
        const patterns = {
            "arm64": {
                "NewSSL_Read": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9",
                "NewSSL_Write": "FF 83 00 D1 ?? ?? ?? ?? F4 4F 02 A9"
            },
            "x64": {
                "NewSSL_Read": "55 48 89 E5 ?? ?? ?? ?? 48 83 EC ??",
                "NewSSL_Write": "55 48 89 E5 ?? ?? ?? ?? 48 8B 45 ??"
            }
        };
        
        const archPatterns = patterns[Process.arch as keyof typeof patterns];
        if (!archPatterns) {
            devlog_error(`No patterns defined for architecture: ${Process.arch}`);
            return;
        }
        
        // Search for each function pattern
        for (const [funcName, pattern] of Object.entries(archPatterns)) {
            try {
                const matches = Memory.scanSync(module.base, module.size, pattern);
                
                if (matches.length > 0) {
                    addresses[funcName] = matches[0].address;
                    devlog(`[${this.moduleName}] Found ${funcName} at ${matches[0].address} via pattern`);
                } else {
                    devlog_error(`[${this.moduleName}] Pattern not found for ${funcName}`);
                }
                
            } catch (error) {
                devlog_error(`[${this.moduleName}] Pattern search failed for ${funcName}: ${error}`);
            }
        }
    }
    
    /**
     * Install all hooks for this library.
     */
    public install(): boolean {
        if (Object.keys(this.addresses).length === 0) {
            devlog_error(`[${this.moduleName}] No function addresses found`);
            return false;
        }
        
        let successCount = 0;
        
        // Install read/write hooks
        if (this.hookSSLRead()) successCount++;
        if (this.hookSSLWrite()) successCount++;
        if (this.hookKeyExtraction()) successCount++;
        
        if (successCount > 0) {
            log(`Successfully installed ${successCount} hooks for ${this.moduleName}`);
            return true;
        } else {
            devlog_error(`[${this.moduleName}] Failed to install any hooks`);
            return false;
        }
    }
    
    /**
     * Hook SSL read function.
     */
    private hookSSLRead(): boolean {
        const readAddress = this.addresses["NewSSL_Read"];
        if (!readAddress) {
            devlog_error(`[${this.moduleName}] NewSSL_Read address not found`);
            return false;
        }
        
        try {
            Interceptor.attach(readAddress, {
                onEnter(args) {
                    // Store arguments for onLeave
                    this.ssl = args[0];          // SSL context
                    this.buffer = args[1];       // Data buffer
                    this.bufferSize = args[2];   // Buffer size
                    
                    devlog(`[${this.moduleName}] SSL_Read called with buffer size: ${this.bufferSize}`);
                },
                
                onLeave(retval) {
                    const bytesRead = retval.toInt32();
                    
                    if (bytesRead > 0) {
                        try {
                            const data = this.buffer.readByteArray(bytesRead);
                            
                            // Get connection info
                            const connectionInfo = this.getConnectionInfo(this.ssl);
                            
                            // Process data using shared functions
                            SharedStructures.logSSLRead(this.ssl, data, connectionInfo);
                            
                            devlog(`[${this.moduleName}] Captured ${bytesRead} bytes via SSL_Read`);
                            
                        } catch (error) {
                            devlog_error(`[${this.moduleName}] Error processing SSL_Read data: ${error}`);
                        }
                    }
                }
            });
            
            devlog(`[${this.moduleName}] Hooked NewSSL_Read at ${readAddress}`);
            return true;
            
        } catch (error) {
            devlog_error(`[${this.moduleName}] Failed to hook NewSSL_Read: ${error}`);
            return false;
        }
    }
    
    /**
     * Hook SSL write function.
     */
    private hookSSLWrite(): boolean {
        const writeAddress = this.addresses["NewSSL_Write"];
        if (!writeAddress) {
            devlog_error(`[${this.moduleName}] NewSSL_Write address not found`);
            return false;
        }
        
        try {
            Interceptor.attach(writeAddress, {
                onEnter(args) {
                    const ssl = args[0];
                    const dataPtr = args[1];
                    const dataSize = args[2].toInt32();
                    
                    if (dataSize > 0) {
                        try {
                            const data = dataPtr.readByteArray(dataSize);
                            
                            // Get connection info
                            const connectionInfo = this.getConnectionInfo(ssl);
                            
                            // Process data using shared functions
                            SharedStructures.logSSLWrite(ssl, data, connectionInfo);
                            
                            devlog(`[${this.moduleName}] Captured ${dataSize} bytes via SSL_Write`);
                            
                        } catch (error) {
                            devlog_error(`[${this.moduleName}] Error processing SSL_Write data: ${error}`);
                        }
                    }
                }
            });
            
            devlog(`[${this.moduleName}] Hooked NewSSL_Write at ${writeAddress}`);
            return true;
            
        } catch (error) {
            devlog_error(`[${this.moduleName}] Failed to hook NewSSL_Write: ${error}`);
            return false;
        }
    }
    
    /**
     * Hook key extraction functions.
     */
    private hookKeyExtraction(): boolean {
        const keyAddress = this.addresses["NewSSL_GetKeys"];
        if (!keyAddress) {
            devlog(`[${this.moduleName}] Key extraction function not found (optional)`);
            return false;
        }
        
        try {
            Interceptor.attach(keyAddress, {
                onLeave(retval) {
                    // Extract keys based on library-specific format
                    const keyData = this.extractKeyData(retval);
                    if (keyData) {
                        SharedStructures.logSSLKeys(keyData);
                        devlog(`[${this.moduleName}] Extracted SSL keys`);
                    }
                }
            });
            
            devlog(`[${this.moduleName}] Hooked key extraction at ${keyAddress}`);
            return true;
            
        } catch (error) {
            devlog_error(`[${this.moduleName}] Failed to hook key extraction: ${error}`);
            return false;
        }
    }
    
    /**
     * Extract connection information from SSL context.
     */
    private getConnectionInfo(ssl: NativePointer): any {
        try {
            // Library-specific SSL context parsing
            // This will vary significantly between libraries
            
            // Example structure access (adjust for actual library)
            const socketFd = ssl.add(0x10).readInt();  // Offset to socket descriptor
            
            // Get socket information using shared utilities
            return SharedStructures.getSocketInfo(socketFd);
            
        } catch (error) {
            devlog_error(`[${this.moduleName}] Failed to get connection info: ${error}`);
            return { src: "0.0.0.0", dst: "0.0.0.0", src_port: 0, dst_port: 0 };
        }
    }
    
    /**
     * Extract key data from library-specific structures.
     */
    private extractKeyData(keyPtr: NativePointer): any {
        try {
            // Parse library-specific key structures
            // Return in standard friTap format
            
            return {
                client_random: keyPtr.readByteArray(32),
                master_secret: keyPtr.add(32).readByteArray(48)
            };
            
        } catch (error) {
            devlog_error(`[${this.moduleName}] Failed to extract key data: ${error}`);
            return null;
        }
    }
}

/**
 * Main entry point for new library detection and hooking.
 */
export function installNewLibraryHooks(): boolean {
    const possibleNames = [
        "libnewssl.so",      // Linux
        "libnewssl.so.1",    // Linux versioned
        "newssl.dll",        // Windows
        "NewSSL",            // macOS framework
        "libNewSSL.dylib"    // macOS dynamic library
    ];
    
    for (const name of possibleNames) {
        try {
            const module = Process.getModuleByName(name);
            if (module) {
                devlog(`[NewLibrary] Found module: ${name}`);
                
                const hooks = new NewLibraryHooks(name);
                const success = hooks.install();
                
                if (success) {
                    log(`NewLibrary hooks installed for ${name}`);
                    return true;
                }
            }
        } catch (error) {
            // Module not found, continue to next
            devlog(`[NewLibrary] Module ${name} not found`);
        }
    }
    
    devlog(`[NewLibrary] No compatible modules found`);
    return false;
}
```

### Step 3: Add Platform-Specific Integration

Create platform-specific integration files for each supported platform:

```typescript
// agent/linux/new_library_linux.ts
import { installNewLibraryHooks } from "../ssl_lib/new_library.js";
import { devlog } from "../util/log.js";

export function installNewLibraryLinux(): boolean {
    devlog("[Linux] Attempting NewLibrary detection");
    
    // Linux-specific module names and paths
    const linuxModules = [
        "libnewssl.so",
        "libnewssl.so.1",
        "libnewssl.so.1.0",
        "/usr/lib/x86_64-linux-gnu/libnewssl.so",
        "/usr/local/lib/libnewssl.so"
    ];
    
    // Check for library presence
    for (const moduleName of linuxModules) {
        try {
            const module = Process.getModuleByName(moduleName);
            if (module) {
                devlog(`[Linux] Found NewLibrary module: ${moduleName}`);
                return installNewLibraryHooks();
            }
        } catch (error) {
            // Continue to next module
        }
    }
    
    devlog("[Linux] NewLibrary not found");
    return false;
}
```

```typescript
// agent/android/new_library_android.ts
import { installNewLibraryHooks } from "../ssl_lib/new_library.js";
import { devlog, devlog_error } from "../util/log.js";

export function installNewLibraryAndroid(): boolean {
    devlog("[Android] Attempting NewLibrary detection");
    
    // Android-specific considerations
    const androidModules = [
        "libnewssl.so",
        "libapp.so",  // May be statically linked in app
        "libflutter.so"  // If using Flutter with NewSSL
    ];
    
    // Check if we're in an Android app context
    if (!Java.available) {
        devlog_error("[Android] Java runtime not available");
        return false;
    }
    
    // Attempt to find NewLibrary in loaded modules
    for (const moduleName of androidModules) {
        try {
            const module = Process.getModuleByName(moduleName);
            if (module) {
                devlog(`[Android] Found potential NewLibrary module: ${moduleName}`);
                
                // Additional Android-specific checks
                if (this.validateAndroidModule(module)) {
                    return installNewLibraryHooks();
                }
            }
        } catch (error) {
            // Continue to next module
        }
    }
    
    devlog("[Android] NewLibrary not found");
    return false;
}

function validateAndroidModule(module: Module): boolean {
    // Android-specific validation
    // Check for expected exports or patterns
    try {
        const exports = module.enumerateExports();
        const newSSLExports = exports.filter(exp => 
            exp.name.toLowerCase().includes('newssl') ||
            exp.name.toLowerCase().includes('ssl_read') ||
            exp.name.toLowerCase().includes('ssl_write')
        );
        
        return newSSLExports.length > 0;
        
    } catch (error) {
        devlog_error(`[Android] Module validation failed: ${error}`);
        return false;
    }
}
```

### Step 4: Update Main Agent

Integrate the new library into the main detection loop:

```typescript
// agent/ssl_log.ts (add to main detection function)
import { installNewLibraryLinux } from "./linux/new_library_linux.js";
import { installNewLibraryAndroid } from "./android/new_library_android.js";
import { installNewLibraryWindows } from "./windows/new_library_windows.js";
import { installNewLibraryMacOS } from "./macos/new_library_macos.js";
import { installNewLibraryIOS } from "./ios/new_library_ios.js";

// In main SSL library detection function
function detectSSLLibraries(): void {
    let librariesFound = 0;
    
    // Existing libraries...
    librariesFound += installOpenSSLHooks() ? 1 : 0;
    librariesFound += installBoringSSLHooks() ? 1 : 0;
    librariesFound += installNSSHooks() ? 1 : 0;
    
    // Add new library detection
    if (isLinux()) {
        librariesFound += installNewLibraryLinux() ? 1 : 0;
    } else if (isAndroid()) {
        librariesFound += installNewLibraryAndroid() ? 1 : 0;
    } else if (isWindows()) {
        librariesFound += installNewLibraryWindows() ? 1 : 0;
    } else if (isMacOS()) {
        librariesFound += installNewLibraryMacOS() ? 1 : 0;
    } else if (isiOS()) {
        librariesFound += installNewLibraryIOS() ? 1 : 0;
    }
    
    log(`Detected ${librariesFound} SSL/TLS libraries`);
}
```

### Step 5: Compile and Test

```bash
# Compile the agent
npm run build

# Verify compilation succeeded
ls -la friTap/_ssl_log.js friTap/_ssl_log_legacy.js

# Test with a simple application
python -m friTap.friTap -k test_keys.log ground_truth/new_library_test_app

# Test with debug output
python -m friTap.friTap -do -k test_keys.log ground_truth/new_library_test_app

# Verify key extraction
grep "CLIENT_RANDOM" test_keys.log
```

### Step 6: Add Python Integration

Update Python code to handle the new library:

```python
# friTap/ssl_logger.py (add detection logic)
def _detect_ssl_libraries(self) -> Dict[str, Any]:
    """Detect available SSL libraries in target process."""
    libraries = {}
    
    try:
        # Get loaded modules from Frida
        modules = self.session.enumerate_modules()
        
        for module in modules:
            # Existing library detection...
            
            # Add new library detection
            if self._is_new_library_module(module):
                libraries["NewLibrary"] = {
                    "name": "NewLibrary",
                    "module": module.name,
                    "base": module.base_address,
                    "size": module.size,
                    "version": self._get_new_library_version(module)
                }
                
    except Exception as e:
        self.logger.error(f"SSL library detection failed: {e}")
    
    return libraries

def _is_new_library_module(self, module) -> bool:
    """Check if module contains NewLibrary."""
    new_library_indicators = [
        "libnewssl",
        "newssl.dll",
        "NewSSL"
    ]
    
    module_name_lower = module.name.lower()
    return any(indicator in module_name_lower for indicator in new_library_indicators)

def _get_new_library_version(self, module) -> str:
    """Get NewLibrary version from module."""
    try:
        # Extract version from module exports or metadata
        # This is library-specific
        return "1.0.0"  # Default version
    except Exception:
        return "unknown"
```

### Step 7: Add Tests

Create comprehensive tests for the new library:

```python
# tests/unit/test_new_library.py
import pytest
from unittest.mock import MagicMock, patch
from friTap.ssl_logger import SSL_Logger

class TestNewLibraryDetection:
    """Test NewLibrary SSL detection and hooking."""
    
    @patch('friTap.ssl_logger.frida')
    def test_new_library_detection(self, mock_frida):
        """Test detection of NewLibrary SSL."""
        # Mock module detection
        mock_process = MagicMock()
        mock_module = MagicMock()
        mock_module.name = "libnewssl.so"
        mock_module.base_address = 0x7f0000000000
        mock_module.size = 1024 * 1024
        
        mock_process.enumerate_modules.return_value = [mock_module]
        mock_frida.get_local_device.return_value.attach.return_value = mock_process
        
        logger = SSL_Logger("test_app")
        detected_libraries = logger._detect_ssl_libraries()
        
        assert "NewLibrary" in detected_libraries
        assert detected_libraries["NewLibrary"]["module"] == "libnewssl.so"
        
    def test_new_library_version_extraction(self):
        """Test NewLibrary version extraction."""
        logger = SSL_Logger("test_app")
        
        mock_module = MagicMock()
        mock_module.name = "libnewssl.so.1.2.3"
        
        version = logger._get_new_library_version(mock_module)
        assert version is not None
        
    @patch('subprocess.run')
    def test_new_library_ground_truth(self, mock_subprocess):
        """Test NewLibrary with ground truth application."""
        # Mock successful friTap execution
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "NewLibrary hooks installed"
        
        # This would be a real test with actual ground truth app
        assert True  # Placeholder
```

```python
# tests/agent/test_new_library_compilation.py
def test_new_library_agent_compiles():
    """Test that new library agent code compiles successfully."""
    result = subprocess.run(['npm', 'run', 'build'], 
                          capture_output=True, text=True)
    
    assert result.returncode == 0
    assert "error" not in result.stderr.lower()
    
    # Verify new library code is included
    with open('friTap/_ssl_log.js', 'r') as f:
        content = f.read()
    
    assert 'NewLibraryHooks' in content
    assert 'installNewLibraryHooks' in content
```

### Step 8: Update Documentation

Update the documentation to include the new library:

```markdown
<!-- docs/libraries/new-library.md -->
# NewLibrary Support

friTap supports NewLibrary SSL/TLS implementation with full key extraction and traffic analysis capabilities.

## Overview

NewLibrary is a [description of the library, its features, common usage].

## Supported Features

| Platform | Key Extraction | Traffic Capture | Notes |
|----------|---------------|-----------------|-------|
| Linux    | ✅ Full       | ✅ Full         | All versions |
| Windows  | ✅ Full       | ✅ Full         | Windows 10+ |
| Android  | ✅ Full       | ✅ Full         | API 21+ |
| macOS    | ⚠️ Limited    | ✅ Full         | Key extraction partial |
| iOS      | ⚠️ Limited    | ✅ Full         | Requires jailbreak |

## Usage Examples

### Basic Key Extraction

```bash
# Linux/Windows application
fritap -k newlibrary_keys.log target_app

# Android application
fritap -m -k newlibrary_keys.log com.example.app
```

### Traffic Analysis

```bash
# Full traffic capture with keys
fritap -k keys.log -p traffic.pcap target_app

# Live analysis with Wireshark
fritap -l target_app
```

## Implementation Details

NewLibrary hooks are implemented using:
- Symbol-based detection (preferred)
- Pattern-based detection (for stripped libraries)
- Multiple architecture support (x86, x64, ARM, ARM64)

## Troubleshooting

Common issues and solutions:

### Library Not Detected

```bash
# Check if library is loaded
fritap --list-libraries target_app

# Enable debug output
fritap -do -v target_app
```

### Pattern-Based Hooking

For stripped NewLibrary implementations:

```bash
# Generate patterns with BoringSecretHunter
mkdir -p binary results
cp libnewssl.so binary/
docker run --rm -v "$(pwd)/binary":/usr/local/src/binaries -v "$(pwd)/results":/host_output boringsecrethunter

# Use generated patterns
fritap --patterns results/libnewssl.so_patterns.json -k keys.log target_app
```
```

Update the main library support matrix:

```markdown
<!-- docs/libraries/index.md -->
| Library     | Linux | Windows | macOS | Android | iOS |
|-------------|-------|---------|-------|---------|-----|
| OpenSSL     | Full  | R/W     | TBI   | Full    | TBI |
| BoringSSL   | Full  | R/W     | KeyEo | Full    | KeyEo |
| NSS         | Full  | R/W     | TBI   | TBA     | TBI |
| GnuTLS      | R/W   | R/W     | TBI   | Full    | TBI |
| NewLibrary  | Full  | Full    | KeyEo | Full    | KeyEo |
```

## Adding Platform Support

When adding support for a new platform (operating system or architecture):

### Step 1: Platform Analysis

Research the new platform's characteristics:

```bash
# Analyze target platform
uname -a                    # System information
file /path/to/executable    # Binary format
ldd /path/to/executable     # Library dependencies
readelf -h /path/to/executable  # ELF header (Linux)

# Study platform-specific SSL libraries
find /usr -name "*ssl*" 2>/dev/null
find /lib -name "*ssl*" 2>/dev/null
```

### Step 2: Platform Detection

Add platform detection to TypeScript agent:

```typescript
// agent/util/process_infos.ts
export function isNewPlatform(): boolean {
    // Platform-specific detection logic
    return Process.platform === "new_platform_name" && 
           // Additional platform-specific checks
           checkNewPlatformFeatures();
}

function checkNewPlatformFeatures(): boolean {
    try {
        // Platform-specific API availability checks
        // For example, check for specific system calls, libraries, or features
        return true;
    } catch (error) {
        return false;
    }
}
```

### Step 3: Platform-Specific Code

Create platform-specific directory and implementations:

```typescript
// agent/new_platform/ssl_libraries_new_platform.ts
import { log, devlog } from "../util/log.js";

export function installNewPlatformSSLHooks(): boolean {
    devlog("[NewPlatform] Starting SSL library detection");
    
    let hookCount = 0;
    
    // Platform-specific SSL library detection
    hookCount += installOpenSSLNewPlatform() ? 1 : 0;
    hookCount += installBoringSSLNewPlatform() ? 1 : 0;
    // Add other libraries...
    
    if (hookCount > 0) {
        log(`[NewPlatform] Installed hooks for ${hookCount} SSL libraries`);
        return true;
    } else {
        devlog("[NewPlatform] No SSL libraries found");
        return false;
    }
}

function installOpenSSLNewPlatform(): boolean {
    // Platform-specific OpenSSL module names and paths
    const platformModules = [
        "platform_libssl.so",
        "/platform/path/to/libssl.so"
    ];
    
    for (const moduleName of platformModules) {
        try {
            const module = Process.getModuleByName(moduleName);
            if (module) {
                // Use existing OpenSSL hooks with platform adaptations
                return installOpenSSLHooks(moduleName);
            }
        } catch (error) {
            // Continue to next module
        }
    }
    
    return false;
}
```

### Step 4: Python Platform Handler

Create Python platform handler:

```python
# friTap/platforms/new_platform.py
import logging
import subprocess
from typing import List, Dict, Any, Optional

class NewPlatformHandler:
    """Handle NewPlatform-specific operations."""
    
    def __init__(self):
        self.platform_name = "NewPlatform"
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
    def setup_environment(self) -> bool:
        """Setup NewPlatform environment for analysis."""
        try:
            # Platform-specific setup
            self._check_permissions()
            self._setup_dependencies()
            return True
        except Exception as e:
            self.logger.error(f"NewPlatform setup failed: {e}")
            return False
            
    def get_process_list(self) -> List[Dict[str, Any]]:
        """Get list of running processes on NewPlatform."""
        try:
            # Platform-specific process enumeration
            result = subprocess.run(['platform_ps_command'], 
                                  capture_output=True, text=True)
            
            processes = []
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    processes.append({
                        'pid': int(parts[0]),
                        'name': parts[1],
                        'full_path': ' '.join(parts[1:])
                    })
            
            return processes
            
        except Exception as e:
            self.logger.error(f"Failed to get process list: {e}")
            return []
            
    def attach_to_process(self, target: str) -> Optional[Any]:
        """Attach to process on NewPlatform."""
        try:
            import frida
            
            # Platform-specific attachment logic
            device = frida.get_device("new_platform_device_id")
            
            # Handle different target formats
            if target.isdigit():
                # PID
                session = device.attach(int(target))
            else:
                # Process name
                session = device.attach(target)
                
            return session
            
        except Exception as e:
            self.logger.error(f"Failed to attach to process: {e}")
            return None
            
    def _check_permissions(self) -> None:
        """Check required permissions for NewPlatform."""
        # Platform-specific permission checks
        pass
        
    def _setup_dependencies(self) -> None:
        """Setup required dependencies for NewPlatform."""
        # Platform-specific dependency setup
        pass

def is_new_platform() -> bool:
    """Check if running on NewPlatform."""
    import platform
    return platform.system().lower() == "newplatform"
```

### Step 5: Integration Points

Update main SSL_Logger class:

```python
# friTap/ssl_logger.py
from .platforms.new_platform import NewPlatformHandler, is_new_platform

class SSL_Logger:
    def _detect_platform(self):
        """Detect current platform and return appropriate handler."""
        if is_android():
            return AndroidHandler()
        elif is_ios():
            return IOSHandler()
        elif is_new_platform():
            return NewPlatformHandler()
        else:
            return DesktopHandler()  # Default for Linux/Windows/macOS
```

### Step 6: Platform Testing

Create platform-specific tests:

```python
# tests/platforms/test_new_platform.py
import pytest
import platform
from friTap.platforms.new_platform import NewPlatformHandler, is_new_platform

@pytest.mark.skipif(not is_new_platform(), reason="NewPlatform only")
class TestNewPlatformSupport:
    """Test NewPlatform-specific functionality."""
    
    def test_platform_detection(self):
        """Test NewPlatform detection."""
        assert is_new_platform() == True
        
    def test_environment_setup(self):
        """Test NewPlatform environment setup."""
        handler = NewPlatformHandler()
        assert handler.setup_environment() == True
        
    def test_process_enumeration(self):
        """Test process enumeration on NewPlatform."""
        handler = NewPlatformHandler()
        processes = handler.get_process_list()
        
        assert isinstance(processes, list)
        if len(processes) > 0:
            assert 'pid' in processes[0]
            assert 'name' in processes[0]
            
    @pytest.mark.slow
    def test_ssl_analysis_workflow(self):
        """Test complete SSL analysis workflow on NewPlatform."""
        from friTap.ssl_logger import SSL_Logger
        
        logger = SSL_Logger("test_app")
        # Test platform-specific workflow
        assert logger.platform_handler.platform_name == "NewPlatform"
```

## Adding Analysis Features

When adding new analysis capabilities to friTap:

### Step 1: Feature Design

Design the new analysis feature:

```python
# friTap/analysis/new_feature.py
import logging
from typing import Dict, List, Any, Optional

class NewAnalysisFeature:
    """Implement new analysis capability."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.results: Dict[str, Any] = {}
        
    def analyze(self, ssl_data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Perform new type of analysis on SSL data."""
        try:
            # Core analysis logic
            results = self._process_data(ssl_data, metadata)
            
            # Format results
            formatted_results = self._format_results(results)
            
            # Update internal state
            self.results.update(formatted_results)
            
            return formatted_results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"error": str(e)}
            
    def _process_data(self, data: bytes, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Core data processing logic."""
        # Implement specific analysis algorithm
        # Example: pattern detection, anomaly analysis, etc.
        
        processed_results = {
            "data_size": len(data),
            "analysis_timestamp": time.time(),
            "patterns_found": self._find_patterns(data),
            "statistics": self._calculate_statistics(data)
        }
        
        return processed_results
        
    def _format_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format analysis results for output."""
        return {
            "feature_name": "new_analysis_feature",
            "version": "1.0.0",
            "results": results,
            "summary": self._generate_summary(results)
        }
        
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        return {
            "total_analyzed": len(self.results),
            "feature_specific_metrics": self._calculate_metrics()
        }
```

### Step 2: CLI Integration

Add command-line interface for the new feature:

```python
# friTap/friTap.py (add new CLI argument)
@click.option(
    "--new-feature",
    is_flag=True,
    help="Enable new analysis feature"
)
@click.option(
    "--new-feature-config",
    type=str,
    help="Configuration file for new analysis feature"
)
def main(..., new_feature: bool, new_feature_config: Optional[str]):
    """Main friTap entry point."""
    
    # Initialize new feature if enabled
    analysis_features = []
    
    if new_feature:
        config = {}
        if new_feature_config:
            with open(new_feature_config, 'r') as f:
                config = json.load(f)
                
        from friTap.analysis.new_feature import NewAnalysisFeature
        analysis_features.append(NewAnalysisFeature(config))
    
    # Pass features to SSL_Logger
    logger = SSL_Logger(target, analysis_features=analysis_features)
```

### Step 3: Output Integration

Integrate with existing output formats:

```python
# friTap/ssl_logger.py
def _process_ssl_data(self, data: bytes, metadata: Dict[str, Any]) -> None:
    """Process SSL data with all enabled analysis features."""
    
    # Existing processing...
    self._log_to_pcap(data, metadata)
    self._log_keys(metadata.get('keys', []))
    
    # Run analysis features
    for feature in self.analysis_features:
        try:
            feature_results = feature.analyze(data, metadata)
            
            # Add to JSON output
            if self.json_output:
                self._add_to_json_output("analysis", feature_results)
                
            # Log significant findings
            if feature_results.get("significant_finding"):
                self.logger.info(f"Analysis finding: {feature_results['summary']}")
                
        except Exception as e:
            self.logger.error(f"Analysis feature failed: {e}")

def _add_to_json_output(self, category: str, data: Dict[str, Any]) -> None:
    """Add analysis results to JSON output."""
    if category not in self.session_data:
        self.session_data[category] = []
    
    self.session_data[category].append({
        "timestamp": time.time(),
        "data": data
    })
```

### Step 4: Feature Testing

Create comprehensive tests for the new feature:

```python
# tests/analysis/test_new_feature.py
import pytest
from friTap.analysis.new_feature import NewAnalysisFeature

class TestNewAnalysisFeature:
    """Test new analysis feature."""
    
    def test_feature_initialization(self):
        """Test feature initialization with config."""
        config = {"param1": "value1", "param2": 42}
        feature = NewAnalysisFeature(config)
        
        assert feature.config == config
        assert hasattr(feature, 'results')
        
    def test_data_analysis(self):
        """Test data analysis functionality."""
        feature = NewAnalysisFeature({})
        
        test_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        metadata = {"src": "192.168.1.1", "dst": "8.8.8.8"}
        
        results = feature.analyze(test_data, metadata)
        
        assert "feature_name" in results
        assert "results" in results
        assert results["results"]["data_size"] == len(test_data)
        
    def test_results_formatting(self):
        """Test results formatting."""
        feature = NewAnalysisFeature({})
        
        raw_results = {
            "data_size": 100,
            "patterns_found": ["pattern1", "pattern2"]
        }
        
        formatted = feature._format_results(raw_results)
        
        assert "feature_name" in formatted
        assert "version" in formatted
        assert "summary" in formatted
        
    def test_error_handling(self):
        """Test error handling in analysis."""
        feature = NewAnalysisFeature({})
        
        # Test with invalid data
        results = feature.analyze(None, {})
        
        assert "error" in results
```

## Best Practices for Feature Development

### 1. Incremental Development
- Start with basic functionality
- Add platform support incrementally
- Test thoroughly at each stage
- Document as you develop

### 2. Compatibility Considerations
- Maintain backward compatibility
- Test with existing features
- Consider performance impact
- Follow established patterns

### 3. Error Handling
- Graceful degradation
- Comprehensive logging
- User-friendly error messages
- Recovery mechanisms

### 4. Testing Strategy
- Unit tests for all components
- Integration tests for workflows
- Platform-specific testing
- Performance benchmarking

### 5. Documentation Requirements
- API documentation
- Usage examples
- Troubleshooting guides
- Platform-specific notes

## Next Steps

After adding new features:

1. **Test thoroughly**: Use the [Testing Guide](testing.md)
2. **Update documentation**: Follow [Documentation Guide](documentation.md)
3. **Submit for review**: Use [Pull Request Process](pull-requests.md)
4. **Monitor performance**: Check for regressions
5. **Gather feedback**: From community and maintainers

For more information:
- **[Development Setup](development-setup.md)**: Environment configuration
- **[Coding Standards](coding-standards.md)**: Code quality guidelines
- **[Testing Guide](testing.md)**: Comprehensive testing strategies