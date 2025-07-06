# Coding Standards

This guide outlines the coding standards and style guidelines for friTap development, covering both TypeScript (Frida agent) and Python (host application) code.

## Overview

friTap follows established conventions for both languages:
- **TypeScript**: Frida-specific patterns with strict typing
- **Python**: PEP 8 compliance with Black formatting
- **Documentation**: Clear, consistent, and comprehensive

## TypeScript Standards (Frida Agent)

The Frida agent is written in TypeScript and compiled with frida-compile. It requires special considerations for the Frida runtime environment.

### File Organization

```typescript
// agent/ssl_lib/new_library.ts
import { log, devlog, devlog_error } from "../util/log.js";
import { SharedStructures } from "../shared/shared_structures.js";

export class NewLibraryHooks {
    private moduleName: string;
    private baseAddress: NativePointer;
    
    constructor(moduleName: string) {
        this.moduleName = moduleName;
        this.baseAddress = Module.getBaseAddress(moduleName);
    }
    
    public install(): void {
        this.hookSSLRead();
        this.hookSSLWrite();
    }
    
    private hookSSLRead(): void {
        // Implementation
    }
}
```

### TypeScript Conventions

#### Naming Conventions
- **Variables and functions**: `camelCase`
- **Classes and interfaces**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private members**: prefix with underscore `_privateMethod()`

```typescript
// Good examples
const sslModule = Process.getModuleByName("libssl.so");
class OpenSSLHooks { }
interface ISSLContext { }
const MAX_BUFFER_SIZE = 8192;
private _hookFunction(): void { }

// Avoid
const SSL_module = Process.getModuleByName("libssl.so");  // Inconsistent case
class opensslHooks { }  // Should be PascalCase
const maxBufferSize = 8192;  // Should be UPPER_SNAKE_CASE
```

#### Type Annotations
Use strict TypeScript with proper type annotations:

```typescript
// Always specify types for function parameters and return values
function hookSSLFunction(
    address: NativePointer, 
    name: string,
    onEnter?: (args: InvocationArguments) => void
): boolean {
    // Implementation
    return true;
}

// Use interfaces for complex types
interface SSLContext {
    ssl: NativePointer;
    buffer: NativePointer;
    bufferSize: number;
}

// Use type aliases for unions
type LogLevel = "info" | "debug" | "error";
```

#### Function Style
Prefer arrow functions for callbacks, regular functions for methods:

```typescript
class SSLHooks {
    // Regular method
    public install(): void {
        this.findSSLFunctions();
    }
    
    // Arrow function for Frida callbacks
    private createReadHook = (address: NativePointer): void => {
        Interceptor.attach(address, {
            onEnter: (args) => {
                this.ssl = args[0];
                this.buffer = args[1];
                this.bufferSize = args[2];
            },
            
            onLeave: (retval) => {
                if (retval.toInt32() > 0) {
                    const data = this.buffer.readByteArray(retval.toInt32());
                    this.processData(data);
                }
            }
        });
    }
}
```

### Frida-Specific Guidelines

#### Module and Memory Access
```typescript
// Safe module access with error handling
try {
    const module = Process.getModuleByName("libssl.so");
    const sslRead = module.getExportByName("SSL_read");
    
    Interceptor.attach(sslRead, {
        onEnter(args) {
            // Hook implementation
        }
    });
} catch (error) {
    devlog_error(`Failed to hook SSL_read: ${error}`);
}

// Memory scanning with proper bounds checking
const pattern = "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9";
const matches = Memory.scanSync(module.base, module.size, pattern);

for (const match of matches) {
    // Validate address before using
    if (match.address.isNull()) continue;
    
    Interceptor.attach(match.address, {
        // Hook implementation
    });
}
```

#### Platform Detection
```typescript
// Use consistent OS detection patterns
function isiOS(): boolean {
    return Process.platform === "darwin" && 
           Process.isDebuggerAttached() === false &&
           ObjC.available;
}

function isAndroid(): boolean {
    return Process.platform === "linux" && 
           Java.available;
}

function isLinux(): boolean {
    return Process.platform === "linux" && 
           !Java.available;
}
```

#### Error Handling
```typescript
// Graceful error handling for hook failures
function tryHookFunction(moduleName: string, functionName: string): boolean {
    try {
        const module = Process.getModuleByName(moduleName);
        const func = module.getExportByName(functionName);
        
        Interceptor.attach(func, {
            onEnter(args) {
                // Hook logic
            }
        });
        
        log(`Successfully hooked ${functionName}`);
        return true;
        
    } catch (error) {
        devlog_error(`Failed to hook ${functionName}: ${error}`);
        return false;
    }
}
```

### Documentation Standards

#### JSDoc Comments
Use JSDoc for public methods and complex functions:

```typescript
/**
 * Installs SSL hooks for the specified library module.
 * 
 * @param moduleName - Name of the SSL library module
 * @param options - Configuration options for hooking
 * @returns True if hooks were successfully installed
 * 
 * @example
 * ```typescript
 * const hooks = new OpenSSLHooks();
 * const success = hooks.install("libssl.so", { enableKeyLogging: true });
 * ```
 */
public install(moduleName: string, options: HookOptions = {}): boolean {
    // Implementation
}
```

#### Inline Comments
```typescript
// Use comments to explain complex logic or Frida-specific behavior
const sslCtx = args[0];  // SSL_CTX pointer from first argument

// Pattern-based hook for stripped libraries
const armPattern = "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9";  // ARM64 function prologue

// Check if this is a TLS 1.3 connection (requires different key extraction)
if (version.toInt32() >= 0x0304) {
    this.extractTLS13Keys(sslCtx);
}
```

## Python Standards (Host Application)

The Python host application follows PEP 8 with Black formatting and additional friTap-specific conventions.

### Code Formatting

#### Black Configuration
We use Black with these settings (in `pyproject.toml`):

```toml
[tool.black]
line-length = 88
target-version = ['py37', 'py38', 'py39', 'py310', 'py311']
include = '\.pyi?$'
extend-exclude = '''
/(
  # Exclude compiled agent files
  _ssl_log.*\.js
)/
'''
```

#### Import Organization
Follow this import order (enforced by isort):

```python
# Standard library imports
import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union

# Third-party imports
import frida
import click
from scapy.all import wrpcap

# Local application imports
from friTap.ssl_logger import SSL_Logger
from friTap.android import Android
from friTap.pcap import PCAPProcessor
```

### Naming Conventions

```python
# Variables and functions: snake_case
ssl_logger = SSL_Logger()
target_process = "firefox"

def extract_ssl_keys(target_app: str) -> bool:
    """Extract SSL keys from target application."""
    pass

# Classes: PascalCase
class SSL_Logger:
    def __init__(self):
        pass

# Constants: UPPER_SNAKE_CASE
DEFAULT_TIMEOUT = 30
MAX_BUFFER_SIZE = 8192

# Private methods: leading underscore
class SSL_Logger:
    def _detect_platform(self) -> str:
        """Private method for platform detection."""
        pass
```

### Type Hints

Use comprehensive type hints throughout:

```python
from typing import Dict, List, Optional, Union, Tuple, Any

def extract_ssl_keys(
    target_app: str,
    output_file: Optional[str] = None,
    mobile: bool = False,
    timeout: int = 30
) -> Dict[str, Any]:
    """Extract SSL/TLS keys from target application.
    
    Args:
        target_app: Name or path of target application
        output_file: Optional file to save extracted keys
        mobile: Whether to use mobile analysis mode
        timeout: Maximum time to wait for key extraction
        
    Returns:
        Dictionary containing extracted keys and metadata
        
    Raises:
        FridaError: If Frida injection fails
        PermissionError: If insufficient privileges
    """
    results: Dict[str, Any] = {
        "keys": [],
        "metadata": {},
        "errors": []
    }
    
    return results
```

### Function Documentation

#### Docstring Format
Use Google-style docstrings:

```python
def process_ssl_data(
    data: bytes, 
    connection_info: Dict[str, str],
    output_format: str = "pcap"
) -> Optional[bytes]:
    """Process SSL/TLS data and format for output.
    
    This function takes raw SSL data and processes it according to the
    specified output format. It handles both encrypted and decrypted data.
    
    Args:
        data: Raw SSL/TLS data bytes
        connection_info: Dictionary containing connection metadata with keys:
            - 'src_ip': Source IP address
            - 'dst_ip': Destination IP address  
            - 'src_port': Source port number
            - 'dst_port': Destination port number
        output_format: Output format ('pcap', 'json', 'raw')
        
    Returns:
        Processed data in the specified format, or None if processing fails
        
    Raises:
        ValueError: If output_format is not supported
        ProcessingError: If data processing fails
        
    Example:
        >>> connection = {'src_ip': '192.168.1.1', 'dst_ip': '8.8.8.8', 
        ...               'src_port': '443', 'dst_port': '12345'}
        >>> result = process_ssl_data(data, connection, 'pcap')
        >>> print(f"Processed {len(result)} bytes")
        Processed 1024 bytes
    """
    if output_format not in ["pcap", "json", "raw"]:
        raise ValueError(f"Unsupported output format: {output_format}")
    
    # Implementation
    return processed_data
```

### Error Handling

#### Exception Patterns
```python
# Use specific exception types
try:
    device = frida.get_local_device()
    session = device.attach(target_process)
except frida.ProcessNotFoundError:
    logger.error(f"Process '{target_process}' not found")
    return False
except frida.PermissionDeniedError:
    logger.error("Permission denied - try running as administrator")
    return False
except frida.ServerNotRunningError:
    logger.error("Frida server not running on target device")
    return False
except Exception as e:
    logger.error(f"Unexpected Frida error: {e}")
    raise

# Custom exceptions for friTap-specific errors
class FriTapError(Exception):
    """Base exception for friTap-specific errors."""
    pass

class AgentCompilationError(FriTapError):
    """Raised when TypeScript agent compilation fails."""
    pass

class SSLLibraryNotFoundError(FriTapError):
    """Raised when no supported SSL library is detected."""
    pass
```

### Logging Standards

#### Logger Configuration
```python
import logging

# Use module-level logger
logger = logging.getLogger(__name__)

# Configure logger with appropriate levels
def setup_logging(verbose: bool = False, debug: bool = False):
    """Setup logging configuration for friTap."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

# Use appropriate log levels
logger.debug("Detailed debugging information")
logger.info("General program flow information")
logger.warning("Unexpected situation, but program continues")
logger.error("Serious problem occurred")
logger.critical("Program cannot continue")
```

#### Log Message Formatting
```python
# Good logging practices
logger.info(f"Starting SSL analysis for process: {process_name}")
logger.debug(f"Found {len(modules)} loaded modules")
logger.warning(f"SSL library {lib_name} detected but no symbols found")
logger.error(f"Failed to attach to process {pid}: {error_message}")

# Include context in error messages
try:
    result = risky_operation(param)
except Exception as e:
    logger.error(f"Operation failed for {param}: {e}", exc_info=True)
```

### Class Design

#### Class Structure
```python
class SSL_Logger:
    """Main class for SSL/TLS key extraction and traffic analysis."""
    
    def __init__(
        self, 
        target: str,
        mobile: bool = False,
        verbose: bool = False
    ):
        """Initialize SSL logger.
        
        Args:
            target: Target application name or process ID
            mobile: Enable mobile analysis mode
            verbose: Enable verbose logging
        """
        self.target = target
        self.mobile = mobile
        self.verbose = verbose
        
        # Initialize internal state
        self._session: Optional[frida.core.Session] = None
        self._script: Optional[frida.core.Script] = None
        self._running = False
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def start(self) -> bool:
        """Start SSL logging session."""
        try:
            self._setup_frida_session()
            self._inject_agent()
            self._running = True
            return True
        except Exception as e:
            self.logger.error(f"Failed to start SSL logging: {e}")
            return False
    
    def stop(self) -> None:
        """Stop SSL logging session and cleanup resources."""
        if self._session:
            self._session.detach()
        self._running = False
        
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.stop()
```

## Code Quality Tools

### Automated Formatting

```bash
# Format Python code with Black
black friTap/ tests/

# Sort imports with isort
isort friTap/ tests/

# Lint with flake8
flake8 friTap/ tests/

# Type checking with mypy
mypy friTap/
```

### Pre-commit Configuration

The `.pre-commit-config.yaml` includes:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
        language_version: python3
        
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]
        
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ["--max-line-length=88", "--extend-ignore=E203,W503"]
        
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.0.1
    hooks:
      - id: mypy
        additional_dependencies: [types-requests]
```

### Quality Checklist

Before submitting code:

```bash
# Run full quality check
python run_tests.py lint

# Or run individual tools
black --check friTap/ tests/        # Check formatting
isort --check-only friTap/ tests/   # Check import order
flake8 friTap/ tests/               # Check style and errors
mypy friTap/                        # Check types
pytest tests/                       # Run tests

# TypeScript compilation check
npm run build                       # Verify agent compiles
```

## Testing Standards

### Test Structure

```python
# tests/unit/test_ssl_logger.py
import pytest
from unittest.mock import Mock, patch, MagicMock
from friTap.ssl_logger import SSL_Logger

class TestSSLLogger:
    """Test suite for SSL_Logger class."""
    
    def test_initialization(self):
        """Test SSL_Logger initialization with default parameters."""
        logger = SSL_Logger("test_app")
        assert logger.target == "test_app"
        assert logger.mobile is False
        assert logger.verbose is False
        
    def test_initialization_with_mobile(self):
        """Test SSL_Logger initialization with mobile mode enabled."""
        logger = SSL_Logger("com.example.app", mobile=True)
        assert logger.target == "com.example.app"
        assert logger.mobile is True
        
    @patch('friTap.ssl_logger.frida')
    def test_frida_session_creation(self, mock_frida):
        """Test Frida session creation and attachment."""
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_frida.get_local_device.return_value = mock_device
        mock_device.attach.return_value = mock_session
        
        logger = SSL_Logger("test_app")
        logger._setup_frida_session()
        
        mock_frida.get_local_device.assert_called_once()
        mock_device.attach.assert_called_with("test_app")
```

### Test Naming

```python
# Test method naming pattern: test_<feature>_<condition>_<expected_result>
def test_ssl_key_extraction_with_openssl_returns_keys(self):
def test_mobile_detection_without_device_raises_error(self):
def test_agent_compilation_with_invalid_typescript_fails(self):
def test_pcap_generation_with_valid_data_creates_file(self):
```

## Performance Considerations

### Efficient Patterns

```python
# Use generators for large datasets
def process_ssl_packets(packets: List[bytes]) -> Iterator[Dict[str, Any]]:
    """Process SSL packets efficiently using generator."""
    for packet in packets:
        if is_ssl_packet(packet):
            yield parse_ssl_packet(packet)

# Use context managers for resource management
class SSLAnalyzer:
    def __enter__(self):
        self.session = frida.attach(self.target)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.detach()

# Efficient string operations
def format_ssl_keys(keys: List[str]) -> str:
    """Format SSL keys efficiently."""
    return '\n'.join(f"CLIENT_RANDOM {key}" for key in keys)
```

### Memory Management

```python
# Clear sensitive data from memory when possible
def process_keys(raw_keys: bytes) -> str:
    """Process SSL keys and clear sensitive data."""
    try:
        keys_str = raw_keys.decode('utf-8')
        processed = format_keys(keys_str)
        return processed
    finally:
        # Clear sensitive data
        raw_keys = b'\x00' * len(raw_keys)
```

## Security Guidelines

### Sensitive Data Handling

```python
# Avoid logging sensitive information
logger.debug(f"Processing {len(ssl_data)} bytes of SSL data")  # Good
logger.debug(f"SSL data: {ssl_data}")  # Avoid - exposes sensitive data

# Use secure defaults
def save_keys(keys: List[str], filename: str, mode: int = 0o600) -> bool:
    """Save SSL keys with secure file permissions."""
    try:
        with open(filename, 'w') as f:
            os.chmod(filename, mode)  # Restrict permissions
            f.write('\n'.join(keys))
        return True
    except Exception as e:
        logger.error(f"Failed to save keys: {e}")
        return False
```

### Input Validation

```python
def validate_target(target: str) -> bool:
    """Validate target application parameter."""
    if not target or not isinstance(target, str):
        return False
        
    # Check for potential command injection
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')']
    if any(char in target for char in dangerous_chars):
        return False
        
    return True
```

## Next Steps

After reviewing these coding standards:

1. **Set up quality tools**: Configure Black, flake8, mypy, and pre-commit hooks
2. **Review existing code**: Ensure consistency with these standards
3. **Write tests**: Follow the testing patterns outlined above
4. **Submit contributions**: Use the [Pull Request Process](pull-requests.md) guide

For more detailed information:
- **[Development Setup](development-setup.md)**: Environment configuration
- **[Testing Guide](testing.md)**: Comprehensive testing strategies
- **[Pull Request Process](pull-requests.md)**: Code review and submission