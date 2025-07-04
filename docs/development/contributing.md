# Contributing to friTap

We welcome contributions to friTap! This guide will help you get started with contributing code, documentation, bug reports, and feature requests.

## Quick Contributing Guide

### 🐛 Found a Bug?

1. **Check existing issues** on [GitHub Issues](https://github.com/fkie-cad/friTap/issues)
2. **Create a detailed bug report** with reproduction steps
3. **Include system information** (OS, Python version, friTap version)
4. **Provide sample code or applications** if possible

### 💡 Have a Feature Idea?

1. **Search existing feature requests** to avoid duplicates
2. **Open a feature request issue** with detailed description
3. **Explain the use case** and why it would benefit users
4. **Discuss implementation approaches** with maintainers

### 🔧 Want to Contribute Code?

1. **Fork the repository** and create a feature branch
2. **Make your changes** following our coding standards
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Submit a pull request** with clear description

## Development Setup

### Prerequisites

```bash
# Python development environment
python3 -m venv fritap_dev
source fritap_dev/bin/activate  # Linux/macOS
# fritap_dev\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Install friTap in development mode
pip install -e .
```

### Repository Structure

```
friTap/
├── friTap/                 # Main Python package directory
│   ├── __init__.py
│   ├── friTap.py          # Main CLI application
│   ├── ssl_logger.py      # Core SSL logging functionality
│   ├── android.py         # Android-specific features
│   ├── pcap.py           # PCAP handling
│   ├── _ssl_log.js       # Compiled Frida agent (generated)
│   └── _ssl_log_legacy.js # Legacy Frida agent (generated)
├── agent/                  # TypeScript Frida agent source code
│   ├── ssl_log.ts         # Main agent entry point
│   ├── android/           # Android-specific hooks
│   ├── ios/              # iOS-specific hooks
│   ├── linux/            # Linux-specific hooks
│   ├── macos/            # macOS-specific hooks
│   ├── windows/          # Windows-specific hooks
│   ├── ssl_lib/          # SSL library implementations
│   ├── shared/           # Shared utilities and functions
│   ├── misc/             # Socket tracing and utilities
│   └── util/             # Utility functions
├── compile_agent.sh       # Agent compilation script (Unix)
├── compile_agent.bat      # Agent compilation script (Windows)
├── package.json          # Node.js dependencies for TypeScript
├── tsconfig.json         # TypeScript configuration
├── docs/                 # Documentation (MkDocs)
├── ground_truth/         # Test applications for different platforms
├── requirements.txt      # Python dependencies
└── setup.py             # Python package configuration
```

### Development Dependencies

**Python Development Tools:**
```bash
# Core development tools
pip install pytest pytest-cov black flake8 mypy

# Documentation tools
pip install mkdocs mkdocs-material

# Frida and testing tools
pip install frida-tools

# Development utilities
pip install pre-commit setuptools wheel twine
```

**TypeScript/Node.js Dependencies (for agent development):**
```bash
# Install Node.js dependencies
npm install

# Key dependencies include:
# - @types/frida-gum: TypeScript definitions for Frida
# - frida-compile: Compiles TypeScript to JavaScript
# - typescript: TypeScript compiler

# Compile the agent
npm run build
# or manually:
./compile_agent.sh  # Unix/Linux/macOS
compile_agent.bat   # Windows
```

## Coding Standards

### TypeScript Code Style (Frida Agent)

The Frida agent is written in TypeScript and compiled with frida-compile. Follow these conventions:

**File Organization:**
```typescript
// agent/ssl_lib/new_library.ts
import { log } from "../util/log";
import { SharedStructures } from "../shared/shared_structures";

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

**TypeScript Conventions:**
- Use **strict TypeScript** with proper type annotations
- Follow **camelCase** for variables and functions
- Use **PascalCase** for classes and interfaces
- Add **JSDoc comments** for public methods
- Use **arrow functions** for callbacks
- Prefer **const** over **let** where possible

**Frida-specific Guidelines:**
```typescript
// Use Frida's type system
const sslRead = Module.getExportByName("libssl.so", "SSL_read");

// Proper hook implementation
Interceptor.attach(sslRead, {
    onEnter(args) {
        this.ssl = args[0];
        this.buffer = args[1];
        this.bufferSize = args[2];
    },
    
    onLeave(retval) {
        if (retval.toInt32() > 0) {
            const data = this.buffer.readByteArray(retval.toInt32());
            // Process data
        }
    }
});
```

**Agent Compilation:**
```bash
# Always compile after making changes
./compile_agent.sh

# Verify compilation succeeded
ls -la friTap/_ssl_log.js

# Test with a simple application
python -m friTap.friTap -k test.log curl https://httpbin.org/get
```

### Python Code Style

We follow [PEP 8](https://pep8.org/) with some specific conventions:

```python
# Use Black for code formatting
black friTap/

# Use flake8 for linting
flake8 friTap/

# Use mypy for type checking
mypy friTap/
```

### Code Formatting

**Line Length**: 88 characters (Black default)

**Import Order**:
```python
# Standard library imports
import os
import sys
import json

# Third-party imports
import frida
import click

# Local application imports
from .ssl_logger import SSL_Logger
from .android import Android
```

**Function Documentation**:
```python
def extract_ssl_keys(target_app: str, output_file: str) -> bool:
    """Extract SSL/TLS keys from target application.
    
    Args:
        target_app: Name or path of target application
        output_file: Path to save extracted keys
        
    Returns:
        True if keys were successfully extracted, False otherwise
        
    Raises:
        FridaError: If Frida injection fails
        FileNotFoundError: If target application not found
    """
    pass
```

### Logging Standards

```python
import logging

# Use module-level logger
logger = logging.getLogger(__name__)

# Log levels
logger.debug("Detailed information for debugging")
logger.info("General information about program execution")
logger.warning("Something unexpected happened, but program continues")
logger.error("Serious problem occurred")
logger.critical("Program cannot continue")
```

### Error Handling

```python
# Use specific exception types
try:
    result = risky_operation()
except FridaError as e:
    logger.error(f"Frida operation failed: {e}")
    return False
except PermissionError as e:
    logger.error(f"Permission denied: {e}")
    return False
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise
```

## Testing Strategy

### Testing Challenges

friTap presents unique testing challenges due to:

1. **Multi-platform support** (Linux, Windows, macOS, Android, iOS)
2. **Different CPU architectures** (x86, x64, ARM, ARM64)
3. **Dynamic instrumentation** requiring running processes
4. **SSL library diversity** with different implementations
5. **Platform-specific dependencies** (root access, jailbreak, etc.)

### Testing Architecture

We use a **multi-layered testing approach** that addresses these challenges:

#### 1. Unit Tests (Python Components)

Test Python components in isolation with mocked dependencies:

```python
# tests/test_ssl_logger.py
import pytest
from unittest.mock import Mock, patch, MagicMock
from friTap.ssl_logger import SSL_Logger

class TestSSLLogger:
    """Test suite for SSL_Logger class."""
    
    def test_initialization(self):
        """Test SSL_Logger initialization."""
        logger = SSL_Logger("test_app")
        assert logger.target_app == "test_app"
        assert logger.running is True
        
    def test_json_output_initialization(self):
        """Test JSON output file creation."""
        with patch('builtins.open', create=True) as mock_open:
            logger = SSL_Logger("test_app", json_output="test.json")
            mock_open.assert_called_with("test.json", "w")
        
    @patch('friTap.ssl_logger.frida')
    def test_frida_device_detection(self, mock_frida):
        """Test Frida device detection."""
        mock_device = MagicMock()
        mock_frida.get_local_device.return_value = mock_device
        
        logger = SSL_Logger("test_app")
        logger._detect_platform()
        
        mock_frida.get_local_device.assert_called_once()

class TestAndroid:
    """Test Android-specific functionality."""
    
    @patch('subprocess.run')
    def test_adb_check_root(self, mock_subprocess):
        """Test ADB root access checking."""
        from friTap.android import Android
        
        # Mock successful root check
        mock_subprocess.return_value.stdout = "uid=0(root)"
        android = Android()
        
        assert android.adb_check_root() is True
```

#### 2. Agent Tests (TypeScript Validation)

Test TypeScript compilation and basic agent functionality:

```bash
# tests/test_agent_compilation.py
import subprocess
import os
import pytest

class TestAgentCompilation:
    """Test TypeScript agent compilation."""
    
    def test_agent_compiles_successfully(self):
        """Test that TypeScript agent compiles without errors."""
        result = subprocess.run(['./compile_agent.sh'], 
                              capture_output=True, text=True)
        assert result.returncode == 0
        assert os.path.exists('friTap/_ssl_log.js')
        
    def test_compiled_agent_syntax(self):
        """Test that compiled agent has valid JavaScript syntax."""
        with open('friTap/_ssl_log.js', 'r') as f:
            content = f.read()
        
        # Basic syntax validation
        assert 'function' in content or '=>' in content
        assert content.strip().endswith(';') or content.strip().endswith('}')
```

#### 3. Ground Truth Tests (Real Applications)

Use the `ground_truth/` applications for realistic testing:

```python
# tests/test_ground_truth.py
import pytest
import subprocess
import platform
import os

class TestGroundTruthApplications:
    """Test friTap against known test applications."""
    
    @pytest.mark.skipif(platform.system() != "Linux", 
                       reason="Linux ground truth test")
    def test_linux_openssl_client(self):
        """Test against Linux OpenSSL ground truth application."""
        if not os.path.exists('ground_truth/example_app_linux/openssl_impl'):
            pytest.skip("Linux ground truth app not built")
            
        # Start SSL server in background
        server = subprocess.Popen([
            'ground_truth/example_app_linux/sslserver'
        ])
        
        try:
            # Test friTap against client
            result = subprocess.run([
                'python', '-m', 'friTap.friTap', 
                '-k', 'test_keys.log',
                '--timeout', '10',
                'ground_truth/example_app_linux/openssl_impl'
            ], capture_output=True, text=True, timeout=15)
            
            assert result.returncode == 0
            
            # Verify key extraction
            with open('test_keys.log', 'r') as f:
                keys = f.read()
            assert 'CLIENT_RANDOM' in keys
            
        finally:
            server.terminate()
            server.wait()

    @pytest.mark.android
    @pytest.mark.skipif(not has_android_device(), 
                       reason="Android device required")
    def test_android_ground_truth(self):
        """Test against Android ground truth application."""
        # Install test APK
        subprocess.run(['adb', 'install', '-r', 
                       'ground_truth/example_app_android/app/build/outputs/apk/debug/app-debug.apk'])
        
        # Run friTap test
        result = subprocess.run([
            'python', '-m', 'friTap.friTap',
            '-m', '-k', 'android_test.log',
            '--timeout', '30',
            'com.example.sslplayground'
        ], capture_output=True, text=True, timeout=45)
        
        # Verify results
        assert result.returncode == 0
        assert os.path.exists('android_test.log')

def has_android_device():
    """Check if Android device is connected."""
    try:
        result = subprocess.run(['adb', 'devices'], 
                              capture_output=True, text=True)
        return len(result.stdout.split('\n')) > 2
    except FileNotFoundError:
        return False
```

#### 4. Platform-Specific Test Suites

Organize tests by platform with appropriate markers:

```python
# pytest.ini or pyproject.toml
[tool.pytest.ini_options]
markers = [
    "linux: Linux-specific tests",
    "windows: Windows-specific tests", 
    "macos: macOS-specific tests",
    "android: Android-specific tests (requires device)",
    "ios: iOS-specific tests (requires jailbroken device)",
    "slow: Slow tests requiring real SSL connections",
    "ground_truth: Tests against ground truth applications",
    "requires_root: Tests requiring root/admin privileges"
]
```

#### 5. Mock-based Architecture Tests

Test SSL library detection and hooking logic with mocks:

```python
# tests/test_library_detection.py
class TestLibraryDetection:
    """Test SSL library detection mechanisms."""
    
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_openssl_detection(self, mock_device):
        """Test OpenSSL library detection."""
        # Mock process with OpenSSL
        mock_process = MagicMock()
        mock_module = MagicMock()
        mock_module.name = "libssl.so.1.1"
        mock_module.base = 0x7f0000000000
        
        mock_process.enumerate_modules.return_value = [mock_module]
        mock_device.return_value.attach.return_value = mock_process
        
        logger = SSL_Logger("test_app")
        # Test detection logic
        
    @patch('subprocess.run')
    def test_android_library_detection(self, mock_subprocess):
        """Test Android SSL library detection."""
        # Mock Android environment
        mock_subprocess.return_value.stdout = "libssl.so\nlibcrypto.so"
        
        from friTap.android import Android
        android = Android()
        
        # Test library enumeration
```

### Running Tests

#### Local Development Testing

```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock pytest-timeout

# Run unit tests only (fast)
pytest tests/unit/ -v

# Run with coverage
pytest --cov=friTap --cov-report=html tests/unit/

# Run platform-specific tests
pytest -m linux tests/  # Linux only
pytest -m "not android and not ios" tests/  # Desktop only

# Run ground truth tests (requires built applications)
pytest -m ground_truth tests/ --timeout=60
```

#### Cross-Platform Testing

```bash
# Linux testing
./scripts/test_linux.sh

# Windows testing (PowerShell)
.\scripts\test_windows.ps1

# Android testing (requires device)
./scripts/test_android.sh

# macOS testing
./scripts/test_macos.sh
```

#### Continuous Integration

For CI/CD, we use **GitHub Actions** with platform-specific runners:

```yaml
# .github/workflows/test.yml
name: friTap Tests

on: [push, pull_request]

jobs:
  test-python:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10', 3.11]
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov
    - name: Run unit tests
      run: pytest tests/unit/ --cov=friTap
      
  test-agent-compilation:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    - name: Install TypeScript dependencies
      run: npm install
    - name: Compile agent
      run: ./compile_agent.sh
    - name: Verify compilation
      run: |
        test -f friTap/_ssl_log.js
        test -s friTap/_ssl_log.js

  test-ground-truth-linux:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build ground truth applications
      run: |
        cd ground_truth/example_app_linux
        make all
    - name: Test against ground truth
      run: |
        pytest tests/ground_truth/test_linux.py -v
```

### Test Data and Fixtures

#### SSL Library Test Fixtures

```python
# tests/fixtures/ssl_libraries.py
import pytest

@pytest.fixture
def mock_openssl_module():
    """Mock OpenSSL module for testing."""
    from unittest.mock import MagicMock
    module = MagicMock()
    module.name = "libssl.so.1.1"
    module.base = 0x7f0000000000
    module.exports = {
        "SSL_read": 0x7f0000001000,
        "SSL_write": 0x7f0000001100,
        "SSL_get_cipher": 0x7f0000001200
    }
    return module

@pytest.fixture
def sample_ssl_keys():
    """Sample SSL key log data for testing."""
    return """CLIENT_RANDOM 0123456789abcdef... master_secret
CLIENT_RANDOM fedcba9876543210... master_secret"""

@pytest.fixture  
def sample_json_output():
    """Sample JSON output structure for testing."""
    return {
        "friTap_version": "1.3.4.2",
        "session_info": {"target_app": "test_app"},
        "connections": [],
        "key_extractions": [],
        "statistics": {"total_connections": 0}
    }
```

### Manual Testing Procedures

#### Platform-Specific Manual Tests

**Linux Manual Testing:**
```bash
# Test OpenSSL
curl https://httpbin.org/get &
python -m friTap.friTap -k curl_keys.log curl

# Test Firefox
firefox &
python -m friTap.friTap -k firefox_keys.log firefox
```

**Android Manual Testing:**
```bash
# Install and test
adb install ground_truth/example_app_android/app/build/outputs/apk/debug/app-debug.apk
python -m friTap.friTap -m -k android_test.log com.example.sslplayground
```

**Windows Manual Testing:**
```powershell
# Test Edge
Start-Process msedge
python -m friTap.friTap -k edge_keys.log msedge.exe
```

### Testing Best Practices

#### 1. Test Isolation
- Each test should be independent
- Clean up generated files after tests
- Use temporary directories for output files
- Mock external dependencies

#### 2. Platform Considerations  
- Use pytest markers for platform-specific tests
- Skip tests gracefully when platform requirements aren't met
- Test both native and emulated environments where possible

#### 3. Performance Testing
- Set reasonable timeouts for SSL connection tests
- Test with various SSL library versions
- Monitor memory usage during long-running tests

#### 4. Security Testing
- Test with certificate pinning scenarios
- Verify proper handling of invalid certificates
- Test anti-analysis evasion capabilities

This testing strategy provides comprehensive coverage while addressing the unique challenges of testing a multi-platform dynamic instrumentation tool.

## Adding New Features

### SSL/TLS Library Support

When adding support for a new SSL/TLS library:

1. **Research the Library**:
   ```bash
   # Analyze library structure
   objdump -T new_library.so | grep -E "(ssl|tls|read|write)"
   
   # Study function signatures
   readelf -s new_library.so | grep FUNC
   
   # Test with ground truth application
   cd ground_truth/example_app_linux
   # Add new library test case
   ```

2. **Create TypeScript Implementation**:
   ```typescript
   // agent/ssl_lib/new_library.ts
   import { log } from "../util/log";
   import { SharedStructures } from "../shared/shared_structures";
   
   export class NewLibraryHooks {
       private moduleName: string;
       private addresses: { [key: string]: NativePointer } = {};
       
       constructor(moduleName: string) {
           this.moduleName = moduleName;
           this.addresses = this.getAddresses();
       }
       
       private getAddresses(): { [key: string]: NativePointer } {
           const addresses: { [key: string]: NativePointer } = {};
           
           try {
               // Try symbol-based detection first
               addresses["NewSSL_Read"] = Module.getExportByName(this.moduleName, "NewSSL_Read");
               addresses["NewSSL_Write"] = Module.getExportByName(this.moduleName, "NewSSL_Write");
           } catch (error) {
               log(`Symbol-based detection failed for ${this.moduleName}: ${error}`);
               return {};
           }
           
           return addresses;
       }
       
       public install(): boolean {
           if (Object.keys(this.addresses).length === 0) {
               log(`No addresses found for ${this.moduleName}`);
               return false;
           }
           
           this.hookSSLRead();
           this.hookSSLWrite();
           
           log(`Successfully installed hooks for ${this.moduleName}`);
           return true;
       }
       
       private hookSSLRead(): void {
           const readAddress = this.addresses["NewSSL_Read"];
           if (!readAddress) return;
           
           Interceptor.attach(readAddress, {
               onEnter(args) {
                   this.ssl = args[0];
                   this.buffer = args[1];
                   this.bufferSize = args[2];
               },
               
               onLeave(retval) {
                   if (retval.toInt32() > 0) {
                       const data = this.buffer.readByteArray(retval.toInt32());
                       // Use shared functions for data processing
                       SharedStructures.logSSLRead(this.ssl, data);
                   }
               }
           });
       }
       
       private hookSSLWrite(): void {
           const writeAddress = this.addresses["NewSSL_Write"];
           if (!writeAddress) return;
           
           Interceptor.attach(writeAddress, {
               onEnter(args) {
                   this.ssl = args[0];
                   const data = args[1].readByteArray(args[2].toInt32());
                   SharedStructures.logSSLWrite(this.ssl, data);
               }
           });
       }
   }
   ```

3. **Add Platform-Specific Integration**:
   ```typescript
   // agent/linux/new_library_linux.ts
   import { NewLibraryHooks } from "../ssl_lib/new_library";
   
   export function installNewLibraryLinux(): boolean {
       const possibleNames = ["libnewssl.so", "libnewssl.so.1", "libnewssl.so.1.0"];
       
       for (const name of possibleNames) {
           try {
               const module = Process.getModuleByName(name);
               if (module) {
                   const hooks = new NewLibraryHooks(name);
                   return hooks.install();
               }
           } catch (error) {
               // Continue to next possible name
           }
       }
       
       return false;
   }
   ```

4. **Update Main Agent**:
   ```typescript
   // agent/ssl_log.ts (add to main detection loop)
   import { installNewLibraryLinux } from "./linux/new_library_linux";
   import { installNewLibraryAndroid } from "./android/new_library_android";
   // ... other platform imports
   
   // In main detection function:
   if (isLinux()) {
       installNewLibraryLinux();
   } else if (isAndroid()) {
       installNewLibraryAndroid();
   }
   // ... other platforms
   ```

5. **Compile and Test**:
   ```bash
   # Compile the agent
   ./compile_agent.sh
   
   # Test with ground truth application
   python -m friTap.friTap -k test_keys.log ground_truth/new_library_test_app
   
   # Verify key extraction
   grep "CLIENT_RANDOM" test_keys.log
   ```

6. **Add Tests**:
   ```python
   # tests/test_new_library.py
   def test_new_library_detection():
       """Test detection of NewLibrary SSL."""
       with patch('friTap.ssl_logger.frida') as mock_frida:
           # Mock module detection
           mock_process = MagicMock()
           mock_module = MagicMock()
           mock_module.name = "libnewssl.so"
           
           mock_process.enumerate_modules.return_value = [mock_module]
           mock_frida.get_local_device.return_value.attach.return_value = mock_process
           
           logger = SSL_Logger("test_app")
           # Test detection logic
   ```

7. **Update Documentation**:
   - Add library to support matrix in `docs/index.md` and `docs/libraries/index.md`
   - Create library-specific guide in `docs/libraries/new_library.md`
   - Update platform guides with examples
   - Add to `docs/libraries/others.md` if it's a specialized library

### Platform Support

When adding support for a new platform:

1. **Platform-Specific Code**:
   ```python
   class NewPlatformHandler:
       """Handle NewPlatform-specific operations."""
       
       def __init__(self):
           self.platform_name = "NewPlatform"
           
       def setup_environment(self):
           """Setup NewPlatform environment for analysis."""
           pass
           
       def get_process_list(self):
           """Get list of running processes on NewPlatform."""
           pass
   ```

2. **Integration Points**:
   ```python
   # In main SSL_Logger class
   def _detect_platform(self):
       """Detect current platform."""
       if self._is_new_platform():
           return NewPlatformHandler()
       # ... other platforms
   ```

3. **Platform Testing**:
   ```python
   @pytest.mark.skipif(not is_new_platform(), reason="NewPlatform only")
   def test_new_platform_features():
       """Test NewPlatform-specific features."""
       pass
   ```

### Analysis Features

When adding new analysis capabilities:

1. **Feature Design**:
   ```python
   class NewAnalysisFeature:
       """Implement new analysis capability."""
       
       def __init__(self, config):
           self.config = config
           
       def analyze(self, ssl_data):
           """Perform new type of analysis."""
           results = self._process_data(ssl_data)
           return self._format_results(results)
   ```

2. **CLI Integration**:
   ```python
   # Add new CLI argument
   parser.add_argument(
       "--new-feature",
       action="store_true",
       help="Enable new analysis feature"
   )
   ```

3. **Output Integration**:
   ```python
   # Add to JSON output
   if self.new_feature_enabled:
       self.session_data["new_analysis"] = new_feature.analyze(data)
   ```

## Documentation Guidelines

### Writing Documentation

**Style Guide**:
- Use clear, concise language
- Include practical examples
- Provide troubleshooting tips
- Use consistent formatting

**Structure**:
```markdown
# Feature Name

Brief description of the feature.

## Overview

Detailed explanation of what the feature does.

## Usage

### Basic Usage
```bash
fritap --new-feature target_app
```

### Advanced Usage
```bash
fritap --new-feature --options value target_app
```

## Examples

### Example 1: Common Use Case
Description and code example.

### Example 2: Advanced Use Case
Description and code example.

## Troubleshooting

Common issues and solutions.

## Next Steps

Links to related documentation.
```

### Documentation Tools

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy
```

### API Documentation

Use docstrings with type hints:

```python
def extract_keys(
    target: str,
    output_file: Optional[str] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    """Extract SSL/TLS keys from target application.
    
    This function performs real-time SSL/TLS key extraction using
    dynamic instrumentation with Frida.
    
    Args:
        target: Target application name, path, or PID
        output_file: Optional file to save extracted keys
        verbose: Enable verbose logging output
        
    Returns:
        Dictionary containing extracted keys and metadata:
        {
            "keys": ["CLIENT_RANDOM ...", ...],
            "metadata": {"sessions": 5, "libraries": ["OpenSSL"]},
            "errors": []
        }
        
    Raises:
        FridaError: When Frida injection fails
        PermissionError: When insufficient privileges
        
    Example:
        >>> result = extract_keys("firefox", "keys.log", True)
        >>> print(f"Extracted {len(result['keys'])} keys")
        Extracted 12 keys
    """
    pass
```

## Pull Request Process

### Before Submitting

1. **Code Quality**:
   ```bash
   # Format code
   black friTap/
   
   # Check linting
   flake8 friTap/
   
   # Run type checking
   mypy friTap/
   
   # Run tests
   pytest --cov=friTap
   ```

2. **Documentation**:
   - Update relevant documentation
   - Add examples for new features
   - Update changelog

3. **Testing**:
   - Add tests for new functionality
   - Ensure all tests pass
   - Test on multiple platforms if possible

### Pull Request Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update

## Testing

- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Manual testing performed

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings introduced
```

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and checks
2. **Code Review**: Maintainers review code and provide feedback
3. **Discussion**: Address feedback and make necessary changes
4. **Approval**: Maintainers approve and merge

## Community Guidelines

### Code of Conduct

- **Be respectful** to all community members
- **Be constructive** in feedback and discussions
- **Be inclusive** and welcoming to newcomers
- **Focus on the technical merit** of contributions

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Pull Requests**: Code contributions and reviews
- **Email**: daniel.baier@fkie.fraunhofer.de for direct contact

### Getting Help

**For Users**:
- Check [documentation](https://fkie-cad.github.io/friTap)
- Search [existing issues](https://github.com/fkie-cad/friTap/issues)
- Ask questions in [GitHub Discussions](https://github.com/fkie-cad/friTap/discussions)

**For Contributors**:
- Read this contributing guide
- Check [development documentation](development.md)
- Join discussions on pull requests
- Contact maintainers for major changes

## Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Update Version**:
   ```python
   # In friTap/about.py
   __version__ = "1.4.0"
   ```

2. **Update Changelog**:
   ```markdown
   ## [1.4.0] - 2024-12-XX
   ### Added
   - New SSL library support
   - Enhanced JSON output
   
   ### Fixed
   - Bug fixes and improvements
   ```

3. **Create Release**:
   ```bash
   # Tag release
   git tag -a v1.4.0 -m "Release v1.4.0"
   git push origin v1.4.0
   
   # Build distribution
   python setup.py sdist bdist_wheel
   
   # Upload to PyPI
   twine upload dist/*
   ```

## Advanced Contributing Topics

### Performance Optimization

When optimizing performance:

```python
# Use profiling to identify bottlenecks
import cProfile
import pstats

def profile_function():
    pr = cProfile.Profile()
    pr.enable()
    
    # Code to profile
    result = expensive_operation()
    
    pr.disable()
    stats = pstats.Stats(pr)
    stats.sort_stats('cumulative')
    stats.print_stats()
    
    return result
```

### Security Considerations

When handling sensitive data:

```python
# Clear sensitive data from memory
import ctypes

def clear_memory(data):
    """Securely clear sensitive data from memory."""
    if isinstance(data, str):
        data = data.encode()
    
    # Overwrite memory location
    ctypes.memset(id(data), 0, len(data))
```

### Cross-Platform Compatibility

```python
import platform
import os

def get_platform_specific_path():
    """Get platform-specific path for friTap data."""
    system = platform.system()
    
    if system == "Windows":
        return os.path.join(os.environ["APPDATA"], "friTap")
    elif system == "Darwin":  # macOS
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support", "friTap")
    else:  # Linux and others
        return os.path.join(os.path.expanduser("~"), ".fritap")
```

## Acknowledgments

### Contributors

We thank all contributors who have helped improve friTap:

- Core maintainers and developers
- Community contributors and bug reporters
- Documentation writers and translators
- Beta testers and feedback providers

### Attribution

friTap builds upon and acknowledges:

- **[Frida](https://frida.re/)**: Dynamic instrumentation framework
- **[SSL_Logger](https://github.com/google/ssl_logger)**: Original inspiration
- **[BoringSecretHunter](https://github.com/fkie-cad/BoringSecretHunter)**: Pattern generation tool

## Getting Started with Contributing

### First Contribution Ideas

**Good for beginners**:
- Fix typos in documentation
- Add examples for existing features
- Improve error messages
- Add tests for existing functionality

**Intermediate**:
- Add support for new applications
- Improve cross-platform compatibility
- Enhance performance
- Add new output formats

**Advanced**:
- Add support for new SSL libraries
- Implement new analysis features
- Improve security and anti-detection
- Add support for new platforms

### Mentorship

New contributors can get help from:
- Maintainers through GitHub issues and discussions
- Community members in pull request reviews
- Documentation and examples for guidance

We encourage learning and provide constructive feedback to help contributors improve their skills and contributions.

## Next Steps

Ready to contribute? Here's how to start:

1. **[Fork the repository](https://github.com/fkie-cad/friTap/fork)**
2. **[Set up development environment](#development-setup)**
3. **[Choose an issue to work on](https://github.com/fkie-cad/friTap/issues)**
4. **[Submit your first pull request](#pull-request-process)**

Thank you for contributing to friTap! 🚀