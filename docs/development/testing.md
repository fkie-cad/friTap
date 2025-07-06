# Testing Guide

This guide covers friTap's comprehensive testing strategy, addressing the unique challenges of testing a multi-platform dynamic instrumentation tool.

## Overview

friTap presents unique testing challenges due to:

1. **Multi-platform support** (Linux, Windows, macOS, Android, iOS)
2. **Different CPU architectures** (x86, x64, ARM, ARM64)
3. **Dynamic instrumentation** requiring running processes
4. **SSL library diversity** with different implementations
5. **Platform-specific dependencies** (root access, jailbreak, etc.)

## Testing Architecture

We use a **multi-layered testing approach** that addresses these challenges:

### Testing Pyramid

```
    ┌─────────────────────────┐
    │   Ground Truth Tests    │  ← Real applications
    │     (Integration)       │
    ├─────────────────────────┤
    │   Mock Integration      │  ← Simulated workflows
    │       Tests             │
    ├─────────────────────────┤
    │    Agent Tests          │  ← TypeScript compilation
    │   (Compilation)         │
    ├─────────────────────────┤
    │     Unit Tests          │  ← Python components
    │     (Isolated)          │
    └─────────────────────────┘
```

## Test Categories

### 1. Unit Tests (Python Components)

Test Python components in isolation with mocked dependencies.

#### Test Structure

```python
# tests/unit/test_ssl_logger.py
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
```

#### Android Unit Tests

```python
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
        
    @patch('subprocess.run')
    def test_adb_device_detection(self, mock_subprocess):
        """Test Android device detection via ADB."""
        mock_subprocess.return_value.stdout = "List of devices attached\nemulator-5554\tdevice"
        
        from friTap.android import Android
        android = Android()
        devices = android.get_connected_devices()
        
        assert "emulator-5554" in devices
```

### 2. Agent Tests (TypeScript Validation)

Test TypeScript compilation and basic agent functionality.

#### Compilation Tests

```python
# tests/agent/test_compilation.py
import subprocess
import os
import pytest
from pathlib import Path

class TestAgentCompilation:
    """Test TypeScript agent compilation."""
    
    def test_agent_compiles_successfully(self):
        """Test that TypeScript agent compiles without errors."""
        result = subprocess.run(['npm', 'run', 'build'], 
                              capture_output=True, text=True)
        assert result.returncode == 0
        assert "error" not in result.stderr.lower()
        
    def test_compiled_files_exist(self):
        """Test that compilation generates expected files."""
        # Run compilation
        subprocess.run(['npm', 'run', 'build'], check=True)
        
        # Check files exist
        ssl_log_js = Path("friTap/_ssl_log.js")
        ssl_log_legacy_js = Path("friTap/_ssl_log_legacy.js")
        
        assert ssl_log_js.exists()
        assert ssl_log_legacy_js.exists()
        assert ssl_log_js.stat().st_size > 1000  # Non-empty
        
    def test_compiled_agent_syntax(self):
        """Test that compiled agent has valid JavaScript syntax."""
        subprocess.run(['npm', 'run', 'build'], check=True)
        
        with open('friTap/_ssl_log.js', 'r') as f:
            content = f.read()
        
        # Basic syntax validation
        assert 'function' in content or '=>' in content
        assert content.strip().endswith(';') or content.strip().endswith('}')
        
    def test_typescript_linting(self):
        """Test TypeScript code passes linting checks."""
        result = subprocess.run(['npx', 'tsc', '--noEmit'], 
                              capture_output=True, text=True)
        assert result.returncode == 0, f"TypeScript errors: {result.stdout}"
```

#### Agent Functionality Tests

```python
# tests/agent/test_agent_functionality.py
import json
import tempfile
from pathlib import Path

class TestAgentFunctionality:
    """Test compiled agent functionality."""
    
    def test_agent_loads_without_errors(self):
        """Test that agent can be loaded by Frida."""
        import frida
        
        # Load compiled agent
        with open('friTap/_ssl_log.js', 'r') as f:
            agent_code = f.read()
        
        # Test with local device
        device = frida.get_local_device()
        
        # This tests basic syntax and Frida compatibility
        try:
            session = device.attach("nonexistent")  # Will fail, but agent should load
        except frida.ProcessNotFoundError:
            pass  # Expected - we just want to test agent loading
            
    def test_pattern_file_loading(self):
        """Test agent can load pattern files correctly."""
        # Create test pattern file
        test_patterns = {
            "version": "1.0",
            "patterns": {
                "SSL_Read": {
                    "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_patterns, f)
            pattern_file = f.name
        
        try:
            # Test pattern file validation (this would be done by the agent)
            with open(pattern_file, 'r') as f:
                loaded_patterns = json.load(f)
            
            assert loaded_patterns["version"] == "1.0"
            assert "SSL_Read" in loaded_patterns["patterns"]
        finally:
            Path(pattern_file).unlink()
```

### 3. Mock Integration Tests

Test SSL library detection and hooking logic with comprehensive mocks.

#### Library Detection Tests

```python
# tests/integration/test_library_detection.py
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
        mock_module.size = 1024 * 1024
        
        mock_process.enumerate_modules.return_value = [mock_module]
        mock_device.return_value.attach.return_value = mock_process
        
        logger = SSL_Logger("test_app")
        detected_libraries = logger._detect_ssl_libraries()
        
        assert "OpenSSL" in detected_libraries
        assert detected_libraries["OpenSSL"]["module"] == "libssl.so.1.1"
        
    @patch('subprocess.run')
    def test_android_library_detection(self, mock_subprocess):
        """Test Android SSL library detection."""
        # Mock Android environment
        mock_subprocess.return_value.stdout = "libssl.so\nlibcrypto.so\nlibboringssl.so"
        
        from friTap.android import Android
        android = Android()
        libraries = android.enumerate_ssl_libraries()
        
        assert "libssl.so" in libraries
        assert "libboringssl.so" in libraries
        
    @patch('friTap.ssl_logger.frida')
    def test_multiple_ssl_libraries(self, mock_frida):
        """Test detection when multiple SSL libraries are present."""
        mock_process = MagicMock()
        
        # Mock multiple SSL libraries
        modules = [
            MagicMock(name="libssl.so.1.1", base=0x7f0000000000),
            MagicMock(name="libboringssl.so", base=0x7f0001000000),
            MagicMock(name="libnss3.so", base=0x7f0002000000)
        ]
        
        mock_process.enumerate_modules.return_value = modules
        mock_frida.get_local_device.return_value.attach.return_value = mock_process
        
        logger = SSL_Logger("test_app")
        detected = logger._detect_ssl_libraries()
        
        assert len(detected) >= 2  # Should detect multiple libraries
```

#### Workflow Integration Tests

```python
# tests/integration/test_workflows.py
class TestWorkflowIntegration:
    """Test complete friTap workflows with mocks."""
    
    @patch('friTap.ssl_logger.frida')
    @patch('builtins.open', new_callable=mock_open)
    def test_key_extraction_workflow(self, mock_file, mock_frida):
        """Test complete key extraction workflow."""
        # Setup mocks
        mock_session = MagicMock()
        mock_script = MagicMock()
        
        mock_frida.get_local_device.return_value.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        
        # Simulate key extraction
        test_keys = ["CLIENT_RANDOM 12345 abcdef", "CLIENT_RANDOM 67890 fedcba"]
        
        def mock_message_handler(message, data):
            if message['type'] == 'send' and 'ssl_key' in message['payload']:
                return message['payload']['ssl_key']
        
        mock_script.on.side_effect = lambda event, handler: handler
        
        # Test workflow
        logger = SSL_Logger("test_app")
        logger.start_extraction("keys.log")
        
        # Verify script injection
        mock_session.create_script.assert_called_once()
        mock_script.load.assert_called_once()
        
    @patch('friTap.pcap.PCAPProcessor')
    @patch('friTap.ssl_logger.frida')
    def test_pcap_generation_workflow(self, mock_frida, mock_pcap):
        """Test PCAP generation workflow."""
        mock_processor = MagicMock()
        mock_pcap.return_value = mock_processor
        
        # Mock SSL data
        test_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        logger = SSL_Logger("test_app")
        logger.start_pcap_capture("output.pcap")
        
        # Simulate data processing
        logger._process_ssl_data(test_data, {"src": "127.0.0.1", "dst": "8.8.8.8"})
        
        # Verify PCAP processing
        mock_processor.add_packet.assert_called()
```

### 4. Ground Truth Tests

Use the `ground_truth/` applications for realistic testing.

#### Linux Ground Truth Tests

```python
# tests/ground_truth/test_linux.py
import pytest
import subprocess
import platform
import os
import signal
import time
from pathlib import Path

class TestGroundTruthLinux:
    """Test friTap against known Linux test applications."""
    
    @pytest.mark.skipif(platform.system() != "Linux", 
                       reason="Linux ground truth test")
    def test_openssl_client_server(self):
        """Test against Linux OpenSSL ground truth application."""
        ground_truth_dir = Path("ground_truth/example_app_linux")
        
        if not ground_truth_dir.exists():
            pytest.skip("Linux ground truth applications not found")
            
        server_binary = ground_truth_dir / "ssl_server"
        client_binary = ground_truth_dir / "ssl_client"
        
        if not (server_binary.exists() and client_binary.exists()):
            pytest.skip("Ground truth binaries not built")
        
        # Start SSL server in background
        server = subprocess.Popen([str(server_binary), "8443"])
        
        try:
            # Wait for server to start
            time.sleep(2)
            
            # Test friTap against client
            result = subprocess.run([
                'python', '-m', 'friTap.friTap', 
                '-k', 'test_keys.log',
                '--timeout', '10',
                str(client_binary), 'localhost', '8443'
            ], capture_output=True, text=True, timeout=15)
            
            assert result.returncode == 0, f"friTap failed: {result.stderr}"
            
            # Verify key extraction
            keys_file = Path('test_keys.log')
            assert keys_file.exists(), "Key log file not created"
            
            with open(keys_file, 'r') as f:
                keys = f.read()
            assert 'CLIENT_RANDOM' in keys, "No SSL keys extracted"
            
        finally:
            # Cleanup
            server.terminate()
            server.wait()
            
            # Remove test files
            for file in ['test_keys.log']:
                Path(file).unlink(missing_ok=True)
                
    @pytest.mark.skipif(platform.system() != "Linux", 
                       reason="Linux only test")
    def test_curl_https_request(self):
        """Test friTap with curl making HTTPS requests."""
        result = subprocess.run([
            'python', '-m', 'friTap.friTap',
            '-k', 'curl_keys.log',
            '--timeout', '10',
            'curl', 'https://httpbin.org/get'
        ], capture_output=True, text=True, timeout=20)
        
        try:
            assert result.returncode == 0, f"friTap with curl failed: {result.stderr}"
            
            # Check key extraction
            keys_file = Path('curl_keys.log')
            if keys_file.exists():
                with open(keys_file, 'r') as f:
                    keys = f.read()
                    if keys.strip():  # Keys were extracted
                        assert 'CLIENT_RANDOM' in keys
                        
        finally:
            Path('curl_keys.log').unlink(missing_ok=True)
```

#### Android Ground Truth Tests

```python
# tests/ground_truth/test_android.py
@pytest.mark.android
class TestGroundTruthAndroid:
    """Test friTap against Android applications."""
    
    @pytest.mark.skipif(not has_android_device(), 
                       reason="Android device required")
    def test_android_ssl_playground(self):
        """Test against Android SSL playground application."""
        apk_path = "ground_truth/example_app_android/app/build/outputs/apk/debug/app-debug.apk"
        
        if not Path(apk_path).exists():
            pytest.skip("Android test APK not found")
        
        # Install test APK
        install_result = subprocess.run([
            'adb', 'install', '-r', apk_path
        ], capture_output=True, text=True)
        
        assert install_result.returncode == 0, f"APK installation failed: {install_result.stderr}"
        
        try:
            # Run friTap test
            result = subprocess.run([
                'python', '-m', 'friTap.friTap',
                '-m', '-k', 'android_test.log',
                '--timeout', '30',
                'com.example.sslplayground'
            ], capture_output=True, text=True, timeout=45)
            
            # Verify results
            assert result.returncode == 0, f"Android test failed: {result.stderr}"
            
            keys_file = Path('android_test.log')
            if keys_file.exists() and keys_file.stat().st_size > 0:
                with open(keys_file, 'r') as f:
                    keys = f.read()
                assert 'CLIENT_RANDOM' in keys, "No SSL keys extracted from Android app"
                
        finally:
            # Cleanup
            subprocess.run(['adb', 'uninstall', 'com.example.sslplayground'], 
                         capture_output=True)
            Path('android_test.log').unlink(missing_ok=True)

def has_android_device():
    """Check if Android device is connected."""
    try:
        result = subprocess.run(['adb', 'devices'], 
                              capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        # Look for device lines (not header)
        device_lines = [line for line in lines[1:] if '\tdevice' in line]
        return len(device_lines) > 0
    except FileNotFoundError:
        return False
```

## Test Configuration

### pytest Configuration

```ini
# pytest.ini
[tool:pytest]
minversion = 6.0
addopts = -ra -q --strict-markers --strict-config
testpaths = tests
markers =
    linux: Linux-specific tests
    windows: Windows-specific tests
    macos: macOS-specific tests
    android: Android-specific tests (requires device)
    ios: iOS-specific tests (requires jailbroken device)
    slow: Slow tests requiring real SSL connections
    ground_truth: Tests against ground truth applications
    requires_root: Tests requiring root/admin privileges
    unit: Fast unit tests
    integration: Integration tests with mocks
    agent: Agent compilation and functionality tests
```

### Test Environment Setup

```python
# tests/conftest.py
import pytest
import tempfile
import shutil
from pathlib import Path

@pytest.fixture(scope="session")
def temp_dir():
    """Create temporary directory for test files."""
    temp_path = Path(tempfile.mkdtemp(prefix="fritap_test_"))
    yield temp_path
    shutil.rmtree(temp_path)

@pytest.fixture
def mock_ssl_keys():
    """Sample SSL key log data for testing."""
    return """CLIENT_RANDOM 0123456789abcdef... master_secret_data_here
CLIENT_RANDOM fedcba9876543210... another_master_secret"""

@pytest.fixture
def sample_json_output():
    """Sample JSON output structure for testing."""
    return {
        "friTap_version": "1.3.5.0",
        "session_info": {"target_app": "test_app"},
        "connections": [],
        "key_extractions": [],
        "statistics": {"total_connections": 0}
    }
```

## Running Tests

### Quick Development Testing

```bash
# Run fast tests only (unit + agent compilation)
python run_tests.py --fast

# Run specific test categories
python run_tests.py unit           # Unit tests only
python run_tests.py agent          # Agent compilation tests
python run_tests.py integration    # Mock integration tests

# Run with coverage
python run_tests.py coverage
```

### Platform-Specific Testing

```bash
# Run tests for current platform only
pytest -m "not android and not ios" tests/

# Run Linux-specific tests
pytest -m linux tests/

# Run Android tests (requires device)
pytest -m android tests/

# Skip slow tests
pytest -m "not slow" tests/
```

### Comprehensive Testing

```bash
# Run all applicable tests
python run_tests.py all

# Run ground truth tests (requires built applications)
pytest -m ground_truth tests/ --timeout=60

# Cross-platform CI simulation
tox
```

### Development Workflow Testing

```bash
# Watch mode for continuous testing during development
pytest-watch tests/unit/

# Run specific test file
pytest tests/unit/test_ssl_logger.py -v

# Run with debugging output
pytest tests/unit/test_ssl_logger.py::TestSSLLogger::test_specific -v -s

# Profile test performance
pytest --profile tests/unit/
```

## Test Data and Fixtures

### SSL Library Test Fixtures

```python
# tests/fixtures/ssl_libraries.py
import pytest
from unittest.mock import MagicMock

@pytest.fixture
def mock_openssl_module():
    """Mock OpenSSL module for testing."""
    module = MagicMock()
    module.name = "libssl.so.1.1"
    module.base = 0x7f0000000000
    module.size = 1024 * 1024
    module.exports = {
        "SSL_read": 0x7f0000001000,
        "SSL_write": 0x7f0000001100,
        "SSL_get_cipher": 0x7f0000001200
    }
    return module

@pytest.fixture
def mock_boringssl_module():
    """Mock BoringSSL module (statically linked)."""
    module = MagicMock()
    module.name = "libflutter.so"
    module.base = 0x7f0001000000
    module.size = 50 * 1024 * 1024  # Large Flutter library
    module.exports = {}  # No exports (stripped)
    return module
```

### Pattern Test Data

```python
@pytest.fixture
def sample_patterns():
    """Sample pattern file data for testing."""
    return {
        "version": "1.0",
        "architecture": "arm64",
        "platform": "android",
        "library": "libflutter.so",
        "patterns": {
            "SSL_Read": {
                "primary": "1F 20 03 D5 ?? ?? ?? ?? F4 4F 01 A9",
                "fallback": "1F 20 03 D5 ?? ?? ?? ?? ?? ?? ?? ?? F4 4F 01 A9",
                "offset": 0,
                "description": "BoringSSL SSL_read in Flutter"
            }
        }
    }
```

## Performance Testing

### Memory Usage Tests

```python
# tests/performance/test_memory.py
import pytest
import psutil
import time

class TestMemoryUsage:
    """Test memory usage patterns."""
    
    def test_ssl_logger_memory_usage(self):
        """Test that SSL_Logger doesn't leak memory."""
        initial_memory = psutil.Process().memory_info().rss
        
        # Create and destroy multiple SSL_Logger instances
        for i in range(100):
            logger = SSL_Logger(f"test_app_{i}")
            # Simulate some work
            logger._detect_platform()
            del logger
        
        final_memory = psutil.Process().memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Allow some memory increase but not excessive
        assert memory_increase < 50 * 1024 * 1024  # 50MB threshold
```

### Performance Benchmarks

```bash
# Run performance tests
pytest tests/performance/ --benchmark-only

# Generate performance report
python -m pytest tests/performance/ --benchmark-histogram
```

## Continuous Integration

### GitHub Actions Configuration

```yaml
# .github/workflows/test.yml
name: friTap Tests

on: [push, pull_request]

jobs:
  test-python:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: [3.8, 3.9, '3.10', 3.11]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
        
    - name: Install dependencies
      run: |
        pip install -r requirements-dev.txt
        pip install -e .
        
    - name: Run unit tests
      run: python run_tests.py unit
      
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      
  test-agent:
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
      run: npm run build
      
    - name: Test agent compilation
      run: python run_tests.py agent
```

## Test Best Practices

### 1. Test Isolation
- Each test should be independent
- Clean up generated files after tests
- Use temporary directories for output files
- Mock external dependencies

### 2. Platform Considerations  
- Use pytest markers for platform-specific tests
- Skip tests gracefully when requirements aren't met
- Test both native and emulated environments where possible

### 3. Performance Testing
- Set reasonable timeouts for SSL connection tests
- Test with various SSL library versions
- Monitor memory usage during long-running tests

### 4. Security Testing
- Test with certificate pinning scenarios
- Verify proper handling of invalid certificates
- Test anti-analysis evasion capabilities

### 5. Mock Quality
- Mocks should behave like real objects
- Test both success and failure scenarios
- Verify mock calls and arguments

## Troubleshooting Tests

### Common Test Issues

```bash
# Clear pytest cache
pytest --cache-clear

# Run tests in verbose mode
pytest -v -s tests/unit/test_ssl_logger.py

# Debug specific test failure
pytest --pdb tests/unit/test_ssl_logger.py::test_specific_function

# Check test coverage
pytest --cov=friTap --cov-report=html tests/unit/
```

### Agent Compilation Test Issues

```bash
# Clean compilation artifacts
npm run clean
rm -f friTap/_ssl_log*.js

# Rebuild and test
npm run build
python run_tests.py agent

# Check TypeScript errors
npx tsc --noEmit
```

### Ground Truth Test Setup

```bash
# Build Linux ground truth applications
cd ground_truth/example_app_linux
make clean && make all

# Setup Android test environment
adb start-server
adb devices  # Verify device connection
cd ground_truth/example_app_android
./gradlew assembleDebug
```

## Next Steps

After setting up the testing framework:

1. **Run initial tests**: `python run_tests.py --fast`
2. **Set up CI/CD**: Configure GitHub Actions for your fork
3. **Write new tests**: Follow patterns for new features
4. **Monitor coverage**: Aim for >80% code coverage
5. **Regular testing**: Run tests before each commit

For more information:
- **[Development Setup](development-setup.md)**: Environment configuration
- **[Coding Standards](coding-standards.md)**: Code quality guidelines
- **[Adding Features](adding-features.md)**: Implementation patterns