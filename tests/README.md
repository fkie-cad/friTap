# friTap Testing Framework

Comprehensive testing suite for friTap that covers unit tests, agent compilation validation, and mock integration testing across multiple platforms.

## Overview

The friTap testing framework is designed to address the unique challenges of testing a multi-platform dynamic instrumentation tool:

- **Multi-platform support** (Linux, Windows, macOS, Android, iOS)
- **Different CPU architectures** (x86, x64, ARM, ARM64)
- **Dynamic instrumentation dependencies** (Frida, running processes)
- **SSL library diversity** (OpenSSL, BoringSSL, NSS, etc.)
- **Hybrid codebase** (Python orchestration + TypeScript agent)

## Test Structure

```
tests/
├── unit/                   # Fast isolated unit tests
│   ├── test_ssl_logger.py  # SSL_Logger class tests
│   ├── test_android.py     # Android module tests
│   └── test_pcap.py        # PCAP handling tests
├── agent/                  # TypeScript agent tests
│   └── test_compilation.py # Agent compilation validation
├── integration/            # Mock integration tests
│   └── test_mock_ssl_analysis.py # End-to-end workflow tests
├── fixtures/               # Test data and mock objects
│   └── mock_objects.py     # Standardized mocks
├── conftest.py             # Pytest configuration and fixtures
├── pytest.ini             # Pytest settings and markers
└── requirements.txt        # Testing dependencies
```

## Test Categories

### 1. Unit Tests (`tests/unit/`)

Fast, isolated tests for individual Python components with mocked dependencies.

**What they test:**
- SSL_Logger initialization and configuration
- Android ADB operations
- PCAP file creation and writing
- JSON output functionality
- Error handling and edge cases

**Characteristics:**
- ⚡ Fast execution (< 1 second per test)
- 🔒 Isolated (no external dependencies)
- 🎯 Focused (single function/method)
- 📊 High coverage target (>90%)

### 2. Agent Compilation Tests (`tests/agent/`)

Validates TypeScript agent compilation and JavaScript output quality.

**What they test:**
- TypeScript compilation success
- JavaScript syntax validation
- Frida API presence in output
- SSL function detection
- Error handling for compilation failures

**Characteristics:**
- 🛠️ Requires Node.js and npm
- ⏱️ Medium execution time (10-30 seconds)
- 🔍 Validates build artifacts
- 🚨 Critical for deployment

### 3. Mock Integration Tests (`tests/integration/`)

End-to-end workflow testing using mocked Frida and system components.

**What they test:**
- Complete SSL analysis workflows
- Library detection logic
- Key extraction processes
- PCAP capture integration
- Platform-specific behaviors

**Characteristics:**
- 🔗 Tests component integration
- 🎭 Uses realistic mocks
- 🌐 Cross-platform scenarios
- ⏱️ Medium execution time

## Running Tests

### Quick Start

```bash
# Install testing dependencies
pip install -r tests/requirements.txt

# Run all fast tests
python run_tests.py --fast

# Run specific test categories
python run_tests.py unit
python run_tests.py agent
python run_tests.py integration
```

### Test Runner Commands

The `run_tests.py` script provides comprehensive test management:

```bash
# Test categories
python run_tests.py unit           # Unit tests only
python run_tests.py agent          # Agent compilation tests
python run_tests.py integration    # Mock integration tests
python run_tests.py platform       # Platform-specific tests
python run_tests.py android        # Android tests (requires device)
python run_tests.py all            # All applicable tests

# Utility commands
python run_tests.py coverage       # Generate coverage report
python run_tests.py lint           # Lint test code
python run_tests.py setup          # Setup test environment
python run_tests.py summary        # Environment summary

# Options
python run_tests.py --verbose      # Detailed output
python run_tests.py --fast         # Skip slow tests
```

### Direct Pytest Usage

```bash
# Run specific test files
pytest tests/unit/test_ssl_logger.py -v

# Run tests with markers
pytest -m "unit and not slow" -v
pytest -m "agent_compilation" -v
pytest -m "mock_integration" -v

# Run with coverage
pytest --cov=friTap --cov-report=html tests/unit/

# Platform-specific tests
pytest -m linux tests/
pytest -m android tests/ --timeout=120
```

## Test Markers

Tests are organized using pytest markers:

- `unit`: Fast isolated unit tests
- `agent_compilation`: TypeScript compilation tests
- `mock_integration`: Mock-based integration tests
- `linux/windows/macos`: Platform-specific tests
- `android/ios`: Mobile platform tests
- `slow`: Tests requiring real connections
- `requires_root`: Tests needing admin privileges
- `ground_truth`: Tests against real applications

## Mock Objects

The testing framework provides comprehensive mock objects in `tests/fixtures/mock_objects.py`:

### Frida Mocks
```python
from tests.fixtures.mock_objects import MockFridaDevice, MockFridaProcess

# Create mock Frida environment
device = MockFridaDevice("local")
process = device.attach("test_app")
script = process.create_script("console.log('test');")
```

### SSL Library Mocks
```python
from tests.fixtures.mock_objects import MockSSLSession, MockKeyExtraction

# Mock SSL session data
session = MockSSLSession("session_123")
key_data = MockKeyExtraction("TLS")
```

### Android Mocks
```python
from tests.fixtures.mock_objects import create_mock_android_environment

# Mock Android environment
android = create_mock_android_environment()
packages = android.list_installed_packages()
```

## Writing Tests

### Unit Test Example

```python
import pytest
from unittest.mock import patch, MagicMock
from friTap.ssl_logger import SSL_Logger

class TestSSLLogger:
    @patch('friTap.ssl_logger.frida')
    def test_initialization(self, mock_frida):
        """Test SSL_Logger initialization."""
        mock_device = MagicMock()
        mock_frida.get_local_device.return_value = mock_device
        
        logger = SSL_Logger("test_app")
        assert logger.target_app == "test_app"
        assert logger.running is True
```

### Mock Integration Test Example

```python
@pytest.mark.mock_integration
@patch('friTap.ssl_logger.frida')
def test_ssl_analysis_workflow(mock_frida):
    """Test complete SSL analysis workflow."""
    # Setup mocks
    mock_device = MagicMock()
    mock_frida.get_local_device.return_value = mock_device
    
    # Test workflow
    logger = SSL_Logger("firefox", json_output="test.json")
    logger._attach_to_target()
    logger._load_agent()
    
    # Verify interactions
    mock_device.attach.assert_called_with("firefox")
```

## Coverage Requirements

- **Unit Tests**: >90% code coverage
- **Integration Tests**: >80% workflow coverage
- **Overall Target**: >85% combined coverage

Generate coverage reports:
```bash
python run_tests.py coverage
open tests/coverage_html/index.html
```

## Platform-Specific Testing

### Linux Testing
```bash
# Standard unit and integration tests
pytest -m "linux or not (android or ios or windows or macos)"

# With real applications (requires setup)
pytest -m "ground_truth and linux" --timeout=60
```

### Android Testing
```bash
# Check device connection
adb devices

# Run Android tests
python run_tests.py android

# Mock Android tests only
pytest -m "android and mock_integration"
```

### Windows Testing
```powershell
# PowerShell on Windows
python run_tests.py platform
pytest -m windows tests/
```

## Continuous Integration

### GitHub Actions Example

```yaml
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
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r tests/requirements.txt
    - name: Run unit tests
      run: python run_tests.py unit --verbose
      
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
    - name: Test agent compilation
      run: python run_tests.py agent --verbose
```

## Troubleshooting

### Common Issues

**1. Import Errors**
```bash
# Install friTap in development mode
pip install -e .

# Verify installation
python -c "import friTap; print('OK')"
```

**2. Agent Compilation Failures**
```bash
# Check Node.js installation
node --version
npm --version

# Install dependencies
npm install

# Manual compilation test
./compile_agent.sh
```

**3. Mock Integration Test Failures**
```bash
# Check Frida availability
python -c "import frida; print('OK')"

# Install Frida if missing
pip install frida-tools
```

**4. Android Test Issues**
```bash
# Check ADB connection
adb devices

# Check device root access
adb shell id

# Enable USB debugging on device
```

### Performance Issues

**Slow Test Execution:**
```bash
# Run only fast tests
python run_tests.py --fast

# Run tests in parallel
pytest -n auto tests/unit/

# Skip slow markers
pytest -m "not slow" tests/
```

**Memory Usage:**
```bash
# Run tests with memory profiling
pytest --memray tests/unit/

# Limit test scope
pytest tests/unit/test_ssl_logger.py::TestSSLLogger::test_basic_functionality
```

## Best Practices

### Test Writing Guidelines

1. **Isolation**: Each test should be independent
2. **Mocking**: Mock external dependencies
3. **Assertions**: Use specific, meaningful assertions
4. **Documentation**: Include docstrings explaining test purpose
5. **Performance**: Keep unit tests under 1 second

### Mock Usage

1. **Realistic**: Mocks should behave like real components
2. **Consistent**: Use standardized mock objects from fixtures
3. **Minimal**: Mock only what's necessary for the test
4. **Verification**: Assert on mock interactions when relevant

### Error Testing

1. **Edge Cases**: Test boundary conditions
2. **Error Paths**: Verify error handling
3. **Recovery**: Test error recovery mechanisms
4. **Resources**: Ensure proper cleanup

## Contributing to Tests

### Adding New Tests

1. **Choose Category**: Unit, agent, or integration
2. **Follow Patterns**: Use existing test structure
3. **Add Markers**: Include appropriate pytest markers
4. **Mock Dependencies**: Use fixture mock objects
5. **Update Documentation**: Add to relevant sections

### Test Review Checklist

- [ ] Tests are properly categorized
- [ ] Mocks are realistic and minimal
- [ ] Edge cases are covered
- [ ] Performance is reasonable
- [ ] Documentation is clear
- [ ] CI compatibility is verified

## Future Improvements

### Planned Enhancements

1. **Ground Truth Testing**: Automated real application testing
2. **Performance Benchmarks**: Regression testing for performance
3. **Fuzzing Integration**: Property-based testing expansion
4. **Visual Testing**: UI/output validation
5. **Load Testing**: High-throughput scenario testing

### Research Areas

1. **Multi-platform CI**: Testing across all platforms automatically
2. **Device Farms**: Automated mobile device testing
3. **Container Testing**: Isolated environment testing
4. **Pattern Validation**: Automated pattern generation testing

---

For questions or contributions to the testing framework, please refer to the [Contributing Guide](../docs/development/contributing.md) or open an issue on GitHub.