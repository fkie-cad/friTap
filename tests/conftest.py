"""
Pytest configuration and shared fixtures for friTap testing.

This module provides common fixtures, marks, and configuration
for all friTap tests.
"""

import pytest
import platform
import subprocess
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add friTap to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent))

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "linux: Linux-specific tests"
    )
    config.addinivalue_line(
        "markers", "windows: Windows-specific tests"
    )
    config.addinivalue_line(
        "markers", "macos: macOS-specific tests"
    )
    config.addinivalue_line(
        "markers", "android: Android-specific tests (requires device)"
    )
    config.addinivalue_line(
        "markers", "ios: iOS-specific tests (requires jailbroken device)"
    )
    config.addinivalue_line(
        "markers", "slow: Slow tests requiring real SSL connections"
    )
    config.addinivalue_line(
        "markers", "ground_truth: Tests against ground truth applications"
    )
    config.addinivalue_line(
        "markers", "requires_root: Tests requiring root/admin privileges"
    )
    config.addinivalue_line(
        "markers", "agent_compilation: Tests for TypeScript agent compilation"
    )
    config.addinivalue_line(
        "markers", "mock_integration: Mock-based integration tests"
    )

def has_android_device():
    """Check if Android device is connected."""
    try:
        result = subprocess.run(['adb', 'devices'], 
                              capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split('\n')
        return len(lines) > 1 and any('device' in line for line in lines[1:])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def has_nodejs():
    """Check if Node.js is available for agent compilation."""
    try:
        subprocess.run(['node', '--version'], 
                      capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def has_frida():
    """Check if Frida is available."""
    try:
        __import__('frida')
        return True
    except ImportError:
        return False

# Platform detection fixtures
@pytest.fixture
def current_platform():
    """Return current platform information."""
    return {
        'system': platform.system(),
        'machine': platform.machine(),
        'version': platform.version(),
        'python_version': platform.python_version()
    }

@pytest.fixture
def is_linux():
    """Check if running on Linux."""
    return platform.system() == 'Linux'

@pytest.fixture
def is_windows():
    """Check if running on Windows."""
    return platform.system() == 'Windows'

@pytest.fixture
def is_macos():
    """Check if running on macOS."""
    return platform.system() == 'Darwin'

# File system fixtures
@pytest.fixture
def temp_dir():
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def fritap_root():
    """Return path to friTap root directory."""
    return Path(__file__).parent.parent

@pytest.fixture
def agent_dir(fritap_root):
    """Return path to agent directory."""
    return fritap_root / "agent"

@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / "fixtures" / "test_data"

# Mock fixtures for Frida
@pytest.fixture
def mock_frida_device():
    """Mock Frida device."""
    device = MagicMock()
    device.id = "local"
    device.name = "Local System"
    device.type = "local"
    return device

@pytest.fixture
def mock_frida_process():
    """Mock Frida process."""
    process = MagicMock()
    process.pid = 1234
    process.name = "test_app"
    process.enumerate_modules = MagicMock(return_value=[])
    return process

@pytest.fixture
def mock_frida_module():
    """Mock Frida module."""
    module = MagicMock()
    module.name = "libssl.so.1.1"
    module.base = 0x7f0000000000
    module.size = 0x100000
    module.path = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
    return module

@pytest.fixture
def mock_ssl_logger():
    """Mock SSL_Logger instance."""
    with patch('friTap.ssl_logger.SSL_Logger') as mock_class:
        mock_instance = MagicMock()
        mock_instance.target_app = "test_app"
        mock_instance.verbose = False
        mock_instance.spawn = False
        mock_instance.json_output = None
        mock_instance.running = True
        mock_class.return_value = mock_instance
        yield mock_instance

# SSL library fixtures
@pytest.fixture
def openssl_module():
    """Mock OpenSSL module for testing."""
    module = MagicMock()
    module.name = "libssl.so.1.1"
    module.base = 0x7f0000000000
    module.exports = {
        "SSL_read": 0x7f0000001000,
        "SSL_write": 0x7f0000001100,
        "SSL_get_cipher": 0x7f0000001200,
        "SSL_get_version": 0x7f0000001300
    }
    return module

@pytest.fixture
def boringssl_module():
    """Mock BoringSSL module for testing."""
    module = MagicMock()
    module.name = "libssl.so"
    module.base = 0x7f0000000000
    module.exports = {
        "SSL_read": 0x7f0000002000,
        "SSL_write": 0x7f0000002100,
        "SSL_get_cipher": 0x7f0000002200
    }
    return module

@pytest.fixture
def nss_module():
    """Mock NSS module for testing."""
    module = MagicMock()
    module.name = "libnss3.so"
    module.base = 0x7f0000000000
    module.exports = {
        "PR_Read": 0x7f0000003000,
        "PR_Write": 0x7f0000003100,
        "SSL_ForceHandshake": 0x7f0000003200
    }
    return module

# Test data fixtures
@pytest.fixture
def sample_ssl_keys():
    """Sample SSL key log data."""
    return """CLIENT_RANDOM 0123456789abcdef0123456789abcdef01234567 890abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567
CLIENT_RANDOM fedcba9876543210fedcba9876543210fedcba98 76543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98"""

@pytest.fixture
def sample_json_output():
    """Sample JSON output structure."""
    return {
        "friTap_version": "1.3.4.2",
        "session_info": {
            "target_app": "test_app",
            "platform": "Linux",
            "start_time": "2024-01-01T12:00:00Z"
        },
        "connections": [],
        "ssl_sessions": [],
        "key_extractions": [],
        "statistics": {
            "total_connections": 0,
            "total_keys_extracted": 0,
            "libraries_detected": []
        }
    }

@pytest.fixture
def sample_pcap_data():
    """Sample PCAP data for testing."""
    return b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'

# Pattern-based hooking fixtures
@pytest.fixture
def sample_patterns():
    """Sample patterns for pattern-based hooking."""
    return {
        "library": "libssl.so",
        "patterns": {
            "SSL_Read": {
                "primary": "48 89 E5 41 57 41 56 ?? ?? ?? ??",
                "secondary": "55 48 89 E5 ?? ?? ?? ?? 48 89 7D"
            },
            "SSL_Write": {
                "primary": "48 89 E5 41 56 41 55 ?? ?? ?? ??",
                "secondary": "55 48 89 E5 ?? ?? ?? ?? 48 89 75"
            }
        }
    }

# Skip conditions
def pytest_runtest_setup(item):
    """Setup function to handle platform-specific test skipping."""
    if "android" in item.keywords and not has_android_device():
        pytest.skip("Android device not available")
    
    if "requires_root" in item.keywords and os.geteuid() != 0:
        pytest.skip("Root privileges required")
    
    if "agent_compilation" in item.keywords and not has_nodejs():
        pytest.skip("Node.js not available for agent compilation")
    
    if "mock_integration" in item.keywords and not has_frida():
        pytest.skip("Frida not available for integration tests")

# Test environment fixtures
@pytest.fixture
def test_environment():
    """Provide test environment information."""
    return {
        'has_android': has_android_device(),
        'has_nodejs': has_nodejs(),
        'has_frida': has_frida(),
        'platform': platform.system(),
        'python_version': platform.python_version(),
        'is_ci': os.getenv('CI', '').lower() == 'true'
    }

@pytest.fixture
def mock_subprocess():
    """Mock subprocess for testing command execution."""
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        yield mock_run

@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Automatically cleanup test files after each test."""
    yield
    # Cleanup any test files that might have been created
    test_files = ['test_keys.log', 'test_output.json', 'test_traffic.pcap']
    for file in test_files:
        if os.path.exists(file):
            try:
                os.remove(file)
            except OSError:
                pass  # Ignore cleanup errors