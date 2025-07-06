"""
Unit tests for Android module.

Tests Android-specific functionality including ADB operations,
device detection, and Android SSL library handling.
"""

import subprocess
from unittest.mock import patch, MagicMock

from friTap.android import Android


class TestAndroidInitialization:
    """Test Android class initialization."""
    
    def test_basic_initialization(self):
        """Test basic Android initialization."""
        android = Android()
        
        assert android.device_id is None
        assert android.is_rooted is False
        assert android.adb_available is False
        
    def test_initialization_with_device_id(self):
        """Test Android initialization with specific device ID."""
        android = Android(device_id="emulator-5554")
        
        assert android.device_id == "emulator-5554"


class TestADBOperations:
    """Test ADB-related operations."""
    
    @patch('subprocess.run')
    def test_adb_check_availability_success(self, mock_subprocess):
        """Test successful ADB availability check."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Android Debug Bridge version 1.0.41"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        is_available = android.check_adb_availability()
        
        mock_subprocess.assert_called_with(
            ['adb', 'version'], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        assert is_available is True
        assert android.adb_available is True
        
    @patch('subprocess.run')
    def test_adb_check_availability_failure(self, mock_subprocess):
        """Test ADB availability check when ADB not found."""
        mock_subprocess.side_effect = FileNotFoundError("adb not found")
        
        android = Android()
        is_available = android.check_adb_availability()
        
        assert is_available is False
        assert android.adb_available is False
        
    @patch('subprocess.run')
    def test_adb_check_availability_timeout(self, mock_subprocess):
        """Test ADB availability check timeout."""
        mock_subprocess.side_effect = subprocess.TimeoutExpired('adb', 5)
        
        android = Android()
        is_available = android.check_adb_availability()
        
        assert is_available is False
        
    @patch('subprocess.run')
    def test_adb_devices_list(self, mock_subprocess):
        """Test listing connected Android devices."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """List of devices attached
emulator-5554	device
192.168.1.100:5555	device"""
        mock_subprocess.return_value = mock_result
        
        android = Android()
        devices = android.list_devices()
        
        mock_subprocess.assert_called_with(
            ['adb', 'devices'], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        assert len(devices) == 2
        assert "emulator-5554" in devices
        assert "192.168.1.100:5555" in devices
        
    @patch('subprocess.run')
    def test_adb_devices_list_empty(self, mock_subprocess):
        """Test listing devices when none connected."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "List of devices attached\n"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        devices = android.list_devices()
        
        assert len(devices) == 0
        
    @patch('subprocess.run')
    def test_adb_check_root_success(self, mock_subprocess):
        """Test successful root access check."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "uid=0(root) gid=0(root)"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        is_rooted = android.adb_check_root()
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'id'], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        assert is_rooted is True
        assert android.is_rooted is True
        
    @patch('subprocess.run')
    def test_adb_check_root_failure(self, mock_subprocess):
        """Test root access check when device not rooted."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "uid=2000(shell) gid=2000(shell)"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        is_rooted = android.adb_check_root()
        
        assert is_rooted is False
        assert android.is_rooted is False
        
    @patch('subprocess.run')
    def test_adb_with_device_id(self, mock_subprocess):
        """Test ADB commands with specific device ID."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "uid=0(root) gid=0(root)"
        mock_subprocess.return_value = mock_result
        
        android = Android(device_id="emulator-5554")
        android.adb_check_root()
        
        mock_subprocess.assert_called_with(
            ['adb', '-s', 'emulator-5554', 'shell', 'id'], 
            capture_output=True, 
            text=True, 
            timeout=5
        )


class TestApplicationManagement:
    """Test Android application management."""
    
    @patch('subprocess.run')
    def test_list_installed_packages(self, mock_subprocess):
        """Test listing installed packages."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """package:com.android.chrome
package:com.example.app
package:com.google.android.gm"""
        mock_subprocess.return_value = mock_result
        
        android = Android()
        packages = android.list_installed_packages()
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'pm', 'list', 'packages'], 
            capture_output=True, 
            text=True, 
            timeout=15
        )
        
        assert len(packages) == 3
        assert "com.android.chrome" in packages
        assert "com.example.app" in packages
        assert "com.google.android.gm" in packages
        
    @patch('subprocess.run')
    def test_get_app_pid(self, mock_subprocess):
        """Test getting application PID."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "u0_a123      1234  567  com.example.app"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        pid = android.get_app_pid("com.example.app")
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'ps', '|', 'grep', 'com.example.app'], 
            capture_output=True, 
            text=True, 
            timeout=10,
            shell=True
        )
        
        assert pid == 1234
        
    @patch('subprocess.run')
    def test_get_app_pid_not_running(self, mock_subprocess):
        """Test getting PID when app is not running."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_subprocess.return_value = mock_result
        
        android = Android()
        pid = android.get_app_pid("com.example.app")
        
        assert pid is None
        
    @patch('subprocess.run')
    def test_start_application(self, mock_subprocess):
        """Test starting Android application."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        success = android.start_application("com.example.app")
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'am', 'start', '-n', 'com.example.app/.MainActivity'], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        assert success is True
        
    @patch('subprocess.run')
    def test_start_application_with_activity(self, mock_subprocess):
        """Test starting Android application with specific activity."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        success = android.start_application("com.example.app", "com.example.app.CustomActivity")
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'am', 'start', '-n', 'com.example.app/com.example.app.CustomActivity'], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        
        assert success is True


class TestSSLLibraryDetection:
    """Test Android SSL library detection."""
    
    @patch('subprocess.run')
    def test_detect_ssl_libraries(self, mock_subprocess):
        """Test detecting SSL libraries in Android app."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """/system/lib64/libssl.so
/data/app/com.example.app/lib/arm64/libssl.so
/system/lib64/libcrypto.so
/data/app/com.example.app/lib/arm64/libboringssl.so"""
        mock_subprocess.return_value = mock_result
        
        android = Android()
        libraries = android.detect_ssl_libraries("com.example.app")
        
        assert len(libraries) >= 2
        assert any("libssl.so" in lib for lib in libraries)
        assert any("libboringssl.so" in lib for lib in libraries)
        
    @patch('subprocess.run')
    def test_get_library_path(self, mock_subprocess):
        """Test getting library path in Android app."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "/data/app/com.example.app/lib/arm64/libssl.so"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        path = android.get_library_path("com.example.app", "libssl.so")
        
        assert path == "/data/app/com.example.app/lib/arm64/libssl.so"
        
    @patch('subprocess.run')
    def test_check_library_exports(self, mock_subprocess):
        """Test checking library exports."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """SSL_read
SSL_write
SSL_get_cipher
SSL_get_version"""
        mock_subprocess.return_value = mock_result
        
        android = Android()
        exports = android.check_library_exports("/system/lib64/libssl.so")
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'nm', '-D', '/system/lib64/libssl.so'], 
            capture_output=True, 
            text=True, 
            timeout=15
        )
        
        assert "SSL_read" in exports
        assert "SSL_write" in exports


class TestFileOperations:
    """Test Android file operations."""
    
    @patch('subprocess.run')
    def test_push_file(self, mock_subprocess):
        """Test pushing file to Android device."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        success = android.push_file("local_file.txt", "/sdcard/remote_file.txt")
        
        mock_subprocess.assert_called_with(
            ['adb', 'push', 'local_file.txt', '/sdcard/remote_file.txt'], 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        assert success is True
        
    @patch('subprocess.run')
    def test_pull_file(self, mock_subprocess):
        """Test pulling file from Android device."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        success = android.pull_file("/sdcard/remote_file.txt", "local_file.txt")
        
        mock_subprocess.assert_called_with(
            ['adb', 'pull', '/sdcard/remote_file.txt', 'local_file.txt'], 
            capture_output=True, 
            text=True, 
            timeout=30
        )
        
        assert success is True
        
    @patch('subprocess.run')
    def test_file_exists(self, mock_subprocess):
        """Test checking if file exists on Android device."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "/sdcard/file.txt"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        exists = android.file_exists("/sdcard/file.txt")
        
        mock_subprocess.assert_called_with(
            ['adb', 'shell', 'ls', '/sdcard/file.txt'], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        
        assert exists is True


class TestTcpdumpIntegration:
    """Test tcpdump integration for Android."""
    
    @patch('subprocess.run')
    def test_install_tcpdump(self, mock_subprocess):
        """Test installing tcpdump on Android device."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        success = android.install_tcpdump()
        
        # Should push tcpdump binary to device
        assert mock_subprocess.call_count >= 1
        assert success is True
        
    @patch('subprocess.run')
    def test_start_tcpdump(self, mock_subprocess):
        """Test starting tcpdump on Android device."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        process = android.start_tcpdump("/sdcard/capture.pcap")
        
        # Should start tcpdump in background
        assert mock_subprocess.called
        assert process is not None
        
    @patch('subprocess.run')
    def test_stop_tcpdump(self, mock_subprocess):
        """Test stopping tcpdump on Android device."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        android = Android()
        mock_process = MagicMock()
        
        success = android.stop_tcpdump(mock_process)
        
        mock_process.terminate.assert_called()
        assert success is True


class TestErrorHandling:
    """Test error handling in Android operations."""
    
    @patch('subprocess.run')
    def test_adb_command_failure(self, mock_subprocess):
        """Test handling ADB command failures."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error: device not found"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        devices = android.list_devices()
        
        # Should handle error gracefully
        assert devices == []
        
    @patch('subprocess.run')
    def test_adb_timeout(self, mock_subprocess):
        """Test handling ADB command timeouts."""
        mock_subprocess.side_effect = subprocess.TimeoutExpired('adb', 10)
        
        android = Android()
        success = android.adb_check_root()
        
        assert success is False
        
    def test_invalid_device_id(self):
        """Test handling invalid device ID."""
        android = Android(device_id="invalid-device")
        
        # Should not raise exception during initialization
        assert android.device_id == "invalid-device"
        
    @patch('subprocess.run')
    def test_permission_denied_error(self, mock_subprocess):
        """Test handling permission denied errors."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Permission denied"
        mock_subprocess.return_value = mock_result
        
        android = Android()
        success = android.push_file("test.txt", "/system/test.txt")
        
        assert success is False


class TestUtilityMethods:
    """Test utility methods in Android class."""
    
    def test_get_adb_command_basic(self):
        """Test getting basic ADB command."""
        android = Android()
        cmd = android._get_adb_command(['shell', 'id'])
        
        assert cmd == ['adb', 'shell', 'id']
        
    def test_get_adb_command_with_device(self):
        """Test getting ADB command with device ID."""
        android = Android(device_id="emulator-5554")
        cmd = android._get_adb_command(['shell', 'id'])
        
        assert cmd == ['adb', '-s', 'emulator-5554', 'shell', 'id']
        
    def test_parse_package_name(self):
        """Test parsing package names from pm list output."""
        android = Android()
        
        pm_output = "package:com.example.app"
        package = android._parse_package_name(pm_output)
        
        assert package == "com.example.app"
        
    def test_parse_process_info(self):
        """Test parsing process information from ps output."""
        android = Android()
        
        ps_output = "u0_a123      1234  567  com.example.app"
        pid = android._parse_process_pid(ps_output)
        
        assert pid == 1234
        
    def test_validate_package_name(self):
        """Test package name validation."""
        android = Android()
        
        # Valid package names
        assert android._validate_package_name("com.example.app") is True
        assert android._validate_package_name("com.google.android.gm") is True
        
        # Invalid package names
        assert android._validate_package_name("invalid") is False
        assert android._validate_package_name("") is False
        assert android._validate_package_name(None) is False