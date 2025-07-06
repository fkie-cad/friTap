"""
Unit tests for SSL_Logger class.

Tests the core SSL logging functionality including initialization,
JSON output, device detection, and logging configuration.
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open

# Import friTap modules
from friTap.ssl_logger import SSL_Logger
from friTap.about import __version__


class TestSSLLoggerInitialization:
    """Test SSL_Logger initialization and configuration."""
    
    def test_basic_initialization(self):
        """Test basic SSL_Logger initialization with defaults."""
        logger = SSL_Logger("test_app")
        
        assert logger.target_app == "test_app"
        assert logger.verbose is False
        assert logger.spawn is False
        assert logger.json_output is None
        assert logger.running is True
        
    def test_initialization_with_verbose(self):
        """Test SSL_Logger initialization with verbose enabled."""
        logger = SSL_Logger("test_app", verbose=True)
        
        assert logger.target_app == "test_app"
        assert logger.verbose is True
        
    def test_initialization_with_spawn(self):
        """Test SSL_Logger initialization with spawn enabled."""
        logger = SSL_Logger("test_app", spawn=True)
        
        assert logger.target_app == "test_app"
        assert logger.spawn is True
        
    @patch('builtins.open', new_callable=mock_open)
    def test_initialization_with_json_output(self, mock_file):
        """Test SSL_Logger with JSON output file."""
        logger = SSL_Logger("test_app", json_output="output.json")
        
        mock_file.assert_called_with("output.json", "w")
        assert logger.json_output == "output.json"
        
    def test_initialization_with_mobile(self):
        """Test SSL_Logger with mobile flag."""
        logger = SSL_Logger("test_app", mobile=True)
        
        assert logger.target_app == "test_app"
        assert logger.mobile is True


class TestJSONOutputFunctionality:
    """Test JSON output feature implementation."""
    
    @patch('builtins.open', new_callable=mock_open)
    def test_json_session_data_structure(self, mock_file):
        """Test JSON session data structure initialization."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        # Verify session data structure
        assert "friTap_version" in logger.session_data
        assert "session_info" in logger.session_data
        assert "ssl_sessions" in logger.session_data
        assert "connections" in logger.session_data
        assert "statistics" in logger.session_data
        
        # Verify version is set correctly
        assert logger.session_data["friTap_version"] == __version__
        
        # Verify session info contains target app
        assert logger.session_data["session_info"]["target_app"] == "test_app"
        
    @patch('builtins.open', new_callable=mock_open)
    def test_json_session_data_defaults(self, mock_file):
        """Test JSON session data default values."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        session_data = logger.session_data
        
        # Check default values
        assert session_data["ssl_sessions"] == []
        assert session_data["connections"] == []
        assert session_data["statistics"]["total_connections"] == 0
        assert session_data["statistics"]["total_keys_extracted"] == 0
        assert session_data["statistics"]["libraries_detected"] == []
        
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_write_json_output(self, mock_json_dump, mock_file):
        """Test writing JSON output to file."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        # Simulate writing JSON data
        logger._write_json_output()
        
        # Verify json.dump was called with session data
        mock_json_dump.assert_called_once()
        call_args = mock_json_dump.call_args
        assert call_args[0][0] == logger.session_data  # First argument should be session_data
        
    @patch('builtins.open', new_callable=mock_open)
    def test_json_output_file_creation_error(self, mock_file):
        """Test handling of JSON file creation errors."""
        mock_file.side_effect = PermissionError("Permission denied")
        
        with pytest.raises(PermissionError):
            SSL_Logger("test_app", json_output="/root/no_permission.json")


class TestDeviceDetection:
    """Test device and platform detection functionality."""
    
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_local_device_detection(self, mock_get_device):
        """Test local device detection."""
        mock_device = MagicMock()
        mock_device.id = "local"
        mock_device.name = "Local System"
        mock_get_device.return_value = mock_device
        
        logger = SSL_Logger("test_app")
        device = logger._get_device()
        
        mock_get_device.assert_called_once()
        assert device.id == "local"
        
    @patch('friTap.ssl_logger.frida.get_usb_device')
    def test_mobile_device_detection(self, mock_get_usb_device):
        """Test mobile device detection."""
        mock_device = MagicMock()
        mock_device.id = "usb:1234"
        mock_device.name = "Android Device"
        mock_get_usb_device.return_value = mock_device
        
        logger = SSL_Logger("com.example.app", mobile=True)
        device = logger._get_device()
        
        mock_get_usb_device.assert_called_once()
        assert device.id == "usb:1234"
        
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_device_detection_error(self, mock_get_device):
        """Test device detection error handling."""
        mock_get_device.side_effect = Exception("Device not found")
        
        logger = SSL_Logger("test_app")
        
        with pytest.raises(Exception, match="Device not found"):
            logger._get_device()


class TestProcessManagement:
    """Test process attachment and management."""
    
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_process_attachment_by_name(self, mock_get_device):
        """Test process attachment by name."""
        mock_device = MagicMock()
        mock_process = MagicMock()
        mock_process.pid = 1234
        mock_process.name = "test_app"
        
        mock_device.attach.return_value = mock_process
        mock_get_device.return_value = mock_device
        
        logger = SSL_Logger("test_app")
        process = logger._attach_to_process()
        
        mock_device.attach.assert_called_with("test_app")
        assert process.pid == 1234
        
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_process_attachment_by_pid(self, mock_get_device):
        """Test process attachment by PID."""
        mock_device = MagicMock()
        mock_process = MagicMock()
        mock_process.pid = 1234
        
        mock_device.attach.return_value = mock_process
        mock_get_device.return_value = mock_device
        
        logger = SSL_Logger(1234)  # PID instead of name
        process = logger._attach_to_process()
        
        mock_device.attach.assert_called_with(1234)
        assert process.pid == 1234
        
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_process_spawn(self, mock_get_device):
        """Test process spawning functionality."""
        mock_device = MagicMock()
        mock_device.spawn.return_value = 5678
        mock_process = MagicMock()
        mock_process.pid = 5678
        
        mock_device.attach.return_value = mock_process
        mock_get_device.return_value = mock_device
        
        logger = SSL_Logger("test_app", spawn=True)
        process = logger._spawn_and_attach()
        
        mock_device.spawn.assert_called_with("test_app")
        mock_device.attach.assert_called_with(5678)
        assert process.pid == 5678


class TestLoggingConfiguration:
    """Test logging configuration and output."""
    
    @patch('friTap.ssl_logger.logging')
    def test_logging_setup_verbose(self, mock_logging):
        """Test logging setup with verbose enabled."""
        mock_logger = MagicMock()
        mock_logging.getLogger.return_value = mock_logger
        
        logger = SSL_Logger("test_app", verbose=True)
        logger._setup_logging()
        
        # Verify logging was configured for verbose output
        mock_logger.setLevel.assert_called()
        
    @patch('friTap.ssl_logger.logging')
    def test_logging_setup_quiet(self, mock_logging):
        """Test logging setup with verbose disabled."""
        mock_logger = MagicMock()
        mock_logging.getLogger.return_value = mock_logger
        
        logger = SSL_Logger("test_app", verbose=False)
        logger._setup_logging()
        
        # Verify logging was configured appropriately
        mock_logger.setLevel.assert_called()
        
    def test_log_message_formatting(self):
        """Test log message formatting."""
        logger = SSL_Logger("test_app")
        
        # Test different log levels
        test_message = "Test log message"
        formatted = logger._format_log_message(test_message, "INFO")
        
        assert test_message in formatted
        assert "INFO" in formatted


class TestSSLSessionManagement:
    """Test SSL session tracking and management."""
    
    @patch('builtins.open', new_callable=mock_open)
    def test_ssl_session_creation(self, mock_file):
        """Test SSL session creation and tracking."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        session_id = "session_123"
        session_data = {
            "id": session_id,
            "cipher": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3"
        }
        
        logger._add_ssl_session(session_data)
        
        # Verify session was added to session data
        assert len(logger.session_data["ssl_sessions"]) == 1
        assert logger.session_data["ssl_sessions"][0]["id"] == session_id
        
    @patch('builtins.open', new_callable=mock_open)
    def test_connection_tracking(self, mock_file):
        """Test connection tracking functionality."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        connection_data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "93.184.216.34",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP"
        }
        
        logger._add_connection(connection_data)
        
        # Verify connection was tracked
        assert len(logger.session_data["connections"]) == 1
        assert logger.session_data["connections"][0]["dst_port"] == 443
        
    @patch('builtins.open', new_callable=mock_open)
    def test_statistics_update(self, mock_file):
        """Test statistics tracking and updates."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        # Update statistics
        logger._update_statistics("connections", 1)
        logger._update_statistics("keys_extracted", 5)
        logger._add_detected_library("OpenSSL")
        
        stats = logger.session_data["statistics"]
        assert stats["total_connections"] == 1
        assert stats["total_keys_extracted"] == 5
        assert "OpenSSL" in stats["libraries_detected"]


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_invalid_target_app(self):
        """Test handling of invalid target application."""
        # Test with None
        with pytest.raises((TypeError, ValueError)):
            SSL_Logger(None)
            
        # Test with empty string
        with pytest.raises((TypeError, ValueError)):
            SSL_Logger("")
            
    @patch('builtins.open', new_callable=mock_open)
    def test_json_output_with_invalid_path(self, mock_file):
        """Test JSON output with invalid file path."""
        mock_file.side_effect = FileNotFoundError("Invalid path")
        
        with pytest.raises(FileNotFoundError):
            SSL_Logger("test_app", json_output="/nonexistent/path/output.json")
            
    @patch('friTap.ssl_logger.frida.get_local_device')
    def test_frida_connection_error(self, mock_get_device):
        """Test Frida connection error handling."""
        mock_get_device.side_effect = Exception("Frida daemon not running")
        
        logger = SSL_Logger("test_app")
        
        with pytest.raises(Exception, match="Frida daemon not running"):
            logger._get_device()


class TestCleanup:
    """Test cleanup and resource management."""
    
    @patch('builtins.open', new_callable=mock_open)
    def test_cleanup_resources(self, mock_file):
        """Test proper cleanup of resources."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        # Simulate some activity
        logger._add_ssl_session({"id": "test", "cipher": "AES"})
        
        # Test cleanup
        logger.cleanup()
        
        # Verify cleanup was performed
        # (Implementation depends on actual cleanup logic)
        
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_json_finalization(self, mock_json_dump, mock_file):
        """Test JSON output finalization."""
        logger = SSL_Logger("test_app", json_output="test.json")
        
        # Add some test data
        logger._add_ssl_session({"id": "test", "cipher": "AES"})
        
        # Finalize JSON output
        logger.finalize_json_output()
        
        # Verify JSON was written
        mock_json_dump.assert_called()


class TestIntegrationPoints:
    """Test integration points with other components."""
    
    @patch('friTap.ssl_logger.frida')
    def test_agent_script_loading(self, mock_frida):
        """Test agent script loading and injection."""
        mock_device = MagicMock()
        mock_process = MagicMock()
        mock_script = MagicMock()
        
        mock_frida.get_local_device.return_value = mock_device
        mock_device.attach.return_value = mock_process
        mock_process.create_script.return_value = mock_script
        
        logger = SSL_Logger("test_app")
        logger._load_agent_script()
        
        # Verify script was created and loaded
        mock_process.create_script.assert_called()
        mock_script.load.assert_called()
        
    @patch('friTap.android.Android')
    def test_android_integration(self, mock_android):
        """Test integration with Android module."""
        mock_android_instance = MagicMock()
        mock_android.return_value = mock_android_instance
        
        logger = SSL_Logger("com.example.app", mobile=True)
        android_helper = logger._get_android_helper()
        
        # Verify Android helper was created
        mock_android.assert_called()
        assert android_helper == mock_android_instance