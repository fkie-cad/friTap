"""
Mock objects for friTap testing.

Provides standardized mock objects for Frida components,
SSL libraries, and other friTap dependencies.
"""

from unittest.mock import MagicMock
from typing import Dict, List, Any


class MockFridaDevice:
    """Mock Frida device for testing."""
    
    def __init__(self, device_id: str = "local", device_type: str = "local"):
        self.id = device_id
        self.name = f"Mock Device ({device_id})"
        self.type = device_type
        self._processes: Dict[str, MockFridaProcess] = {}
        
    def attach(self, target):
        """Mock attach to process."""
        if isinstance(target, str):
            # Attach by name
            if target not in self._processes:
                self._processes[target] = MockFridaProcess(target, 1234)
            return self._processes[target]
        elif isinstance(target, int):
            # Attach by PID
            process_name = f"process_{target}"
            if process_name not in self._processes:
                self._processes[process_name] = MockFridaProcess(process_name, target)
            return self._processes[process_name]
        else:
            raise ValueError(f"Invalid target type: {type(target)}")
    
    def spawn(self, program, **kwargs):
        """Mock spawn process."""
        pid = 5678
        process_name = program if isinstance(program, str) else f"spawned_{pid}"
        self._processes[process_name] = MockFridaProcess(process_name, pid)
        return pid
    
    def resume(self, pid):
        """Mock resume process."""
        pass
    
    def enumerate_processes(self):
        """Mock enumerate processes."""
        return [
            MockProcessInfo("firefox", 1234),
            MockProcessInfo("chrome", 5678),
            MockProcessInfo("com.example.app", 9012)
        ]


class MockFridaProcess:
    """Mock Frida process for testing."""
    
    def __init__(self, name: str, pid: int):
        self.name = name
        self.pid = pid
        self._modules: List[MockFridaModule] = []
        self._scripts: List[MockFridaScript] = []
        self._setup_default_modules()
        
    def _setup_default_modules(self):
        """Setup default modules based on process name."""
        if "firefox" in self.name.lower():
            self._modules = [
                MockFridaModule("libnss3.so", 0x7f0000000000),
                MockFridaModule("libssl3.so", 0x7f0100000000),
                MockFridaModule("libplc4.so", 0x7f0200000000)
            ]
        elif "chrome" in self.name.lower():
            self._modules = [
                MockFridaModule("libssl.so", 0x7f0000000000),  # BoringSSL
                MockFridaModule("libcrypto.so", 0x7f0100000000)
            ]
        elif "com." in self.name:  # Android app
            self._modules = [
                MockFridaModule("libssl.so", 0x7f0000000000),
                MockFridaModule("libcrypto.so", 0x7f0100000000),
                MockFridaModule("libconscrypt.so", 0x7f0200000000)
            ]
        else:
            # Default OpenSSL
            self._modules = [
                MockFridaModule("libssl.so.1.1", 0x7f0000000000),
                MockFridaModule("libcrypto.so.1.1", 0x7f0100000000)
            ]
    
    def enumerate_modules(self):
        """Mock enumerate modules."""
        return self._modules
    
    def create_script(self, source, **kwargs):
        """Mock create script."""
        script = MockFridaScript(source)
        self._scripts.append(script)
        return script
    
    def get_module_by_name(self, name):
        """Mock get module by name."""
        for module in self._modules:
            if module.name == name:
                return module
        raise Exception(f"Module not found: {name}")


class MockFridaScript:
    """Mock Frida script for testing."""
    
    def __init__(self, source: str):
        self.source = source
        self.loaded = False
        self.message_handlers = []
        
    def load(self):
        """Mock load script."""
        self.loaded = True
        
    def unload(self):
        """Mock unload script."""
        self.loaded = False
        
    def on(self, signal, handler):
        """Mock event handler registration."""
        if signal == "message":
            self.message_handlers.append(handler)
    
    def post(self, message):
        """Mock post message to script."""
        pass
    
    def simulate_message(self, message_type: str, payload: Any):
        """Simulate receiving a message from script."""
        message = {
            'type': message_type,
            'payload': payload
        }
        for handler in self.message_handlers:
            handler(message, None)


class MockFridaModule:
    """Mock Frida module for testing."""
    
    def __init__(self, name: str, base_address: int, size: int = 0x100000):
        self.name = name
        self.base = base_address
        self.size = size
        self.path = f"/usr/lib/x86_64-linux-gnu/{name}"
        self.exports = self._generate_exports()
        
    def _generate_exports(self):
        """Generate mock exports based on module name."""
        exports = {}
        
        if "ssl" in self.name.lower():
            exports.update({
                "SSL_read": self.base + 0x1000,
                "SSL_write": self.base + 0x1100,
                "SSL_get_cipher": self.base + 0x1200,
                "SSL_get_version": self.base + 0x1300,
                "SSL_connect": self.base + 0x1400,
                "SSL_accept": self.base + 0x1500
            })
            
        if "crypto" in self.name.lower():
            exports.update({
                "RAND_bytes": self.base + 0x2000,
                "EVP_CIPHER_CTX_new": self.base + 0x2100,
                "EVP_EncryptInit": self.base + 0x2200
            })
            
        if "nss" in self.name.lower():
            exports.update({
                "PR_Read": self.base + 0x3000,
                "PR_Write": self.base + 0x3100,
                "SSL_ForceHandshake": self.base + 0x3200,
                "NSS_Init": self.base + 0x3300
            })
            
        if "conscrypt" in self.name.lower():
            exports.update({
                "Java_org_conscrypt_NativeCrypto_SSL_read": self.base + 0x4000,
                "Java_org_conscrypt_NativeCrypto_SSL_write": self.base + 0x4100
            })
            
        return exports
    
    def get_export_by_name(self, name: str):
        """Mock get export by name."""
        if name in self.exports:
            return MockNativePointer(self.exports[name])
        raise Exception(f"Export not found: {name}")


class MockNativePointer:
    """Mock Frida NativePointer for testing."""
    
    def __init__(self, address: int):
        self.address = address
        
    def __str__(self):
        return f"0x{self.address:x}"
    
    def __int__(self):
        return self.address
    
    def add(self, offset):
        return MockNativePointer(self.address + offset)
    
    def sub(self, offset):
        return MockNativePointer(self.address - offset)


class MockProcessInfo:
    """Mock process information for testing."""
    
    def __init__(self, name: str, pid: int):
        self.name = name
        self.pid = pid


class MockSSLSession:
    """Mock SSL session data for testing."""
    
    def __init__(self, session_id: str = "session_123"):
        self.id = session_id
        self.cipher_suite = "TLS_AES_256_GCM_SHA384"
        self.protocol_version = "TLSv1.3"
        self.client_random = "0123456789abcdef" * 4
        self.master_secret = "fedcba9876543210" * 8
        self.server_name = "example.com"
        
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'cipher_suite': self.cipher_suite,
            'protocol_version': self.protocol_version,
            'client_random': self.client_random,
            'master_secret': self.master_secret,
            'server_name': self.server_name
        }


class MockConnectionInfo:
    """Mock connection information for testing."""
    
    def __init__(self, src_ip: str = "192.168.1.100", dst_ip: str = "93.184.216.34"):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = 54321
        self.dst_port = 443
        self.protocol = "TCP"
        
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol
        }


class MockAndroidDevice:
    """Mock Android device for testing."""
    
    def __init__(self, device_id: str = "emulator-5554"):
        self.device_id = device_id
        self.is_rooted = True
        self.packages = [
            "com.android.chrome",
            "com.example.app",
            "com.google.android.gm",
            "com.facebook.katana"
        ]
        
    def get_installed_packages(self):
        """Get list of installed packages."""
        return self.packages
    
    def get_process_pid(self, package_name: str):
        """Get PID of running process."""
        if package_name in self.packages:
            return hash(package_name) % 10000 + 1000
        return None
    
    def is_package_running(self, package_name: str):
        """Check if package is running."""
        return package_name in ["com.android.chrome", "com.example.app"]


class MockKeyExtraction:
    """Mock key extraction data for testing."""
    
    def __init__(self, key_type: str = "TLS"):
        self.key_type = key_type
        self.client_random = self._generate_random()
        self.master_secret = self._generate_secret()
        self.timestamp = "2024-01-01T12:00:00Z"
        
    def _generate_random(self):
        """Generate mock client random."""
        return "".join(f"{i:02x}" for i in range(32))
    
    def _generate_secret(self):
        """Generate mock master secret.""" 
        return "".join(f"{i:02x}" for i in range(48))
    
    def to_keylog_format(self):
        """Convert to keylog format."""
        return f"CLIENT_RANDOM {self.client_random} {self.master_secret}"
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'key_type': self.key_type,
            'client_random': self.client_random,
            'master_secret': self.master_secret,
            'timestamp': self.timestamp
        }


class MockPCAPData:
    """Mock PCAP data for testing."""
    
    def __init__(self):
        self.packets = []
        
    def add_packet(self, data: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Add packet to PCAP data."""
        packet = {
            'data': data,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'timestamp': 1640995200.0  # 2022-01-01 00:00:00
        }
        self.packets.append(packet)
    
    def get_packet_count(self):
        """Get number of packets."""
        return len(self.packets)
    
    def get_total_size(self):
        """Get total size of all packets."""
        return sum(len(packet['data']) for packet in self.packets)


def create_mock_frida_environment():
    """Create a complete mock Frida environment."""
    
    # Mock the frida module
    mock_frida = MagicMock()
    mock_frida.get_local_device.return_value = MockFridaDevice("local")
    mock_frida.get_usb_device.return_value = MockFridaDevice("usb:1234", "usb")
    
    return mock_frida


def create_mock_ssl_logger_with_data():
    """Create a mock SSL logger with sample data."""
    from unittest.mock import patch
    
    with patch('friTap.ssl_logger.frida') as mock_frida:
        mock_frida.get_local_device.return_value = MockFridaDevice()
        
        from friTap.ssl_logger import SSL_Logger
        
        logger = SSL_Logger("test_app")
        
        # Add sample data
        session = MockSSLSession()
        connection = MockConnectionInfo()
        key_extraction = MockKeyExtraction()
        
        logger.session_data['ssl_sessions'].append(session.to_dict())
        logger.session_data['connections'].append(connection.to_dict())
        logger.session_data['key_extractions'] = [key_extraction.to_dict()]
        
        return logger


def create_mock_android_environment():
    """Create a mock Android environment."""
    from unittest.mock import patch
    
    mock_subprocess = MagicMock()
    
    # Mock ADB commands
    def mock_adb_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        
        if 'version' in cmd:
            result.stdout = "Android Debug Bridge version 1.0.41"
        elif 'devices' in cmd:
            result.stdout = "List of devices attached\nemulator-5554\tdevice\n"
        elif 'shell' in cmd and 'id' in cmd:
            result.stdout = "uid=0(root) gid=0(root)"
        elif 'shell' in cmd and 'pm' in cmd and 'list' in cmd:
            result.stdout = "package:com.android.chrome\npackage:com.example.app"
        elif 'shell' in cmd and 'ps' in cmd:
            result.stdout = "u0_a123      1234  567  com.example.app"
        else:
            result.stdout = ""
            
        return result
    
    mock_subprocess.run.side_effect = mock_adb_run
    
    with patch('friTap.android.subprocess', mock_subprocess):
        from friTap.android import Android
        return Android()


# Export commonly used mock objects
__all__ = [
    'MockFridaDevice',
    'MockFridaProcess', 
    'MockFridaScript',
    'MockFridaModule',
    'MockNativePointer',
    'MockProcessInfo',
    'MockSSLSession',
    'MockConnectionInfo',
    'MockAndroidDevice',
    'MockKeyExtraction',
    'MockPCAPData',
    'create_mock_frida_environment',
    'create_mock_ssl_logger_with_data',
    'create_mock_android_environment'
]