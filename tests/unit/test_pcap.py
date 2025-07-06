"""
Unit tests for PCAP handling functionality.

Tests PCAP file creation, writing, and SSL data integration.
"""

import pytest
import tempfile
import os
from unittest.mock import patch

from friTap.pcap import PCAP


class TestPCAPInitialization:
    """Test PCAP class initialization."""
    
    def test_basic_initialization(self):
        """Test basic PCAP initialization."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            assert pcap.filename == tmp_path
            assert pcap.file_handle is not None
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_initialization_with_invalid_path(self):
        """Test PCAP initialization with invalid path."""
        with pytest.raises((FileNotFoundError, PermissionError)):
            PCAP("/invalid/path/file.pcap")
            
    def test_initialization_creates_directory(self):
        """Test PCAP initialization creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, "subdir", "test.pcap")
            
            pcap = PCAP(pcap_path)
            assert os.path.exists(pcap_path)
            assert pcap.filename == pcap_path
            
    def test_pcap_header_written(self):
        """Test that PCAP header is written on initialization."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            pcap.close()
            
            # Check file size - should contain at least PCAP header
            assert os.path.getsize(tmp_path) >= 24  # PCAP header size
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestPCAPWriteOperations:
    """Test PCAP writing operations."""
    
    def test_write_ssl_packet(self):
        """Test writing SSL packet to PCAP."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Sample SSL packet data
            ssl_data = b'\\x16\\x03\\x01\\x00\\x2c'  # TLS handshake
            src_ip = "192.168.1.100"
            dst_ip = "93.184.216.34"
            src_port = 54321
            dst_port = 443
            
            pcap.write_ssl_packet(ssl_data, src_ip, dst_ip, src_port, dst_port)
            pcap.close()
            
            # Verify file was written and has content
            assert os.path.getsize(tmp_path) > 24  # Header + packet data
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_write_tcp_packet(self):
        """Test writing TCP packet to PCAP."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Sample TCP data
            tcp_data = b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'
            src_ip = "192.168.1.100"
            dst_ip = "93.184.216.34"
            src_port = 54321
            dst_port = 80
            
            pcap.write_tcp_packet(tcp_data, src_ip, dst_ip, src_port, dst_port)
            pcap.close()
            
            # Verify file was written
            assert os.path.getsize(tmp_path) > 24
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_write_multiple_packets(self):
        """Test writing multiple packets to PCAP."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Write multiple packets
            for i in range(5):
                ssl_data = f'packet_{i}'.encode()
                pcap.write_ssl_packet(ssl_data, "192.168.1.100", "93.184.216.34", 
                                    54321 + i, 443)
            
            pcap.close()
            
            # File should contain header + multiple packets
            file_size = os.path.getsize(tmp_path)
            assert file_size > 100  # Should be substantial with 5 packets
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestPCAPPacketFormat:
    """Test PCAP packet formatting."""
    
    def test_ethernet_header_creation(self):
        """Test Ethernet header creation."""
        pcap = PCAP.__new__(PCAP)  # Create without calling __init__
        
        eth_header = pcap._create_ethernet_header()
        
        # Ethernet header should be 14 bytes
        assert len(eth_header) == 14
        
        # Check Ethernet type field for IP (0x0800)
        assert eth_header[12:14] == b'\\x08\\x00'
        
    def test_ip_header_creation(self):
        """Test IP header creation."""
        pcap = PCAP.__new__(PCAP)
        
        src_ip = "192.168.1.100"
        dst_ip = "93.184.216.34"
        payload_size = 100
        
        ip_header = pcap._create_ip_header(src_ip, dst_ip, payload_size)
        
        # IP header should be 20 bytes minimum
        assert len(ip_header) >= 20
        
        # Check IP version (should be 4)
        version = (ip_header[0] & 0xF0) >> 4
        assert version == 4
        
    def test_tcp_header_creation(self):
        """Test TCP header creation."""
        pcap = PCAP.__new__(PCAP)
        
        src_port = 54321
        dst_port = 443
        payload_size = 100
        
        tcp_header = pcap._create_tcp_header(src_port, dst_port, payload_size)
        
        # TCP header should be at least 20 bytes
        assert len(tcp_header) >= 20
        
        # Check source port
        port_bytes = tcp_header[0:2]
        decoded_port = int.from_bytes(port_bytes, byteorder='big')
        assert decoded_port == src_port
        
    def test_pcap_packet_header_creation(self):
        """Test PCAP packet header creation."""
        pcap = PCAP.__new__(PCAP)
        
        packet_size = 100
        packet_header = pcap._create_pcap_packet_header(packet_size)
        
        # PCAP packet header should be 16 bytes
        assert len(packet_header) == 16
        
        # Check captured length field
        cap_len = int.from_bytes(packet_header[8:12], byteorder='little')
        assert cap_len == packet_size


class TestPCAPUtilityMethods:
    """Test PCAP utility methods."""
    
    def test_ip_address_to_bytes(self):
        """Test IP address conversion to bytes."""
        pcap = PCAP.__new__(PCAP)
        
        # Test IPv4 address
        ip_bytes = pcap._ip_to_bytes("192.168.1.100")
        assert len(ip_bytes) == 4
        assert ip_bytes == b'\\xc0\\xa8\\x01\\x64'  # 192.168.1.100
        
        # Test another address
        ip_bytes = pcap._ip_to_bytes("10.0.0.1")
        assert ip_bytes == b'\\x0a\\x00\\x00\\x01'  # 10.0.0.1
        
    def test_port_to_bytes(self):
        """Test port conversion to bytes."""
        pcap = PCAP.__new__(PCAP)
        
        port_bytes = pcap._port_to_bytes(443)
        assert len(port_bytes) == 2
        assert port_bytes == b'\\x01\\xbb'  # 443 in big-endian
        
        port_bytes = pcap._port_to_bytes(80)
        assert port_bytes == b'\\x00\\x50'  # 80 in big-endian
        
    def test_checksum_calculation(self):
        """Test checksum calculation."""
        pcap = PCAP.__new__(PCAP)
        
        # Test with known data
        data = b'\\x45\\x00\\x00\\x14\\x00\\x00\\x00\\x00\\x40\\x06'
        checksum = pcap._calculate_checksum(data)
        
        # Checksum should be 2 bytes
        assert len(checksum) == 2
        assert isinstance(checksum, bytes)
        
    def test_timestamp_creation(self):
        """Test timestamp creation for packets."""
        pcap = PCAP.__new__(PCAP)
        
        timestamp = pcap._get_current_timestamp()
        
        # Timestamp should be 8 bytes (4 for seconds, 4 for microseconds)
        assert len(timestamp) == 8
        
        # Should be reasonable timestamp (after year 2020)
        seconds = int.from_bytes(timestamp[0:4], byteorder='little')
        assert seconds > 1577836800  # Jan 1, 2020


class TestPCAPFileHandling:
    """Test PCAP file handling operations."""
    
    def test_file_close(self):
        """Test proper file closing."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            assert pcap.file_handle is not None
            
            pcap.close()
            assert pcap.file_handle is None
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_context_manager(self):
        """Test PCAP as context manager."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            with PCAP(tmp_path) as pcap:
                assert pcap.file_handle is not None
                ssl_data = b'test_data'
                pcap.write_ssl_packet(ssl_data, "127.0.0.1", "127.0.0.1", 1234, 443)
            
            # File should be automatically closed
            assert pcap.file_handle is None
            assert os.path.exists(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_flush_operations(self):
        """Test file flushing operations."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Write data and flush
            ssl_data = b'test_data'
            pcap.write_ssl_packet(ssl_data, "127.0.0.1", "127.0.0.1", 1234, 443)
            pcap.flush()
            
            # Data should be written to disk
            assert os.path.getsize(tmp_path) > 24
            
            pcap.close()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestPCAPErrorHandling:
    """Test PCAP error handling."""
    
    def test_write_after_close(self):
        """Test writing after file is closed."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            pcap.close()
            
            # Should raise exception when writing after close
            with pytest.raises((ValueError, AttributeError)):
                pcap.write_ssl_packet(b'data', "127.0.0.1", "127.0.0.1", 1234, 443)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_invalid_ip_address(self):
        """Test handling of invalid IP addresses."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Should handle invalid IP gracefully
            with pytest.raises((ValueError, AttributeError)):
                pcap.write_ssl_packet(b'data', "invalid.ip", "127.0.0.1", 1234, 443)
            
            pcap.close()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_invalid_port_numbers(self):
        """Test handling of invalid port numbers."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Should handle invalid ports gracefully
            with pytest.raises((ValueError, OverflowError)):
                pcap.write_ssl_packet(b'data', "127.0.0.1", "127.0.0.1", -1, 443)
                
            with pytest.raises((ValueError, OverflowError)):
                pcap.write_ssl_packet(b'data', "127.0.0.1", "127.0.0.1", 1234, 99999)
            
            pcap.close()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_large_packet_handling(self):
        """Test handling of large packets."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Create large packet (64KB)
            large_data = b'A' * 65536
            
            # Should handle large packets
            pcap.write_ssl_packet(large_data, "127.0.0.1", "127.0.0.1", 1234, 443)
            pcap.close()
            
            # File should contain the large packet
            assert os.path.getsize(tmp_path) > 65536
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestPCAPIntegration:
    """Test PCAP integration with friTap components."""
    
    @patch('friTap.ssl_logger.SSL_Logger')
    def test_integration_with_ssl_logger(self, mock_ssl_logger):
        """Test PCAP integration with SSL_Logger."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            # Mock SSL_Logger to use PCAP
            mock_logger = mock_ssl_logger.return_value
            mock_logger.pcap_file = tmp_path
            
            pcap = PCAP(tmp_path)
            
            # Simulate SSL data from logger
            ssl_data = b'\\x16\\x03\\x03\\x00\\x50'  # TLS Application Data
            pcap.write_ssl_packet(ssl_data, "192.168.1.100", "93.184.216.34", 54321, 443)
            
            pcap.close()
            
            # Verify file was created and contains data
            assert os.path.exists(tmp_path)
            assert os.path.getsize(tmp_path) > 24
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_concurrent_writes(self):
        """Test concurrent write operations."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Simulate concurrent writes from different threads/processes
            for i in range(10):
                ssl_data = f'packet_{i}'.encode()
                pcap.write_ssl_packet(ssl_data, "192.168.1.100", "93.184.216.34", 
                                    54321 + i, 443)
                pcap.write_tcp_packet(ssl_data, "192.168.1.100", "93.184.216.34", 
                                    54321 + i, 80)
            
            pcap.close()
            
            # All packets should be written
            assert os.path.getsize(tmp_path) > 200
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestPCAPValidation:
    """Test PCAP file validation and format compliance."""
    
    def test_pcap_magic_number(self):
        """Test PCAP file magic number."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            pcap.close()
            
            # Read and verify magic number
            with open(tmp_path, 'rb') as f:
                magic = f.read(4)
                # Should be PCAP magic number (little-endian)
                assert magic == b'\\xd4\\xc3\\xb2\\xa1'
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    def test_pcap_file_format_compliance(self):
        """Test PCAP file format compliance."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_path = tmp.name
            
        try:
            pcap = PCAP(tmp_path)
            
            # Write a packet
            ssl_data = b'test_packet'
            pcap.write_ssl_packet(ssl_data, "127.0.0.1", "127.0.0.1", 1234, 443)
            pcap.close()
            
            # Verify file structure
            with open(tmp_path, 'rb') as f:
                # PCAP global header (24 bytes)
                global_header = f.read(24)
                assert len(global_header) == 24
                
                # PCAP packet header (16 bytes)
                packet_header = f.read(16)
                assert len(packet_header) == 16
                
                # Packet data should follow
                remaining = f.read()
                assert len(remaining) > 0
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)