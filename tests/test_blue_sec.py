"""
Blue-sec Unit Tests
Basic tests for core functionality
"""

import pytest
import asyncio
from modules.config import BlueSecConfig, ScannerConfig, SecurityConfig
from modules.scanner import BluetoothDevice
from modules.vulnerabilities import Vulnerability, CVEDatabase
from modules.utils import (
    format_mac_address, validate_mac_address, calculate_hash,
    RateLimiter, AuditLogger
)


class TestConfig:
    """Test configuration module"""
    
    def test_default_config(self):
        """Test default configuration"""
        config = BlueSecConfig()
        assert config.scanner.active_scan_timeout == 10
        assert config.security.rate_limit is True
        assert config.reporting.default_format == "json"
    
    def test_config_to_dict(self):
        """Test config serialization"""
        config = BlueSecConfig()
        config_dict = config.to_dict()
        assert 'scanner' in config_dict
        assert 'security' in config_dict
        assert 'reporting' in config_dict
    
    def test_config_from_dict(self):
        """Test config deserialization"""
        data = {
            'scanner': {'active_scan_timeout': 20},
            'debug_mode': True
        }
        config = BlueSecConfig.from_dict(data)
        assert config.scanner.active_scan_timeout == 20
        assert config.debug_mode is True


class TestUtils:
    """Test utility functions"""
    
    def test_format_mac_address(self):
        """Test MAC address formatting"""
        assert format_mac_address("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
        assert format_mac_address("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
        assert format_mac_address("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    
    def test_validate_mac_address(self):
        """Test MAC address validation"""
        assert validate_mac_address("AA:BB:CC:DD:EE:FF") is True
        assert validate_mac_address("aa:bb:cc:dd:ee:ff") is True
        assert validate_mac_address("invalid") is False
        assert validate_mac_address("AA:BB:CC") is False
    
    def test_calculate_hash(self):
        """Test hash calculation"""
        data = "test data"
        hash1 = calculate_hash(data, "sha256")
        hash2 = calculate_hash(data, "sha256")
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 hex characters
    
    @pytest.mark.asyncio
    async def test_rate_limiter(self):
        """Test rate limiter"""
        limiter = RateLimiter(max_calls=2, time_window=1.0)
        
        # First two calls should succeed
        assert limiter.can_proceed() is True
        assert limiter.can_proceed() is True
        
        # Third call should fail
        assert limiter.can_proceed() is False
    
    def test_audit_logger(self):
        """Test audit logger"""
        logger = AuditLogger("/tmp/test_audit.log")
        logger.log_event("test_event", {"key": "value"})
        logger.log_attack("test_attack", "AA:BB:CC:DD:EE:FF", "success")
        # Just verify no exceptions are raised


class TestScanner:
    """Test scanner module"""
    
    def test_bluetooth_device_creation(self):
        """Test BluetoothDevice creation"""
        device = BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            device_type="ble"
        )
        assert device.address == "AA:BB:CC:DD:EE:FF"
        assert device.name == "Test Device"
        assert device.device_type == "ble"
    
    def test_bluetooth_device_to_dict(self):
        """Test device serialization"""
        device = BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            device_type="ble"
        )
        device_dict = device.to_dict()
        assert device_dict['address'] == "AA:BB:CC:DD:EE:FF"
        assert device_dict['name'] == "Test Device"
    
    def test_bluetooth_device_from_dict(self):
        """Test device deserialization"""
        data = {
            'address': "AA:BB:CC:DD:EE:FF",
            'name': "Test Device",
            'device_type': "ble",
            'rssi': -50,
            'services': [],
            'characteristics': [],
            'first_seen': "2025-01-01 00:00:00",
            'last_seen': "2025-01-01 00:00:00",
            'metadata': {}
        }
        device = BluetoothDevice.from_dict(data)
        assert device.address == "AA:BB:CC:DD:EE:FF"
        assert device.rssi == -50


class TestVulnerabilities:
    """Test vulnerability module"""
    
    def test_vulnerability_creation(self):
        """Test Vulnerability creation"""
        vuln = Vulnerability(
            cve_id="CVE-2025-0001",
            title="Test Vulnerability",
            description="Test description",
            severity="high",
            cvss_score=7.5
        )
        assert vuln.cve_id == "CVE-2025-0001"
        assert vuln.severity == "high"
        assert vuln.cvss_score == 7.5
    
    def test_cve_database_initialization(self):
        """Test CVE database initialization"""
        cve_db = CVEDatabase("/tmp/test_cve_db.json")
        assert len(cve_db.vulnerabilities) > 0
    
    def test_cve_database_search(self):
        """Test CVE database search"""
        cve_db = CVEDatabase("/tmp/test_cve_db.json")
        results = cve_db.search_vulnerabilities("BlueBorne")
        assert len(results) > 0
    
    def test_cve_database_get_by_severity(self):
        """Test getting CVEs by severity"""
        cve_db = CVEDatabase("/tmp/test_cve_db.json")
        critical = cve_db.get_by_severity("critical")
        high = cve_db.get_by_severity("high")
        assert isinstance(critical, list)
        assert isinstance(high, list)


class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_scan_workflow(self):
        """Test basic scan workflow"""
        # This is a mock test since actual Bluetooth scanning requires hardware
        from modules.config import ScannerConfig
        from modules.scanner import DeviceScanner
        
        config = ScannerConfig()
        scanner = DeviceScanner(config)
        
        # Just verify scanner initialization
        assert scanner.config.active_scan_timeout == 10
        assert len(scanner.discovered_devices) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
