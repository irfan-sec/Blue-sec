"""
Blue-sec Unit Tests
Basic tests for core functionality
"""

import pytest
import asyncio
from pathlib import Path
from modules.config import BlueSecConfig, ScannerConfig, SecurityConfig
from modules.scanner import BluetoothDevice
from modules.vulnerabilities import Vulnerability, CVEDatabase
from modules.hid_attacks import (
    HIDPayload, HIDKeyboardInjector, RealTimeDeviceTester,
    PayloadGenerator, SCAN_CODES, MODIFIERS
)
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


class TestHIDAttacks:
    """Test HID attack module"""
    
    def test_hid_payload_creation(self):
        """Test HIDPayload creation"""
        payload = HIDPayload(
            name="Test Payload",
            description="Test description",
            commands=["STRING hello", "ENTER"],
            target_os="windows"
        )
        assert payload.name == "Test Payload"
        assert len(payload.commands) == 2
        assert payload.target_os == "windows"
    
    def test_hid_payload_to_dict(self):
        """Test HIDPayload serialization"""
        payload = HIDPayload(
            name="Test",
            description="Test",
            commands=["STRING test"],
            target_os="all"
        )
        data = payload.to_dict()
        assert data['name'] == "Test"
        assert data['target_os'] == "all"
        assert len(data['commands']) == 1
    
    def test_hid_payload_from_dict(self):
        """Test HIDPayload deserialization"""
        data = {
            'name': "Test",
            'description': "Test description",
            'commands': ["STRING hello", "ENTER"],
            'target_os': "linux",
            'delay_ms': 200
        }
        payload = HIDPayload.from_dict(data)
        assert payload.name == "Test"
        assert payload.delay_ms == 200
        assert len(payload.commands) == 2
    
    def test_hid_payload_from_file(self):
        """Test loading HID payload from file"""
        payload_path = Path("data/payloads/hid/rickroll_test.json")
        if payload_path.exists():
            payload = HIDPayload.from_file(str(payload_path))
            assert payload.name == "Rickroll Test"
            assert payload.target_os == "all"
            assert len(payload.commands) > 0
    
    def test_scan_codes_exist(self):
        """Test that scan codes are defined"""
        assert 'a' in SCAN_CODES
        assert 'ENTER' in SCAN_CODES
        assert 'CTRL' in SCAN_CODES
        assert len(SCAN_CODES) > 50  # Should have many keys
    
    def test_modifiers_exist(self):
        """Test that modifiers are defined"""
        assert 'CTRL' in MODIFIERS
        assert 'SHIFT' in MODIFIERS
        assert 'ALT' in MODIFIERS
        assert 'GUI' in MODIFIERS
    
    @pytest.mark.asyncio
    async def test_hid_injector_initialization(self):
        """Test HIDKeyboardInjector initialization"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        injector = HIDKeyboardInjector(attack_config, security_config)
        
        assert injector.connected is False
        assert injector.device_address is None
    
    @pytest.mark.asyncio
    async def test_hid_injector_connect(self):
        """Test HID connection simulation"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        injector = HIDKeyboardInjector(attack_config, security_config)
        
        # Connect should succeed in simulation mode
        result = await injector.connect("AA:BB:CC:DD:EE:FF")
        assert result is True
        assert injector.connected is True
        assert injector.device_address == "AA:BB:CC:DD:EE:FF"
    
    @pytest.mark.asyncio
    async def test_hid_injector_disconnect(self):
        """Test HID disconnection"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        injector = HIDKeyboardInjector(attack_config, security_config)
        
        await injector.connect("AA:BB:CC:DD:EE:FF")
        assert injector.connected is True
        
        await injector.disconnect()
        assert injector.connected is False
        assert injector.device_address is None
    
    def test_parse_command_string(self):
        """Test DuckyScript command parsing"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        injector = HIDKeyboardInjector(attack_config, security_config)
        
        # Test STRING command
        actions = injector._parse_command("STRING hello")
        assert len(actions) == 5  # 5 characters
        assert all(a['type'] == 'keypress' for a in actions)
        
        # Test DELAY command
        actions = injector._parse_command("DELAY 1000")
        assert len(actions) == 1
        assert actions[0]['type'] == 'delay'
        assert actions[0]['duration'] == 1000
        
        # Test single key
        actions = injector._parse_command("ENTER")
        assert len(actions) == 1
        assert actions[0]['type'] == 'keypress'
    
    @pytest.mark.asyncio
    async def test_hid_execute_action_delay(self):
        """Test executing delay action"""
        from modules.config import AttackConfig, SecurityConfig
        import time
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        injector = HIDKeyboardInjector(attack_config, security_config)
        
        await injector.connect("AA:BB:CC:DD:EE:FF")
        
        action = {'type': 'delay', 'duration': 100}
        start = time.time()
        result = await injector.execute_action(action)
        elapsed = time.time() - start
        
        assert result is True
        assert elapsed >= 0.1  # Should wait at least 100ms
    
    @pytest.mark.asyncio
    async def test_hid_execute_action_keypress(self):
        """Test executing keypress action"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        injector = HIDKeyboardInjector(attack_config, security_config)
        
        await injector.connect("AA:BB:CC:DD:EE:FF")
        
        action = {'type': 'keypress', 'key': 'a', 'modifiers': []}
        result = await injector.execute_action(action)
        assert result is True
    
    def test_payload_generator_rickroll(self):
        """Test PayloadGenerator rickroll"""
        payload = PayloadGenerator.rickroll()
        assert payload.name == "Rickroll Test"
        assert payload.target_os == "all"
        assert len(payload.commands) > 0
    
    def test_payload_generator_reverse_shell_linux(self):
        """Test PayloadGenerator reverse shell for Linux"""
        payload = PayloadGenerator.reverse_shell("192.168.1.100", 4444, "linux")
        assert payload.name == "Reverse Shell"
        assert payload.target_os == "linux"
        assert len(payload.commands) > 0
        # Check that IP and port are in the commands
        commands_str = " ".join(payload.commands)
        assert "192.168.1.100" in commands_str
        assert "4444" in commands_str
    
    def test_payload_generator_reverse_shell_windows(self):
        """Test PayloadGenerator reverse shell for Windows"""
        payload = PayloadGenerator.reverse_shell("10.0.0.1", 8080, "windows")
        assert payload.name == "Reverse Shell"
        assert payload.target_os == "windows"
        assert "10.0.0.1" in " ".join(payload.commands)
        assert "8080" in " ".join(payload.commands)
    
    def test_payload_generator_wifi_exfil(self):
        """Test PayloadGenerator WiFi exfiltration"""
        payload = PayloadGenerator.wifi_password_exfiltration("windows")
        assert payload.name == "WiFi Password Exfiltration"
        assert payload.target_os == "windows"
        assert len(payload.commands) > 0
    
    @pytest.mark.asyncio
    async def test_real_time_tester_initialization(self):
        """Test RealTimeDeviceTester initialization"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        tester = RealTimeDeviceTester(attack_config, security_config)
        
        assert tester.hid_injector is not None
        assert len(tester.test_results) == 0
    
    @pytest.mark.asyncio
    async def test_real_time_tester_start_session(self):
        """Test starting interactive session"""
        from modules.config import AttackConfig, SecurityConfig
        
        attack_config = AttackConfig()
        security_config = SecurityConfig()
        tester = RealTimeDeviceTester(attack_config, security_config)
        
        result = await tester.start_interactive_session("AA:BB:CC:DD:EE:FF")
        assert result is True
        assert tester.hid_injector.connected is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
