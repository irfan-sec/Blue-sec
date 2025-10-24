"""
Blue-sec Modules
Core functionality modules for the Blue-sec framework
"""

from modules.config import BlueSecConfig, load_config
from modules.scanner import DeviceScanner, BluetoothDevice, scan_bluetooth_devices
from modules.vulnerabilities import Vulnerability, CVEDatabase, VulnerabilityScanner
from modules.attacks import AttackResult, AttackManager
from modules.reporting import ReportGenerator, SIEMIntegration, MITRE_ATTACK_MAPPING
from modules.utils import (
    banner, setup_logging, check_privileges, require_privileges,
    confirm_action, format_mac_address, validate_mac_address,
    timestamp, display_table, display_panel, AuditLogger, RateLimiter
)

__all__ = [
    # Config
    'BlueSecConfig', 'load_config',
    # Scanner
    'DeviceScanner', 'BluetoothDevice', 'scan_bluetooth_devices',
    # Vulnerabilities
    'Vulnerability', 'CVEDatabase', 'VulnerabilityScanner',
    # Attacks
    'AttackResult', 'AttackManager',
    # Reporting
    'ReportGenerator', 'SIEMIntegration', 'MITRE_ATTACK_MAPPING',
    # Utils
    'banner', 'setup_logging', 'check_privileges', 'require_privileges',
    'confirm_action', 'format_mac_address', 'validate_mac_address',
    'timestamp', 'display_table', 'display_panel', 'AuditLogger', 'RateLimiter'
]
