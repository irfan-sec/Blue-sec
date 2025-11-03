"""
Blue-sec Modules
Core functionality modules for the Blue-sec framework
"""

from modules.config import BlueSecConfig, load_config
from modules.scanner import DeviceScanner, BluetoothDevice, scan_bluetooth_devices
from modules.vulnerabilities import Vulnerability, CVEDatabase, VulnerabilityScanner
from modules.attacks import AttackResult, AttackManager
from modules.hid_attacks import (
    HIDPayload, HIDAttackResult, HIDKeyboardInjector,
    RealTimeDeviceTester, PayloadGenerator
)
from modules.reporting import ReportGenerator, SIEMIntegration, MITRE_ATTACK_MAPPING
from modules.utils import (
    banner, setup_logging, check_privileges, require_privileges,
    confirm_action, format_mac_address, validate_mac_address,
    timestamp, display_table, display_panel, AuditLogger, RateLimiter,
    console
)

# GUI module is optional - only import if tkinter is available
try:
    from modules.gui import BlueSecGUI, run_gui
    _GUI_AVAILABLE = True
except ImportError:
    _GUI_AVAILABLE = False
    BlueSecGUI = None
    run_gui = None

__all__ = [
    # Config
    'BlueSecConfig', 'load_config',
    # Scanner
    'DeviceScanner', 'BluetoothDevice', 'scan_bluetooth_devices',
    # Vulnerabilities
    'Vulnerability', 'CVEDatabase', 'VulnerabilityScanner',
    # Attacks
    'AttackResult', 'AttackManager',
    # HID Attacks
    'HIDPayload', 'HIDAttackResult', 'HIDKeyboardInjector',
    'RealTimeDeviceTester', 'PayloadGenerator',
    # Reporting
    'ReportGenerator', 'SIEMIntegration', 'MITRE_ATTACK_MAPPING',
    # Utils
    'banner', 'setup_logging', 'check_privileges', 'require_privileges',
    'confirm_action', 'format_mac_address', 'validate_mac_address',
    'timestamp', 'display_table', 'display_panel', 'AuditLogger', 'RateLimiter',
    'console',
    # GUI
    'BlueSecGUI', 'run_gui'
]
