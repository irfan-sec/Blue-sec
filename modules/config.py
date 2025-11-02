"""
Blue-sec Configuration Module
Handles all configuration loading and validation
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from loguru import logger

@dataclass
class ScannerConfig:
    """Scanner configuration settings"""
    active_scan_timeout: int = 10
    passive_scan_duration: int = 30
    device_cache_time: int = 300
    max_concurrent_scans: int = 5
    rssi_threshold: int = -80

@dataclass
class SecurityConfig:
    """Security configuration settings"""
    rate_limit: bool = True
    max_attempts: int = 3
    require_confirmation: bool = True
    enable_audit_log: bool = True
    audit_log_path: str = "reports/audit.log"
    dangerous_ops_require_auth: bool = True
    session_timeout: int = 3600

@dataclass
class EnterpriseConfig:
    """Enterprise integration configuration"""
    siem_enabled: bool = False
    siem_url: Optional[str] = None
    api_key: Optional[str] = None
    api_enabled: bool = False
    api_port: int = 8000
    api_host: str = "127.0.0.1"
    compliance_reporting: bool = True

@dataclass
class AttackConfig:
    """Attack module configuration"""
    enable_mitm: bool = True
    enable_bruteforce: bool = True
    enable_injection: bool = True
    max_bruteforce_attempts: int = 1000
    bruteforce_delay: float = 0.1
    payload_directory: str = "data/payloads"

@dataclass
class ReportingConfig:
    """Reporting configuration"""
    output_directory: str = "reports"
    default_format: str = "json"
    include_mitre_mapping: bool = True
    include_screenshots: bool = False
    compress_reports: bool = False
    report_retention_days: int = 30

@dataclass
class BlueSecConfig:
    """Main configuration container"""
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    enterprise: EnterpriseConfig = field(default_factory=EnterpriseConfig)
    attack: AttackConfig = field(default_factory=AttackConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    
    debug_mode: bool = False
    log_level: str = "INFO"
    
    @classmethod
    def load_from_file(cls, config_path: str) -> 'BlueSecConfig':
        """Load configuration from YAML or JSON file"""
        path = Path(config_path)
        
        if not path.exists():
            logger.warning(f"Config file {config_path} not found, using defaults")
            return cls()
        
        try:
            with open(path, 'r') as f:
                if path.suffix in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                elif path.suffix == '.json':
                    data = json.load(f)
                else:
                    logger.error(f"Unsupported config format: {path.suffix}")
                    return cls()
            
            return cls.from_dict(data)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return cls()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlueSecConfig':
        """Create config from dictionary"""
        config = cls()
        
        if 'scanner' in data:
            config.scanner = ScannerConfig(**data['scanner'])
        if 'security' in data:
            config.security = SecurityConfig(**data['security'])
        if 'enterprise' in data:
            config.enterprise = EnterpriseConfig(**data['enterprise'])
        if 'attack' in data:
            config.attack = AttackConfig(**data['attack'])
        if 'reporting' in data:
            config.reporting = ReportingConfig(**data['reporting'])
        
        config.debug_mode = data.get('debug_mode', False)
        config.log_level = data.get('log_level', 'INFO')
        
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'scanner': self.scanner.__dict__,
            'security': self.security.__dict__,
            'enterprise': self.enterprise.__dict__,
            'attack': self.attack.__dict__,
            'reporting': self.reporting.__dict__,
            'debug_mode': self.debug_mode,
            'log_level': self.log_level
        }
    
    def save_to_file(self, config_path: str):
        """Save configuration to file"""
        path = Path(config_path)
        
        try:
            with open(path, 'w') as f:
                if path.suffix in ['.yaml', '.yml']:
                    yaml.dump(self.to_dict(), f, default_flow_style=False)
                elif path.suffix == '.json':
                    json.dump(self.to_dict(), f, indent=2)
                else:
                    logger.error(f"Unsupported config format: {path.suffix}")
                    return
            
            logger.info(f"Configuration saved to {config_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")


def get_default_config() -> BlueSecConfig:
    """Get default configuration"""
    return BlueSecConfig()


def load_config(config_path: Optional[str] = None) -> BlueSecConfig:
    """Load configuration from file or use defaults"""
    if config_path:
        return BlueSecConfig.load_from_file(config_path)
    
    # Try to load from default locations
    default_paths = [
        'config/blue-sec.yaml',
        'config/blue-sec.yml',
        'config/blue-sec.json',
        'blue-sec.yaml',
        'blue-sec.yml'
    ]
    
    for path in default_paths:
        if Path(path).exists():
            logger.info(f"Loading config from {path}")
            return BlueSecConfig.load_from_file(path)
    
    logger.info("No config file found, using defaults")
    return BlueSecConfig()
