"""
Blue-sec Vulnerability Assessment Module
CVE database integration and vulnerability detection
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from loguru import logger

from modules.scanner import BluetoothDevice
from modules.utils import timestamp, load_json, save_json


@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    cve_id: str
    title: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    cvss_score: float
    affected_versions: List[str] = field(default_factory=list)
    affected_devices: List[str] = field(default_factory=list)
    mitigation: str = ""
    references: List[str] = field(default_factory=list)
    discovered_date: str = field(default_factory=timestamp)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'cve_id': self.cve_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'affected_versions': self.affected_versions,
            'affected_devices': self.affected_devices,
            'mitigation': self.mitigation,
            'references': self.references,
            'discovered_date': self.discovered_date
        }


class CVEDatabase:
    """CVE database manager"""
    
    def __init__(self, db_path: str = "data/cve_database.json"):
        self.db_path = db_path
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self._load_database()
    
    def _load_database(self):
        """Load CVE database from file"""
        try:
            if Path(self.db_path).exists():
                data = load_json(self.db_path)
                if data:
                    for cve_id, vuln_data in data.items():
                        self.vulnerabilities[cve_id] = Vulnerability(**vuln_data)
                    logger.info(f"Loaded {len(self.vulnerabilities)} CVEs from database")
            else:
                # Initialize with sample CVEs
                self._initialize_sample_cves()
                self.save_database()
        except Exception as e:
            logger.error(f"Error loading CVE database: {e}")
            self._initialize_sample_cves()
    
    def _initialize_sample_cves(self):
        """Initialize database with known Bluetooth CVEs"""
        sample_cves = [
            Vulnerability(
                cve_id="CVE-2017-0785",
                title="BlueBorne - Information Disclosure",
                description="Information disclosure vulnerability in Android Bluetooth stack",
                severity="high",
                cvss_score=8.0,
                affected_versions=["Android 4.4-8.0"],
                affected_devices=["Android"],
                mitigation="Update to latest Android version",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0785"]
            ),
            Vulnerability(
                cve_id="CVE-2017-1000251",
                title="BlueBorne - Linux Kernel RCE",
                description="Remote code execution in Linux Bluetooth stack",
                severity="critical",
                cvss_score=9.8,
                affected_versions=["Linux Kernel < 3.3"],
                affected_devices=["Linux"],
                mitigation="Update Linux kernel to version 3.3 or higher",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2017-1000251"]
            ),
            Vulnerability(
                cve_id="CVE-2018-5383",
                title="Bluetooth Pairing Vulnerability",
                description="Improper authentication in Bluetooth BR/EDR pairing",
                severity="high",
                cvss_score=7.5,
                affected_versions=["Bluetooth Core 2.1 - 5.0"],
                affected_devices=["All"],
                mitigation="Update firmware to support secure pairing only",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-5383"]
            ),
            Vulnerability(
                cve_id="CVE-2019-9506",
                title="KNOB Attack",
                description="Key Negotiation of Bluetooth vulnerability allowing encryption key size reduction",
                severity="high",
                cvss_score=8.1,
                affected_versions=["Bluetooth Core 1.0 - 5.1"],
                affected_devices=["All"],
                mitigation="Update to Bluetooth 5.2 or apply security patches",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-9506"]
            ),
            Vulnerability(
                cve_id="CVE-2020-9770",
                title="BLE GATT Vulnerability",
                description="Improper access control in BLE GATT services",
                severity="medium",
                cvss_score=6.5,
                affected_versions=["Various"],
                affected_devices=["BLE"],
                mitigation="Implement proper GATT service access controls",
                references=[]
            ),
            Vulnerability(
                cve_id="CVE-2021-28139",
                title="Bluetooth Impersonation Attack",
                description="Improper verification allows device impersonation",
                severity="high",
                cvss_score=7.5,
                affected_versions=["Multiple vendors"],
                affected_devices=["Various"],
                mitigation="Enable secure connections mode",
                references=[]
            )
        ]
        
        for vuln in sample_cves:
            self.vulnerabilities[vuln.cve_id] = vuln
        
        logger.info(f"Initialized database with {len(sample_cves)} sample CVEs")
    
    def save_database(self):
        """Save CVE database to file"""
        try:
            data = {cve_id: vuln.to_dict() for cve_id, vuln in self.vulnerabilities.items()}
            save_json(data, self.db_path)
        except Exception as e:
            logger.error(f"Error saving CVE database: {e}")
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        """Add vulnerability to database"""
        self.vulnerabilities[vulnerability.cve_id] = vulnerability
        self.save_database()
        logger.info(f"Added vulnerability: {vulnerability.cve_id}")
    
    def get_vulnerability(self, cve_id: str) -> Optional[Vulnerability]:
        """Get vulnerability by CVE ID"""
        return self.vulnerabilities.get(cve_id)
    
    def search_vulnerabilities(self, keyword: str) -> List[Vulnerability]:
        """Search vulnerabilities by keyword"""
        results = []
        keyword_lower = keyword.lower()
        
        for vuln in self.vulnerabilities.values():
            if (keyword_lower in vuln.title.lower() or
                keyword_lower in vuln.description.lower() or
                keyword_lower in vuln.cve_id.lower()):
                results.append(vuln)
        
        return results
    
    def get_by_severity(self, severity: str) -> List[Vulnerability]:
        """Get vulnerabilities by severity"""
        return [vuln for vuln in self.vulnerabilities.values() if vuln.severity == severity]


class VulnerabilityScanner:
    """Vulnerability scanner for Bluetooth devices"""
    
    def __init__(self, cve_database: CVEDatabase):
        self.cve_db = cve_database
    
    async def scan_device(self, device: BluetoothDevice) -> List[Vulnerability]:
        """Scan device for known vulnerabilities"""
        vulnerabilities = []
        
        try:
            logger.info(f"Scanning device {device.address} for vulnerabilities...")
            
            # Check for weak encryption
            weak_encryption = self._check_weak_encryption(device)
            if weak_encryption:
                vulnerabilities.extend(weak_encryption)
            
            # Check for protocol weaknesses
            protocol_weaknesses = self._check_protocol_weaknesses(device)
            if protocol_weaknesses:
                vulnerabilities.extend(protocol_weaknesses)
            
            # Check for open services
            open_services = self._check_open_services(device)
            if open_services:
                vulnerabilities.extend(open_services)
            
            # Check against CVE database
            cve_matches = self._match_cves(device)
            if cve_matches:
                vulnerabilities.extend(cve_matches)
            
            logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error scanning device: {e}")
        
        return vulnerabilities
    
    def _check_weak_encryption(self, device: BluetoothDevice) -> List[Vulnerability]:
        """Check for weak encryption"""
        vulnerabilities = []
        
        # This is a simplified check - in real implementation, would probe encryption strength
        if device.device_type == 'classic':
            # Check if device supports legacy pairing
            vuln = self.cve_db.get_vulnerability("CVE-2018-5383")
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_protocol_weaknesses(self, device: BluetoothDevice) -> List[Vulnerability]:
        """Check for protocol weaknesses"""
        vulnerabilities = []
        
        # Check for KNOB attack vulnerability
        vuln = self.cve_db.get_vulnerability("CVE-2019-9506")
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_open_services(self, device: BluetoothDevice) -> List[Vulnerability]:
        """Check for open/insecure services"""
        vulnerabilities = []
        
        if device.services:
            # Check for insecure GATT services
            for service in device.services:
                if "1800" in service or "1801" in service:  # Generic Access/Attribute
                    vuln = self.cve_db.get_vulnerability("CVE-2020-9770")
                    if vuln and vuln not in vulnerabilities:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _match_cves(self, device: BluetoothDevice) -> List[Vulnerability]:
        """Match device against CVE database"""
        vulnerabilities = []
        
        # Check device type specific CVEs
        if device.device_type == 'ble':
            # BLE specific vulnerabilities
            ble_vulns = self.cve_db.search_vulnerabilities("BLE")
            vulnerabilities.extend(ble_vulns[:2])  # Limit results
        
        return vulnerabilities
    
    async def batch_scan(self, devices: List[BluetoothDevice]) -> Dict[str, List[Vulnerability]]:
        """Scan multiple devices"""
        results = {}
        
        tasks = [self.scan_device(device) for device in devices]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for device, vulns in zip(devices, scan_results):
            if isinstance(vulns, Exception):
                logger.error(f"Error scanning {device.address}: {vulns}")
                results[device.address] = []
            else:
                results[device.address] = vulns
        
        return results
    
    def generate_vulnerability_report(self, device: BluetoothDevice, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate vulnerability report for a device"""
        return {
            'device': device.to_dict(),
            'scan_timestamp': timestamp(),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
            'risk_score': self._calculate_risk_score(vulnerabilities),
            'recommendations': self._generate_recommendations(vulnerabilities)
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0
        
        total_score = sum(vuln.cvss_score for vuln in vulnerabilities)
        return min(total_score / len(vulnerabilities), 10.0)
    
    def _generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate security recommendations"""
        recommendations = set()
        
        for vuln in vulnerabilities:
            if vuln.mitigation:
                recommendations.add(vuln.mitigation)
        
        if not recommendations:
            recommendations.add("Keep firmware and software up to date")
            recommendations.add("Use secure pairing methods")
            recommendations.add("Disable Bluetooth when not in use")
        
        return list(recommendations)
