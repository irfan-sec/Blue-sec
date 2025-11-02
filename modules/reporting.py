"""
Blue-sec Reporting Module
Report generation and MITRE ATT&CK mapping
"""

import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from loguru import logger

from modules.scanner import BluetoothDevice
from modules.vulnerabilities import Vulnerability
from modules.attacks import AttackResult
from modules.utils import timestamp, timestamp_filename, create_directory, save_json


# MITRE ATT&CK mapping for Bluetooth attacks
MITRE_ATTACK_MAPPING = {
    'device_discovery': {
        'technique_id': 'T1200',
        'technique_name': 'Hardware Additions',
        'tactic': 'Initial Access',
        'description': 'Bluetooth device discovery and enumeration'
    },
    'mitm': {
        'technique_id': 'T1557',
        'technique_name': 'Man-in-the-Middle',
        'tactic': 'Credential Access, Collection',
        'description': 'Bluetooth traffic interception'
    },
    'bluesnarfing': {
        'technique_id': 'T1005',
        'technique_name': 'Data from Local System',
        'tactic': 'Collection',
        'description': 'Unauthorized data extraction via Bluetooth'
    },
    'bluebugging': {
        'technique_id': 'T1021',
        'technique_name': 'Remote Services',
        'tactic': 'Lateral Movement',
        'description': 'Remote device control via Bluetooth'
    },
    'bluejacking': {
        'technique_id': 'T1534',
        'technique_name': 'Internal Spearphishing',
        'tactic': 'Lateral Movement',
        'description': 'Unsolicited message delivery'
    },
    'pin_bruteforce': {
        'technique_id': 'T1110',
        'technique_name': 'Brute Force',
        'tactic': 'Credential Access',
        'description': 'PIN/Passkey brute force attack'
    }
}


class ReportGenerator:
    """Generate security assessment reports"""
    
    def __init__(self, output_directory: str = "reports"):
        self.output_directory = output_directory
        create_directory(output_directory)
    
    def generate_scan_report(
        self,
        devices: List[BluetoothDevice],
        vulnerabilities: Dict[str, List[Vulnerability]] = None,
        format: str = "json"
    ) -> str:
        """
        Generate scan report
        
        Args:
            devices: List of scanned devices
            vulnerabilities: Device vulnerabilities mapping
            format: Output format (json, xml, html)
        
        Returns:
            Path to generated report
        """
        report_data = {
            'report_type': 'device_scan',
            'generated_at': timestamp(),
            'summary': {
                'total_devices': len(devices),
                'ble_devices': sum(1 for d in devices if d.device_type == 'ble'),
                'classic_devices': sum(1 for d in devices if d.device_type == 'classic')
            },
            'devices': [device.to_dict() for device in devices]
        }
        
        if vulnerabilities:
            report_data['vulnerabilities'] = {
                addr: [vuln.to_dict() for vuln in vulns]
                for addr, vulns in vulnerabilities.items()
            }
            report_data['summary']['total_vulnerabilities'] = sum(
                len(vulns) for vulns in vulnerabilities.values()
            )
        
        filename = f"scan_report_{timestamp_filename()}"
        
        if format == "json":
            return self._save_json_report(report_data, filename)
        elif format == "xml":
            return self._save_xml_report(report_data, filename)
        elif format == "html":
            return self._save_html_report(report_data, filename)
        else:
            logger.error(f"Unsupported format: {format}")
            return self._save_json_report(report_data, filename)
    
    def generate_attack_report(
        self,
        attack_results: List[AttackResult],
        include_mitre: bool = True,
        format: str = "json"
    ) -> str:
        """
        Generate attack simulation report
        
        Args:
            attack_results: List of attack results
            include_mitre: Include MITRE ATT&CK mapping
            format: Output format
        
        Returns:
            Path to generated report
        """
        report_data = {
            'report_type': 'attack_simulation',
            'generated_at': timestamp(),
            'summary': {
                'total_attacks': len(attack_results),
                'successful_attacks': sum(1 for r in attack_results if r.success),
                'failed_attacks': sum(1 for r in attack_results if not r.success)
            },
            'attacks': [result.to_dict() for result in attack_results]
        }
        
        if include_mitre:
            report_data['mitre_mapping'] = self._map_attacks_to_mitre(attack_results)
        
        filename = f"attack_report_{timestamp_filename()}"
        
        if format == "json":
            return self._save_json_report(report_data, filename)
        elif format == "xml":
            return self._save_xml_report(report_data, filename)
        elif format == "html":
            return self._save_html_report(report_data, filename)
        else:
            return self._save_json_report(report_data, filename)
    
    def generate_vulnerability_report(
        self,
        device: BluetoothDevice,
        vulnerabilities: List[Vulnerability],
        format: str = "json"
    ) -> str:
        """Generate vulnerability assessment report"""
        report_data = {
            'report_type': 'vulnerability_assessment',
            'generated_at': timestamp(),
            'device': device.to_dict(),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
            'severity_breakdown': self._get_severity_breakdown(vulnerabilities),
            'risk_score': self._calculate_risk_score(vulnerabilities),
            'recommendations': self._generate_recommendations(vulnerabilities)
        }
        
        filename = f"vuln_report_{device.address.replace(':', '')}_{timestamp_filename()}"
        
        if format == "json":
            return self._save_json_report(report_data, filename)
        elif format == "xml":
            return self._save_xml_report(report_data, filename)
        elif format == "html":
            return self._save_html_report(report_data, filename)
        else:
            return self._save_json_report(report_data, filename)
    
    def generate_compliance_report(
        self,
        devices: List[BluetoothDevice],
        vulnerabilities: Dict[str, List[Vulnerability]],
        standard: str = "NIST"
    ) -> str:
        """Generate compliance report"""
        report_data = {
            'report_type': 'compliance_assessment',
            'standard': standard,
            'generated_at': timestamp(),
            'summary': {
                'total_devices': len(devices),
                'compliant_devices': 0,
                'non_compliant_devices': 0,
                'devices_with_critical_issues': 0
            },
            'device_compliance': []
        }
        
        for device in devices:
            device_vulns = vulnerabilities.get(device.address, [])
            critical_vulns = [v for v in device_vulns if v.severity == 'critical']
            high_vulns = [v for v in device_vulns if v.severity == 'high']
            
            is_compliant = len(critical_vulns) == 0 and len(high_vulns) == 0
            
            if is_compliant:
                report_data['summary']['compliant_devices'] += 1
            else:
                report_data['summary']['non_compliant_devices'] += 1
            
            if critical_vulns:
                report_data['summary']['devices_with_critical_issues'] += 1
            
            report_data['device_compliance'].append({
                'device': device.to_dict(),
                'compliant': is_compliant,
                'critical_issues': len(critical_vulns),
                'high_issues': len(high_vulns),
                'recommendations': self._generate_recommendations(device_vulns)
            })
        
        filename = f"compliance_report_{standard}_{timestamp_filename()}"
        return self._save_json_report(report_data, filename)
    
    def _save_json_report(self, data: Dict[str, Any], filename: str) -> str:
        """Save report as JSON"""
        filepath = f"{self.output_directory}/{filename}.json"
        save_json(data, filepath)
        logger.info(f"Report saved: {filepath}")
        return filepath
    
    def _save_xml_report(self, data: Dict[str, Any], filename: str) -> str:
        """Save report as XML"""
        filepath = f"{self.output_directory}/{filename}.xml"
        
        try:
            root = ET.Element('report')
            self._dict_to_xml(data, root)
            tree = ET.ElementTree(root)
            ET.indent(tree, space='  ')
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            logger.info(f"Report saved: {filepath}")
        except Exception as e:
            logger.error(f"Error saving XML report: {e}")
        
        return filepath
    
    def _dict_to_xml(self, data: Any, parent: ET.Element):
        """Convert dictionary to XML recursively"""
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, str(key))
                self._dict_to_xml(value, child)
        elif isinstance(data, list):
            for item in data:
                item_elem = ET.SubElement(parent, 'item')
                self._dict_to_xml(item, item_elem)
        else:
            parent.text = str(data)
    
    def _save_html_report(self, data: Dict[str, Any], filename: str) -> str:
        """Save report as HTML"""
        filepath = f"{self.output_directory}/{filename}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Blue-sec Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary-item {{ margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #27ae60; }}
        .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Blue-sec Security Report</h1>
        <p><strong>Report Type:</strong> {data.get('report_type', 'N/A')}</p>
        <p><strong>Generated:</strong> {data.get('generated_at', 'N/A')}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            {self._format_summary_html(data.get('summary', {}))}
        </div>
        
        {self._format_data_html(data)}
        
        <div class="footer">
            <p>Generated by Blue-sec - Advanced Bluetooth Security Testing Framework</p>
            <p>© 2025 @irfan-sec</p>
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(filepath, 'w') as f:
                f.write(html_content)
            logger.info(f"Report saved: {filepath}")
        except Exception as e:
            logger.error(f"Error saving HTML report: {e}")
        
        return filepath
    
    def _format_summary_html(self, summary: Dict[str, Any]) -> str:
        """Format summary section for HTML"""
        html = ""
        for key, value in summary.items():
            html += f'<div class="summary-item"><strong>{key.replace("_", " ").title()}:</strong> {value}</div>\n'
        return html
    
    def _format_data_html(self, data: Dict[str, Any]) -> str:
        """Format main data section for HTML"""
        # Simplified HTML formatting
        return f'<pre>{json.dumps(data, indent=2)}</pre>'
    
    def _map_attacks_to_mitre(self, attack_results: List[AttackResult]) -> Dict[str, Any]:
        """Map attacks to MITRE ATT&CK framework"""
        mitre_mapping = {}
        
        for result in attack_results:
            attack_type = result.attack_type.lower().replace('_', '')
            
            if attack_type in MITRE_ATTACK_MAPPING:
                mapping = MITRE_ATTACK_MAPPING[attack_type]
                
                if mapping['technique_id'] not in mitre_mapping:
                    mitre_mapping[mapping['technique_id']] = {
                        'technique_name': mapping['technique_name'],
                        'tactic': mapping['tactic'],
                        'description': mapping['description'],
                        'attacks': []
                    }
                
                mitre_mapping[mapping['technique_id']]['attacks'].append({
                    'target': result.target,
                    'success': result.success,
                    'timestamp': result.timestamp
                })
        
        return mitre_mapping
    
    def _get_severity_breakdown(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Get vulnerability severity breakdown"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            if vuln.severity in breakdown:
                breakdown[vuln.severity] += 1
        
        return breakdown
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall risk score"""
        if not vulnerabilities:
            return 0.0
        
        total_score = sum(vuln.cvss_score for vuln in vulnerabilities)
        return round(min(total_score / len(vulnerabilities), 10.0), 2)
    
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


class SIEMIntegration:
    """SIEM integration for enterprise environments"""
    
    def __init__(self, siem_url: str, api_key: str):
        self.siem_url = siem_url
        self.api_key = api_key
    
    async def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send alert to SIEM"""
        try:
            # In production, this would use aiohttp to send data to SIEM
            logger.info(f"Sending alert to SIEM: {self.siem_url}")
            logger.debug(f"Alert data: {alert_data}")
            
            # Simulated SIEM integration
            return True
        except Exception as e:
            logger.error(f"Error sending alert to SIEM: {e}")
            return False
    
    async def send_event(self, event_data: Dict[str, Any]) -> bool:
        """Send event to SIEM"""
        try:
            logger.debug(f"Sending event to SIEM: {event_data}")
            return True
        except Exception as e:
            logger.error(f"Error sending event to SIEM: {e}")
            return False
