#!/usr/bin/env python3
"""
Blue-sec Example Script
Demonstrates basic usage of Blue-sec as a library
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules import (
    load_config, DeviceScanner, CVEDatabase,
    VulnerabilityScanner, BluetoothDevice,
    console, display_table, display_panel
)


async def example_device_scan():
    """Example: Scan for Bluetooth devices"""
    console.print("\n[bold cyan]Example: Device Scanning[/bold cyan]\n")
    
    # Load configuration
    config = load_config()
    
    # Create scanner
    scanner = DeviceScanner(config.scanner)
    
    # Scan for BLE devices
    console.print("Scanning for BLE devices (this is a demo, no actual scanning)...\n")
    
    # For demonstration, create mock devices
    mock_devices = [
        BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Demo Device 1",
            device_type="ble",
            rssi=-45
        ),
        BluetoothDevice(
            address="11:22:33:44:55:66",
            name="Demo Device 2",
            device_type="ble",
            rssi=-60
        )
    ]
    
    # Display results
    rows = []
    for device in mock_devices:
        rows.append([
            device.address,
            device.name,
            device.device_type,
            f"{device.rssi} dBm"
        ])
    
    display_table(
        "Discovered Devices (Demo)",
        ["Address", "Name", "Type", "RSSI"],
        rows
    )
    
    return mock_devices


async def example_vulnerability_scan():
    """Example: Vulnerability scanning"""
    console.print("\n[bold cyan]Example: Vulnerability Scanning[/bold cyan]\n")
    
    # Create CVE database
    cve_db = CVEDatabase()
    
    # Create vulnerability scanner
    vuln_scanner = VulnerabilityScanner(cve_db)
    
    # Create demo device
    demo_device = BluetoothDevice(
        address="AA:BB:CC:DD:EE:FF",
        name="Demo Device",
        device_type="ble",
        services=["00001800-0000-1000-8000-00805f9b34fb"]
    )
    
    console.print(f"Scanning device: {demo_device.name} ({demo_device.address})\n")
    
    # Scan for vulnerabilities
    vulnerabilities = await vuln_scanner.scan_device(demo_device)
    
    if vulnerabilities:
        console.print(f"[yellow]Found {len(vulnerabilities)} potential vulnerability(ies)[/yellow]\n")
        
        for vuln in vulnerabilities[:3]:  # Show first 3
            info_text = f"""
CVE ID: {vuln.cve_id}
Severity: {vuln.severity.upper()}
CVSS Score: {vuln.cvss_score}
Title: {vuln.title}
"""
            display_panel(
                f"Vulnerability - {vuln.cve_id}",
                info_text.strip(),
                style="yellow"
            )
    else:
        console.print("[green]No vulnerabilities found[/green]")


def example_cve_database():
    """Example: CVE database usage"""
    console.print("\n[bold cyan]Example: CVE Database[/bold cyan]\n")
    
    # Create CVE database
    cve_db = CVEDatabase()
    
    console.print(f"Total CVEs in database: {len(cve_db.vulnerabilities)}\n")
    
    # Search for specific vulnerabilities
    results = cve_db.search_vulnerabilities("BlueBorne")
    console.print(f"CVEs matching 'BlueBorne': {len(results)}")
    
    # Get by severity
    critical = cve_db.get_by_severity("critical")
    high = cve_db.get_by_severity("high")
    
    console.print(f"Critical vulnerabilities: {len(critical)}")
    console.print(f"High severity vulnerabilities: {len(high)}")
    
    # Display some CVEs
    rows = []
    for cve_id, vuln in list(cve_db.vulnerabilities.items())[:5]:
        rows.append([
            vuln.cve_id,
            vuln.title[:40] + "..." if len(vuln.title) > 40 else vuln.title,
            vuln.severity,
            vuln.cvss_score
        ])
    
    display_table(
        "Sample CVEs",
        ["CVE ID", "Title", "Severity", "CVSS"],
        rows
    )


async def main():
    """Main example runner"""
    console.print("""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║              Blue-sec Library Usage Examples                 ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]
""")
    
    console.print("[yellow]Note: These are demonstration examples using mock data.[/yellow]")
    console.print("[yellow]Real Bluetooth scanning requires hardware and privileges.[/yellow]\n")
    
    # Run examples
    await example_device_scan()
    await example_vulnerability_scan()
    example_cve_database()
    
    console.print("\n[bold green]✓ Examples completed![/bold green]")
    console.print("\n[cyan]For more information, see:[/cyan]")
    console.print("  • docs/USAGE.md - Comprehensive usage guide")
    console.print("  • docs/API.md - REST API documentation")
    console.print("  • python3 blue-sec.py --help - CLI help\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
