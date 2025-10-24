#!/usr/bin/env python3
"""
Blue-sec - Advanced Bluetooth Security Testing Framework
Author: @irfan-sec
License: MIT
"""

import sys
import asyncio
import click
from pathlib import Path
from loguru import logger

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules import (
    banner, setup_logging, require_privileges, load_config,
    DeviceScanner, scan_bluetooth_devices, BluetoothDevice,
    CVEDatabase, VulnerabilityScanner,
    AttackManager,
    ReportGenerator, SIEMIntegration,
    display_table, display_panel, console, validate_mac_address
)


@click.group()
@click.option('--config', '-c', help='Path to configuration file')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--log-file', help='Log file path')
@click.pass_context
def cli(ctx, config, debug, log_file):
    """Blue-sec - Advanced Bluetooth Security Testing Framework"""
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Load configuration
    ctx.obj['config'] = load_config(config)
    
    if debug:
        ctx.obj['config'].debug_mode = True
        ctx.obj['config'].log_level = "DEBUG"
    
    # Setup logging
    setup_logging(ctx.obj['config'].log_level, log_file)


@cli.command()
@click.option('--type', '-t', type=click.Choice(['ble', 'classic', 'all']), default='all', help='Scan type')
@click.option('--duration', '-d', type=int, help='Scan duration in seconds')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def scan(ctx, type, duration, output):
    """Scan for Bluetooth devices"""
    banner()
    
    config = ctx.obj['config']
    
    try:
        console.print(f"\n[bold cyan]Starting {type} Bluetooth scan...[/bold cyan]\n")
        
        # Run scan
        devices = asyncio.run(scan_bluetooth_devices(config.scanner, type))
        
        if not devices:
            console.print("[yellow]No devices found[/yellow]")
            return
        
        # Display results
        console.print(f"\n[bold green]Found {len(devices)} device(s)[/bold green]\n")
        
        rows = []
        for device in devices:
            rows.append([
                device.address,
                device.name or "Unknown",
                device.device_type,
                f"{device.rssi} dBm" if device.rssi else "N/A",
                len(device.services)
            ])
        
        display_table(
            "Discovered Devices",
            ["Address", "Name", "Type", "RSSI", "Services"],
            rows
        )
        
        # Save to file if requested
        if output:
            report_gen = ReportGenerator(config.reporting.output_directory)
            report_path = report_gen.generate_scan_report(devices, format='json')
            console.print(f"\n[green]Results saved to: {report_path}[/green]")
    
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('target')
@click.option('--enumerate', '-e', is_flag=True, help='Enumerate services and characteristics')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def info(ctx, target, enumerate, output):
    """Get detailed information about a device"""
    banner()
    
    if not validate_mac_address(target):
        console.print("[bold red]Error:[/bold red] Invalid MAC address format")
        sys.exit(1)
    
    config = ctx.obj['config']
    
    try:
        console.print(f"\n[bold cyan]Gathering information for {target}...[/bold cyan]\n")
        
        scanner = DeviceScanner(config.scanner)
        device = asyncio.run(scanner.get_device_info(target))
        
        if not device:
            console.print(f"[yellow]Could not connect to device {target}[/yellow]")
            return
        
        # Display device info
        info_text = f"""
Address: {device.address}
Name: {device.name or 'Unknown'}
Type: {device.device_type}
RSSI: {device.rssi or 'N/A'} dBm
Services: {len(device.services)}
Characteristics: {len(device.characteristics)}
First Seen: {device.first_seen}
Last Seen: {device.last_seen}
"""
        display_panel("Device Information", info_text.strip())
        
        if device.services:
            console.print("\n[bold]Services:[/bold]")
            for service in device.services:
                console.print(f"  • {service}")
        
        if enumerate and device.characteristics:
            console.print("\n[bold]Characteristics:[/bold]")
            for char in device.characteristics[:10]:  # Show first 10
                console.print(f"  • {char['uuid']} (Handle: {char['handle']})")
    
    except Exception as e:
        logger.error(f"Info gathering failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('target')
@click.option('--output', '-o', help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['json', 'xml', 'html']), default='json', help='Report format')
@click.pass_context
def vuln_scan(ctx, target, output, format):
    """Perform vulnerability assessment on a device"""
    banner()
    
    if not validate_mac_address(target):
        console.print("[bold red]Error:[/bold red] Invalid MAC address format")
        sys.exit(1)
    
    config = ctx.obj['config']
    
    try:
        console.print(f"\n[bold cyan]Scanning {target} for vulnerabilities...[/bold cyan]\n")
        
        # Get device info
        scanner = DeviceScanner(config.scanner)
        device = asyncio.run(scanner.get_device_info(target))
        
        if not device:
            console.print(f"[yellow]Could not connect to device {target}[/yellow]")
            return
        
        # Initialize vulnerability scanner
        cve_db = CVEDatabase()
        vuln_scanner = VulnerabilityScanner(cve_db)
        
        # Scan for vulnerabilities
        vulnerabilities = asyncio.run(vuln_scanner.scan_device(device))
        
        if not vulnerabilities:
            console.print(f"[green]No vulnerabilities found[/green]")
            return
        
        # Display results
        console.print(f"\n[bold yellow]Found {len(vulnerabilities)} potential vulnerability(ies)[/bold yellow]\n")
        
        for vuln in vulnerabilities:
            severity_color = {
                'critical': 'red',
                'high': 'orange',
                'medium': 'yellow',
                'low': 'green'
            }.get(vuln.severity, 'white')
            
            vuln_text = f"""
CVE ID: {vuln.cve_id}
Severity: {vuln.severity.upper()} (CVSS: {vuln.cvss_score})
Title: {vuln.title}
Description: {vuln.description}
Mitigation: {vuln.mitigation or 'N/A'}
"""
            display_panel(f"Vulnerability - {vuln.cve_id}", vuln_text.strip(), style=severity_color)
        
        # Generate report
        report_gen = ReportGenerator(config.reporting.output_directory)
        report_path = report_gen.generate_vulnerability_report(device, vulnerabilities, format)
        console.print(f"\n[green]Report saved to: {report_path}[/green]")
    
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.option('--type', '-t', required=True, 
              type=click.Choice(['mitm', 'bluesnarfing', 'bluebugging', 'bluejacking', 'pin_bruteforce']),
              help='Attack type')
@click.option('--target', required=True, help='Target device address')
@click.option('--target2', help='Second target for MITM attack')
@click.option('--message', help='Message for Bluejacking')
@click.option('--command', help='Command for Bluebugging')
@click.option('--pin-length', type=int, default=4, help='PIN length for brute force')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def attack(ctx, type, target, target2, message, command, pin_length, output):
    """Execute attack simulation (requires confirmation)"""
    banner()
    
    # Require elevated privileges
    require_privileges()
    
    if not validate_mac_address(target):
        console.print("[bold red]Error:[/bold red] Invalid MAC address format")
        sys.exit(1)
    
    config = ctx.obj['config']
    
    # Warning
    console.print("\n[bold red]⚠️  WARNING: Attack simulation mode ⚠️[/bold red]")
    console.print("[yellow]This should only be used on devices you own or have explicit permission to test[/yellow]\n")
    
    try:
        # Initialize attack manager
        attack_mgr = AttackManager(config.attack, config.security)
        
        # Prepare attack parameters
        kwargs = {'target': target}
        
        if type == 'mitm':
            if not target2:
                console.print("[bold red]Error:[/bold red] MITM attack requires --target2")
                sys.exit(1)
            if not validate_mac_address(target2):
                console.print("[bold red]Error:[/bold red] Invalid target2 MAC address format")
                sys.exit(1)
            kwargs = {'target1': target, 'target2': target2, 'duration': 30}
        elif type == 'bluejacking':
            kwargs['message'] = message or "Test message from Blue-sec"
        elif type == 'bluebugging':
            kwargs['command'] = command or "test"
        elif type == 'pin_bruteforce':
            kwargs['pin_length'] = pin_length
        
        # Execute attack
        console.print(f"\n[bold cyan]Executing {type} attack...[/bold cyan]\n")
        result = asyncio.run(attack_mgr.execute_attack(type, **kwargs))
        
        # Display result
        if result.success:
            console.print(f"\n[bold green]✓ Attack successful[/bold green]")
        else:
            console.print(f"\n[bold red]✗ Attack failed[/bold red]")
            if result.error:
                console.print(f"[red]Error: {result.error}[/red]")
        
        result_text = f"""
Attack Type: {result.attack_type}
Target: {result.target}
Success: {result.success}
Duration: {result.duration:.2f} seconds
Timestamp: {result.timestamp}
"""
        display_panel("Attack Result", result_text.strip())
        
        if result.details:
            console.print("\n[bold]Details:[/bold]")
            for key, value in result.details.items():
                console.print(f"  {key}: {value}")
        
        # Generate report
        if output or config.reporting.default_format:
            report_gen = ReportGenerator(config.reporting.output_directory)
            report_path = report_gen.generate_attack_report(
                [result],
                include_mitre=config.reporting.include_mitre_mapping
            )
            console.print(f"\n[green]Report saved to: {report_path}[/green]")
    
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.option('--format', '-f', type=click.Choice(['json', 'xml', 'html']), default='json', help='Report format')
@click.pass_context
def audit(ctx, format):
    """Perform comprehensive security audit"""
    banner()
    require_privileges()
    
    config = ctx.obj['config']
    
    try:
        console.print("\n[bold cyan]Starting comprehensive security audit...[/bold cyan]\n")
        
        # Step 1: Device discovery
        console.print("[1/3] Discovering devices...")
        devices = asyncio.run(scan_bluetooth_devices(config.scanner, 'all'))
        console.print(f"  Found {len(devices)} devices\n")
        
        if not devices:
            console.print("[yellow]No devices found to audit[/yellow]")
            return
        
        # Step 2: Vulnerability scanning
        console.print("[2/3] Scanning for vulnerabilities...")
        cve_db = CVEDatabase()
        vuln_scanner = VulnerabilityScanner(cve_db)
        
        all_vulnerabilities = asyncio.run(vuln_scanner.batch_scan(devices))
        total_vulns = sum(len(vulns) for vulns in all_vulnerabilities.values())
        console.print(f"  Found {total_vulns} potential vulnerabilities\n")
        
        # Step 3: Generate comprehensive report
        console.print("[3/3] Generating report...")
        report_gen = ReportGenerator(config.reporting.output_directory)
        
        scan_report = report_gen.generate_scan_report(devices, all_vulnerabilities, format)
        compliance_report = report_gen.generate_compliance_report(devices, all_vulnerabilities)
        
        console.print(f"\n[bold green]✓ Audit complete[/bold green]")
        console.print(f"\nReports generated:")
        console.print(f"  • Scan report: {scan_report}")
        console.print(f"  • Compliance report: {compliance_report}")
    
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def list_cves(ctx):
    """List known Bluetooth CVEs in database"""
    banner()
    
    try:
        cve_db = CVEDatabase()
        
        rows = []
        for cve_id, vuln in cve_db.vulnerabilities.items():
            rows.append([
                vuln.cve_id,
                vuln.title[:50],
                vuln.severity,
                vuln.cvss_score
            ])
        
        display_table(
            "Known Bluetooth CVEs",
            ["CVE ID", "Title", "Severity", "CVSS"],
            rows
        )
        
        console.print(f"\n[cyan]Total CVEs in database: {len(cve_db.vulnerabilities)}[/cyan]")
    
    except Exception as e:
        logger.error(f"Error listing CVEs: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('target')
@click.option('--payload', '-p', help='HID payload file (JSON format)')
@click.option('--interactive', '-i', is_flag=True, help='Interactive testing mode')
@click.option('--os', type=click.Choice(['windows', 'linux', 'macos', 'all']), default='all', help='Target OS')
@click.pass_context
def hid_test(ctx, target, payload, interactive, os):
    """Real-time HID attack testing (BlueDucky-style)"""
    banner()
    require_privileges()
    
    if not validate_mac_address(target):
        console.print("[bold red]Error:[/bold red] Invalid MAC address format")
        sys.exit(1)
    
    config = ctx.obj['config']
    
    # Warning
    console.print("\n[bold red]⚠️  WARNING: HID Attack Mode ⚠️[/bold red]")
    console.print("[yellow]This performs keyboard/mouse injection attacks similar to BadUSB/Rubber Ducky[/yellow]")
    console.print("[yellow]Only use on devices you own or have explicit permission to test[/yellow]\n")
    
    try:
        from modules import RealTimeDeviceTester, HIDPayload, PayloadGenerator
        
        # Initialize tester
        tester = RealTimeDeviceTester(config.attack, config.security)
        
        if interactive:
            # Interactive mode
            console.print(f"\n[bold cyan]Starting interactive HID testing session with {target}...[/bold cyan]\n")
            
            started = asyncio.run(tester.start_interactive_session(target))
            if not started:
                console.print("[bold red]Failed to start interactive session[/bold red]")
                sys.exit(1)
            
            console.print("\n[green]Interactive session ready![/green]")
            console.print("[cyan]Enter commands (type 'help' for command list, 'exit' to quit):[/cyan]\n")
            
            # Interactive loop would go here
            # For now, just show that it's ready
            console.print("[yellow]Note: Full interactive mode requires a terminal. Use --payload for automated testing.[/yellow]")
            
        elif payload:
            # Execute specific payload
            console.print(f"\n[bold cyan]Executing HID payload from: {payload}[/bold cyan]\n")
            
            # Load payload
            hid_payload = HIDPayload.from_file(payload)
            
            console.print(f"Payload: {hid_payload.name}")
            console.print(f"Description: {hid_payload.description}")
            console.print(f"Target OS: {hid_payload.target_os}")
            console.print(f"Commands: {len(hid_payload.commands)}\n")
            
            # Confirm
            if not confirm_action("Execute this payload?", default=False):
                console.print("[yellow]Cancelled by user[/yellow]")
                return
            
            # Connect and execute
            from modules import HIDKeyboardInjector
            injector = HIDKeyboardInjector(config.attack, config.security)
            
            connected = asyncio.run(injector.connect(target))
            if not connected:
                console.print("[bold red]Failed to connect to device[/bold red]")
                sys.exit(1)
            
            result = asyncio.run(injector.execute_payload(hid_payload))
            
            asyncio.run(injector.disconnect())
            
            # Display result
            if result.success:
                console.print(f"\n[bold green]✓ Payload executed successfully[/bold green]")
            else:
                console.print(f"\n[bold red]✗ Payload execution failed[/bold red]")
                if result.error:
                    console.print(f"[red]Error: {result.error}[/red]")
            
            result_text = f"""
Payload: {result.payload_name}
Commands Executed: {result.commands_executed}
Duration: {result.duration:.2f} seconds
Success: {result.success}
"""
            display_panel("HID Attack Result", result_text.strip())
            
        else:
            # Show example payloads
            console.print("\n[bold cyan]Available HID Attack Modes:[/bold cyan]\n")
            console.print("1. [green]Interactive Mode[/green] - Real-time keyboard injection")
            console.print("   Usage: blue-sec.py hid-test <target> --interactive\n")
            console.print("2. [green]Payload Execution[/green] - Execute pre-defined payload")
            console.print("   Usage: blue-sec.py hid-test <target> --payload <file.json>\n")
            
            console.print("[bold cyan]Example Payloads:[/bold cyan]")
            console.print("  • data/payloads/hid/test_keyboard.json - Simple keyboard test")
            console.print("  • data/payloads/hid/rickroll_test.json - Harmless test payload")
            console.print("  • data/payloads/hid/info_gather_windows.json - System info gathering")
            console.print("  • data/payloads/hid/reverse_shell_linux.json - Linux reverse shell")
            console.print("  • data/payloads/hid/reverse_shell_windows.json - Windows reverse shell\n")
            
            console.print("[yellow]See docs/USAGE.md for detailed HID attack documentation[/yellow]")
    
    except Exception as e:
        logger.error(f"HID test failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.option('--name', '-n', required=True, help='Payload name')
@click.option('--type', '-t', required=True, 
              type=click.Choice(['reverse_shell', 'wifi_exfil', 'info_gather', 'custom']),
              help='Payload type')
@click.option('--os', type=click.Choice(['windows', 'linux', 'macos']), default='windows', help='Target OS')
@click.option('--ip', help='Attacker IP (for reverse shell)')
@click.option('--port', type=int, default=4444, help='Attacker port (for reverse shell)')
@click.option('--output', '-o', required=True, help='Output file path')
@click.pass_context
def generate_payload(ctx, name, type, os, ip, port, output):
    """Generate HID attack payload"""
    banner()
    
    try:
        from modules import PayloadGenerator
        
        console.print(f"\n[bold cyan]Generating {type} payload for {os}...[/bold cyan]\n")
        
        if type == 'reverse_shell':
            if not ip:
                console.print("[bold red]Error:[/bold red] --ip required for reverse shell payload")
                sys.exit(1)
            payload = PayloadGenerator.reverse_shell(ip, port, os)
        elif type == 'wifi_exfil':
            payload = PayloadGenerator.wifi_password_exfiltration(os)
        elif type == 'rickroll':
            payload = PayloadGenerator.rickroll()
        else:
            console.print("[yellow]Custom payload generation not yet implemented[/yellow]")
            console.print("[cyan]Use existing payloads in data/payloads/hid/ as templates[/cyan]")
            return
        
        # Save to file
        import json
        with open(output, 'w') as f:
            json.dump(payload.to_dict(), f, indent=4)
        
        console.print(f"[bold green]✓ Payload saved to: {output}[/bold green]")
        console.print(f"\nPayload details:")
        console.print(f"  Name: {payload.name}")
        console.print(f"  Description: {payload.description}")
        console.print(f"  Target OS: {payload.target_os}")
        console.print(f"  Commands: {len(payload.commands)}")
        
        console.print(f"\n[cyan]Execute with: python3 blue-sec.py hid-test <target> --payload {output}[/cyan]")
    
    except Exception as e:
        logger.error(f"Payload generation failed: {e}")
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information"""
    console.print("""
[bold cyan]Blue-sec v2.0[/bold cyan]
Advanced Bluetooth Security Testing Framework with Real-Time HID Attacks

Features:
  • Bluetooth device scanning and enumeration
  • Vulnerability assessment with CVE database
  • Attack simulation (MITM, Bluesnarfing, Bluebugging, etc.)
  • Real-time HID attacks (BadUSB/Rubber Ducky style)
  • Interactive device testing
  • Enterprise integration (SIEM, REST API)
  • Comprehensive reporting

Author: @irfan-sec
License: MIT
Website: https://cyberlearn.systems
GitHub: https://github.com/irfan-sec/Blue-sec
    """)


def main():
    """Main entry point"""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        console.print(f"\n[bold red]Fatal error:[/bold red] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
