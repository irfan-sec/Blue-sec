# Blue-sec GUI Documentation

## Overview

Blue-sec now includes a comprehensive Graphical User Interface (GUI) that provides an intuitive way to interact with all the framework's features. The GUI is built using Python's tkinter library, ensuring cross-platform compatibility without additional dependencies.

## Getting Started

### Prerequisites

- Python 3.11+
- tkinter (usually included with Python, or install with `apt-get install python3-tk` on Linux)
- All Blue-sec dependencies from `requirements.txt`

### Launching the GUI

```bash
# From the Blue-sec directory
python3 blue-sec-gui.py
```

Or on Windows:
```bash
python blue-sec-gui.py
```

## Interface Overview

The Blue-sec GUI is organized into five main tabs:

### 1. Device Scanner Tab

**Purpose**: Discover and enumerate Bluetooth devices in range.

**Features**:
- **Scan Type Selection**: Choose between BLE, Classic Bluetooth, or All
- **Start/Stop Scan**: Real-time device scanning with live updates
- **Device List**: Displays all discovered devices with:
  - MAC Address
  - Device Name
  - Device Type (BLE/Classic)
  - Signal Strength (RSSI)
  - Number of Services
- **Device Information Panel**: Shows detailed info for selected device
  - Address, Name, Type
  - RSSI value
  - Services list
  - First/Last seen timestamps

**How to Use**:
1. Select scan type (all/ble/classic)
2. Click "Start Scan"
3. Wait for devices to be discovered
4. Click on a device in the list to view details
5. Use "Use Selected" button in other tabs to target this device

### 2. Vulnerability Scanner Tab

**Purpose**: Assess security vulnerabilities in discovered Bluetooth devices.

**Features**:
- **Target Selection**: Enter MAC address or use selected device
- **Automated Scanning**: Scan devices for known CVEs
- **Vulnerability Display**: Shows detailed vulnerability information:
  - CVE ID
  - Severity level (Critical/High/Medium/Low)
  - CVSS Score
  - Description
  - Mitigation advice

**How to Use**:
1. Select a device from the Scanner tab OR enter MAC address manually
2. Click "Use Selected" to populate target field
3. Click "Scan" to start vulnerability assessment
4. Review discovered vulnerabilities in the results panel
5. Generate reports from the Tools menu

### 3. HID Attacks Tab

**Purpose**: Execute keyboard/mouse injection attacks (BadUSB/Rubber Ducky style).

**⚠️ WARNING**: This tab contains dangerous features. Only use on authorized devices!

**Features**:
- **Target Selection**: Choose device for HID attack
- **Payload Browser**: Select from pre-built payloads or load custom ones
- **Available Payloads**: List of built-in payloads:
  - `test_keyboard.json` - Harmless keyboard test
  - `rickroll_test.json` - Fun demonstration
  - `info_gather_windows.json` - System information gathering
  - `wifi_exfil_windows.json` - WiFi password extraction
  - `reverse_shell_linux.json` - Linux reverse shell
  - `reverse_shell_windows.json` - Windows reverse shell
- **Test Connection**: Verify device connectivity before payload execution
- **Execution Results**: Shows payload execution status and logs

**How to Use**:
1. Select or enter target device MAC address
2. Choose a payload from the list OR browse for custom payload
3. Click "Test Connection" to verify connectivity (optional)
4. Click "Execute Payload" (requires confirmation)
5. Review execution results

**Safety Features**:
- Confirmation dialog before execution
- Visual warnings throughout the interface
- Detailed logging of all actions
- Connection testing before payload execution

### 4. Attack Simulation Tab

**Purpose**: Execute various Bluetooth attack simulations for security testing.

**⚠️ WARNING**: Only use on authorized devices with proper permission!

**Features**:
- **Attack Type Selection**: Choose from:
  - MITM (Man-in-the-Middle)
  - Bluesnarfing
  - Bluebugging
  - Bluejacking
  - PIN Brute Force
- **Target Selection**: Specify device for attack
- **Execution Results**: Detailed attack outcome logs

**How to Use**:
1. Select attack type from dropdown
2. Enter target MAC address or use selected device
3. Click "Execute Attack" (requires confirmation)
4. Review attack results and success/failure status

### 5. Logs Tab

**Purpose**: Monitor all operations and maintain activity history.

**Features**:
- **Real-time Logging**: All operations are logged with timestamps
- **Clear Logs**: Remove all log entries
- **Export Logs**: Save logs to file for documentation
- **Auto-scroll**: Automatically scrolls to show latest entries

**Log Information Includes**:
- Scan operations
- Device discoveries
- Vulnerability assessments
- Attack executions
- Errors and warnings

## Menu Bar Features

### File Menu

- **Load Config**: Load custom configuration file
- **Exit**: Close the application

### Tools Menu

- **List CVEs**: View complete CVE database
  - Opens new window with all known Bluetooth vulnerabilities
  - Sortable by severity, CVSS score, etc.
- **Generate Report**: Create comprehensive security report
  - Includes all scanned devices
  - Vulnerability assessments
  - Configurable output format

### Help Menu

- **About**: Display version and author information
- **Documentation**: Links to documentation files

## Workflow Examples

### Example 1: Basic Device Security Assessment

1. Launch GUI: `python3 blue-sec-gui.py`
2. Go to **Device Scanner** tab
3. Select "all" scan type
4. Click **Start Scan**
5. Wait for devices to appear in list
6. Select a device by clicking on it
7. Go to **Vulnerability Scanner** tab
8. Click **Use Selected** button
9. Click **Scan** to assess vulnerabilities
10. Review results
11. Go to **Tools** → **Generate Report** to save findings

### Example 2: HID Attack Testing (Authorized Only!)

1. Ensure you have authorization for the target device
2. Go to **Device Scanner** tab and scan for devices
3. Select your target device
4. Go to **HID Attacks** tab
5. Click **Use Selected** to populate target
6. Select `test_keyboard.json` from payload list
7. Click **Test Connection** to verify connectivity
8. Click **Execute Payload** and confirm
9. Observe results in execution panel
10. Check **Logs** tab for detailed execution log

### Example 3: Monitoring and Logging

1. Perform any operations (scanning, testing, attacks)
2. Go to **Logs** tab to review all activities
3. Click **Export Logs** to save to file
4. Use logs for documentation or audit purposes

## Best Practices

### Security

- ✅ **Always obtain written authorization** before testing any device
- ✅ **Use on test environments** whenever possible
- ✅ **Document all activities** using the logging feature
- ✅ **Review warnings** before executing dangerous operations
- ✅ **Test connections** before executing payloads
- ❌ **Never use** on production systems without authorization
- ❌ **Never ignore** confirmation dialogs

### Performance

- **Scan Duration**: Keep scans under 30 seconds to avoid overwhelming the interface
- **Device Limits**: GUI handles 50+ devices comfortably; more may slow down
- **Background Operations**: Long operations run in background threads
- **Responsiveness**: GUI remains responsive during scans and attacks

### Troubleshooting

**Issue**: GUI doesn't start
- **Solution**: Check tkinter is installed: `python3 -c "import tkinter"`
- **Solution**: Install tkinter: `sudo apt-get install python3-tk` (Linux)

**Issue**: No devices found during scan
- **Solution**: Ensure Bluetooth adapter is enabled
- **Solution**: Run with elevated privileges if required
- **Solution**: Check that target devices are in range and discoverable

**Issue**: HID attacks fail
- **Solution**: Verify device pairing/connection
- **Solution**: Ensure target device accepts HID connections
- **Solution**: Check payload compatibility with target OS

**Issue**: GUI freezes during operations
- **Solution**: Wait for operation to complete (check logs)
- **Solution**: Restart GUI if unresponsive after 60 seconds
- **Solution**: Check system resources (CPU/Memory)

## Keyboard Shortcuts

- **Ctrl+Q**: Quit application (when supported)
- **F5**: Refresh device list (future feature)
- **Ctrl+L**: Clear logs

## Technical Details

### Architecture

The GUI is built using:
- **tkinter**: Cross-platform GUI framework
- **asyncio**: Asynchronous operation handling
- **threading**: Background task execution
- **ttk**: Modern themed widgets

### Thread Safety

- All long-running operations execute in background threads
- UI updates are thread-safe using `root.after()`
- Event loop runs in separate daemon thread

### Resource Management

- Automatically cleans up connections
- Closes threads on application exit
- Minimal memory footprint (~50MB)

## Accessibility

- **High Contrast**: Use system theme settings
- **Font Size**: Configurable via tkinter settings
- **Keyboard Navigation**: Full tab/arrow key support
- **Screen Readers**: Basic support (platform dependent)

## Future Enhancements

Planned features for future releases:
- Dark mode toggle
- Customizable layouts
- Real-time signal strength graphing
- Device relationship mapping
- Export to multiple report formats
- Scheduled scanning
- Plugin system for custom attacks

## Support

For issues, feature requests, or contributions:
- GitHub: https://github.com/irfan-sec/Blue-sec
- Documentation: See docs/USAGE.md and docs/API.md
- Issues: https://github.com/irfan-sec/Blue-sec/issues

## License

The GUI is part of Blue-sec and is licensed under MIT License.

## Disclaimer

**The Blue-sec GUI is for authorized security testing only.**

- Use responsibly and ethically
- Obtain proper authorization before testing
- Comply with all applicable laws
- Follow responsible disclosure practices
- Understand legal implications in your jurisdiction

The authors are NOT responsible for misuse or damage caused by this software.

---

**Made with ❤️ by @irfan-sec**
