# Blue-sec

<div align="center">
  <h1>🔵 Blue-sec</h1>
  <p><strong>Advanced Bluetooth Security Testing Framework with Real-Time HID Attacks</strong></p>
  <p>The World's Most Comprehensive Bluetooth Security Testing Tool</p>

  [![GitHub license](https://img.shields.io/github/license/irfan-sec/Blue-sec)](https://github.com/irfan-sec/Blue-sec/blob/main/LICENSE)
  [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
  [![GitHub issues](https://img.shields.io/github/issues/irfan-sec/Blue-sec)](https://github.com/irfan-sec/Blue-sec/issues)
  [![GitHub stars](https://img.shields.io/github/stars/irfan-sec/Blue-sec)](https://github.com/irfan-sec/Blue-sec/stargazers)
  [![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/irfan-sec/Blue-sec/graphs/commit-activity)
  [![Security: Bandit](https://img.shields.io/badge/Security-Bandit-yellow.svg)](https://github.com/PyCQA/bandit)
</div>

---

## 🚨 Security Warning

**This tool is designed for authorized security testing only.** Unauthorized use against systems you don't own or have explicit permission to test is **illegal and unethical**. Users are responsible for complying with all applicable laws and regulations.

---

## 🌟 What Makes Blue-sec the World's Best?

Blue-sec combines **traditional Bluetooth security testing** with **cutting-edge HID attack capabilities** similar to **BlueDucky** and **Rubber Ducky**, making it the most comprehensive Bluetooth security framework available:

### ✨ Unique Features
- 🎯 **Real-Time HID Attacks** - BadUSB/Rubber Ducky style keyboard injection via Bluetooth
- 🔴 **Interactive Device Testing** - Live testing on real hardware
- 💉 **Payload Injection System** - Pre-built and custom payloads
- 🎮 **DuckyScript Support** - Compatible payload format
- 📡 **Bluetooth & Classic** - Full BLE and Classic Bluetooth support
- 🏢 **Enterprise Ready** - SIEM integration, REST API, compliance reporting
- 📊 **CVE Database** - Real-time vulnerability assessment
- 🛡️ **Attack Simulation** - MITM, Bluesnarfing, Bluebugging, and more

### 🆚 Blue-sec vs BlueDucky

| Feature | Blue-sec | BlueDucky |
|---------|----------|-----------|
| **HID Keyboard Injection** | ✅ | ✅ |
| **Bluetooth Wireless** | ✅ | ✅ |
| **Device Scanning** | ✅ | ❌ |
| **Vulnerability Assessment** | ✅ | ❌ |
| **MITM Attacks** | ✅ | ❌ |
| **Interactive Testing** | ✅ | ❌ |
| **Payload Generator** | ✅ | ⚠️ Limited |
| **Cross-Platform** | ✅ | ⚠️ Hardware-dependent |
| **Enterprise Features** | ✅ | ❌ |
| **REST API** | ✅ | ❌ |
| **Compliance Reporting** | ✅ | ❌ |
| **CVE Database** | ✅ | ❌ |

--- ## 🎯 Features

### 🎮 Real-Time HID Attacks (NEW!)
- **BadUSB/Rubber Ducky Style Attacks**
  - Bluetooth HID keyboard emulation
  - Mouse injection capabilities
  - DuckyScript-compatible payload format
  - Interactive testing mode
  - Pre-built payload library
  - Custom payload generator

### 📡 Device Discovery & Enumeration
  - Active and passive Bluetooth device scanning
  - Service and characteristic enumeration
  - Device fingerprinting and profiling
  - RSSI monitoring and mapping

### 🛡️ Vulnerability Assessment
  - Real-time CVE database integration
  - Protocol weakness detection
  - Firmware version analysis
  - Configuration auditing

### ⚔️ Attack Simulation
  - Man-in-the-Middle (MITM) framework
  - Bluesnarfing detection
  - Bluebugging simulation
  - Bluejacking testing
  - Custom payload creation

### 🏢 Enterprise Integration
  - SIEM compatibility
  - REST API endpoints
  - Compliance reporting
  - Audit logging

---

## 🔧 Installation

### Prerequisites
- Python 3.11+
- Root/Administrator privileges
- Linux/macOS/Windows support
- Bluetooth adapter with BLE capability

### Quick Start
```bash
# Clone the repository
git clone https://github.com/irfan-sec/Blue-sec.git

# Navigate to the directory
cd Blue-sec

# Install required packages
pip install -r requirements.txt

# Run the tool
sudo python3 blue-sec.py --help
```

### Docker Installation
```bash
# Build the Docker image
docker build -t blue-sec .

# Run in container
docker run --net=host --privileged -it blue-sec
```

## 📚 Usage

### 🎮 HID Attack Mode (BlueDucky-Style)

**Test keyboard injection (harmless):**
```bash
# Interactive testing
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF --interactive

# Execute test payload
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF --payload data/payloads/hid/test_keyboard.json

# Rickroll test (harmless)
sudo python3 blue-sec.py hid-test AA:BB:CC:DD:EE:FF --payload data/payloads/hid/rickroll_test.json
```

**Generate custom payloads:**
```bash
# Generate reverse shell payload
sudo python3 blue-sec.py generate-payload \
  --name "Custom Shell" \
  --type reverse_shell \
  --os linux \
  --ip 192.168.1.100 \
  --port 4444 \
  --output my_payload.json

# Generate info gathering payload
sudo python3 blue-sec.py generate-payload \
  --name "System Info" \
  --type info_gather \
  --os windows \
  --output sysinfo.json
```

**Available HID Payloads:**
- `test_keyboard.json` - Harmless keyboard test
- `rickroll_test.json` - Fun test payload
- `info_gather_windows.json` - System information gathering
- `wifi_exfil_windows.json` - WiFi password extraction
- `reverse_shell_linux.json` - Linux reverse shell
- `reverse_shell_windows.json` - Windows reverse shell

### 📡 Basic Scanning
```bash
# Perform basic device discovery
sudo python3 blue-sec.py scan

# Run vulnerability assessment
sudo python3 blue-sec.py vuln-scan <target-address>

# Execute security audit
sudo python3 blue-sec.py audit --format json
```

### ⚔️ Advanced Attack Simulation
```bash
# MITM Attack Simulation
sudo python3 blue-sec.py attack --type mitm --target <target1> --target2 <target2>

# Bluesnarfing Test
sudo python3 blue-sec.py attack --type bluesnarfing --target <target-address>

# Bluejacking Test
sudo python3 blue-sec.py attack --type bluejacking --target <target-address> --message "Test"
```

---

## 🏗️ Project Structure
```
Blue-sec/
├── blue-sec.py              # Main CLI application
├── modules/
│   ├── __init__.py          # Module exports
│   ├── config.py            # Configuration management
│   ├── scanner.py           # Device discovery & enumeration
│   ├── vulnerabilities.py   # Vulnerability assessment & CVE DB
│   ├── attacks.py           # Attack simulation modules
│   ├── hid_attacks.py       # HID keyboard/mouse injection (NEW!)
│   ├── reporting.py         # Report generation & MITRE mapping
│   ├── api.py               # REST API for enterprise integration
│   └── utils.py             # Utility functions & helpers
├── data/
│   ├── cve_database.json    # CVE information (auto-generated)
│   └── payloads/
│       ├── hid/             # HID attack payloads (NEW!)
│       │   ├── test_keyboard.json
│       │   ├── rickroll_test.json
│       │   ├── reverse_shell_linux.json
│       │   ├── reverse_shell_windows.json
│       │   ├── wifi_exfil_windows.json
│       │   └── info_gather_windows.json
│       └── example_payload.json
├── reports/                 # Generated security reports
├── config/
│   └── blue-sec.yaml        # Default configuration
├── tests/
│   └── test_blue_sec.py     # Unit tests
├── docs/
│   ├── API.md               # API documentation
│   └── USAGE.md             # Usage guide
├── Dockerfile               # Docker container definition
├── docker-compose.yml       # Docker Compose configuration
├── requirements.txt         # Python dependencies
└── LICENSE                  # MIT License
```

---

## 🛡️ Security Features

- ✅ Rate limiting for aggressive operations
- ✅ Authentication for dangerous functions
- ✅ Comprehensive audit logging
- ✅ Fail-safe mechanisms and kill switches
- ✅ User confirmation for HID attacks
- ✅ Warning systems for dangerous operations
- ✅ CVE database integration
- ✅ Payload validation and sanitization

---

## 📝 Configuration

Configuration options can be set in `config/blue-sec.conf`:
```ini
[Scanner]
active_scan_timeout = 10
passive_scan_duration = 30
device_cache_time = 300

[Security]
rate_limit = true
max_attempts = 3
require_confirmation = true

[Enterprise]
siem_url = http://siem.local
api_key = your_api_key
```

## 📊 Report Examples

Blue-sec generates comprehensive reports in multiple formats:

- **Vulnerability Assessment Reports** - Detailed CVE analysis with CVSS scores
- **Attack Simulation Results** - Complete attack logs with success metrics
- **HID Attack Reports** - Payload execution logs and results
- **Compliance Audit Reports** - NIST/compliance framework mappings
- **Device Discovery Logs** - Full device enumeration data
- **MITRE ATT&CK Mapping** - Technique and tactic correlation

All reports support JSON, XML, and HTML formats.

---

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=modules --cov-report=html
```

---

## 🎓 Learning Resources

### Video Tutorials
- Coming soon: YouTube channel with full demonstrations
- HID attack walkthroughs
- Enterprise deployment guides

### Documentation
- [Usage Guide](docs/USAGE.md) - Comprehensive usage instructions
- [API Documentation](docs/API.md) - REST API reference
- [Configuration Guide](config/blue-sec.yaml) - Configuration options

### Example Scenarios
1. **Testing Corporate Bluetooth Security**
2. **HID Attack Demonstrations (Authorized Labs)**
3. **Vulnerability Assessment Workflows**
4. **Compliance Auditing Procedures**

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Add/update tests as needed
5. Run tests (`pytest tests/`)
6. Commit changes (`git commit -m 'Add AmazingFeature'`)
7. Push to branch (`git push origin feature/AmazingFeature`)
8. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **BlueDucky** - Inspiration for HID attack implementation
- **Rubber Ducky** - DuckyScript format reference
- Bluetooth SIG Documentation
- NIST Special Publication 800-121
- CVE Database Contributors
- Open Source Security Community

---

## 📬 Contact

**Irfan Ali**
- Twitter: [@irfan_sec](https://twitter.com/irfan_sec)
- Website: [cyberlearn.systems](https://cyberlearn.systems)
- Email: ceoirfan@cyberlearn.systems
- GitHub: [@irfan-sec](https://github.com/irfan-sec)

---

## ⚠️ Disclaimer

**This tool is for educational and authorized testing purposes only.** The authors assume no liability for misuse or damage caused by this program. 

**Key Points:**
- ⚠️ **NEVER** use on systems you don't own without written authorization
- ⚠️ **ALWAYS** comply with local laws and regulations
- ⚠️ **OBTAIN** explicit permission before testing
- ⚠️ **FOLLOW** responsible disclosure practices
- ⚠️ **UNDERSTAND** the legal implications in your jurisdiction

The authors and contributors:
- Do NOT condone illegal use of this software
- Are NOT responsible for any misuse or damage
- Recommend following responsible disclosure practices
- Encourage compliance with all applicable laws and regulations

**Use responsibly and ethically. Always obtain proper authorization before testing.**

---

<div align="center">
  <p><strong>Made with ❤️ by @irfan-sec</strong></p>
  <p>© 2025 Blue-sec - The World's Most Comprehensive Bluetooth Security Testing Framework</p>
  <p>Combining Traditional Bluetooth Security Testing with Real-Time HID Attacks</p>
</div>
