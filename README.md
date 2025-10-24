# Blue-sec

```markdown
<div align="center">
  <img src="assets/logo.png" alt="Blue-sec Logo" width="200"/>
  <h1>Blue-sec</h1>
  <p>Advanced Bluetooth Security Testing Framework for Enterprise Environments</p>

  [![GitHub license](https://img.shields.io/github/license/irfan-sec/Blue-sec)](https://github.com/irfan-sec/Blue-sec/blob/main/LICENSE)
  [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
  [![GitHub issues](https://img.shields.io/github/issues/irfan-sec/Blue-sec)](https://github.com/irfan-sec/Blue-sec/issues)
  [![GitHub stars](https://img.shields.io/github/stars/irfan-sec/Blue-sec)](https://github.com/irfan-sec/Blue-sec/stargazers)
  [![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/irfan-sec/Blue-sec/graphs/commit-activity)
  [![Security: Bandit](https://img.shields.io/badge/Security-Bandit-yellow.svg)](https://github.com/PyCQA/bandit)
</div>

## 🚨 Security Warning

This tool is designed for **authorized security testing only**. Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical. Users are responsible for complying with all applicable laws and regulations.

## 🎯 Features

- **Device Discovery & Enumeration**
  - Active and passive Bluetooth device scanning
  - Service and characteristic enumeration
  - Device fingerprinting and profiling
  - RSSI monitoring and mapping

- **Vulnerability Assessment**
  - Real-time CVE database integration
  - Protocol weakness detection
  - Firmware version analysis
  - Configuration auditing

- **Attack Simulation**
  - Man-in-the-Middle (MITM) framework
  - Bluesnarfing detection
  - Bluebugging simulation
  - Bluejacking testing
  - Custom payload creation

- **Enterprise Integration**
  - SIEM compatibility
  - REST API endpoints
  - Compliance reporting
  - Audit logging

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

### Basic Scanning
```bash
# Perform basic device discovery
sudo python3 blue-sec.py --scan

# Run vulnerability assessment
sudo python3 blue-sec.py --vuln-scan <target-address>

# Execute security audit
sudo python3 blue-sec.py --audit <target-address> --report pdf
```

### Advanced Features
```bash
# MITM Attack Simulation
sudo python3 blue-sec.py --mitm <target1-address> <target2-address>

# Custom Payload Injection
sudo python3 blue-sec.py --inject <target-address> --payload <payload-file>

# Enterprise Scanning
sudo python3 blue-sec.py --enterprise-scan --output json --siem-forward
```

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
│   ├── reporting.py         # Report generation & MITRE mapping
│   ├── api.py               # REST API for enterprise integration
│   └── utils.py             # Utility functions & helpers
├── data/
│   ├── cve_database.json    # CVE information (auto-generated)
│   └── payloads/            # Custom attack payloads
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

## 🛡️ Security Features

- Rate limiting for aggressive operations
- Authentication for dangerous functions
- Comprehensive audit logging
- Fail-safe mechanisms
- Warning systems
- CVE database integration

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
- **Compliance Audit Reports** - NIST/compliance framework mappings
- **Device Discovery Logs** - Full device enumeration data
- **MITRE ATT&CK Mapping** - Technique and tactic correlation

All reports support JSON, XML, and HTML formats.

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

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Run tests (`pytest tests/`)
5. Push to branch (`git push origin feature/AmazingFeature`)
6. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Bluetooth SIG Documentation
- NIST Special Publication 800-121
- CVE Database Contributors
- Open Source Security Community

## 📬 Contact

Irfan Ali - [@irfan_sec](https://twitter.com/irfan_sec)
Website - [cyberlearn.systems](https://cyberlearn.systems)
Email - ceoirfan@cyberlearn.systems

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. The authors assume no liability for misuse or damage caused by this program. Use responsibly and ethically.

---
<div align="center">
  <p>Made with ❤️ by @irfan-sec</p>
  <p>© 2025 Blue-sec - Enterprise Bluetooth Security Testing Framework</p>
</div>
```

## 📖 Documentation

- [Usage Guide](docs/USAGE.md) - Comprehensive usage instructions
- [API Documentation](docs/API.md) - REST API reference
- [Configuration Guide](config/blue-sec.yaml) - Configuration options

## 🔒 Security Notice

This tool is designed for **authorized security testing only**. The authors and contributors:

- Do NOT condone illegal use of this software
- Are NOT responsible for any misuse or damage
- Recommend following responsible disclosure practices
- Encourage compliance with all applicable laws and regulations

**Use responsibly and ethically. Always obtain proper authorization before testing.**
