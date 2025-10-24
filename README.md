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
sudo python3 blue-sec.py
