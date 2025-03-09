# Network Scanner

## Overview
This script is a comprehensive network scanning tool that performs various reconnaissance tasks, including:

- **Ping Sweep**: Identifies live hosts in a given network range.
- **Port Scanning**: Detects open ports on live hosts.
- **MAC Address Retrieval**: Attempts to retrieve MAC addresses of discovered devices.
- **Service Detection**: Identifies services running on open ports using basic banner grabbing.
- **OS Fingerprinting**: Uses Nmap to estimate the operating system running on a host.
- **Network Mapping**: Provides a summary of discovered hosts and their MAC addresses.

## Features
- Cross-platform compatibility (Windows, Linux, MacOS)
- Multi-threaded for efficiency
- Logs results in `network_scanner.log`
- Simple command-line interface

## Prerequisites
Ensure you have the following dependencies installed:

- Python 3.x
- `nmap` (for OS fingerprinting)

## Installation
Clone the repository and navigate into the project directory:

```sh
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

Install required dependencies:

```sh
pip install socket threading subproces ipaddress platform  # If any external libraries are needed
```

## Usage
Run the script using:

```sh
python network_scanner.py
```

It will prompt you to enter:
- Network range (e.g., `192.168.1.0/24`)
- Start and end ports for scanning

## Ethical Considerations & Legal Awareness
This tool is intended for **authorized security assessments** and educational purposes only. Unauthorized scanning of networks without explicit permission is illegal in many jurisdictions and may lead to legal consequences. Always ensure you have **explicit permission** before scanning any network.

### **Responsible Use Guidelines:**
- **Only scan networks you own or have permission to scan.**
- **Obtain written consent** before scanning third-party networks.
- **Do not use this tool for malicious purposes.**
- Be aware of laws like the **Computer Fraud and Abuse Act (CFAA)** and **GDPR** regulations regarding network reconnaissance.

## Logging
The script logs all activities to `network_scanner.log`, including discovered hosts, open ports, and detected services.


## License
This project is licensed under the MIT License. See `LICENSE` for details.

## Contribution
Contributions are welcome! Feel free to submit a pull request or open an issue.


---
*Disclaimer: This tool is for educational and authorized security testing purposes only.*
