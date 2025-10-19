# Nmap Menu Script

A comprehensive, interactive command-line menu interface for Nmap (Network Mapper) that provides easy access to scanning capabilities, documentation, and best practices.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Menu Options](#menu-options)
- [Examples](#examples)
- [Legal Disclaimer](#legal-disclaimer)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This Python-based interactive menu system simplifies the use of Nmap for network scanning and security auditing. Whether you're a beginner learning about network scanning or a professional conducting security assessments, this tool provides an organized interface to access Nmap's powerful features.

## ✨ Features

- **Interactive Menu System**: Easy-to-navigate interface with 28+ options
- **Built-in Documentation**: Access Nmap command references without leaving the tool
- **Automated Scanning**: Perform quick, standard, intensive, ping, and custom scans
- **Educational Content**: Learn about scan types, options, and best practices
- **Multiple Scan Types**: Support for various Nmap scan modes
- **Output Management**: Information about saving and formatting scan results
- **Security Guidance**: Legal and ethical considerations for responsible scanning
- **Troubleshooting Help**: FAQ and common issue resolution

## 📦 Prerequisites

### Required Software

1. **Python 3.6+**
   ```bash
   python --version
   ```

2. **Nmap**
   - **Ubuntu/Debian**: `sudo apt-get install nmap`
   - **CentOS/RHEL/Fedora**: `sudo yum install nmap`
   - **macOS**: `brew install nmap`
   - **Windows**: Download from [nmap.org](https://nmap.org/download.html)

3. **Python Nmap Library**
   ```bash
   pip install python-nmap
   ```

### System Requirements

- Operating System: Linux, macOS, or Windows
- RAM: 512MB minimum
- Disk Space: 50MB for Nmap and dependencies
- Network: Internet connection (for scanning external targets)
- Permissions: Root/Administrator privileges for certain scan types

## 🚀 Installation

### Step 1: Clone or Download

```bash
# If using git
git clone <repository-url>
cd nmap-menu-script

# Or download main.py directly
```

### Step 2: Install Dependencies

```bash
pip install python-nmap
```

### Step 3: Verify Nmap Installation

```bash
nmap --version
```

### Step 4: Run the Script

```bash
python main.py
```

## 💻 Usage

### Basic Usage

```bash
python main.py
```

### Running with Sudo (for advanced scans)

```bash
sudo python main.py
```

### Quick Start Example

1. Run the script
2. Select option `1` to check if Nmap is installed
3. Select option `6` to perform a scan
4. Enter target IP address
5. Choose scan type
6. Review results

## 📖 Menu Options

### Main Menu Structure

| Option | Description |
|--------|-------------|
| 1 | Check if Nmap is installed |
| 2 | Install Nmap (instructions) |
| 3 | Nmap Scan Types |
| 4 | Nmap Scan Options |
| 5 | Nmap Output Formats |
| 6 | **Perform Nmap Scan** |
| 7 | Advanced Nmap Options |
| 8 | Nmap Scripting Engine Options |
| 9 | Timing and Performance Options |
| 10 | Firewall Evasion Techniques |
| 11 | Output Options |
| 12 | Host Discovery Options |
| 13 | Port Specification and Scan Order |
| 14 | Service and Version Detection |
| 15 | OS Detection Options |
| 16 | Miscellaneous Options |
| 17 | Debugging and Verbosity Options |
| 18 | Example Commands |
| 19 | References and Documentation |
| 20 | Common Use Cases |
| 21 | Tips and Best Practices |
| 22 | Alternatives and Complementary Tools |
| 23 | FAQ and Troubleshooting |
| 24 | Changelog and Release Notes |
| 25 | Community and Support Resources |
| 26 | Legal and Ethics Considerations |
| 27 | Future Developments and Roadmap |
| 28 | Conclusion and Summary |
| 29 | Return to Main Menu |
| 0 | Exit |

## 🎯 Examples

### Example 1: Quick Port Scan

```
1. Run: python main.py
2. Select: 6 (Perform Nmap Scan)
3. Enter target: 192.168.1.1
4. Select scan type: 1 (Quick scan)
```

### Example 2: Service Version Detection

```
1. Run: python main.py
2. Select: 6 (Perform Nmap Scan)
3. Enter target: scanme.nmap.org
4. Select scan type: 2 (Standard scan)
```

### Example 3: Learn About Scan Types

```
1. Run: python main.py
2. Select: 3 (Nmap Scan Types)
3. Review available scan types
4. Press Enter to return to menu
```

### Example 4: Custom Scan

```
1. Run: python main.py
2. Select: 6 (Perform Nmap Scan)
3. Enter target: 192.168.1.0/24
4. Select scan type: 5 (Custom scan)
5. Enter arguments: -sV -p 80,443 -T4
```

## ⚠️ Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

### You Must:

✅ Only scan networks and systems you **own** or have **explicit written permission** to scan

✅ Comply with all local, state, and federal laws regarding network scanning

✅ Follow your organization's security and acceptable use policies

✅ Obtain proper authorization before conducting security assessments

✅ Document all authorized scanning activities

### You Must Not:

❌ Scan networks without permission (this may be illegal)

❌ Use this tool for malicious purposes

❌ Scan critical infrastructure without proper authorization

❌ Perform scans that may disrupt services or networks

❌ Use discovered vulnerabilities to harm systems or data

### Legal Consequences

Unauthorized network scanning may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

**Penalties may include fines, civil liability, and criminal prosecution.**

### Recommended Practice

Always obtain a **signed agreement** or **scope document** before scanning, which includes:
- List of authorized targets
- Approved scanning time windows
- Approved scanning methods
- Contact information for escalation
- Defined reporting procedures

## 🔧 Troubleshooting

### Common Issues

#### "Nmap not found" Error

**Solution:**
```bash
# Verify installation
nmap --version

# If not installed, install Nmap:
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install nmap

# macOS
brew install nmap
```

#### "Permission denied" Error

**Solution:**
```bash
# Run with sudo for raw socket access
sudo python main.py
```

#### "python-nmap not installed"

**Solution:**
```bash
pip install python-nmap

# Or with pip3
pip3 install python-nmap
```

#### Scans Running Very Slowly

**Solutions:**
- Use timing template: `-T4`
- Limit port range: `-p 1-1000`
- Use fast scan option in menu (Option 6, Choice 1)
- Check network connectivity

#### No Results from Scan

**Solutions:**
- Verify target is online: `ping <target>`
- Use `-Pn` flag to skip host discovery
- Check firewall rules
- Ensure you have network connectivity

#### Script Crashes During Scan

**Solutions:**
- Update python-nmap: `pip install --upgrade python-nmap`
- Update Nmap to latest version
- Check target format (ensure valid IP/hostname)
- Review any custom arguments for syntax errors

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with details about the problem
2. **Suggest Features**: Submit feature requests via issues
3. **Submit Pull Requests**: Fork, modify, and submit PRs
4. **Improve Documentation**: Help make the README clearer
5. **Share Use Cases**: Contribute examples and tutorials

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd nmap-menu-script

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install python-nmap

# Run the script
python main.py
```

## 📚 Additional Resources

### Official Nmap Resources

- **Website**: https://nmap.org
- **Documentation**: https://nmap.org/docs.html
- **Book**: https://nmap.org/book/
- **NSE Scripts**: https://nmap.org/nsedoc/

### Learning Resources

- Nmap Network Scanning (Official Book)
- Cybrary Nmap Courses
- TryHackMe Nmap Rooms
- HackTheBox Academy

### Community

- **Mailing Lists**: https://nmap.org/mailman/listinfo
- **IRC**: #nmap on Libera.Chat
- **GitHub Issues**: https://github.com/nmap/nmap/issues

## 📄 License

This script is provided "as-is" for educational and authorized security testing purposes only.

**Nmap License**: Nmap is distributed under the Nmap Public Source License (NPSL). See https://nmap.org/npsl/ for details.

## 👤 Author

Created for educational purposes and authorized security testing.

## 🔄 Version History

### Version 1.0.0
- Initial release
- 28+ interactive menu options
- Basic and advanced scanning capabilities
- Comprehensive documentation
- Educational content

## 📞 Support

For issues or questions:

1. Check the Troubleshooting section above
2. Review Nmap documentation at https://nmap.org/docs.html
3. Open an issue on the repository
4. Consult the Nmap community resources

---

**Remember: Scan responsibly, scan legally, and always get permission first!**

*Last Updated: 2025*
