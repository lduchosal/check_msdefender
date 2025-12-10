# 🛡️ Check MS Defender

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/lduchosal/check_msdefender)

A comprehensive **Nagios plugin** for monitoring Microsoft Defender for Endpoint API endpoints. Built with modern Python practices and designed for enterprise monitoring environments.

## ✨ Features

- 🔐 **Dual Authentication** - Support for Client Secret and Certificate-based authentication
- 🎯 **Multiple Endpoints** - Monitor onboarding status, last seen, vulnerabilities, products with CVEs, alerts, and machine details
- 📊 **Nagios Compatible** - Standard exit codes and performance data output
- 🏗️ **Clean Architecture** - Modular design with testable components
- 🔧 **Flexible Configuration** - File-based configuration with sensible defaults
- 📈 **Verbose Logging** - Multi-level debugging support
- 🐍 **Modern Python** - Built with Python 3.9+ using type hints and async patterns

## 🚀 Quick Start

### Installation

```bash
# Create virtual environment (recommended)
python -m venv /usr/local/libexec/nagios/check_msdefender
source /usr/local/libexec/nagios/check_msdefender/bin/activate

# Install from source
pip install git+https://github.com/lduchosal/check_msdefender.git
```

### Basic Usage

```bash
# Check machine onboarding status
check_msdefender onboarding -d machine.domain.tld

# Check last seen (with custom thresholds)
check_msdefender lastseen -d machine.domain.tld -W 7 -C 30

# Check vulnerabilities
check_msdefender vulnerabilities -d machine.domain.tld -W 10 -C 100

# Check products with CVE vulnerabilities
check_msdefender products -d machine.domain.tld -W 5 -C 1

# Check alerts
check_msdefender alerts -d machine.domain.tld -W 1 -C 5

# List all machines
check_msdefender machines

# Get detailed machine info
check_msdefender detail -d machine.domain.tld
```

## 📋 Available Commands

| Command | Description | Default Thresholds |
|---------|-------------|-------------------|
| `onboarding` | Check machine onboarding status | W:1, C:2 |
| `lastseen` | Days since machine last seen | W:7, C:30 |
| `vulnerabilities` | Vulnerability score calculation | W:10, C:100 |
| `products` | Count of vulnerable software with CVEs | W:5, C:1 |
| `alerts` | Count of unresolved alerts | W:1, C:0 |
| `machines` | List all machines | W:10, C:25 |
| `detail` | Get detailed machine information | - |

### Vulnerability Scoring

The vulnerability score is calculated as:
- **Critical vulnerabilities** × 100
- **High vulnerabilities** × 10
- **Medium vulnerabilities** × 5
- **Low vulnerabilities** × 1

### Products CVE Monitoring

The products command monitors installed software with known CVE vulnerabilities:
- **Groups CVEs by software** (name, version, vendor)
- **Shows CVE details** including severity levels and disk paths
- **Counts vulnerable software** (not individual CVEs)
- **Default thresholds**: Warning at 5 vulnerable software, Critical at 1
- **Displays up to 10 software entries** with first 5 CVEs per software

### Alert Monitoring

The alerts command monitors unresolved security alerts for a machine:
- **Counts only unresolved alerts** (status ≠ "Resolved")
- **Excludes informational alerts** when critical/warning alerts exist
- **Shows alert details** including creation time, title, and severity
- **Default thresholds**: Warning at 1 alert, Critical at 0 (meaning any alert triggers warning)

### Onboarding Status Values

- `0` - Onboarded ✅
- `1` - InsufficientInfo ⚠️
- `2` - Unknown ❌

## ⚙️ Configuration

### Authentication Setup

Create `check_msdefender.ini` in your Nagios directory or current working directory:

#### Client Secret Authentication
```ini
[auth]
client_id = your-application-client-id
client_secret = your-client-secret
tenant_id = your-azure-tenant-id

[settings]
timeout = 5
```

#### Certificate Authentication
```ini
[auth]
client_id = your-application-client-id
tenant_id = your-azure-tenant-id
certificate_path = /path/to/certificate.pem
private_key_path = /path/to/private_key.pem

[settings]
timeout = 5
```

### Microsoft Defender API Setup

1. **Register Application** in Azure Active Directory
2. **Grant API Permissions**:
   - `Machine.Read.All`
   - `Vulnerability.Read`
   - `Vulnerability.Read.All`
   - `Alert.Read.All`
3. **Create Authentication** (Secret or Certificate)
4. **Note Credentials** (Client ID, Tenant ID, Secret/Certificate)

📚 [Complete API Setup Guide](https://learn.microsoft.com/en-us/defender-endpoint/api/api-hello-world)

## 🔧 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-c, --config` | Configuration file path | `-c /custom/path/config.ini` |
| `-m, --machineId` | Machine ID (GUID) | `-m "12345678-1234-1234-1234-123456789abc"` |
| `-d, --computerDnsName` | Computer DNS Name (FQDN) | `-d "server.domain.com"` |
| `-W, --warning` | Warning threshold | `-W 10` |
| `-C, --critical` | Critical threshold | `-C 100` |
| `-v, --verbose` | Verbosity level | `-v`, `-vv`, `-vvv` |
| `--version` | Show version | `--version` |

## 🏢 Nagios Integration

### Command Definitions

```cfg
# Microsoft Defender Commands
define command {
    command_name    check_defender_onboarding
    command_line    $USER1$/check_msdefender/bin/check_msdefender onboarding -d $HOSTALIAS$
}

define command {
    command_name    check_defender_lastseen
    command_line    $USER1$/check_msdefender/bin/check_msdefender lastseen -d $HOSTALIAS$ -W 7 -C 30
}

define command {
    command_name    check_defender_vulnerabilities
    command_line    $USER1$/check_msdefender/bin/check_msdefender vulnerabilities -d $HOSTALIAS$ -W 10 -C 100
}

define command {
    command_name    check_defender_products
    command_line    $USER1$/check_msdefender/bin/check_msdefender products -d $HOSTALIAS$ -W 5 -C 1
}

define command {
    command_name    check_defender_alerts
    command_line    $USER1$/check_msdefender/bin/check_msdefender alerts -d $HOSTALIAS$ -W 1 -C 5
}
```

### Service Definitions

```cfg
# Microsoft Defender Services
define service {
    use                     generic-service
    service_description     DEFENDER_ONBOARDING
    check_command           check_defender_onboarding
    hostgroup_name          msdefender
}

define service {
    use                     generic-service
    service_description     DEFENDER_LASTSEEN
    check_command           check_defender_lastseen
    hostgroup_name          msdefender
}

define service {
    use                     generic-service
    service_description     DEFENDER_VULNERABILITIES
    check_command           check_defender_vulnerabilities
    hostgroup_name          msdefender
}

define service {
    use                     generic-service
    service_description     DEFENDER_PRODUCTS
    check_command           check_defender_products
    hostgroup_name          msdefender
}

define service {
    use                     generic-service
    service_description     DEFENDER_ALERTS
    check_command           check_defender_alerts
    hostgroup_name          msdefender
}
```

## 🏗️ Architecture

This plugin follows **clean architecture** principles with clear separation of concerns:

```
check_msdefender/
├── 📁 cli/                     # Command-line interface
│   ├── commands/               # Individual command handlers
│   │   ├── onboarding.py      # Onboarding status command
│   │   ├── lastseen.py        # Last seen command
│   │   ├── vulnerabilities.py # Vulnerabilities command
│   │   ├── products.py        # Products CVE monitoring command
│   │   ├── alerts.py          # Alerts monitoring command
│   │   ├── machines.py        # List machines command
│   │   └── detail.py          # Machine detail command
│   ├── decorators.py          # Common CLI decorators
│   └── handlers.py            # CLI handlers
├── 📁 core/                    # Core business logic
│   ├── auth.py                # Authentication management
│   ├── config.py              # Configuration handling
│   ├── defender.py            # Defender API client
│   ├── exceptions.py          # Custom exceptions
│   ├── nagios.py              # Nagios plugin framework
│   └── logging_config.py      # Logging configuration
├── 📁 services/                # Business services
│   ├── onboarding_service.py  # Onboarding business logic
│   ├── lastseen_service.py    # Last seen business logic
│   ├── vulnerabilities_service.py # Vulnerability business logic
│   ├── products_service.py    # Products CVE monitoring business logic
│   ├── alerts_service.py      # Alerts monitoring business logic
│   ├── machines_service.py    # Machines business logic
│   ├── detail_service.py      # Detail business logic
│   └── models.py              # Data models
└── 📁 tests/                   # Comprehensive test suite
    ├── unit/                   # Unit tests
    ├── integration/            # Integration tests
    └── fixtures/               # Test fixtures
```

### Key Design Principles

- **🎯 Single Responsibility** - Each module has one clear purpose
- **🔌 Dependency Injection** - Easy testing and mocking
- **🧪 Testable** - Comprehensive test coverage
- **📈 Extensible** - Easy to add new commands and features
- **🔒 Secure** - No secrets in code, proper credential handling

## 🧪 Development

### Development Setup

```bash
# Clone repository
git clone https://github.com/lduchosal/check_msdefender.git
cd check_msdefender

# Create development environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .
```

### Code Quality Tools

```bash
# Format code
black check_msdefender/

# Lint code
flake8 check_msdefender/

# Type checking
mypy check_msdefender/

# Run tests
pytest tests/ -v --cov=check_msdefender
```

### Building & Publishing

```bash
# Build package
python -m build

# Test installation
pip install dist/*.whl

# Publish to PyPI
python -m twine upload dist/*
```

## 🔍 Output Examples

### Successful Check
```
DEFENDER OK - Onboarding status: 0 (Onboarded) | onboarding=0;1;2;0;2
```

### Warning State
```
DEFENDER WARNING - Last seen: 10 days ago | lastseen=10;7;30;0;
```

### Critical State
```
DEFENDER CRITICAL - Vulnerability score: 150 (1 Critical, 5 High) | vulnerabilities=150;10;100;0;
```

### Alerts Warning
```
DEFENDER WARNING - Unresolved alerts for machine.domain.com | alerts=2;1;5;0;
Unresolved alerts for machine.domain.com
2025-09-14T10:22:14.12Z - Suspicious activity detected (New high)
2025-09-14T12:00:00.00Z - Malware detection (InProgress medium)
```

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Authentication Errors** | Verify Azure app permissions and credentials |
| **Network Connectivity** | Check firewall rules for Microsoft endpoints |
| **Import Errors** | Ensure all dependencies are installed |
| **Configuration Issues** | Validate config file syntax and paths |

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
# Maximum verbosity
check_msdefender vulnerabilities -d machine.domain.tld -vvv

# Check specific configuration
check_msdefender onboarding -c /path/to/config.ini -d machine.domain.tld -vv
```

### Required Network Access

Ensure connectivity to:
- `login.microsoftonline.com`
- `api.securitycenter.microsoft.com`
- `api-eu.securitycenter.microsoft.com`
- `api-eu3.securitycenter.microsoft.com`
- `api-uk.securitycenter.microsoft.com`

## 📊 Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| `0` | OK | Value within acceptable range |
| `1` | WARNING | Value exceeds warning threshold |
| `2` | CRITICAL | Value exceeds critical threshold |
| `3` | UNKNOWN | Error occurred during execution |

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow [PEP 8](https://pep8.org/) style guide
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [nagiosplugin](https://nagiosplugin.readthedocs.io/) framework
- Uses [Azure Identity SDK](https://docs.microsoft.com/python/api/azure-identity/) for authentication
- Powered by [Click](https://click.palletsprojects.com/) for CLI interface

---

<div align="center">

**[⭐ Star this repository](https://github.com/lduchosal/check_msdefender)** if you find it useful!

[🐛 Report Bug](https://github.com/lduchosal/check_msdefender/issues) • [💡 Request Feature](https://github.com/lduchosal/check_msdefender/issues) • [📖 Documentation](https://github.com/lduchosal/check_msdefender/blob/main/README.md)

</div>