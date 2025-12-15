# SafeNet - Local-First Privacy Auditor

A comprehensive, terminal-based privacy auditor that discovers every device on your LAN, profiles each device, analyzes real privacy risks, and provides actionable mitigation steps — all while keeping data on your machine.

## Overview

SafeNet answers critical privacy questions:

- **What devices are on my network?** Comprehensive LAN discovery with vendor identification
- **What type are they?** Device classification (Router, Laptop, SmartTV, Camera, etc.)
- **Who made them?** Vendor detection via MAC OUI, mDNS, and banner grabbing  
- **Are they tracking me?** Privacy risk analysis combining static (ports, vendor) and live (connections, DNS) signals
- **Are they uploading data?** Optional packet capture for throughput classification (Streaming/Upload/Telemetry)
- **How do I fix it?** Platform-specific blocking rules (Windows/Linux/Router/PiHole/dnsmasq)

## Key Features

### Device Discovery and Profiling
- ARP scanning for network device discovery
- Port scanning (20+ common ports)
- MAC OUI lookup (90+ manufacturers)
- mDNS/Bonjour discovery (device services)
- Banner grabbing (SSH, HTTP headers)
- Vendor identification (30+ vendors, 80+ domains)

### Privacy Risk Analysis
- Static signals: Ports, vendor, OS type
- Live behavioral data: Active connections, DNS queries
- Optional throughput metrics: Traffic classification (Streaming/Upload/Telemetry)
- Risk scoring: Combines all signals for comprehensive assessment
- Risk levels: LOW / MEDIUM / HIGH / CRITICAL

### Mitigation and Blocking
- Connection-level rules (IP:Port blocking)
- Domain-level rules (DNS-based blocking)
- Multi-platform support:
  - Windows Firewall (PowerShell)
  - Linux iptables
  - Router iptables
  - PiHole DNS blocking
  - dnsmasq configuration
  - Unbound DNS
  - Hosts file

### Optional Router Integration
- SSH into supported routers (OpenWrt, Merlin, DD-WRT)
- Per-device network visibility:
  - Active connections per device
  - DNS queries per device
  - Bytes sent/received per device
- Network-wide analysis beyond local machine
- User-consented (interactive credential prompt)

### Optional AI Explanations
- Detailed reasoning for each detected risk
- Actionable guidance for mitigation
- Local LLM integration (data stays on your machine)

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/SafeNet.git
cd SafeNet

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Local-only analysis (no router needed)
python main.py

# With router integration (prompts for SSH credentials)
python main.py --router

# With packet capture (requires admin/root)
python main.py --pcap

# With AI explanations
python main.py --ai

# All features together
python main.py --router --pcap --ai

# Specify custom router IP
python main.py --router --router-ip 192.168.0.1
```

## Command-Line Options

```
python main.py [OPTIONS]

Options:
  --ai              Enable AI-generated explanations for risks
  --router          Enable router integration (prompts for SSH credentials)
  --router-ip IP    Specify router IP address (default: 192.168.1.1)
  --pcap            Enable packet capture and throughput analysis (requires admin)
  --help            Show this help message
```

## Output

### Generated Report

SafeNet generates a comprehensive text report including:

1. **Risk Summary**
   - Total devices found
   - Risk distribution (HIGH/MEDIUM/LOW)

2. **Local Machine Activity**
   - Active connections
   - Vendors contacted
   - Connection categories
   - Applications using network

3. **Device Analysis** (per device)
   - IP, MAC, Vendor, Type
   - Open ports
   - Risk level and reasoning
   - Detected risks
   - Mitigation actions

4. **Network-Wide Analysis** (with router)
   - Per-device connections
   - Per-device DNS queries
   - Per-device byte counters

5. **Throughput Analysis** (with --pcap)
   - Traffic classification summary
   - Top flows by throughput
   - Streaming/Upload/Telemetry breakdown

6. **Blocking Recommendations**
   - Connection-level rules
   - Domain-level rules
   - Platform-specific syntax

Reports are saved to: `reports/privacy_report_YYYY-MM-DD_HH-MM-SS.txt`

## Privacy and Security

### Data Protection

Your data stays on your machine:
- All scanning performed locally
- No cloud API calls
- No data transmission
- No telemetry or analytics
- User remains in control

### User Consent

Features requiring user consent:
- Router integration requires SSH credentials prompt
- Packet capture shows privacy warning before capture
- Graceful fallback if features unavailable

## Project Structure

```
SafeNet/
├── monitoring/              # Network monitoring modules
│   ├── router_monitor.py    # SSH router integration (NEW)
│   ├── pcap_sampler.py      # Packet capture and throughput (NEW)
│   ├── connection_monitor.py  # Local connection tracking
│   ├── connection_analyzer.py # Correlation and analysis
│   ├── dns_monitor.py       # DNS query tracking
│   ├── process_mapper.py    # Process-to-connection mapping
│   ├── vendor_database.py   # 30+ vendors, 80+ domains
│   └── __init__.py
├── profiling/               # Device identification
│   ├── identify.py          # mDNS + banner grab + MAC OUI (NEW)
│   └── __init__.py
├── analysis/                # Privacy risk analysis
│   ├── privacy_risk.py      # Base risk scoring
│   ├── privacy_risk_enhanced.py  # Throughput-aware scoring (NEW)
│   └── __init__.py
├── mitigation/              # Mitigation suggestions
│   ├── suggestions.py       # Platform-specific blocking rules (NEW)
│   └── __init__.py
├── reports/                 # Report generation
│   ├── generate_report.py   # Enhanced report writer (NEW)
│   └── privacy_report_*.txt # Generated reports
├── discovery/               # Network discovery
│   └── network_scan.py      # ARP + port scanning
├── ai/                      # AI explanations
│   └── explainer.py         # LLM integration
├── main.py                  # Entry point (NEW integration)
├── test_privacy_analysis.py # 22 comprehensive tests (NEW)
├── requirements.txt         # Dependencies
├── .gitignore              # Git ignore rules
└── CODE_REVIEW_REPORT.md   # Code quality analysis
```

## Testing

```bash
# Run all tests
python test_privacy_analysis.py

# Expected output:
# Ran 22 tests in X.XXXs
# OK
```

### Test Coverage

- Router connection parsing
- Router data merging
- Packet capture and throughput classification
- Device profiling (MAC OUI, mDNS, banners)
- Risk scoring with throughput
- Mitigation rule generation
- Report generation
- End-to-end pipelines
- Graceful degradation

## Documentation

See [CODE_REVIEW_REPORT.md](CODE_REVIEW_REPORT.md) for:
- Code quality analysis
- Module dependencies
- Function documentation
- Implementation details

See [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) for:
- Complete feature list
- Architecture decisions
- Validation results
- Usage examples

## Troubleshooting

### "Unable to connect to port 22 on router"

Your router does not have SSH enabled. Either:
1. Enable SSH in router admin settings, OR
2. Run without `--router` flag for local-only analysis

### "No packets captured"

- Ensure you are running with administrator/root privileges for packet capture
- Or use local-only mode without `--pcap` flag

### "ModuleNotFoundError: No module named 'zeroconf'"

```bash
# Install dependencies
pip install -r requirements.txt
```

## Contributing

Contributions are welcome. Areas for enhancement:
- Additional router firmware support (ASUS, TP-Link, Netgear)
- Device type classifier improvements
- ML-based anomaly detection
- Integration with threat intelligence feeds
- Mobile app frontend

## License

[Choose appropriate license - MIT, GPL, etc.]

## Disclaimer

SafeNet is designed for monitoring networks you own or have permission to monitor. Unauthorized network monitoring may be illegal. Always:
- Get proper authorization before scanning networks
- Respect privacy of network users
- Comply with local laws and regulations

## How It Works

### 1. Device Discovery

- ARP scan identifies all devices on your LAN
- Port scanning detects open ports
- Initial vendor lookup via MAC OUI

### 2. Device Profiling

- mDNS discovery finds device services
- Banner grabbing identifies services (SSH, HTTP)
- Vendor database lookup (30+ vendors)
- Device type inference

### 3. Risk Analysis

- Static signals: Ports, vendor info, OS type
- Live signals: Active connections, DNS queries
- Throughput signals (optional): Traffic classification
- Combined risk scoring

### 4. Mitigation

- Identify blockable connections
- Generate platform-specific rules
- Provide actionable next steps

### 5. Report Generation

- Human-readable text report
- Per-device analysis
- Network-wide summary
- Blocking recommendations

## Support

For issues, questions, or feature requests:
1. Check [CODE_REVIEW_REPORT.md](CODE_REVIEW_REPORT.md)
2. Review [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md)
3. Run tests: `python test_privacy_analysis.py`
4. Create GitHub issue with details

## Credits

Built with:
- **paramiko** - SSH protocol
- **zeroconf** - mDNS/Bonjour discovery
- **scapy** - Packet analysis
- **tabulate** - Formatted output
- **colorama** - Terminal colors

---

Status: Production Ready | Tests Passing: 22/22 | Version: 1.0.0
