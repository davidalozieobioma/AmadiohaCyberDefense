# Amadioha Cyber Defense

A **professional-grade cybersecurity toolkit** for network scanning, brute-force detection, and threat intelligence analysis. Built with Python, designed for security professionals and SOC analysts.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Status](https://img.shields.io/badge/Status-Production-green)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## 🎯 Features

### 🔍 **Network Scanner**
- Concurrent multi-threaded TCP port scanning
- Three scanning profiles: **Fast** (200 workers), **Balanced** (50), **Safe** (20)
- Custom port ranges and timeouts
- Results export to file

### 🛡️ **Brute-Force Detection**
- Parse and analyze Linux `auth.log` files
- Detect repeated failed SSH login attempts
- Count attempts per IP address
- Display results in formatted tables
- Export analysis to CSV

### ⚠️ **Threat Intelligence**
- IP reputation lookups
- Risk scoring (0–100)
- Threat type classification
- Abuse report counting
- Known attack patterns
- Confidence levels

### 📋 **Integrated Reporting**
- One command to scan, analyze, and enrich
- Tables with risk levels (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW)
- Combined output showing:
  - Open ports discovered
  - Brute-force attack sources
  - Threat intelligence for each IP
  - Reputation scores and risk levels

### 🌐 **Web Dashboard** ✨
- Professional HTML5 interface with Bootstrap styling
- Real-time scan and analysis execution
- Interactive threat intelligence lookup
- Beautiful data visualization and results tables
- REST API endpoints for integration
- Responsive design (mobile-friendly)

---

## 📦 Installation

### Prerequisites
- Python 3.9+
- pip (Python package manager)
- Windows/Linux/macOS

### Quick Setup

```bash
# Clone or download the repository
git clone https://github.com/yourusername/AmadiohaCyberDefense.git
cd AmadiohaCyberDefense

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start

### 1. **Scan a Network**

```bash
# Balanced scan (default)
python -m amadioha scan --target 192.168.1.1

# Fast scan on specific port range
python -m amadioha scan --target 192.168.1.1 --start 1 --end 1024 --profile fast

# Custom settings
python -m amadioha scan --target 192.168.1.1 --workers 200 --timeout 0.3 --out open_ports.txt
```

### 2. **Analyze Auth Logs**

```bash
# Linux/WSL
python -m amadioha analyze --log-file /var/log/auth.log

# Windows (with sample)
python -m amadioha analyze --log-file sample_auth.log

# Save results
python -m amadioha analyze --log-file sample_auth.log --out results.csv
```

### 3. **Lookup Threat Intelligence**

```bash
# Single IP lookup
python -m amadioha intel --ip 185.220.101.1

# Output: Risk level, reputation score, threat type, abuse reports, confidence
```

### 4. **Generate Integrated Report** ⭐

```bash
# Scan → Analyze → Enrich with threat intel (all in one command!)
python -m amadioha report \
  --target 192.168.1.1 \
  --log-file /var/log/auth.log \
  --scan-start 1 \
  --scan-end 1024 \
  --profile balanced \
  --out security_report.txt
```

### 5. **Launch Web Dashboard** 🌐

```bash
# Start the web server
python run_web.py

# Open your browser to http://localhost:5000
# Use the interactive dashboard to:
#   • Run port scans
#   • Analyze auth logs
#   • Lookup IP threat intelligence
#   • View results in real-time
```

---

## 🌐 Web Dashboard Guide

### Starting the Dashboard

```bash
# Option 1: Run the launcher script
python run_web.py

# Option 2: Run directly with Flask
venv\Scripts\python -m amadioha.web

# Then open browser to: http://localhost:5000
```

### Dashboard Features

1. **Network Scanner Panel**
   - Set target IP, port range, and scan profile
   - Choose between Fast (aggressive), Balanced (default), or Safe (slow)
   - View results immediately with list of open ports

2. **Log Analyzer Panel**
   - Specify path to auth.log file
   - Analyzes failed SSH login attempts
   - Shows attacking IPs ranked by number of attempts

3. **Threat Intelligence Panel**
   - Enter any IP address to lookup
   - Get instant reputation score (0–100)
   - View threat type, abuse reports, and confidence level

4. **Results Tables**
   - Scan results with port listings
   - Analysis results with RichText formatting
   - Threat levels color-coded (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)

### Web API Endpoints

```bash
# Health check
GET /health

# Network scan
POST /api/scan
  { "target": "192.168.1.1", "start": 1, "end": 1024, "profile": "balanced" }

# Log analysis
POST /api/analyze
  { "log_file": "sample_auth.log" }

# Threat lookup
POST /api/intel
  { "ip": "185.220.101.1" }

# Get all results
GET /api/results
```

---

## 📚 Command Reference

### Global Help
```bash
python -m amadioha --help
```

### Scan Subcommand
```bash
python -m amadioha scan --help

Options:
  --target TARGET       Target IP or hostname (default: 127.0.0.1)
  --start START         Start port (default: 1)
  --end END             End port (default: 1024)
  --profile {fast|balanced|safe}  Preconfigured scan profile
  --workers WORKERS     Number of threads (overrides profile)
  --timeout TIMEOUT     Connection timeout seconds (overrides profile)
  --out OUT             Output file for open port list
```

### Analyze Subcommand
```bash
python -m amadioha analyze --help

Options:
  --log-file LOG_FILE   Path to auth.log file (required)
  --out OUT             Output file (CSV format)
```

### Intel Subcommand
```bash
python -m amadioha intel --help

Options:
  --ip IP               IP address to lookup (required)
```

### Report Subcommand
```bash
python -m amadioha report --help

Options:
  --target TARGET       Target IP for scan (default: 127.0.0.1)
  --log-file LOG_FILE   Path to auth.log file (required)
  --scan-start START    Start port (default: 1)
  --scan-end END        End port (default: 1024)
  --profile PROFILE     Scan profile (default: balanced)
  --scan-workers N      Override scan workers
  --scan-timeout SEC    Override scan timeout
  --out OUT             Output file for report
```

---

## 📊 Example Output

### Network Scan
```
Scanning 192.168.1.1 ports 1-1024 with 50 workers...
[+] Port 22 is open
[+] Port 80 is open
[+] Port 443 is open
Wrote 3 open ports to open_ports.txt
```

### Brute-Force Analysis
```
 Amadioha Cyber Defense — Failed Login Attempts
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ IP Address    ┃ Attempts ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ 185.220.101.1 │ 127      │
│ 203.0.113.45  │ 89       │
│ 198.51.100.22 │ 34       │
└───────────────┴──────────┘
```

### Threat Intelligence
```
╭─────── Threat Intel Report ────────╮
│ IP Address: 185.220.101.1          │
│ Risk Level: 🔴 CRITICAL            │
│ Reputation Score: 92/100           │
│ Threat Type: Tor Exit Node         │
│ Abuse Reports: 127                 │
│ Known for Attacks: ✓ Yes           │
│ Confidence: 98%                    │
│ Last Reported: 2026-02-16          │
╰────────────────────────────────────╯
```

### Integrated Report
```
Amadioha Security Report Generation

1. Running network scan...
✓ Found 3 open ports

2. Analyzing auth logs...
✓ Found 3 unique attacking IPs

3. Enriching with threat intelligence...
 Integrated Security Report — Brute Force Attacks with Intelligence
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ IP Address    ┃ Attempts ┃ Risk Level  ┃ Reputation ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 185.220.101.1 │ 127      │ 🔴 CRITICAL │ 92/100     │
│ 203.0.113.45  │ 89       │ 🔴 CRITICAL │ 85/100     │
│ 198.51.100.22 │ 34       │ 🟠 HIGH      │ 75/100     │
└───────────────┴──────────┴─────────────┴────────────┘

✓ Report saved to security_report.txt
```

---

## 🏗️ Project Structure

```
AmadiohaCyberDefense/
├── amadioha/
│   ├── __init__.py              # Package initialization
│   ├── __main__.py              # Module execution entry point
│   ├── cli.py                   # Master CLI with all subcommands
│   ├── network_scanner.py       # Concurrent port scanning
│   ├── log_analyzer.py          # Brute-force detection
│   ├── threat_intel.py          # IP reputation & threat lookup
│   └── utils.py                 # Helper utilities (IP validation)
├── requirements.txt             # Python dependencies
├── sample_auth.log              # Sample log data for testing
├── README.md                    # This file
└── security_report.txt          # Example generated report
```

---

## 🔧 Configuration & Customization

### Scanning Profiles

| Profile | Workers | Timeout | Best For |
|---------|---------|---------|----------|
| **Fast** | 200 | 0.3s | Large networks, fast feedback |
| **Balanced** | 50 | 0.2s | General-purpose scanning (recommended) |
| **Safe** | 20 | 0.5s | Network-constrained environments |

### Threat Intelligence Database

The built-in threat database includes known malicious IPs. To integrate with real APIs like **AbuseIPDB** or **AlienVault OTX**, modify `threat_intel.py`:

```python
# Example: Add real API integration
def lookup_ip_abuseipdb(ip: str) -> Dict:
    """Lookup IP reputation from AbuseIPDB API"""
    # Implement API call here
    pass
```

---

## 🔐 Security & Ethical Use

### ⚠️ IMPORTANT
This toolkit is designed for **authorized security testing only**:

- ✅ Use on systems you own or have explicit permission to test
- ✅ Perform scans during approved maintenance windows
- ❌ Do NOT scan systems without written authorization
- ❌ Do NOT use for unauthorized network reconnaissance

**Disclaimer**: Users are responsible for complying with all applicable laws and regulations. Unauthorized port scanning and access attempts are illegal.

---

## 📈 Use Cases

### 1. **SOC Analyst Workflow**
```bash
# Morning routine: check for overnight attacks
python -m amadioha analyze --log-file /var/log/auth.log --out daily_threats.csv

# Look up suspicious IPs
python -m amadioha intel --ip suspicious_ip_here
```

### 2. **Network Administrator Assessment**
```bash
# Full security report on company network
python -m amadioha report \
  --target internal.corp.com \
  --log-file /var/log/auth.log \
  --out weekly_security_report.txt
```

### 3. **Penetration Tester Reconnaissance**
```bash
# Scan target network (with authorization!)
python -m amadioha scan --target 192.168.0.0/24 --profile fast --out recon_ports.txt
```

### 4. **Threat Intelligence Research**
```bash
# Batch IP lookups
for ip in $(cat suspicious_ips.txt); do
  python -m amadioha intel --ip $ip
done
```

---

## 🛠️ Troubleshooting

### ModuleNotFoundError: No module named 'rich'
```bash
# Make sure venv is activated
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Reinstall dependencies
pip install -r requirements.txt
```

### Scan taking too long?
- Use `--profile fast` for faster results (more aggressive)
- Reduce `--scan-end` to scan fewer ports
- Use `--workers` to increase thread count (be careful on shared networks)

### No auth.log found on Windows?
- Use the included `sample_auth.log` for testing
- If on WSL, path is `/var/log/auth.log`
- If on native Windows with SSH server, check SSH logs location

---

## 📚 Learning Resources

This project teaches:
- **Concurrent programming** with ThreadPoolExecutor
- **Log parsing** with regex
- **CLI development** with argparse
- **Network security concepts** (port scanning, brute-force detection, threat intel)
- **Python best practices** (modules, type hints, error handling)

Perfect for **job interviews** and **portfolio projects**!

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- [ ] Real API integration (AbuseIPDB, VirusTotal, AlienVault)
- [ ] Async scanning with asyncio
- [ ] JSON/HTML report export
- [ ] Configuration file support (`config.yaml`)
- [ ] Unit tests and CI/CD
- [ ] Database logging (SQLite)
- [ ] Web dashboard
- [ ] Multi-threaded log analysis

---

## 📄 License

MIT License - See LICENSE file for details

---

## ✨ Credits

Built for cybersecurity professionals who want to make an impact.

**Version**: 0.2.0  
**Last Updated**: February 2026

---

## 📞 Support

Issues? Questions?
1. Check the [Quick Start](#-quick-start) section
2. Review example commands in [Example Output](#-example-output)
3. Check troubleshooting guide above
4. Open an issue on GitHub

---

## 🚀 Deployment (Docker, Heroku, AWS)

### Quick Deploy Methods

| Platform | Time | Difficulty | Cost |
|----------|------|-----------|------|
| **Docker** | 5 min | Easy | Free |
| **Heroku** | 2 min | Very Easy | $7/mo (or free tier) |
| **AWS EC2** | 15 min | Medium | $10–50/mo |
| **AWS ECS/Fargate** | 20 min | Medium | $15–100/mo |

### Docker (Easiest)

```bash
# Build image
docker build -t amadioha-cyber-defense:latest .

# Run container
docker run -p 5000:5000 amadioha-cyber-defense:latest

# Or use docker-compose
docker-compose up -d
```

### Heroku (Fastest, 2 Commands)

```bash
# Login and create app
heroku login
heroku create amadioha-cyber-defense

# Deploy
git push heroku main

# Open
heroku open
```

### AWS EC2 (Full Control)

```bash
# SSH into instance, then:
git clone <repo>
cd AmadiohaCyberDefense
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
gunicorn amadioha.web:app
```

### AWS ECS (Scalable)

```bash
# Push to ECR
aws ecr create-repository --repository-name amadioha-cyber-defense
docker build -t amadioha-cyber-defense:latest .
docker push 123456789.dkr.ecr.us-east-1.amazonaws.com/amadioha-cyber-defense:latest

# Create ECS cluster
aws ecs create-cluster --cluster-name amadioha-cluster
```

### **See [DEPLOYMENT.md](DEPLOYMENT.md) for complete step-by-step guides**

---

## 🚀 Next Steps

**Want to extend Amadioha further?**

1. **Real threat APIs** → Integrate AbuseIPDB, VirusTotal, or AlienVault OTX
2. **Database storage** → Migrate from in-memory to PostgreSQL/SQLite
3. **Authentication** → Add user login and API key management
4. **Automated scanning** → Schedule scans with cron/Task Scheduler
5. **Advanced analytics** → Historical trend analysis and reporting

**What's Already Implemented:** ✅
- [x] Network scanning (threaded, profiles)
- [x] Brute-force detection (log parsing)
- [x] Threat intelligence (reputation scoring)
- [x] Integrated reporting
- [x] Web dashboard (HTML5/Bootstrap)
- [x] REST API endpoints
- [x] Docker containerization
- [x] Heroku deployment ready
- [x] AWS deployment guides

**Enjoy building! Happy hacking! 🎯**
