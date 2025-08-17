# ReconExpert
"A fast automated web scanner with animation and recon modules"
# ReconExpert

**ReconExpert** 
Full-stack Automated Reconnaissance & Reporting Framework

ReconExpertWeb is a modular, CV-ready recon automation tool that integrates industry-standard scanners with custom parsing, reporting, and false-positive reduction.
Designed for penetration testers, bug bounty hunters, and security researchers who want both depth of scanning and professional deliverables.

## Features

- Multi-tool Integration

Nmap – service enumeration & scripts
Gobuster – content discovery with false-positive suppression
Wappalyzer – technology fingerprinting
Nikto – web vulnerability scanning
WPScan – WordPress vuln enumeration (conditional)
NVD API – CVE lookup & enrichment

- Smart Automation

Conditional WPScan (only runs if WP detected)
Parallel execution for faster recon
Cleans & filters noisy tool output
Professional Reporting
Generates HTML + PDF reports (via wkhtmltopdf)
CVEs auto-linked with CVSS severity & references
Pentest-style structured output (client-ready)

- UX Enhancements

Animated banners & spinners for real-time feedback
Consistent styling across reports
Minimal config → just run & go

## Demo

![Banner](https://img.shields.io/badge/Style-Terminal-green)
# Installation Guide (for Kali Linux)

Follow the steps below to install and run ReconExpert:

### 1. Clone the Repository

```bash
git clone https://github.com/AShif7/ReconExpert.git
cd ReconExpert


---

2. Install Python Requirements

Make sure Python 3 is installed.

pip3 install -r requirements.txt


---

3. Install Required Tools (nmap and gobuster)

These tools are needed for scanning. Run:

sudo apt update
sudo apt install nmap gobuster -y
sudo apt install nmap nikto gobuster wkhtmltopdf -y
# WPScan is optional
sudo gem install wpscan

---

4. Run the Tool

Use the command below to start scanning:

python3 reconexpert.py --target example.com


> Replace example.com with your target domain or IP address.




---

Example

python3 reconexpert.py --target 192.168.0.101

The tool will show terminal animation and scan the target step by step.


Options:

--target → Target domain or IP (required)

--output → Save directory (default: ./reports)

--threads → Parallel scan threads (default: 5)
---

Notes

This tool is for educational purposes only.

Do not scan any system without proper authorization.


---
___        _              _____                         
   /   |  ____(_)___ ___     / ___/______________ _____ ___ 
  / /| | / __/ / __ `__ \    \__ \/ ___/ ___/ __ `/ __ `__ \
 / ___ |/ /_/ / / / / / /   ___/ / /__/ /  / /_/ / / / / / /
/_/  |_/___/_/_/ /_/ /_/   /____/\___/_/   \__,_/_/ /_/ /_/
