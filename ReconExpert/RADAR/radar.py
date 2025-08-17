# radar7.py
# RADAR — Real-time Attack Detection & Risk Console (user-friendly, counted duplicates, saved output)

import sys
import time
import re
import os
from collections import defaultdict
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import pyfiglet

init(autoreset=True)

# Banner
ascii_banner = (
    Fore.RED + Style.BRIGHT +
    pyfiglet.figlet_format("RADAR", font="slant") +
    Fore.YELLOW + "   ⚡ RADAR — Real-time Attack Detection & Risk ⚡\n"
)

severity_colors = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High": Fore.MAGENTA + Style.BRIGHT,
    "Medium": Fore.YELLOW + Style.BRIGHT,
    "Low": Fore.CYAN + Style.BRIGHT
}

patterns = {
    "Critical": [
        {"regex": r"unauthorized\s+access", "exploitability": 1},
        {"regex": r"rce|remote code execution", "exploitability": 1},
        {"regex": r"sql\s+injection", "exploitability": 1},
        {"regex": r"admin\s+password|default\s+credentials", "exploitability": 2},
        {"regex": r"0day|critical vulnerability", "exploitability": 1},
    ],
    "High": [
        {"regex": r"open\s+port\s+3306", "exploitability": 2},
        {"regex": r"mysql", "exploitability": 2},
        {"regex": r"ftp\s+anonymous", "exploitability": 3},
        {"regex": r"outdated\s+wordpress|unpatched", "exploitability": 2},
        {"regex": r"xml-rpc", "exploitability": 2},
        {"regex": r"exposed\s+config|leaked\s+key", "exploitability": 2},
    ],
    "Medium": [
        {"regex": r"missing\s+security\s+headers", "exploitability": 4},
        {"regex": r"no\s+hsts", "exploitability": 4},
        {"regex": r"x-frame-options", "exploitability": 3},
        {"regex": r"clickjacking", "exploitability": 3},
        {"regex": r"dir\s+listing", "exploitability": 4},
        {"regex": r"weak\s+encryption|tls\s+1\.0", "exploitability": 3},
    ],
    "Low": [
        {"regex": r"info\s+leak", "exploitability": 5},
        {"regex": r"server\s+version", "exploitability": 5},
        {"regex": r"public\s+tech\s+stack", "exploitability": 5},
        {"regex": r"robots\.txt", "exploitability": 4},
        {"regex": r"open\s+port\s+\d+", "exploitability": 4},
    ]
}

def assign_severity(text):
    for sev, regex_list in patterns.items():
        for entry in regex_list:
            if re.search(entry["regex"], text, re.IGNORECASE):
                return sev, entry["exploitability"]
    return None, None

def read_file(path):
    ext = os.path.splitext(path)[1].lower()
    findings = []
    if ext in [".html", ".htm"]:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            soup = BeautifulSoup(f, "html.parser")
            text = soup.get_text(separator="\n")
            findings = [line.strip() for line in text.splitlines() if line.strip()]
    elif ext in [".txt", ".csv"]:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            findings = [line.strip() for line in f if line.strip()]
    else:
        print(Fore.RED + "[ERROR] Unsupported file format.")
        sys.exit(1)
    return findings

def explain_finding(severity):
    explanations = {
        "Critical": {
            "Why": "A known vulnerability exists that can be exploited remotely.",
            "What": "Server, website, or database; sensitive business data.",
            "Exploit": "Attackers can gain unauthorized access, escalate privileges, or execute code."
        },
        "High": {
            "Why": "Exposed services or unpatched software may allow compromise.",
            "What": "Databases, user credentials, website content.",
            "Exploit": "Brute force, data leakage, or exploitation of misconfigurations."
        },
        "Medium": {
            "Why": "Security misconfigurations or missing headers may allow attacks.",
            "What": "Users, web application behavior.",
            "Exploit": "Clickjacking, information disclosure, minor privilege misuse."
        },
        "Low": {
            "Why": "Information disclosure or minor misconfigurations.",
            "What": "Low-risk data, server banners, site structure.",
            "Exploit": "Reconnaissance, enumeration, minimal impact attacks."
        }
    }
    return explanations[severity]

def deduplicate_and_count(findings):
    counter = defaultdict(int)
    unique_findings = []
    for f in findings:
        key = (f["severity"], f["text"].lower())
        counter[key] += 1
    for (sev, text), count in counter.items():
        unique_findings.append({
            "text": text,
            "severity": sev,
            "count": count
        })
    return unique_findings

def print_progress(idx, total):
    bar_len = 40
    filled_len = int(round(bar_len * idx / float(total)))
    percents = round(100.0 * idx / float(total), 1)
    bar = "█" * filled_len + '-' * (bar_len - filled_len)
    print(f"\rScanning: |{bar}| {percents}% Complete", end='')

def main():
    print(ascii_banner)
    print("Example: recon_report.html or findings.txt")
    file_path = input(Fore.GREEN + "Enter path to pentest findings file: ").strip()
    if not os.path.isfile(file_path):
        print(Fore.RED + "[ERROR] File not found.")
        sys.exit(1)

    print(Fore.GREEN + "[BOOT] Initializing RADAR systems...")
    time.sleep(1)

    raw_findings = read_file(file_path)
    findings_list = []

    for line in raw_findings:
        severity, _ = assign_severity(line)
        if severity:
            findings_list.append({
                "text": line,
                "severity": severity
            })

    # Deduplicate and count
    findings_list = deduplicate_and_count(findings_list)

    # Sort by severity
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    findings_list.sort(key=lambda x: (severity_order[x["severity"]]))

    print(Fore.YELLOW + "[STATUS] RADAR is ONLINE. Beginning analysis...\n")
    time.sleep(0.5)

    # Progress bar
    total_findings = len(findings_list)
    for idx, _ in enumerate(findings_list, start=1):
        print_progress(idx, total_findings)
        time.sleep(0.05)
    print("\n")

    # Prepare output text
    output_lines = []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for idx, f in enumerate(findings_list, start=1):
        sev_color = severity_colors[f["severity"]]
        counts[f["severity"]] += 1
        explanation = explain_finding(f["severity"])
        occ_text = f" ({f['count']} occurrences)" if f['count'] > 1 else ""
        line1 = f"#{idx} [{f['severity']}] {f['text']}{occ_text}"
        line2 = f"   - Why dangerous: {explanation['Why']}"
        line3 = f"   - What’s at risk: {explanation['What']}"
        line4 = f"   - Potential exploit: {explanation['Exploit']}\n"

        print(sev_color + line1)
        print(line2)
        print(line3)
        print(line4)

        output_lines.extend([line1, line2, line3, line4])

    summary_lines = [
        "=" * 50,
        "Analysis Summary",
        "=" * 50
    ]
    for sev, count in counts.items():
        summary_lines.append(f"{sev}: {count}")
    total = sum(counts.values())
    summary_lines.append(f"Total Findings: {total}")
    summary_lines.append("=" * 50)

    for l in summary_lines:
        print(l)
    output_lines.extend(summary_lines)

    # Save to Relay folder
    os.makedirs("Relay", exist_ok=True)
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    out_file = os.path.join("Relay", f"{base_name}_analysis.txt")
    with open(out_file, "w", encoding="utf-8") as f:
        for line in output_lines:
            f.write(line + "\n")

    print(Fore.GREEN + f"\n[INFO] Full report saved to: {out_file}")

if __name__ == "__main__":
    main()
