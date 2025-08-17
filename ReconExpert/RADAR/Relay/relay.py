#!/usr/bin/env python3
import os
import re
from datetime import datetime

print("Relay — Security Remediation Advisor")
print("=" * 50)

file_path = input("Enter path to RADAR analysis file: ").strip()
if not os.path.exists(file_path):
    print(f"Error: File '{file_path}' not found.")
    exit(1)

# Output folder and timestamped file
output_folder = "Output"
os.makedirs(output_folder, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(output_folder, f"Relay_output_{timestamp}.txt")

with open(file_path, "r") as f:
    content = f.read()

# Extract findings
pattern = r"(#\d+\s*\[.*?\].*?)(?=(\n#\d+|\Z))"
matches = re.findall(pattern, content, re.DOTALL)

# Deduplicate by key
seen_keys = set()
findings = []

def get_key(finding):
    text = finding.lower()
    if "elementor" in text: return "elementor"
    if "php" in text: return "php"
    if "mysql" in text or "mariadb" in text: return "mysql"
    if "xml-rpc" in text: return "xmlrpc"
    if "x-frame-options" in text: return "xframe"
    if "robots.txt" in text: return "robots"
    return finding[:50]

for match in matches:
    finding = match[0].strip()
    key = get_key(finding)
    if key not in seen_keys:
        seen_keys.add(key)
        findings.append(finding)

# Output
output_lines = [
    "Relay — Security Action Report",
    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "="*60,
    "Security Advice",
    "="*60
]

def remediation(finding):
    advice = []
    text = finding.lower()
    if "elementor" in text or "wordpress" in text:
        advice.extend([
            "-> Update Elementor plugin and WordPress themes to the latest secure version.",
            "-> Remove unused or vulnerable plugins/themes.",
            "-> Verify no insecure external resources are loaded.",
            "-> Backup site before making changes.",
            "-> Test site functionality after updates."
        ])
    elif "php" in text:
        advice.extend([
            "-> Upgrade PHP to the latest supported version.",
            "-> Apply all available security patches.",
            "-> Review php.ini settings for secure configuration (disable expose_php, enable error logging).",
            "-> Backup site and test functionality after upgrade."
        ])
    elif "mysql" in text:
        advice.extend([
            "-> Update MariaDB/MySQL to latest patched version.",
            "-> Restrict database access to localhost or trusted IPs.",
            "-> Change default passwords, remove unnecessary accounts.",
            "-> Disable remote root access.",
            "-> Verify user privileges and secure file permissions.",
            "-> Backup databases before applying changes."
        ])
    elif "xml-rpc" in text:
        advice.extend([
            "-> Disable XML-RPC if not needed or restrict to trusted IPs.",
            "-> Upgrade WordPress and PHP to latest versions.",
            "-> Test XML-RPC functionality if legitimately used."
        ])
    elif "x-frame-options" in text:
        advice.extend([
            "-> Add X-Frame-Options headers to prevent clickjacking.",
            "-> Implement CSP headers.",
            "-> Test site in multiple browsers for enforcement."
        ])
    elif "robots.txt" in text:
        advice.extend([
            "-> Review robots.txt and ensure sensitive directories are not exposed.",
            "-> Avoid listing sensitive paths publicly.",
            "-> Consider restricting access via .htaccess or server config."
        ])
    else:
        advice.append("-> Manual review required for this finding.")
    return advice

# Clean numbering without extra numbers
for idx, f in enumerate(findings, start=1):
    f_clean = re.sub(r"^#\d+\s*", "", f)
    output_lines.append(f"#{idx} {f_clean}")
    output_lines.extend(remediation(f))
    output_lines.append("-"*60)

# Summary
output_lines.extend([
    "="*60,
    "Analysis Summary",
    "="*60
])
severity_count = {"Critical":0,"High":0,"Medium":0,"Low":0}
for f in findings:
    m = re.search(r"\[(Critical|High|Medium|Low)\]", f)
    if m:
        severity_count[m.group(1)] += 1
output_lines.extend([f"{sev}: {count}" for sev, count in severity_count.items()])
output_lines.append(f"Total Findings: {len(findings)}")
output_lines.append("="*60)

with open(output_file, "w") as f:
    f.write("\n".join(output_lines))

print("\n".join(output_lines))
print(f"\nRemediation report saved to: {output_file}")
