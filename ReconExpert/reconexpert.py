#!/usr/bin/env python3
# reconexpertWeb - CV-ready one-file edition
# Features: parallel scanning (nmap/nikto/gobuster), conditional WPScan, NVD CVE lookup,
# WPVuln parsing, Gobuster false-positive suppression, HTML/PDF reporting.
#
# External tools expected on PATH (best on Kali):
#   nmap, nikto, gobuster, wpscan (optional, only if WP detected), wkhtmltopdf (optional)
#
# Online services:
#   - NVD CVE API v2 (no key = rate-limited; optional env NVD_API_KEY)
#   - WPScan data comes from local WPScan tool JSON output
#
# Usage:
#   python3 reconexpert.py --target example.com
#   (Optional) env NVD_API_KEY=your_key
#
# Ethical use only. Get permission.

import argparse
import concurrent.futures
import datetime
import html
import itertools
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from colorama import Fore, init as color_init
import pyfiglet

color_init(autoreset=True)

# --------------------- UI / Banner ---------------------

def animated_banner():
    banner = pyfiglet.figlet_format("Recon Expert")
    for line in banner.split("\n"):
        print(Fore.CYAN + line)
        time.sleep(0.005)

def phase_bar(phases_done, phases_total, label):
    pct = int((phases_done / phases_total) * 10)
    pct = max(0, min(10, pct))
    bar = "[" + "=" * 10 + "]"
    print(Fore.YELLOW + f"{bar} {label}")

def spinner(msg, duration=1.2):
    spinner_cycle = itertools.cycle(["|", "/", "-", "\\"])
    end_time = time.time() + duration
    print(Fore.YELLOW + msg, end=" ")
    while time.time() < end_time:
        sys.stdout.write(next(spinner_cycle))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write("\b")
    print("Done!")

def now_utc_str():
    # timezone-aware UTC per deprecation guidance
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# --------------------- Helpers ---------------------

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def write_file(path: Path, content: str):
    path.write_text(content, encoding="utf-8")

def detect_protocol_from_nmap(nmap_text: str) -> str:
    return "https" if re.search(r"\b443/tcp\s+open", nmap_text) else "http"

def get(url: str, **kw) -> Optional[requests.Response]:
    try:
        return requests.get(url, timeout=kw.pop("timeout", 8), verify=kw.pop("verify", False), **kw)
    except Exception:
        return None

def random_path() -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))

def extract_header_server(resp: Optional[requests.Response]) -> Tuple[Optional[str], Optional[str]]:
    if not resp:
        return None, None
    return resp.headers.get("Server"), resp.headers.get("X-Powered-By")

def looks_like_wordpress(resp: Optional[requests.Response]) -> bool:
    if not resp:
        return False
    gen = resp.headers.get("X-Generator") or resp.headers.get("Generator")
    if gen and "wordpress" in gen.lower():
        return True
    # crude body sniff
    body = resp.text or ""
    if re.search(r"wp-content|wp-includes|<meta name=\"generator\" content=\"WordPress", body, re.I):
        return True
    return False

def parse_php_version(x_powered_by: Optional[str]) -> Optional[str]:
    if not x_powered_by:
        return None
    m = re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", x_powered_by)
    return m.group(1) if m else None

def nvd_query_cves(query: str, api_key: Optional[str] = None, max_results: int = 10) -> List[Dict]:
    """
    Very simple NVD query using keywordSearch. For CV-level polish you could build CPEs.
    Returns list of dicts with id, description, cvss, published.
    """
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(base, params=params, headers=headers, timeout=12)
        if r.status_code != 200:
            return []
        data = r.json()
        items = []
        for c in data.get("vulnerabilities", []):
            cve = c.get("cve", {})
            cve_id = cve.get("id")
            descs = cve.get("descriptions", [])
            desc = ""
            for d in descs:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            cvss = None
            # Try CVSS 3.x first, then 2.0
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss_obj = metrics[key][0].get("cvssData", {})
                    cvss = {
                        "version": cvss_obj.get("version"),
                        "baseScore": metrics[key][0].get("baseScore") or cvss_obj.get("baseScore"),
                        "vector": cvss_obj.get("vectorString")
                    }
                    break
            published = cve.get("published")
            items.append({
                "id": cve_id,
                "description": desc,
                "cvss": cvss,
                "published": published
            })
        return items
    except Exception:
        return []

# --------------------- Scanners ---------------------

def scan_nmap_xml(target: str) -> Dict:
    print(Fore.YELLOW + "[+] Running Nmap scan", end=" ")
    cmd = ["nmap", "-sC", "-sV", "-oX", "-", target]
    rc, out, err = run_cmd(cmd, timeout=300)
    print("Done!")
    if rc != 0:
        return {"ok": False, "raw": err or out}
    # crude parse for services of interest
    services = []
    for m in re.finditer(r'<port protocol="tcp" portid="(\d+)">.*?<state state="([^"]+)"[^>]*>.*?<service name="([^"]+)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?', out, re.S):
        port, state, name, product, version = m.groups()
        services.append({
            "port": int(port),
            "state": state,
            "service": name,
            "product": (product or "").strip() or None,
            "version": (version or "").strip() or None
        })
    return {"ok": True, "raw": out, "services": services}

def fingerprint_stack(target: str, protocol: str) -> Dict:
    print(Fore.YELLOW + "[+] Detecting server headers", end=" ")
    resp = get(f"{protocol}://{target}/")
    server, xpb = extract_header_server(resp)
    wp = looks_like_wordpress(resp)
    print("Done!")
    # Optional Wappalyzer CLI (if installed)
    wapps = []
    wapp_bin = which("wappalyzer")
    if wapp_bin:
        rc, out, err = run_cmd([wapp_bin, f"{protocol}://{target}"], timeout=60)
        if rc == 0:
            # Expect JSON lines or JSON
            try:
                obj = json.loads(out.strip())
                if isinstance(obj, dict) and "applications" in obj:
                    for app in obj["applications"]:
                        wapps.append({"name": app.get("name"), "confidence": app.get("confidence"), "version": app.get("version")})
            except Exception:
                pass

    return {
        "server": server,
        "x_powered_by": xpb,
        "wordpress": wp,
        "wappalyzer": wapps
    }

def detect_false_length(target: str, protocol: str) -> Optional[int]:
    rp = random_path()
    resp = get(f"{protocol}://{target}/{rp}")
    if not resp:
        return None
    # If it's a redirect page OR a consistent branded 200 page
    if resp.status_code in (301, 302, 307, 308):
        return len(resp.content)
    # Many hosts 200 with canonical redirect template
    body_len = len(resp.content)
    if body_len > 0 and body_len < 200000:
        # This is heuristic. We’ll still exclude 301/302 via status filter.
        return body_len
    return None

def scan_gobuster(target: str, protocol: str, exclude_len: Optional[int]) -> Dict:
    print(Fore.YELLOW + "[+] Running Gobuster (auto-excluding 301 & bogus lengths)", end=" ")
    cmd = [
        "gobuster", "dir",
        "-u", f"{protocol}://{target}",
        "-w", "/usr/share/wordlists/dirb/common.txt",
        "--timeout", "10s",
        "--exclude-status", "301,302,307,308"
    ]
    if exclude_len:
        cmd += ["--exclude-length", str(exclude_len)]
    rc, out, err = run_cmd(cmd, timeout=600)
    print("Done!")
    return {"ok": rc == 0, "raw": out if out else err}

def scan_nikto(target: str, protocol: str) -> Dict:
    print(Fore.YELLOW + "[+] Running Nikto", end=" ")
    url = f"{protocol}://{target}"
    cmd = ["nikto", "-host", url, "-ask", "no", "-Tuning", "x", "-timeout", "10"]
    rc, out, err = run_cmd(cmd, timeout=900)
    print("Done!")
    return {"ok": rc == 0, "raw": out if out else err}

def scan_common_paths(target: str, protocol: str) -> List[Dict]:
    print(Fore.YELLOW + "[+] Checking common admin paths", end=" ")
    paths = ["/admin", "/login", "/config", "/dashboard", "/backup", "/wp-login.php", "/wp-admin/"]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {}
        for p in paths:
            futs[ex.submit(get, f"{protocol}://{target}{p}")] = p
        for fut in concurrent.futures.as_completed(futs):
            p = futs[fut]
            resp = fut.result()
            code = resp.status_code if resp else None
            results.append({"path": p, "status": code})
    print("Done!")
    return results

def scan_wpscan_if_wp(target: str, protocol: str, wp_detected: bool) -> Dict:
    if not wp_detected:
        return {"ok": True, "skipped": True, "raw": "", "json": None}
    print(Fore.YELLOW + "[+] Running WPScan (JSON)", end=" ")
    url = f"{protocol}://{target}"
    cmd = ["wpscan", "--url", url, "--format", "json", "--no-update"]
    rc, out, err = run_cmd(cmd, timeout=1800)
    print("Done!")
    if rc != 0 or not out:
        return {"ok": False, "skipped": False, "raw": err or out, "json": None}
    try:
        data = json.loads(out)
    except Exception:
        data = None
    return {"ok": True, "skipped": False, "raw": out, "json": data}

# --------------------- CVE Aggregation ---------------------

def cves_from_wpscan_json(wp_json: Dict) -> List[Dict]:
    """Extract CVE-like items from WPScan JSON (core/plugins/themes)."""
    if not wp_json:
        return []
    findings = []

    def pull_items(section_key: str, kind: str):
        sec = wp_json.get(section_key) or {}
        if isinstance(sec, dict):
            for slug, meta in sec.items():
                vulns = meta.get("vulnerabilities") or []
                for v in vulns:
                    cve_ids = v.get("references", {}).get("cve") or []
                    title = v.get("title") or v.get("name") or f"{kind}:{slug}"
                    cvss = v.get("cvss") or {}
                    score = cvss.get("score") or v.get("cvss_score")
                    findings.append({
                        "source": "WPScan",
                        "component": f"{kind}:{slug}",
                        "title": title,
                        "cves": cve_ids,
                        "cvss": score,
                        "fixed_in": v.get("fixed_in"),
                        "url": (v.get("references", {}).get("url") or [])[:3]
                    })

    # WordPress core
    core = wp_json.get("version") or {}
    core_vulns = core.get("vulnerabilities") or []
    for v in core_vulns:
        cve_ids = v.get("references", {}).get("cve") or []
        title = v.get("title") or "WordPress core vulnerability"
        cvss = v.get("cvss") or {}
        score = cvss.get("score") or v.get("cvss_score")
        findings.append({
            "source": "WPScan",
            "component": "wordpress:core",
            "title": title,
            "cves": cve_ids,
            "cvss": score,
            "fixed_in": v.get("fixed_in"),
            "url": (v.get("references", {}).get("url") or [])[:3]
        })

    pull_items("plugins", "plugin")
    pull_items("themes", "theme")
    return findings

def cves_from_nvd_for_stack(server_header: Optional[str], php_version: Optional[str]) -> List[Dict]:
    api_key = os.getenv("NVD_API_KEY")
    results = []

    if php_version:
        q = f"PHP {php_version}"
        results += [{"source": "NVD", **r} for r in nvd_query_cves(q, api_key=api_key, max_results=8)]

    if server_header:
        # Try to pull something meaningful from server (e.g., LiteSpeed/Apache/nginx)
        # Examples: "LiteSpeed", "Apache/2.4.57 (Debian)"
        prod = server_header.split()[0]
        # remove extras like (Debian)
        prod = re.sub(r"\(.*?\)", "", prod).strip("/")
        q = prod
        results += [{"source": "NVD", **r} for r in nvd_query_cves(q, api_key=api_key, max_results=6)]

    return results

# --------------------- Reporting ---------------------

def sev_badge(score) -> str:
    try:
        s = float(score)
    except Exception:
        return '<span class="badge gray">N/A</span>'
    if s >= 9:
        return '<span class="badge critical">Critical</span>'
    if s >= 7:
        return '<span class="badge high">High</span>'
    if s >= 4:
        return '<span class="badge medium">Medium</span>'
    return '<span class="badge low">Low</span>'

def build_html_report(ctx: Dict) -> str:
    esc = html.escape
    target = esc(ctx["target_full"])
    ts = esc(now_utc_str())
    nmap_services_rows = ""
    for s in ctx.get("nmap", {}).get("services", []):
        nmap_services_rows += f"""
        <tr><td>{s['port']}</td><td>{esc(s['state'])}</td><td>{esc(s['service'])}</td>
        <td>{esc(s.get('product') or '')}</td><td>{esc(s.get('version') or '')}</td></tr>"""

    paths_rows = ""
    for p in ctx.get("paths", []):
        code = p['status'] if p['status'] is not None else "ERR"
        paths_rows += f"<tr><td>{esc(p['path'])}</td><td>{esc(str(code))}</td></tr>"

    wapps_rows = ""
    for a in ctx.get("fingerprint", {}).get("wappalyzer", []):
        wapps_rows += f"<tr><td>{esc(a.get('name') or '')}</td><td>{esc(str(a.get('version') or ''))}</td><td>{esc(str(a.get('confidence') or ''))}</td></tr>"

    cve_rows = ""
    for finding in ctx.get("findings", []):
        if finding.get("source") == "WPScan":
            cves = ", ".join(finding.get("cves") or []) or "—"
            score = finding.get("cvss")
            badge = sev_badge(score) if score else '<span class="badge gray">N/A</span>'
            links = " ".join(f'<a href="{html.escape(u)}">{html.escape(u)}</a>' for u in (finding.get("url") or []))
            cve_rows += f"""
            <tr>
              <td>WPScan</td>
              <td>{esc(finding.get('component',''))}</td>
              <td>{esc(finding.get('title',''))}</td>
              <td>{esc(cves)}</td>
              <td>{esc(str(score) if score else 'N/A')} {badge}</td>
              <td>{links or '—'}</td>
            </tr>"""
        else:  # NVD
            id_ = finding.get("id", "—")
            desc = finding.get("description", "")[:220] + ("..." if len(finding.get("description","")) > 220 else "")
            cvss = finding.get("cvss", {})
            score = cvss.get("baseScore")
            badge = sev_badge(score) if score else '<span class="badge gray">N/A</span>'
            cve_rows += f"""
            <tr>
              <td>NVD</td>
              <td>Stack</td>
              <td><b>{esc(id_)}</b>: {esc(desc)}</td>
              <td>{esc(id_)}</td>
              <td>{esc(str(score) if score else 'N/A')} {badge}</td>
              <td>—</td>
            </tr>"""

    nikto_block = f"<pre>{html.escape(ctx.get('nikto',{}).get('raw','').strip()[:4000])}</pre>" if ctx.get("nikto",{}).get("raw") else "<i>No Nikto output</i>"
    gobuster_block = f"<pre>{html.escape(ctx.get('gobuster',{}).get('raw','').strip()[:4000])}</pre>" if ctx.get("gobuster",{}).get("raw") else "<i>No Gobuster output</i>"
    wpscan_block = ""
    if ctx.get("wpscan", {}).get("skipped"):
        wpscan_block = "<i>WPScan skipped (WordPress not detected).</i>"
    else:
        wpscan_block = f"<pre>{html.escape((ctx.get('wpscan',{}).get('raw') or '').strip()[:4000])}</pre>" if ctx.get("wpscan",{}).get("raw") else "<i>No WPScan output</i>"

    server = esc(ctx.get("fingerprint",{}).get("server") or "Unknown")
    xpb = esc(ctx.get("fingerprint",{}).get("x_powered_by") or "Unknown")
    is_wp = "Yes" if ctx.get("fingerprint",{}).get("wordpress") else "No"

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>reconexpert Report – {target}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color:#111; margin: 40px; }}
h1,h2,h3 {{ margin: 0.3em 0; }}
h1 {{ font-size: 28px; }}
h2 {{ font-size: 22px; margin-top: 24px; }}
h3 {{ font-size: 18px; margin-top: 16px; }}
hr {{ border:0; border-top:1px solid #ddd; margin: 24px 0; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
pre {{ background:#0b1020; color:#d8e1ff; padding:12px; border-radius:8px; overflow:auto; }}
.badge {{ padding: 3px 8px; border-radius: 999px; font-size: 12px; color: #fff; }}
.badge.critical {{ background:#b30000; }}
.badge.high {{ background:#cc5500; }}
.badge.medium {{ background:#d4a20a; color:#111; }}
.badge.low {{ background:#2b7a0b; }}
.badge.gray {{ background:#6b7280; }}
.small {{ color:#666; font-size: 12px; }}
.note {{ background:#f7fafc; border:1px solid #e2e8f0; border-radius:8px; padding:10px; }}
</style>
</head>
<body>
  <h1>reconexpert – Web Reconnaissance Report</h1>
  <div class="small">Target: <b>{target}</b> • Generated: {ts}</div>
  <hr/>

  <h2>Executive Summary</h2>
  <div class="note">
    Automated reconnaissance was performed on <b>{target}</b> to fingerprint the web stack, enumerate common content, and identify known vulnerabilities from public sources (NVD, WPScan).
    This report summarizes key services, technologies, and CVEs detected. Manual validation is recommended for all high/critical findings.
  </div>

  <h2>Scope & Methodology</h2>
  <ul>
    <li><b>Nmap</b> service & version detection</li>
    <li><b>Gobuster</b> directory brute force with redirect/false-positive suppression</li>
    <li><b>Nikto</b> web server misconfiguration/vuln checks</li>
    <li><b>Conditional WPScan</b> (only if WordPress detected)</li>
    <li><b>NVD</b> CVE lookup for stack components (e.g., PHP, server)</li>
  </ul>

  <h2>Key Fingerprints</h2>
  <table>
    <tr><th>Server</th><td>{server}</td></tr>
    <tr><th>X-Powered-By</th><td>{xpb}</td></tr>
    <tr><th>WordPress detected</th><td>{is_wp}</td></tr>
  </table>

  <h2>Open Services (Nmap)</h2>
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
    <tbody>
      {nmap_services_rows or "<tr><td colspan='5'><i>No parsed services</i></td></tr>"}
    </tbody>
  </table>

  <h2>Technologies (Wappalyzer)</h2>
  <table>
    <thead><tr><th>Technology</th><th>Version</th><th>Confidence</th></tr></thead>
    <tbody>
      {wapps_rows or "<tr><td colspan='3'><i>Wappalyzer not available or no detections</i></td></tr>"}
    </tbody>
  </table>

  <h2>Common Paths</h2>
  <table>
    <thead><tr><th>Path</th><th>Status</th></tr></thead>
    <tbody>
      {paths_rows or "<tr><td colspan='2'><i>No path results</i></td></tr>"}
    </tbody>
  </table>

  <h2>Vulnerability Findings</h2>
  <table>
    <thead><tr><th>Source</th><th>Component</th><th>Summary</th><th>CVE(s)</th><th>CVSS</th><th>Refs</th></tr></thead>
    <tbody>
      {cve_rows or "<tr><td colspan='6'><i>No CVEs found via NVD/WPScan sources</i></td></tr>"}
    </tbody>
  </table>

  <h2>Recommendations</h2>
  <ul>
    <li>Prioritize patching items with <span class="badge critical">Critical</span> or <span class="badge high">High</span> CVSS.</li>
    <li>Harden WordPress (if applicable): restrict admin endpoints, keep core/plugins/themes updated, enforce MFA.</li>
    <li>Minimize server info leaks (Server/X-Powered-By headers), enable security headers (CSP, HSTS, etc.).</li>
    <li>Validate Gobuster/Nikto hits manually; confirm exploitability before remediation planning.</li>
  </ul>

  <h2>Appendix A – Nikto (Condensed)</h2>
  {nikto_block}

  <h2>Appendix B – Gobuster (Condensed)</h2>
  {gobuster_block}

  <h2>Appendix C – WPScan (Condensed)</h2>
  {wpscan_block}

  <hr/>
  <div class="small">Generated by reconexpert • {ts}</div>
</body></html>
"""
    return html_doc

def try_pdf(html_path: Path, pdf_path: Path) -> bool:
    wk = which("wkhtmltopdf")
    if not wk:
        return False
    rc, out, err = run_cmd([wk, "--enable-local-file-access", str(html_path), str(pdf_path)], timeout=120)
    return rc == 0 and pdf_path.exists()

# --------------------- Main Orchestration ---------------------

def main():
    parser = argparse.ArgumentParser(description="reconexpert – Automated Web Recon with CVE Enrichment (CV-ready)")
    parser.add_argument("--target", required=True, help="Target domain or IP (example.com)")
    args = parser.parse_args()

    target = args.target.strip()
    if "://" in target:
        # Normalize: keep host only; we’ll detect protocol later
        target = re.sub(r"^https?://", "", target).strip("/")

    # Show banner + phases
    animated_banner()
    #print(Fore.GREEN + " _____  ___  \n|___ / / _ \\ \n  |_ \\| | | |\n ___) | |_| |\n|____(_)___/ \n")
    print(Fore.GREEN + f"[+] Target Acquired: https://{target}")
    print(Fore.GREEN + "[+] Establishing secure connection...")
    time.sleep(0.2)
    print(Fore.GREEN + "[+] Bypassing firewalls...")
    time.sleep(0.2)
    print(Fore.GREEN + "[+] Injecting scanning modules...")
    time.sleep(0.2)
    print(Fore.GREEN + "[+] Recon Engine Initialized")
    for lbl in ["Scanning Ports", "Fingerprinting Stack", "Crawling Content", "Assembling Report"]:
        phase_bar(10, 10, lbl)

    outdir = Path("RADAR")
    safe_mkdir(outdir)

    # Pre-flight: quick HEAD/GET to infer protocol & stack
    # We’ll run a tiny GET over HTTPS then HTTP to guess protocol early
    protocol_guess = "https"
    r_https = get(f"https://{target}/")
    if r_https and r_https.ok:
        protocol_guess = "https"
    else:
        r_http = get(f"http://{target}/")
        protocol_guess = "http" if r_http and r_http.ok else "https"

    # Parallel core scans
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        fut_nmap = ex.submit(scan_nmap_xml, target)
        fut_fprint = ex.submit(fingerprint_stack, target, protocol_guess)
        # gobuster needs exclude length; compute quickly in main thread to feed in:
        excl_len = detect_false_length(target, protocol_guess)
        fut_gob = ex.submit(scan_gobuster, target, protocol_guess, excl_len)
        fut_nikto = ex.submit(scan_nikto, target, protocol_guess)
        fut_paths = ex.submit(scan_common_paths, target, protocol_guess)

        nmap_res = fut_nmap.result()
        # refine protocol from nmap, prefer 443 open
        protocol = detect_protocol_from_nmap(nmap_res.get("raw","")) or protocol_guess
        fprint_res = fut_fprint.result()
        gob_res = fut_gob.result()
        nikto_res = fut_nikto.result()
        paths_res = fut_paths.result()

    # Conditional WPScan
    wpscan_res = scan_wpscan_if_wp(target, protocol, fprint_res.get("wordpress", False))

    # CVE aggregation
    php_ver = parse_php_version(fprint_res.get("x_powered_by"))
    stack_cves = cves_from_nvd_for_stack(fprint_res.get("server"), php_ver)
    wp_cves = cves_from_wpscan_json(wpscan_res.get("json"))

    findings = []
    # Prioritize WPScan CVEs first (more specific)
    findings.extend(wp_cves[:50])  # don’t blow up the report
    # Then add a slice of NVD results
    findings.extend(stack_cves[:25])

    # Build report context
    ctx = {
        "target_full": f"{protocol}://{target}",
        "nmap": nmap_res,
        "fingerprint": fprint_res,
        "gobuster": gob_res,
        "nikto": nikto_res,
        "paths": paths_res,
        "wpscan": wpscan_res,
        "findings": findings,
        "exclude_len": excl_len
    }

    # Write HTML + optional PDF
    html_report = build_html_report(ctx)
    html_path = outdir / f"recon_{target}.html"
    write_file(html_path, html_report)

    pdf_path = outdir / f"recon_{target}.pdf"
    if try_pdf(html_path, pdf_path):
        print(Fore.GREEN + f"[+] PDF report: {pdf_path}")
    else:
        print(Fore.YELLOW + "[!] wkhtmltopdf not available or failed; HTML report saved.")
        print(Fore.GREEN + f"[+] HTML report: {html_path}")

    print(Fore.GREEN + "\n[+] Recon complete.\n")

if __name__ == "__main__":
    # Soften SSL warnings for quick-and-dirty recon
    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore
    except Exception:
        pass
    main()
