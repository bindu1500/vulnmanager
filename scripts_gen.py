"""Generates realistic sample data: an asset inventory and a vulnerability scan export.
Run once to (re)create data/assets.csv and data/scan_results.csv."""
import csv
import random
from datetime import datetime, timedelta

random.seed(11)
TODAY = datetime(2026, 10, 26)

# ---- Real, well-known CVEs so CVE research is a genuine talking point ----
# (cve, name, cvss_base, in_cisa_kev)  KEV = CISA Known Exploited Vulnerabilities
CVE_CATALOG = [
    ("CVE-2021-44228", "Apache Log4j2 RCE (Log4Shell)", 10.0, True),
    ("CVE-2014-0160", "OpenSSL Heartbleed information disclosure", 7.5, True),
    ("CVE-2017-0144", "Windows SMBv1 RCE (EternalBlue)", 8.1, True),
    ("CVE-2019-0708", "Windows RDP RCE (BlueKeep)", 9.8, True),
    ("CVE-2021-34527", "Windows Print Spooler RCE (PrintNightmare)", 8.8, True),
    ("CVE-2023-23397", "Microsoft Outlook privilege escalation", 9.8, True),
    ("CVE-2022-1388", "F5 BIG-IP iControl REST auth bypass", 9.8, True),
    ("CVE-2023-34362", "MOVEit Transfer SQL injection", 9.8, True),
    ("CVE-2020-1472", "Netlogon privilege escalation (Zerologon)", 10.0, True),
    ("CVE-2021-26855", "Microsoft Exchange SSRF (ProxyLogon)", 9.8, True),
    ("CVE-2022-30190", "Microsoft Office RCE (Follina)", 7.8, True),
    ("CVE-2018-13379", "Fortinet FortiOS path traversal", 9.8, True),
    ("CVE-2023-4863", "libwebp heap buffer overflow", 8.8, True),
    ("CVE-2016-2183", "SSL/TLS SWEET32 birthday attack (3DES)", 7.5, False),
    ("CVE-2015-0204", "SSL/TLS FREAK downgrade", 4.3, False),
    ("CVE-2021-3156", "Sudo heap overflow (Baron Samedit)", 7.8, True),
    ("CVE-2022-0847", "Linux kernel privilege escalation (Dirty Pipe)", 7.8, False),
    ("CVE-2023-38545", "curl SOCKS5 heap buffer overflow", 8.8, False),
    ("CVE-2024-3094", "XZ Utils backdoor (supply chain)", 10.0, True),
    ("CVE-2017-5638", "Apache Struts2 RCE", 10.0, True),
    ("CVE-2019-11510", "Pulse Secure VPN arbitrary file read", 10.0, True),
    ("CVE-2020-0601", "Windows CryptoAPI spoofing (CurveBall)", 8.1, False),
    ("CVE-2016-5195", "Linux kernel privilege escalation (Dirty COW)", 7.8, True),
    ("CVE-2012-1823", "PHP-CGI query string RCE", 7.5, True),
    ("CVE-2023-2650", "OpenSSL OBJECT IDENTIFIER DoS", 5.3, False),
    ("CVE-2021-41773", "Apache HTTP Server path traversal", 7.5, True),
    ("CVE-2014-6271", "Bash remote code execution (Shellshock)", 9.8, True),
    ("CVE-2018-0886", "Windows CredSSP RCE", 8.1, False),
    ("CVE-2022-26134", "Atlassian Confluence OGNL RCE", 9.8, True),
    ("CVE-2023-0669", "Fortra GoAnywhere MFT RCE", 7.2, True),
]

# ---- Asset inventory across the categories the JD names ----
# type, count, criticality, env, pci_scope_bias
ASSET_PLAN = [
    ("Windows Server", 6, ["Critical", "High", "High", "Medium", "Medium", "High"], "Production", True),
    ("Linux Server", 6, ["High", "High", "Critical", "Medium", "Medium", "Low"], "Production", True),
    ("Network Device", 3, ["High", "High", "Medium"], "Production", False),
    ("Cloud Resource", 4, ["Critical", "High", "Medium", "Medium"], "Cloud", True),
    ("Workstation", 4, ["Medium", "Medium", "Low", "Low"], "Corporate", False),
    ("Database", 2, ["Critical", "Critical"], "Production", True),
]
TEAMS = {
    "Windows Server": "Windows Infrastructure",
    "Linux Server": "Linux Infrastructure",
    "Network Device": "Network Operations",
    "Cloud Resource": "Cloud Platform",
    "Workstation": "End-User Computing",
    "Database": "Database Administration",
}

assets = []
n = 0
for atype, count, crits, env, pci_bias in ASSET_PLAN:
    for i in range(count):
        n += 1
        pci = "Yes" if (pci_bias and random.random() < 0.6) else "No"
        assets.append({
            "asset_id": f"AST-{n:03d}",
            "hostname": f"{atype.split()[0].lower()}-{env[:4].lower()}-{i+1:02d}",
            "asset_type": atype,
            "ip_address": f"10.{random.randint(10,40)}.{random.randint(1,50)}.{random.randint(2,250)}",
            "environment": env,
            "criticality": crits[i],
            "owner_team": TEAMS[atype],
            "pci_scope": pci,
        })

with open("data/assets.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(assets[0].keys()))
    w.writeheader()
    w.writerows(assets)

# ---- Vulnerability scan export (Nessus/Qualys-style rows) ----
def severity_from_cvss(c):
    if c >= 9.0: return "Critical"
    if c >= 7.0: return "High"
    if c >= 4.0: return "Medium"
    return "Low"

STATUS_CHOICES = ["Open", "Open", "Open", "In Progress", "Remediated", "Risk Accepted"]
findings = []
fid = 0
for a in assets:
    # critical assets tend to show more findings
    k = {"Critical": 12, "High": 9, "Medium": 6, "Low": 4}[a["criticality"]]
    picks = random.sample(CVE_CATALOG, min(k, len(CVE_CATALOG)))
    for cve, name, cvss, kev in picks:
        fid += 1
        detected = TODAY - timedelta(days=random.randint(1, 160))
        status = random.choice(STATUS_CHOICES)
        remediated = ""
        if status == "Remediated":
            # remediated some days after detection
            rem = detected + timedelta(days=random.randint(3, 50))
            if rem > TODAY:
                rem = TODAY - timedelta(days=1)
            remediated = rem.strftime("%Y-%m-%d")
        findings.append({
            "finding_id": f"VLN-{fid:04d}",
            "asset_id": a["asset_id"],
            "hostname": a["hostname"],
            "cve": cve,
            "vuln_name": name,
            "cvss_base": cvss,
            "scanner_severity": severity_from_cvss(cvss),
            "first_detected": detected.strftime("%Y-%m-%d"),
            "status": status,
            "remediated_date": remediated,
        })

random.shuffle(findings)
with open("data/scan_results.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(findings[0].keys()))
    w.writeheader()
    w.writerows(findings)

print(f"assets: {len(assets)}  findings: {len(findings)}")
