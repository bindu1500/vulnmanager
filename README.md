# VulnManager — Risk-Based Vulnerability Management

A Python tool that takes raw vulnerability scan results and does what a Vulnerability Management Analyst does: it scores every finding by **business risk**, assigns a **priority tier and remediation SLA**, generates **remediation tickets** for the owning teams, and produces a **metrics report and dashboard** for stakeholders.

> Sample data only. No real patient or cardholder data.

## The problem it solves

A scanner can report thousands of vulnerabilities. Fixing them in CVSS order is the wrong move, because a CVSS 9.8 on a spare test box matters less than a CVSS 7.5 on a critical database that is in PCI scope and is being actively exploited. This tool turns a flat scan export into a **ranked, SLA-tracked remediation plan** using a risk-based method.

## How it prioritizes

Each finding gets a 0–100 risk score:

```
risk = CVSS severity           (up to 50 pts)
     + asset business impact   (up to 30 pts: Critical/High/Medium/Low)
     + active exploitation     (20 pts if the CVE is in CISA's KEV catalog)
     + PCI-scope bonus         (5 pts)
```

The score maps to a priority tier, each with a remediation SLA:

| Tier | Risk score | SLA |
|---|---|---|
| P1 | 80–100 | 15 days |
| P2 | 60–79 | 30 days |
| P3 | 40–59 | 90 days |
| P4 | < 40 | 180 days |

Any CVE in **CISA KEV** (Known Exploited Vulnerabilities — the authoritative list of what attackers are actively using) is floored at **P2**, so an actively exploited issue can never be deprioritized to routine patching. This is the "risk-based vulnerability prioritization" the role asks for.

## What it produces

Running `python vm.py` writes four files to `output/`:

- `prioritized_findings.csv` — every finding enriched with risk score, tier, SLA due date and status
- `remediation_tickets.csv` — a triaged ticket queue assigned to each owning team (the Jira/ServiceNow hand-off)
- `report.md` — an executive report with KPIs
- `dashboard.html` — a self-contained dashboard (open in any browser)

The dashboard shows open findings by priority, severity and team; SLA compliance; mean time to remediate (MTTR); overdue counts; actively-exploited counts; and the most widespread CVEs.

## Run it

```bash
python vm.py                                 # use the sample data in data/
python vm.py --scan my_scan.csv --assets my_assets.csv
python -m pytest -q                          # run the tests
```

## How it maps to the job

| Job requirement | Where it shows up |
|---|---|
| Analyze scan results, determine severity and business impact | `vmtool/prioritize.py` |
| CVSS scoring, CVE research, threat intelligence | CVSS + CISA KEV enrichment |
| Risk-based prioritization | 0–100 score and P1–P4 tiers |
| Create, assign, track remediation tickets | `vmtool/tickets.py`, `remediation_tickets.csv` |
| Monitor SLA compliance and follow up | SLA due dates, overdue flags, compliance % |
| Track program KPIs, identify improvements | `vmtool/metrics.py`, dashboard |
| Reporting and dashboards | `report.md`, `dashboard.html` |
| PCI DSS, CIS, risk methodologies | PCI-scope weighting, risk-based SLAs |
| Scripting / automation (Python) | the whole tool |

## Project layout

```
data/scan_results.csv     Sample scanner export (Nessus/Qualys-style)
data/assets.csv           Asset inventory with criticality, owner, PCI scope
vmtool/prioritize.py      Risk scoring and SLA engine
vmtool/kev.py             CISA Known Exploited Vulnerabilities list
vmtool/metrics.py         Program KPIs
vmtool/tickets.py         Remediation ticket generation
vmtool/dashboard.py       Self-contained HTML dashboard
vm.py                     Command-line entry point
test_vm.py                Tests for the scoring logic
```

## Tech

Python 3 (standard library only) · CVSS · CISA KEV · MITRE-aligned risk method · HTML/SVG dashboard · pytest
