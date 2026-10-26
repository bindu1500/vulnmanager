#!/usr/bin/env python3
"""
VulnManager - a risk-based vulnerability management tool.

Reads a vulnerability scan export and an asset inventory, scores every finding by
business risk (CVSS + asset criticality + CISA KEV threat intel), assigns a
priority tier and remediation SLA, generates remediation tickets, and produces a
metrics report plus a self-contained HTML dashboard.

Usage:
    python vm.py                              # use the sample data in data/
    python vm.py --scan s.csv --assets a.csv  # your own exports
    python vm.py --out-dir output             # where results are written
"""
import argparse
import csv
import os
import sys
from datetime import datetime

from vmtool.metrics import summarize
from vmtool.prioritize import enrich
from vmtool.tickets import build_tickets, write_tickets
from vmtool.dashboard import render_dashboard

TODAY = datetime(2026, 10, 26)
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def load_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_enriched(rows, path):
    cols = ["finding_id", "asset_id", "hostname", "cve", "vuln_name", "cvss_base",
            "scanner_severity", "criticality", "environment", "owner_team", "pci_scope",
            "kev", "risk_score", "priority", "sla_days", "first_detected", "due_date",
            "status", "sla_state"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in sorted(rows, key=lambda r: r["risk_score"], reverse=True):
            w.writerow(r)


def write_report(m, rows, path):
    L = []
    L.append("# Vulnerability Management Report")
    L.append("")
    L.append(f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    L.append(f"- Findings analyzed: {m['total']}  |  Open: {m['open']}  |  Remediated: {m['remediated']}  |  Risk accepted: {m['accepted']}")
    L.append("")
    L.append("## Executive summary")
    L.append("")
    p = m["by_priority"]
    L.append(f"- **{p.get('P1',0)} P1 (critical-risk)** and **{p.get('P2',0)} P2** findings are open and need priority attention.")
    L.append(f"- **{m['overdue_count']} findings are past their remediation SLA.**")
    L.append(f"- **{m['kev_open_count']} open findings are actively exploited (CISA KEV)** and should be fixed first regardless of CVSS.")
    L.append(f"- SLA compliance on closed findings: **{m['sla_compliance']}%**. Mean time to remediate: **{m['mttr']} days**.")
    L.append("")
    L.append("## Open findings by priority")
    L.append("")
    L.append("| Priority | SLA (days) | Open count |")
    L.append("| --- | --- | --- |")
    for tier in ["P1", "P2", "P3", "P4"]:
        sla = {"P1": 15, "P2": 30, "P3": 90, "P4": 180}[tier]
        L.append(f"| {tier} | {sla} | {p.get(tier,0)} |")
    L.append("")
    L.append("## Top 15 findings by risk score")
    L.append("")
    L.append("| Risk | Priority | Host | CVE | Vulnerability | CVSS | KEV | Due | SLA state |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    top = sorted([r for r in rows if r["status"] in ("Open", "In Progress")],
                 key=lambda r: r["risk_score"], reverse=True)[:15]
    for r in top:
        L.append(f"| {r['risk_score']} | {r['priority']} | {r['hostname']} | {r['cve']} | {r['vuln_name']} | {r['cvss_base']} | {r['kev']} | {r['due_date']} | {r['sla_state']} |")
    L.append("")
    L.append("## Risk by owning team")
    L.append("")
    L.append("| Team | Open | Overdue |")
    L.append("| --- | --- | --- |")
    for team, d in sorted(m["by_team"].items(), key=lambda kv: kv[1]["open"], reverse=True):
        L.append(f"| {team} | {d['open']} | {d['overdue']} |")
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="VulnManager - risk-based vulnerability management")
    ap.add_argument("--scan", default="data/scan_results.csv")
    ap.add_argument("--assets", default="data/assets.csv")
    ap.add_argument("--out-dir", default="output")
    args = ap.parse_args(argv)

    findings = load_csv(args.scan)
    assets = load_csv(args.assets)
    assets_by_id = {a["asset_id"]: a for a in assets}

    rows = []
    skipped = 0
    for fnd in findings:
        asset = assets_by_id.get(fnd["asset_id"])
        if not asset:
            skipped += 1
            continue
        rows.append(enrich(fnd, asset, TODAY))

    m = summarize(rows)
    tickets = build_tickets(rows, assets_by_id)

    os.makedirs(args.out_dir, exist_ok=True)
    write_enriched(rows, os.path.join(args.out_dir, "prioritized_findings.csv"))
    write_tickets(tickets, os.path.join(args.out_dir, "remediation_tickets.csv"))
    write_report(m, rows, os.path.join(args.out_dir, "report.md"))
    render_dashboard(m, rows, assets, os.path.join(args.out_dir, "dashboard.html"), TODAY)

    print("=" * 60)
    print("  VulnManager - risk-based vulnerability management")
    print("=" * 60)
    print(f"  Analyzed {m['total']} findings across {len(assets)} assets"
          + (f" ({skipped} skipped: no matching asset)" if skipped else ""))
    print(f"  Open: {m['open']}   Remediated: {m['remediated']}   Risk accepted: {m['accepted']}")
    print(f"  Open by priority: " + "  ".join(f"{t}:{m['by_priority'].get(t,0)}" for t in ['P1','P2','P3','P4']))
    print(f"  Overdue (past SLA): {m['overdue_count']}")
    print(f"  Actively exploited (KEV) still open: {m['kev_open_count']}")
    print(f"  SLA compliance on closed: {m['sla_compliance']}%   MTTR: {m['mttr']} days")
    print(f"  Remediation tickets generated: {len(tickets)}")
    print("-" * 60)
    print(f"  Wrote: {args.out_dir}/prioritized_findings.csv")
    print(f"         {args.out_dir}/remediation_tickets.csv")
    print(f"         {args.out_dir}/report.md")
    print(f"         {args.out_dir}/dashboard.html  <- open this in a browser")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
