"""
Program metrics (KPIs). These are the numbers a vulnerability-management analyst
reports in a weekly review: how many open issues by priority, how many are past
their SLA, how fast the team is fixing things, and which teams and CVEs carry the
most risk.
"""
from collections import defaultdict


def summarize(rows):
    open_rows = [r for r in rows if r["status"] in ("Open", "In Progress")]
    remediated = [r for r in rows if r["status"] == "Remediated"]
    accepted = [r for r in rows if r["status"] == "Risk Accepted"]

    by_priority = defaultdict(int)
    for r in open_rows:
        by_priority[r["priority"]] += 1

    by_severity = defaultdict(int)
    for r in open_rows:
        by_severity[r["scanner_severity"]] += 1

    overdue = [r for r in open_rows if r["sla_state"] == "Overdue"]

    # SLA compliance on closed items: how many were fixed on time
    closed_with_state = [r for r in remediated if r.get("sla_state") in ("Met", "Missed")]
    met = sum(1 for r in closed_with_state if r["sla_state"] == "Met")
    sla_compliance = round(100 * met / len(closed_with_state), 1) if closed_with_state else 0.0

    # Mean time to remediate (days)
    ttr = [r["days_to_remediate"] for r in remediated if isinstance(r.get("days_to_remediate"), int)]
    mttr = round(sum(ttr) / len(ttr), 1) if ttr else 0.0

    by_team = defaultdict(lambda: {"open": 0, "overdue": 0})
    for r in open_rows:
        by_team[r["owner_team"]]["open"] += 1
        if r["sla_state"] == "Overdue":
            by_team[r["owner_team"]]["overdue"] += 1

    kev_open = [r for r in open_rows if r["kev"] == "Yes"]

    # Top CVEs by number of affected open findings
    cve_counts = defaultdict(lambda: {"count": 0, "name": "", "score": 0})
    for r in open_rows:
        c = cve_counts[r["cve"]]
        c["count"] += 1
        c["name"] = r["vuln_name"]
        c["score"] = max(c["score"], r["risk_score"])
    top_cves = sorted(cve_counts.items(), key=lambda kv: (kv[1]["count"], kv[1]["score"]), reverse=True)[:10]

    return {
        "total": len(rows),
        "open": len(open_rows),
        "remediated": len(remediated),
        "accepted": len(accepted),
        "by_priority": dict(by_priority),
        "by_severity": dict(by_severity),
        "overdue": overdue,
        "overdue_count": len(overdue),
        "sla_compliance": sla_compliance,
        "mttr": mttr,
        "by_team": dict(by_team),
        "kev_open": kev_open,
        "kev_open_count": len(kev_open),
        "top_cves": top_cves,
    }
