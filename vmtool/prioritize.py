"""
Risk-based prioritization.

A raw CVSS score alone is a poor way to decide what to fix first: a CVSS 9.8 on a
spare test box matters less than a CVSS 7.5 on a critical database that processes
cardholder data and is being actively exploited. This module combines three
factors the job description calls for -- technical severity, business context, and
active-exploitation threat intel -- into a single 0-100 risk score and a priority
tier (P1-P4) with a remediation SLA.

    risk = (CVSS/10 * 50)              technical severity, up to 50 pts
         + asset-criticality weight    business impact, up to 30 pts
         + KEV / exploit weight        real-world threat, up to 20 pts

The weights are a policy choice, kept in ONE place so they are easy to defend in a
review meeting and easy to tune.
"""
from datetime import datetime

from vmtool.kev import is_known_exploited

CRITICALITY_POINTS = {"Critical": 30, "High": 22, "Medium": 12, "Low": 6}
PCI_BONUS = 5          # in-scope for PCI DSS raises urgency
KEV_POINTS = 20        # actively exploited in the wild

# Remediation SLA in days by priority tier (a common risk-based policy)
SLA_DAYS = {"P1": 15, "P2": 30, "P3": 90, "P4": 180}


def risk_score(cvss_base, criticality, pci_scope, cve):
    score = (float(cvss_base) / 10.0) * 50.0
    score += CRITICALITY_POINTS.get(criticality, 6)
    if is_known_exploited(cve):
        score += KEV_POINTS
    if str(pci_scope).strip().lower() in ("yes", "true", "1"):
        score += PCI_BONUS
    return round(min(score, 100.0), 1)


def priority_tier(score, cve):
    """Map a risk score to a tier. Known-exploited vulns are floored at P2 so an
    actively exploited issue can never be deprioritized to routine patching."""
    if score >= 80:
        tier = "P1"
    elif score >= 60:
        tier = "P2"
    elif score >= 40:
        tier = "P3"
    else:
        tier = "P4"
    if is_known_exploited(cve) and tier in ("P3", "P4"):
        tier = "P2"
    return tier


def due_date(first_detected, tier):
    detected = datetime.strptime(first_detected, "%Y-%m-%d")
    return detected.replace(hour=0) + _days(SLA_DAYS[tier])


def _days(n):
    from datetime import timedelta
    return timedelta(days=n)


def enrich(finding, asset, today):
    """Return the finding augmented with risk score, tier, SLA due date and SLA state."""
    score = risk_score(finding["cvss_base"], asset["criticality"], asset["pci_scope"], finding["cve"])
    tier = priority_tier(score, finding["cve"])
    due = due_date(finding["first_detected"], tier)

    out = dict(finding)
    out["criticality"] = asset["criticality"]
    out["environment"] = asset["environment"]
    out["owner_team"] = asset["owner_team"]
    out["pci_scope"] = asset["pci_scope"]
    out["kev"] = "Yes" if is_known_exploited(finding["cve"]) else "No"
    out["risk_score"] = score
    out["priority"] = tier
    out["sla_days"] = SLA_DAYS[tier]
    out["due_date"] = due.strftime("%Y-%m-%d")

    status = finding["status"]
    if status == "Remediated":
        rem = datetime.strptime(finding["remediated_date"], "%Y-%m-%d")
        out["sla_state"] = "Met" if rem <= due else "Missed"
        out["days_to_remediate"] = (rem - datetime.strptime(finding["first_detected"], "%Y-%m-%d")).days
    elif status == "Risk Accepted":
        out["sla_state"] = "Exception"
        out["days_to_remediate"] = ""
    else:  # Open or In Progress
        if today > due:
            out["sla_state"] = "Overdue"
            out["days_overdue"] = (today - due).days
        else:
            out["sla_state"] = "Within SLA"
            out["days_overdue"] = 0
        out["days_to_remediate"] = ""
    return out
