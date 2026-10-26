"""
Remediation ticketing. Turns each actionable (Open / In Progress) finding into a
remediation ticket assigned to the owning team, with the SLA due date and a
plain-language remediation action. In a real program these would be pushed into
Jira or ServiceNow through their API; here we write a CSV that mirrors those
fields so the workflow is identical.
"""
import csv

# Short, generic remediation guidance by asset type. Real guidance comes from the
# vendor advisory for each CVE; these are the sensible defaults an analyst writes.
GUIDANCE = {
    "Windows Server": "Apply the latest Microsoft security rollup; reboot in the next patch window.",
    "Linux Server": "Update the affected package via the distro package manager; restart the service.",
    "Network Device": "Upgrade device firmware to the vendor-fixed release; review ACLs.",
    "Cloud Resource": "Patch the base image and redeploy; confirm the managed service is on a fixed version.",
    "Workstation": "Deploy the patch through the endpoint management tool; verify on next check-in.",
    "Database": "Apply the database vendor's critical patch update during a maintenance window.",
}


def build_tickets(rows, assets_by_id):
    tickets = []
    actionable = [r for r in rows if r["status"] in ("Open", "In Progress")]
    # Highest risk first so the queue is already triaged
    actionable.sort(key=lambda r: r["risk_score"], reverse=True)
    for i, r in enumerate(actionable, 1):
        atype = assets_by_id[r["asset_id"]]["asset_type"]
        tickets.append({
            "ticket_id": f"REM-{i:04d}",
            "finding_id": r["finding_id"],
            "priority": r["priority"],
            "risk_score": r["risk_score"],
            "asset_id": r["asset_id"],
            "hostname": r["hostname"],
            "cve": r["cve"],
            "vuln_name": r["vuln_name"],
            "cvss_base": r["cvss_base"],
            "kev": r["kev"],
            "assigned_team": r["owner_team"],
            "status": r["status"],
            "first_detected": r["first_detected"],
            "due_date": r["due_date"],
            "sla_state": r["sla_state"],
            "remediation_action": GUIDANCE.get(atype, "Apply the vendor-recommended fix."),
        })
    return tickets


def write_tickets(tickets, path):
    if not tickets:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(tickets[0].keys()))
        w.writeheader()
        w.writerows(tickets)
