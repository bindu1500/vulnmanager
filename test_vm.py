"""Tests for the prioritization logic - the analytical core."""
from datetime import datetime
from vmtool.prioritize import risk_score, priority_tier, enrich

def test_criticality_raises_score():
    assert risk_score(7.5,"Critical","No","CVE-0000-0000") > risk_score(7.5,"Low","No","CVE-0000-0000")

def test_kev_raises_score_and_floors_tier():
    base = risk_score(5.0,"Low","No","CVE-2016-5195")   # Dirty COW is in KEV
    assert priority_tier(base,"CVE-2016-5195") in ("P1","P2")  # never P3/P4 for KEV

def test_pci_bonus():
    assert risk_score(6.0,"Medium","Yes","CVE-0000-0000") == risk_score(6.0,"Medium","No","CVE-0000-0000") + 5

def test_tier_boundaries():
    assert priority_tier(80,"x")=="P1"
    assert priority_tier(60,"x")=="P2"
    assert priority_tier(40,"x")=="P3"
    assert priority_tier(39.9,"x")=="P4"

def test_overdue_detection():
    f={"finding_id":"V1","cve":"CVE-0000-0000","cvss_base":"9.0","first_detected":"2026-01-01",
       "status":"Open","remediated_date":""}
    a={"criticality":"Critical","environment":"Production","owner_team":"T","pci_scope":"No"}
    out=enrich(f,a,datetime(2026,10,26))
    assert out["sla_state"]=="Overdue" and out["days_overdue"]>0

def test_remediated_sla_met():
    f={"finding_id":"V2","cve":"CVE-0000-0000","cvss_base":"9.0","first_detected":"2026-10-01",
       "status":"Remediated","remediated_date":"2026-10-05"}
    a={"criticality":"Critical","environment":"Production","owner_team":"T","pci_scope":"No"}
    out=enrich(f,a,datetime(2026,10,26))
    assert out["sla_state"]=="Met" and out["days_to_remediate"]==4
