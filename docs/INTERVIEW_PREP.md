# Interview Prep — Associate Vulnerability Management Analyst

## Resume bullet (Projects section)

**VulnManager — Risk-Based Vulnerability Management Tool** | Python, CVSS, CISA KEV
Built a Python tool that ingests vulnerability scan exports and asset inventory, scores each finding by business risk (CVSS + asset criticality + CISA Known Exploited Vulnerabilities + PCI scope), assigns P1–P4 priority tiers with remediation SLAs, auto-generates remediation tickets to owning teams, and produces an executive dashboard tracking SLA compliance, MTTR, and overdue findings across 25 assets and ~200 findings.

## 30-second project pitch

"I built a vulnerability management tool because I wanted to understand how you go from a raw scan with thousands of findings to an actual remediation plan. It takes a scanner export and an asset inventory, and scores every finding on business risk, not just CVSS — because a 9.8 on a test box matters less than a 7.5 on a PCI database that's being actively exploited. It assigns priority tiers with SLAs, creates tickets for the right teams, and builds a dashboard showing SLA compliance and what's overdue. It's the end-to-end workflow this role runs."

## Core concepts — know these cold

**CVSS** (Common Vulnerability Scoring System): a 0–10 score for how severe a vulnerability is. Base score covers how exploitable it is and its impact. 9.0+ = Critical, 7.0–8.9 = High, 4.0–6.9 = Medium, below 4 = Low. It measures the vuln, not your risk from it.

**CVE** (Common Vulnerabilities and Exposures): the unique public ID for a specific vulnerability, like CVE-2021-44228 (Log4Shell). You research the CVE in the vendor advisory and the NVD to learn what's affected and how to fix it.

**CISA KEV** (Known Exploited Vulnerabilities): CISA's authoritative list of CVEs confirmed to be exploited in the wild. If a CVE is on KEV, patch it first regardless of CVSS — real-world exploitation beats a theoretical score. My tool floors any KEV finding at P2 for exactly this reason.

**Risk-based prioritization**: ranking by business risk = technical severity + asset importance + active-exploitation + exposure, not raw CVSS. This is the single most important idea for this role.

**Remediation SLA**: the deadline to fix a vuln, set by priority. Common policy: Critical 15 days, High 30, Medium 90, Low 180. Tracking SLA compliance is a core KPI.

**MTTR** (Mean Time To Remediate): average days from detection to fix. A key program-health metric.

**False positive / validation**: scanners flag things that aren't truly exploitable (wrong version detected, compensating control in place). An analyst validates before sending a ticket, to keep teams' trust.

**Exception / risk acceptance**: when a vuln can't be fixed in time (breaks a legacy app), the business formally accepts the risk for a set period, with sign-off. My tool models this as a "Risk Accepted" status.

**PCI DSS**: the payment-card security standard. Requirement 11 mandates regular vulnerability scanning; Requirement 6 mandates patching. That's why PCI-scope assets get a risk bonus in my tool.

**CIS Controls / CIS Benchmarks**: Controls are prioritized security best practices (Control 7 is continuous vulnerability management); Benchmarks are hardening configs for specific systems.

**NIST CSF**: the five-function framework — Identify, Protect, Detect, Respond, Recover. Vuln management lives mostly in Identify and Protect.

## Likely questions and answers

| Question | Your answer |
|---|---|
| You have 5,000 findings. Where do you start? | Not CVSS order. I rank by business risk: anything in CISA KEV on an internet-facing or critical/PCI asset first, then by my combined score. I'd fix a KEV 7.5 on a critical DB before a 9.8 on an isolated test box. |
| What's the difference between a vulnerability, a threat, and a risk? | A vulnerability is a weakness. A threat is something that could exploit it. Risk is the combination plus impact: vulnerability × threat × business impact. |
| How do you handle a team that won't patch? | Track the SLA, follow up, and escalate with data: show the risk score, KEV status, and days overdue. If they genuinely can't patch, route it to a formal risk-acceptance with an owner and an expiry date — not silence. |
| How do you deal with false positives? | Validate before ticketing: confirm the version, check for compensating controls, sometimes test. Document it so the same finding isn't re-raised. Unvalidated tickets erode trust with the teams doing the fixing. |
| What do you do when a new critical CVE drops (like Log4Shell)? | Research the advisory to learn affected products and versions, query the asset inventory to find what's exposed, raise priority tickets to those owners immediately, track remediation daily, and report status to leadership until it's closed. |
| How would you measure if the program is improving? | Trend MTTR down, SLA compliance up, overdue count down, and KEV-open count toward zero. I built those exact metrics into the dashboard. |
| CVSS 10 vs CVSS 7 — always patch the 10 first? | No. If the 7 is actively exploited (KEV) and on a critical asset and the 10 isn't exploitable in our environment, the 7 wins. Context and exploitation beat the raw number. |

## Connect it to your background (your edge)

You're a Healthcare Informatics Analyst who builds Power BI dashboards and automated reporting on regulated (HIPAA) data. Say that directly: "I already build compliance reporting and dashboards on regulated healthcare data, so SLA tracking, audit evidence, and translating technical findings for non-technical stakeholders is my day job. This project applies those same skills to vulnerability data." That reframes your experience as directly relevant, not a career switch from zero.

## One honest line if asked about hands-on scanner experience

"I haven't run Qualys or Tenable in production yet, so I built this tool against scanner-style exports to learn the full workflow end to end — prioritization, SLAs, ticketing, and reporting. The platform is the data source; the analysis and the risk decisions are the part I wanted to own, and that's what this demonstrates." Then mention you're working toward CompTIA Security+ or CySA+ (the certs the JD lists) if that's true.
