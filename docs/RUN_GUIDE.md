# VulnManager - fast setup (under 1 hour, before your interview)

Everything is written and tested. Run it, read it, push it, learn it.

## 1. Install (10 min)
- [ ] Python 3 from python.org (TICK "Add python.exe to PATH" on the first screen).
- [ ] Git for Windows (git-scm.com) and VS Code (code.visualstudio.com).

## 2. Run it (10 min)
- [ ] Unzip to C:\Projects\vulnmanager and open the folder in VS Code.
- [ ] Terminal menu -> New Terminal, then:
      python vm.py
- [ ] Open output\dashboard.html in your browser. Open output\report.md too.
- [ ] Show it is tested:
      python -m pytest -q

## 3. Understand it (30 min) - the part that wins the interview
Read these and be able to explain each in one sentence:
- [ ] vmtool\prioritize.py  - the risk formula and SLA logic (read the top comment)
- [ ] vmtool\kev.py         - why CISA KEV matters
- [ ] vmtool\metrics.py     - the KPIs
Then open output\prioritized_findings.csv and find:
- the highest risk-score rows (all P1), and WHY they score 100 (CVSS + Critical asset + KEV + PCI)
- a low-CVSS CVE that still became P2 because it is actively exploited (KEV floor)

## 4. Put it on GitHub (15 min)
- [ ] Create a PUBLIC repo "vulnmanager" (no initialize boxes).
- [ ] In the VS Code terminal (replace YOUR-USERNAME):
      git init
      git add .
      git commit -m "VulnManager: risk-based vulnerability management with SLA tracking and dashboard"
      git branch -M main
      git remote add origin https://github.com/YOUR-USERNAME/vulnmanager.git
      git push -u origin main
- [ ] Add repo topics: vulnerability-management, cybersecurity, cvss, cisa-kev, python, pci-dss. Pin it.

## 5. Read INTERVIEW_PREP.md
That file has your resume bullet and the questions you will likely be asked, with answers.
