"""
Builds a self-contained HTML dashboard (inline CSS + hand-drawn SVG charts, no
external libraries, works offline and in both light and dark mode). This mirrors
the kind of reporting a vulnerability-management program shows stakeholders.
"""
import html

PALETTE = {"P1": "#c0392b", "P2": "#e67e22", "P3": "#f1c40f", "P4": "#3498db"}
SEV_COLOR = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f1c40f", "Low": "#3498db"}


def _bar_chart(data, colors, max_w=360):
    """Horizontal bars: data is list of (label, value)."""
    if not data:
        return "<p>No data.</p>"
    mx = max(v for _, v in data) or 1
    rows = []
    for label, v in data:
        w = int((v / mx) * max_w)
        c = colors.get(label, "#667")
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{html.escape(str(label))}</span>'
            f'<span class="bar"><span class="bar-fill" style="width:{w}px;background:{c}"></span></span>'
            f'<span class="bar-val">{v}</span></div>'
        )
    return "".join(rows)


def _stat(label, value, sub="", accent=""):
    style = f'style="color:{accent}"' if accent else ""
    sub = f'<div class="stat-sub">{html.escape(sub)}</div>' if sub else ""
    return (f'<div class="stat"><div class="stat-val" {style}>{value}</div>'
            f'<div class="stat-label">{html.escape(label)}</div>{sub}</div>')


def render_dashboard(m, rows, assets, path, today):
    p = m["by_priority"]
    prio_bars = _bar_chart([(t, p.get(t, 0)) for t in ["P1", "P2", "P3", "P4"]], PALETTE)
    sev_bars = _bar_chart(
        [(s, m["by_severity"].get(s, 0)) for s in ["Critical", "High", "Medium", "Low"]], SEV_COLOR)
    team_data = sorted(m["by_team"].items(), key=lambda kv: kv[1]["open"], reverse=True)
    team_bars = _bar_chart([(t, d["open"]) for t, d in team_data], {})

    # top findings table
    top = sorted([r for r in rows if r["status"] in ("Open", "In Progress")],
                 key=lambda r: r["risk_score"], reverse=True)[:15]
    trows = []
    for r in top:
        kev = '<span class="kev">KEV</span>' if r["kev"] == "Yes" else ""
        sla_cls = "overdue" if r["sla_state"] == "Overdue" else "ok"
        trows.append(
            f"<tr><td><b>{r['risk_score']}</b></td>"
            f'<td><span class="pill" style="background:{PALETTE[r["priority"]]}">{r["priority"]}</span></td>'
            f"<td>{html.escape(r['hostname'])}</td>"
            f"<td>{r['cve']} {kev}</td>"
            f"<td>{html.escape(r['vuln_name'])}</td>"
            f"<td>{r['cvss_base']}</td>"
            f"<td>{r['due_date']}</td>"
            f'<td class="{sla_cls}">{r["sla_state"]}</td></tr>'
        )

    # top CVEs
    crows = []
    for cve, d in m["top_cves"]:
        crows.append(f"<tr><td>{cve}</td><td>{html.escape(d['name'])}</td>"
                     f"<td>{d['count']}</td><td>{d['score']}</td></tr>")

    sla_color = "#27ae60" if m["sla_compliance"] >= 80 else ("#e67e22" if m["sla_compliance"] >= 50 else "#c0392b")

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability Management Dashboard</title>
<style>
  :root {{ --bg:#f5f6f8; --card:#fff; --ink:#1a1f2b; --muted:#667085; --line:#e4e7ec; }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{ --bg:#0f1420; --card:#171d2b; --ink:#e7ebf3; --muted:#93a0b5; --line:#263041; }}
  }}
  :root[data-theme="dark"] {{ --bg:#0f1420; --card:#171d2b; --ink:#e7ebf3; --muted:#93a0b5; --line:#263041; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; line-height:1.45; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:24px 16px 60px; }}
  header h1 {{ margin:0 0 4px; font-size:24px; }}
  header .sub {{ color:var(--muted); font-size:14px; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:20px 0; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px; }}
  .stat-val {{ font-size:30px; font-weight:700; }}
  .stat-label {{ color:var(--muted); font-size:13px; margin-top:2px; }}
  .stat-sub {{ color:var(--muted); font-size:12px; margin-top:4px; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  @media (max-width:760px) {{ .grid {{ grid-template-columns:1fr; }} }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; margin-bottom:16px; }}
  .card h2 {{ margin:0 0 14px; font-size:15px; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin:7px 0; font-size:13px; }}
  .bar-label {{ width:160px; color:var(--muted); }}
  .bar {{ flex:1; background:var(--line); border-radius:6px; height:16px; overflow:hidden; }}
  .bar-fill {{ display:block; height:100%; border-radius:6px; }}
  .bar-val {{ width:34px; text-align:right; font-variant-numeric:tabular-nums; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-weight:600; }}
  .pill {{ color:#fff; padding:1px 8px; border-radius:20px; font-size:12px; font-weight:600; }}
  .kev {{ background:#7d1d1d; color:#fff; padding:0 6px; border-radius:4px; font-size:10px; font-weight:700; margin-left:4px; }}
  .overdue {{ color:#c0392b; font-weight:700; }}
  .ok {{ color:var(--muted); }}
  .note {{ color:var(--muted); font-size:12px; margin-top:24px; }}
</style></head>
<body><div class="wrap">
  <header>
    <h1>Vulnerability Management Dashboard</h1>
    <div class="sub">CareTrack enterprise &middot; as of {today.strftime('%Y-%m-%d')} &middot; {len(assets)} assets, {m['total']} findings</div>
  </header>

  <div class="stats">
    {_stat("Open findings", m['open'])}
    {_stat("P1 critical-risk", p.get('P1',0), "15-day SLA", PALETTE['P1'])}
    {_stat("Past SLA", m['overdue_count'], "overdue", "#c0392b")}
    {_stat("Actively exploited", m['kev_open_count'], "CISA KEV, still open", "#c0392b")}
    {_stat("SLA compliance", f"{m['sla_compliance']}%", "on closed findings", sla_color)}
    {_stat("MTTR", f"{m['mttr']}d", "mean time to remediate")}
  </div>

  <div class="grid">
    <div class="card"><h2>Open findings by priority</h2>{prio_bars}</div>
    <div class="card"><h2>Open findings by CVSS severity</h2>{sev_bars}</div>
  </div>

  <div class="card"><h2>Open findings by owning team</h2>{team_bars}</div>

  <div class="card"><h2>Top 15 open findings by risk score</h2>
    <div style="overflow-x:auto"><table>
      <tr><th>Risk</th><th>Pri</th><th>Host</th><th>CVE</th><th>Vulnerability</th><th>CVSS</th><th>Due</th><th>SLA</th></tr>
      {''.join(trows)}
    </table></div>
  </div>

  <div class="card"><h2>Most widespread CVEs (open)</h2>
    <table>
      <tr><th>CVE</th><th>Vulnerability</th><th>Affected assets</th><th>Max risk</th></tr>
      {''.join(crows)}
    </table>
  </div>

  <p class="note">Risk score = CVSS severity (50%) + asset business criticality (30%) + active-exploitation / KEV (20%), with a PCI-scope bonus. Known-exploited vulnerabilities are floored at P2. Sample data only; no real patient or cardholder data.</p>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
