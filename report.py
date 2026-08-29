"""
report.py
---------
Turns the enriched host/service/CVE data into three output formats:
a console summary, a JSON file (machine-readable), and a styled HTML
report (portfolio-friendly).
"""

import json
from datetime import datetime, timezone

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

SEVERITY_COLORS = {
    "CRITICAL": "#8b0000",
    "HIGH": "#d9534f",
    "MEDIUM": "#f0ad4e",
    "LOW": "#5bc0de",
    "UNKNOWN": "#888888",
}

ANSI_COLORS = {
    "CRITICAL": "\033[1;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "UNKNOWN": "\033[1;37m",
    "RESET": "\033[0m",
}


def build_report_data(hosts):
    """Wrap the scanned/enriched host data with a summary + timestamp."""
    summary = {sev: 0 for sev in SEVERITY_ORDER}
    total_cves = 0
    flagged_services = 0

    for host in hosts:
        for svc in host["services"]:
            cves = svc.get("cves", [])
            if cves:
                flagged_services += 1
            for cve in cves:
                sev = (cve.get("severity") or "UNKNOWN").upper()
                if sev not in summary:
                    sev = "UNKNOWN"
                summary[sev] += 1
                total_cves += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
        "summary": {
            "by_severity": summary,
            "total_cves": total_cves,
            "flagged_services": flagged_services,
        },
    }


def print_console_report(report_data):
    print("\n" + "=" * 70)
    print(" VULNERABILITY SCAN REPORT")
    print("=" * 70)
    print(f" Generated: {report_data['generated_at']}")

    summary = report_data["summary"]
    print(f" Services flagged: {summary['flagged_services']}   "
          f"Total CVEs matched: {summary['total_cves']}")
    sev_line = "  ".join(f"{sev}: {summary['by_severity'][sev]}" for sev in SEVERITY_ORDER)
    print(f" {sev_line}")
    print("=" * 70)

    for host in report_data["hosts"]:
        label = f"{host['ip']}" + (f" ({host['hostname']})" if host["hostname"] else "")
        print(f"\nHost: {label}")

        for svc in host["services"]:
            svc_label = f"  [{svc['port']}/{svc['protocol']}] {svc['service']} — {svc['product']} {svc['version']}".strip()
            print(svc_label)

            cves = svc.get("cves", [])
            if not cves:
                print("      No CVE matches found.")
                continue

            for cve in cves:
                sev = (cve.get("severity") or "UNKNOWN").upper()
                color = ANSI_COLORS.get(sev, "")
                reset = ANSI_COLORS["RESET"]
                score = cve.get("cvss_score", 0.0)
                desc = (cve.get("description") or "")[:100]
                print(f"      {color}[{sev:<8}]{reset} {cve['id']}  CVSS {score}  — {desc}...")

    print("\n" + "=" * 70 + "\n")


def write_json_report(report_data, path):
    with open(path, "w") as f:
        json.dump(report_data, f, indent=2)
    return path


def _severity_badge(sev):
    sev = (sev or "UNKNOWN").upper()
    color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["UNKNOWN"])
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def write_html_report(report_data, path):
    summary = report_data["summary"]
    sev_cards = "".join(
        f'<div class="card"><div class="num">{summary["by_severity"][s]}</div>'
        f'<div class="label" style="color:{SEVERITY_COLORS[s]}">{s}</div></div>'
        for s in SEVERITY_ORDER
    )

    host_blocks = ""
    for host in report_data["hosts"]:
        label = host["ip"] + (f" ({host['hostname']})" if host["hostname"] else "")
        svc_rows = ""
        for svc in host["services"]:
            svc_title = f"{svc['port']}/{svc['protocol']} — {svc['service']} ({svc['product']} {svc['version']})"
            cves = svc.get("cves", [])
            if not cves:
                cve_rows = '<tr><td colspan="4" class="none">No CVE matches found</td></tr>'
            else:
                cve_rows = "".join(
                    f"<tr><td>{_severity_badge(c['severity'])}</td>"
                    f"<td class='cveid'>{c['id']}</td>"
                    f"<td>{c.get('cvss_score', 'N/A')}</td>"
                    f"<td class='desc'>{(c.get('description') or '')[:220]}</td></tr>"
                    for c in cves
                )
            svc_rows += (
                f'<div class="service"><h3>{svc_title}</h3>'
                f'<table><tr><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Description</th></tr>'
                f"{cve_rows}</table></div>"
            )
        host_blocks += f'<div class="host"><h2>Host: {label}</h2>{svc_rows}</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f5f6f8; color:#222; margin:0; padding:2rem; }}
  h1 {{ margin-bottom:0.2rem; }}
  .meta {{ color:#666; margin-bottom:1.5rem; }}
  .summary {{ display:flex; gap:1rem; margin-bottom:2rem; flex-wrap:wrap; }}
  .card {{ background:#fff; border-radius:8px; padding:1rem 1.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.1); text-align:center; min-width:100px; }}
  .card .num {{ font-size:1.8rem; font-weight:700; }}
  .card .label {{ font-size:0.85rem; font-weight:600; letter-spacing:0.05em; }}
  .host {{ background:#fff; border-radius:8px; padding:1.2rem 1.5rem; margin-bottom:1.5rem; box-shadow:0 1px 3px rgba(0,0,0,0.1); }}
  .host h2 {{ margin-top:0; border-bottom:1px solid #eee; padding-bottom:0.5rem; }}
  .service h3 {{ font-size:1rem; margin-bottom:0.4rem; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:1.2rem; font-size:0.9rem; }}
  th, td {{ text-align:left; padding:0.4rem 0.6rem; border-bottom:1px solid #eee; vertical-align:top; }}
  th {{ background:#fafafa; }}
  .cveid {{ font-family:monospace; white-space:nowrap; }}
  .desc {{ color:#444; }}
  .none {{ color:#888; font-style:italic; }}
  .badge {{ color:#fff; padding:0.15rem 0.5rem; border-radius:4px; font-size:0.75rem; font-weight:700; }}
</style>
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
  <div class="meta">Generated: {report_data['generated_at']}</div>
  <div class="summary">
    <div class="card"><div class="num">{summary['flagged_services']}</div><div class="label">SERVICES FLAGGED</div></div>
    <div class="card"><div class="num">{summary['total_cves']}</div><div class="label">TOTAL CVEs</div></div>
    {sev_cards}
  </div>
  {host_blocks}
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    return path
