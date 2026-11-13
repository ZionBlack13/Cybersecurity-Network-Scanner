
from pathlib import Path
from datetime import datetime, timezone
from html import escape


def generate_html_report(hosts, ports, vulnerabilities):
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    rows = ""
    for port in ports:
        rows += (
            "<tr>"
            f"<td>{escape(str(port.get('host', '')))}</td>"
            f"<td>{escape(str(port.get('port', '')))}</td>"
            f"<td>{escape(str(port.get('protocol', '')))}</td>"
            f"<td>{escape(str(port.get('service', '')))}</td>"
            f"<td>{escape(str(port.get('version', '')))}</td>"
            "</tr>"
        )

    findings = ""
    for vuln in vulnerabilities:
        findings += (
            "<div class='finding'>"
            f"<strong>{escape(str(vuln.get('id', '')))}</strong>"
            "<span class='status'>Unverified keyword match</span>"
            f"<p>{escape(str(vuln.get('description', '')))}</p>"
            "</div>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cybersecurity Network Scan Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0b1220;
    color: #e5e7eb;
    padding: 40px;
}}
h1 {{ color: #38bdf8; }}
.summary {{
    display: flex;
    gap: 20px;
    margin: 30px 0;
}}
.card, .finding {{
    background: #1e293b;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 15px;
}}
.card strong {{
    display: block;
    font-size: 32px;
    color: #38bdf8;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    padding: 12px;
    border-bottom: 1px solid #334155;
    text-align: left;
}}
.status {{
    color: #fbbf24;
    margin-left: 15px;
}}
</style>
</head>
<body>
<h1>Cybersecurity Network Scanner</h1>
<p>Security Assessment Report | {timestamp}</p>

<div class="summary">
<div class="card"><strong>{len(hosts)}</strong>Active Hosts</div>
<div class="card"><strong>{len(ports)}</strong>Detected Ports</div>
<div class="card"><strong>{len(vulnerabilities)}</strong>Potential CVE Matches</div>
</div>

<h2>Discovered Services</h2>
<table>
<tr><th>Host</th><th>Port</th><th>Protocol</th>
<th>Service</th><th>Version</th></tr>
{rows}
</table>

<h2>Potential Vulnerability Matches</h2>
<p>These are unverified keyword matches, not confirmed vulnerabilities.</p>
{findings if findings else "<p>No potential matches returned.</p>"}

</body>
</html>"""

    Path("reports").mkdir(exist_ok=True)
    filename = datetime.now(timezone.utc).strftime(
        "security_report_%Y%m%d_%H%M%S.html"
    )
    path = Path("reports") / filename
    path.write_text(html, encoding="utf-8")

    print(f"[+] HTML report saved: {path}")
    return str(path)
