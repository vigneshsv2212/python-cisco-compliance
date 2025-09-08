import json, datetime, os
from jinja2 import Template

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Network Compliance Report</title>
  <style>
    body{font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; line-height:1.4}
    .ok{color:#1b5e20}
    .bad{color:#b71c1c}
    table{border-collapse: collapse; width:100%; margin-bottom: 24px}
    th,td{border:1px solid #ddd; padding:8px}
    th{background:#f5f5f5}
    .score{font-weight:700}
    .chip{display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; border:1px solid #ddd; margin-right:6px}
    .sev-high{background:#ffebee}
    .sev-medium{background:#fff8e1}
    .sev-low{background:#e8f5e9}
    h2{margin-top:32px}
  </style>
</head>
<body>
  <h1>Network Compliance Report</h1>
  <p>Generated: {{ ts }}</p>

  <table>
    <tr><th>Device</th><th>Score</th><th>SSH</th><th>Telnet Off</th><th>HTTP Off</th><th>HTTPS Off</th><th>Banner</th><th>Exec Timeout</th><th>VTY ACL</th><th>SNMP Secure</th><th>Remote Logging</th><th>Buffered</th><th>NTP</th></tr>
    {% for name, r in results.items() %}
    <tr>
      <td>{{ name }}</td>
      <td class="score">{{ r.score }}</td>
      {% for k in ["ssh_only","telnet_forbidden","http_server_disabled","https_server_disabled","banner_present","exec_timeout_ok","vty_acl_present","snmp_secure","remote_logging","buffer_logging","ntp_present"] %}
        <td class="{{ 'ok' if r.checks[k] else 'bad' }}">{{ '✔' if r.checks[k] else '✖' }}</td>
      {% endfor %}
    </tr>
    {% endfor %}
  </table>

  {% for name, r in results.items() %}
    {% if r.findings %}
    <h2>{{ name }} — Failed Checks</h2>
    <table>
      <tr><th>Finding</th><th>Severity</th><th>Control</th></tr>
      {% for f in r.findings %}
        {% set sevclass = 'sev-high' if f.severity=='high' else ('sev-medium' if f.severity=='medium' else 'sev-low') %}
        <tr>
          <td>{{ f.title }}</td>
          <td><span class="chip {{ sevclass }}">{{ f.severity|capitalize }}</span></td>
          <td>{{ f.control }}</td>
        </tr>
      {% endfor %}
    </table>
    {% endif %}
  {% endfor %}
</body>
</html>
"""

os.makedirs("data/reports", exist_ok=True)
results = json.load(open("data/reports/compliance.json"))
html = Template(TEMPLATE).render(results=results, ts=str(datetime.datetime.now()))
open("data/reports/report.html","w").write(html)
print("Report written to data/reports/report.html")
