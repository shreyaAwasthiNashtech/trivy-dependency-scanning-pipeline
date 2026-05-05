import json
from datetime import datetime, timedelta

sla = {
    "CRITICAL": 2,
    "HIGH": 5
}

with open("trivy-report.json") as f:
    data = json.load(f)

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        severity = vuln["Severity"]

        if severity in sla:
            due_date = datetime.now() + timedelta(days=sla[severity])

            print(f"""
--- CREATE TICKET ---
CVE: {vuln['VulnerabilityID']}
Package: {vuln['PkgName']}
Severity: {severity}
Fix Version: {vuln.get('FixedVersion')}
SLA Due Date: {due_date.date()}
---------------------
""")