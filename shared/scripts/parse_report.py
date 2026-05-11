import json
import os
import requests
from datetime import datetime, timedelta

# ---------------------------------------------------
# Configuration
# ---------------------------------------------------

REPORTS = [
    {
        "name": "Python",
        "path": "shared/reports/python-report.json"
    },
    {
        "name": "Node.js",
        "path": "shared/reports/nodejs-report.json"
    },
    {
        "name": "Java",
        "path": "shared/reports/java-report.json"
    }
]

OUTPUT_FILE = "shared/reports/consolidated-ticket-report.json"

# SLA rules based on severity
SLA_RULES = {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 30,
    "LOW": 90
}

# GitHub configuration
GITHUB_TOKEN = os.getenv("TRIVY_SECRET")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/issues"

# ---------------------------------------------------
# Helper Functions
# ---------------------------------------------------

def calculate_due_date(severity):
    days = SLA_RULES.get(severity.upper(), 30)
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")


def load_report(report_path):
    if not os.path.exists(report_path):
        print(f"[WARNING] Report not found: {report_path}")
        return None

    try:
        with open(report_path, "r") as file:
            return json.load(file)
    except Exception as error:
        print(f"[ERROR] Failed to read {report_path}: {error}")
        return None


def extract_vulnerabilities(report_data, application_name):
    vulnerabilities = []

    if not report_data:
        return vulnerabilities

    results = report_data.get("Results", [])

    for result in results:

        target = result.get("Target", "Unknown Target")

        for vuln in result.get("Vulnerabilities", []):

            vulnerability = {
                "application": application_name,
                "target": target,
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": vuln.get("Severity"),
                "cve_id": vuln.get("VulnerabilityID"),
                "title": vuln.get("Title"),
                "description": vuln.get("Description"),
                "primary_url": vuln.get("PrimaryURL"),
                "sla_due_date": calculate_due_date(
                    vuln.get("Severity", "MEDIUM")
                ),
                "status": "OPEN",

                # Placeholder for future GitHub integration
                "github_issue": {
                    "created": False,
                    "issue_number": None,
                    "issue_url": None
                }
            }

            # PHASE 7: Create GitHub issue automatically
            github_issue = create_github_issue(vulnerability)
            vulnerability["github_issue"] = github_issue

            vulnerabilities.append(vulnerability)

    return vulnerabilities


def create_github_issue(vulnerability):
    """Create a GitHub issue for a vulnerability."""
    if not GITHUB_TOKEN:
        print("[WARNING] GitHub token not found")
        return None

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    title = (
        f"[{vulnerability['severity']}] "
        f"{vulnerability['cve_id']} in "
        f"{vulnerability['package']}"
    )

    body = f"""
## Vulnerability Details

| Field | Value |
|---|---|
| Application | {vulnerability['application']} |
| Severity | {vulnerability['severity']} |
| CVE ID | {vulnerability['cve_id']} |
| Package | {vulnerability['package']} |
| Installed Version | {vulnerability['installed_version']} |
| Fixed Version | {vulnerability['fixed_version']} |
| SLA Due Date | {vulnerability['sla_due_date']} |

## Description

{vulnerability['description']}

## Recommended Action

Upgrade package to fixed version:
{vulnerability['fixed_version']}

## Reference

{vulnerability['primary_url']}
"""

    payload = {
        "title": title,
        "body": body,
        "labels": [
            "security",
            vulnerability["severity"].lower()
        ]
    }

    response = requests.post(
        GITHUB_API_URL,
        headers=headers,
        json=payload
    )

    if response.status_code == 201:
        issue_data = response.json()
        print(f"[INFO] GitHub issue created: {title}")
        return {
            "created": True,
            "issue_number": issue_data["number"],
            "issue_url": issue_data["html_url"]
        }
    else:
        print(
            f"[ERROR] Failed to create issue: "
            f"{response.status_code}"
        )
        return {
            "created": False,
            "issue_number": None,
            "issue_url": None
        }


def generate_html_report(summary):
    """Generate human-readable HTML report."""
    html_content = f"""
    <html>
    <head>
        <title>DevSecOps Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .critical {{ background-color: #ff6b6b; color: white; }}
            .high {{ background-color: #ee5a52; color: white; }}
            .medium {{ background-color: #ffd93d; }}
            .low {{ background-color: #95e1d3; }}
        </style>
    </head>
    <body>

    <h1>DevSecOps Vulnerability Report</h1>
    <p><strong>Generated:</strong> {summary['generated_at']}</p>

    <h2>Summary</h2>
    <p><strong>Total Vulnerabilities:</strong> {summary['total_vulnerabilities']}</p>

    <h2>Severity Breakdown</h2>
    <ul>
        <li><strong>CRITICAL:</strong> {summary['severity_breakdown']['CRITICAL']}</li>
        <li><strong>HIGH:</strong> {summary['severity_breakdown']['HIGH']}</li>
        <li><strong>MEDIUM:</strong> {summary['severity_breakdown']['MEDIUM']}</li>
        <li><strong>LOW:</strong> {summary['severity_breakdown']['LOW']}</li>
    </ul>

    <h2>Applications Scanned</h2>
    <ul>
"""

    for app in summary['applications_scanned']:
        html_content += f"        <li>{app}</li>\n"

    html_content += """    </ul>

    <h2>Vulnerabilities</h2>

    <table border="1" cellpadding="5">
        <tr>
            <th>Application</th>
            <th>Severity</th>
            <th>CVE</th>
            <th>Package</th>
            <th>Installed</th>
            <th>Fixed</th>
            <th>SLA Due Date</th>
        </tr>
    """

    for vuln in summary["tickets"]:
        severity_class = vuln['severity'].lower()
        html_content += f"""
        <tr>
            <td>{vuln['application']}</td>
            <td class="{severity_class}">{vuln['severity']}</td>
            <td>{vuln['cve_id']}</td>
            <td>{vuln['package']}</td>
            <td>{vuln['installed_version']}</td>
            <td>{vuln['fixed_version']}</td>
            <td>{vuln['sla_due_date']}</td>
        </tr>
        """

    html_content += """
    </table>
    </body>
    </html>
    """

    with open(
        "shared/reports/security-report.html",
        "w"
    ) as file:
        file.write(html_content)

    print("[INFO] HTML report generated: shared/reports/security-report.html")


# ---------------------------------------------------
# Main Execution
# ---------------------------------------------------

all_vulnerabilities = []

print("\n===================================================")
print(" DevSecOps Multi-Technology Vulnerability Parser ")
print("===================================================\n")

for report in REPORTS:

    print(f"[INFO] Processing {report['name']} report...")

    report_data = load_report(report["path"])

    vulnerabilities = extract_vulnerabilities(
        report_data,
        report["name"]
    )

    print(f"[INFO] Found {len(vulnerabilities)} vulnerabilities")

    all_vulnerabilities.extend(vulnerabilities)

# ---------------------------------------------------
# Generate Consolidated Summary
# ---------------------------------------------------

summary = {
    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total_vulnerabilities": len(all_vulnerabilities),

    "severity_breakdown": {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    },

    "applications_scanned": [
        "Python",
        "Node.js",
        "Java"
    ],

    "tickets": all_vulnerabilities
}

# Count severity totals
for vuln in all_vulnerabilities:
    severity = vuln.get("severity", "LOW")

    if severity in summary["severity_breakdown"]:
        summary["severity_breakdown"][severity] += 1

# ---------------------------------------------------
# Save Consolidated Report
# ---------------------------------------------------

os.makedirs("shared/reports", exist_ok=True)

with open(OUTPUT_FILE, "w") as outfile:
    json.dump(summary, outfile, indent=4)

# PHASE 9: Generate HTML report automatically
generate_html_report(summary)

# ---------------------------------------------------
# Console Summary Output
# ---------------------------------------------------

print("\n===================================================")
print(" Vulnerability Scan Summary ")
print("===================================================\n")

print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}\n")

print("Severity Breakdown:")
for severity, count in summary["severity_breakdown"].items():
    print(f"  {severity}: {count}")

print("\nApplications Scanned:")
for app in summary["applications_scanned"]:
    print(f"  - {app}")

print(f"\n[INFO] Consolidated ticket report saved:")
print(f"       {OUTPUT_FILE}")

print("\n===================================================")
print(" Ticket Simulation Complete ")
print("===================================================\n")