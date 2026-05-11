import json
import os
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

            vulnerabilities.append(vulnerability)

    return vulnerabilities


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