#!/usr/bin/env python3
"""
Parse Trivy JSON report and simulate ticket creation with SLA tracking.
This script demonstrates DevSecOps best practices with SLA-based remediation.
"""

import json
import os
import sys
from datetime import datetime, timedelta

# SLA Configuration (in days)
SLA_CONFIG = {
    "CRITICAL": 1,
    "HIGH": 7,
    "MEDIUM": 30,
    "LOW": 90
}

def calculate_due_date(severity):
    """Calculate SLA due date based on severity level"""
    sla_days = SLA_CONFIG.get(severity, 90)
    due_date = datetime.now() + timedelta(days=sla_days)
    return due_date.strftime("%Y-%m-%d")

def parse_report():
    """Parse Trivy JSON report and simulate ticket creation"""
    report_file = "trivy-report.json"
    
    if not os.path.exists(report_file):
        print(f"⚠️  Report file '{report_file}' not found. Trivy scan may have skipped or failed.")
        print(f"    This is expected if there are no vulnerabilities at specified severity levels.")
        return False
    
    try:
        with open(report_file, 'r') as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing JSON report: {e}")
        return False
    
    # Extract vulnerabilities
    vulnerabilities = {}
    for result in report.get("Results", []):
        artifact_type = result.get("Type", "Unknown")
        
        # Collect Misconfigurations
        for misconfig in result.get("Misconfigurations", []):
            severity = misconfig.get("Severity", "UNKNOWN")
            vulnerabilities.setdefault(severity, []).append({
                "type": "Misconfiguration",
                "title": misconfig.get("Title", "Unknown"),
                "id": misconfig.get("ID", "N/A"),
                "description": misconfig.get("Description", "N/A")[:100]
            })
        
        # Collect Vulnerabilities
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN")
            vulnerabilities.setdefault(severity, []).append({
                "type": "Vulnerability",
                "title": vuln.get("Title", "Unknown"),
                "id": vuln.get("VulnerabilityID", "N/A"),
                "description": vuln.get("Description", "N/A")[:100]
            })
    
    # Display Summary
    print("\n" + "=" * 70)
    print("🔍 TRIVY VULNERABILITY REPORT - DEVSECOPS DEMO")
    print("=" * 70)
    print(f"📅 Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    total_vulns = sum(len(v) for v in vulnerabilities.values())
    
    if total_vulns == 0:
        print("✅ NO VULNERABILITIES FOUND - Great job!")
        print("=" * 70 + "\n")
        return True
    
    print(f"📊 Total Issues Found: {total_vulns}\n")
    
    # Create simulated tickets grouped by severity
    tickets_created = []
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    for severity in severity_order:
        if severity not in vulnerabilities:
            continue
        
        issues = vulnerabilities[severity]
        sla_date = calculate_due_date(severity)
        sla_days = SLA_CONFIG.get(severity, 90)
        
        print(f"[{severity}] - SLA: {sla_days} days (Due: {sla_date})")
        print("-" * 70)
        
        for i, issue in enumerate(issues[:5], 1):  # Show top 5 per severity
            ticket_id = f"SEC-{severity[0]}-{hash(issue['id']) % 10000:04d}"
            print(f"  🎫 Ticket {ticket_id}: {issue['title'][:50]}")
            print(f"     Type: {issue['type']} | ID: {issue['id']}")
            print(f"     Due: {sla_date}\n")
            
            tickets_created.append({
                "ticket_id": ticket_id,
                "severity": severity,
                "title": issue['title'],
                "due_date": sla_date
            })
        
        remaining = len(issues) - 5
        if remaining > 0:
            print(f"  ... and {remaining} more {severity} issues\n")
    
    # Save ticket metadata for CI/CD integration
    ticket_report = {
        "scan_date": datetime.now().isoformat(),
        "total_issues": total_vulns,
        "severity_breakdown": {sev: len(vulns) for sev, vulns in vulnerabilities.items()},
        "tickets": tickets_created
    }
    
    with open("ticket-report.json", "w") as f:
        json.dump(ticket_report, f, indent=2)
    
    print("=" * 70)
    print(f"✅ Tickets created and saved to 'ticket-report.json'")
    print(f"📌 Total Tickets: {len(tickets_created)}")
    print("=" * 70 + "\n")
    
    # Return exit code based on critical vulnerabilities
    critical_count = len(vulnerabilities.get("CRITICAL", []))
    if critical_count > 0:
        print(f"🚨 ALERT: {critical_count} CRITICAL vulnerabilities found!")
        print(f"   SLA: Must fix within 24 hours\n")
        return False  # Exit with failure
    
    return True

if __name__ == "__main__":
    success = parse_report()
    sys.exit(0 if success else 1)
