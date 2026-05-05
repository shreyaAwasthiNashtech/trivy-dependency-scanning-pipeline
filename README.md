# Vulnerable Python App - Trivy Security Scanning Demo

## What is This Project?

This project demonstrates how to automatically detect security issues in a Python application using a dependency scanning tool. It shows how vulnerabilities in third-party libraries can be identified early during development and how teams can enforce security checks as part of their build process.


## Problem Statement

Applications depend on third-party libraries, which may contain known security vulnerabilities (CVEs). If these are not identified early, they can expose systems to risks such as data breaches or unauthorised access.

This project provides an automated approach to:

- Detect vulnerabilities during development
- Prevent insecure code from progressing
- Track and prioritise fixes

## Project Overview

A Python application with intentionally outdated dependencies is created and scanned using a security tool.

The pipeline:

- Scans dependencies for vulnerabilities
- Filters critical issues
- Fails builds when necessary
- Generates reports
- Simulates ticket creation with SLA tracking

## Project Structure
vulnerable-python-app/
│
├── app.py
├── requirements.txt
├── Dockerfile
├── parse_report.py
├── .trivyignore
├── scan-output/
└── .github/workflows/
    └── security.yml

## How the Pipeline Works
Code Push
   ↓
CI Pipeline Triggered
   ↓
Docker Image Build
   ↓
Trivy Scan
   ↓
Critical/High Vulnerabilities Detected
   ↓
Fail Build (if applicable)
   ↓
Generate JSON Report
   ↓
Parse Report
   ↓
Simulate Ticket Creation
   ↓
Assign SLA Deadlines


## Key Functionalities
**Dependency Scanning**

Scans application dependencies and system packages for known vulnerabilities.

**Severity Filtering**

Focuses on **Critical** and **High** vulnerabilities to reduce noise.

**Build Failure Enforcement**

Stops the pipeline if critical vulnerabilities are found.

**Report Generation**

Outputs scan results in JSON format for further processing.

**Ticket Simulation**

Creates structured outputs representing security tickets.

**SLA Tracking**

Assigns deadlines based on severity:

- Critical → 2 days
- High → 5 days

## Failure Scenarios Demonstrated

This project includes controlled failure cases:

- Dependency conflicts (build failure)
- Vulnerable dependencies (security failure)
- Docker misconfigurations
- Policy-based enforcement failures

## Running the Project Locally
**Build Docker Image**
docker build -t vulnerable-app .

**Run Vulnerability Scan**
docker run --rm aquasec/trivy image vulnerable-app

**Generate JSON Report**
docker run --rm aquasec/trivy image \
  --format json \
  -o /app/result.json \
  vulnerable-app

## CI/CD Integration

A GitHub Actions workflow automates:

- Docker image build
- Vulnerability scanning
- Report generation
- Ticket simulation

The pipeline runs automatically on every code push.

## Why This Approach Is Important
- Security issues are detected early
- Developers get immediate feedback
- Risky code is blocked automatically
- Teams can prioritise fixes based on severity
- Encourages secure coding practices


## What I Learned
- How dependency vulnerabilities work
- How to use Trivy for scanning
- How CI/CD pipelines enforce security
- How to handle dependency conflicts
- How to automate reporting and tracking
- How SLA helps in managing security issues

## Future Improvements
- Integrate with a real ticketing system (e.g., Jira)
- Add email or Slack alerts (Notification System)
- Create a dashboard for vulnerability tracking
- Extend support for multiple languages/projects
- Add automated dependency updates

## Further Reading

- **Trivy Documentation**: https://aquasecurity.github.io/trivy/
- **CVE Database**: https://cve.mitre.org/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

## Summary

This project shows how security can be built directly into the development process. Instead of reacting to problems later, vulnerabilities are detected and handled early.

It provides a practical example of how modern teams can ensure safer and more reliable software delivery.

By understanding this project, we're learning how enterprise teams prevent security breaches before they happen.

