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
```
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
 ```

## How the Pipeline Works
```
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
```

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

- Critical → 2-4 hrs
- High → 24 hrs

## Failure Scenarios Demonstrated

This project includes controlled failure cases:

- Dependency conflicts (build failure)
- Vulnerable dependencies (security failure)
- Docker misconfigurations
- Policy-based enforcement failures

## Trivy Installation
command: docker pull aquasec/trivy

Initially, I scanned the project directory directly:
docker run --rm -v ${PWD}:/app aquasec/trivy fs /app

## Problems Faced During Installation and Setup

Problem 1 — Dependency Conflict During Docker Build

While building the Docker image, I initially used:

requests==2.19.1
urllib3==1.24.1

This caused a build failure because:

requests 2.19.1 requires:

urllib3 < 1.24
but urllib3==1.24.1 was installed
Error Encountered
ResolutionImpossible
Fix Applied

Updated dependency to:

urllib3==1.23

This kept the dependency intentionally vulnerable while also maintaining compatibility.

Problem 2 — Trivy Could Not Find Local Docker Image

When running:

docker run --rm aquasec/trivy image vulnerable-app

Trivy failed with:

unable to find the specified image "vulnerable-app"
Root Cause

Trivy was running inside a container and could not access Docker images stored on the host machine.

Containers are isolated environments.

Fix Applied:

Docker socket mounting was added:

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image vulnerable-app

Why This Worked:
The Docker socket gives the Trivy container access to the host Docker daemon.

This allowed Trivy to:
inspect local images
access image layers
perform vulnerability scanning successfully

Problem 3 — PowerShell Formatting Error

While using multiline commands in PowerShell, the backtick character was incorrectly placed.

This caused:

docker: invalid reference format
Cause

In PowerShell:

backtick (`) is a line continuation character
it must appear at the end of the line

**Fix**
Used either:

proper multiline formatting
or a simpler single-line command

Example:

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image vulnerable-a

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

