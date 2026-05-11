import json
import os
import shutil
from datetime import datetime

# ---------------------------------------------------
# Report Management Configuration
# ---------------------------------------------------

ARCHIVE_DIR = "shared/reports/archive"
HISTORY_FILE = "shared/reports/history.json"
AUDIT_LOG_FILE = "shared/reports/audit.log"
REPORTS_DIR = "shared/reports"


# ---------------------------------------------------
# Archive Management Functions
# ---------------------------------------------------

def create_archive_directory():
    """Create archive directory structure."""
    os.makedirs(ARCHIVE_DIR, exist_ok=True)


def get_timestamp():
    """Return current timestamp in YYYYMMDD_HHMMSS format."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def archive_scan_reports():
    """Archive current scan reports with timestamp."""
    timestamp = get_timestamp()
    archive_path = os.path.join(ARCHIVE_DIR, timestamp)
    os.makedirs(archive_path, exist_ok=True)

    files_to_archive = [
        "consolidated-ticket-report.json",
        "security-report.html",
        "python-report.json",
        "nodejs-report.json",
        "java-report.json",
        "python-results.sarif",
        "nodejs-results.sarif",
        "java-results.sarif"
    ]

    for file_name in files_to_archive:
        source_path = os.path.join(REPORTS_DIR, file_name)
        if os.path.exists(source_path):
            dest_path = os.path.join(archive_path, file_name)
            shutil.copy2(source_path, dest_path)
            log_audit(f"ARCHIVED: {file_name} -> {archive_path}")

    return archive_path


# ---------------------------------------------------
# Scan History Management
# ---------------------------------------------------

def initialize_history():
    """Initialize scan history JSON database if not exists."""
    if not os.path.exists(HISTORY_FILE):
        history = {
            "scans": [],
            "total_scans": 0
        }
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
        log_audit("INIT: Scan history database created")


def add_scan_to_history(summary):
    """Add current scan to history database."""
    initialize_history()

    with open(HISTORY_FILE, "r") as f:
        history = json.load(f)

    timestamp = get_timestamp()
    scan_record = {
        "timestamp": timestamp,
        "generated_at": summary["generated_at"],
        "total_vulnerabilities": summary["total_vulnerabilities"],
        "severity_breakdown": summary["severity_breakdown"],
        "applications_scanned": summary["applications_scanned"],
        "archive_path": f"{ARCHIVE_DIR}/{timestamp}",
        "status": "COMPLETED"
    }

    history["scans"].append(scan_record)
    history["total_scans"] = len(history["scans"])

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

    log_audit(
        f"HISTORY: Scan recorded - "
        f"Total Vulns: {summary['total_vulnerabilities']}, "
        f"CRITICAL: {summary['severity_breakdown']['CRITICAL']}, "
        f"HIGH: {summary['severity_breakdown']['HIGH']}"
    )


def get_scan_history():
    """Retrieve complete scan history."""
    initialize_history()

    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)

    return {"scans": [], "total_scans": 0}


def get_scan_trends():
    """Calculate vulnerability trends from scan history."""
    history = get_scan_history()

    if len(history["scans"]) < 2:
        return None

    latest = history["scans"][-1]
    previous = history["scans"][-2]

    trends = {
        "latest_scan": latest,
        "previous_scan": previous,
        "vulnerability_change": latest["total_vulnerabilities"] - previous["total_vulnerabilities"],
        "critical_change": latest["severity_breakdown"]["CRITICAL"] - previous["severity_breakdown"]["CRITICAL"],
        "high_change": latest["severity_breakdown"]["HIGH"] - previous["severity_breakdown"]["HIGH"]
    }

    return trends


# ---------------------------------------------------
# Audit Logging Functions
# ---------------------------------------------------

def log_audit(message):
    """Write message to audit log with timestamp."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"

    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(log_entry)

    print(f"[AUDIT] {message}")


def get_audit_log(limit=50):
    """Retrieve last N lines of audit log."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return []

    with open(AUDIT_LOG_FILE, "r") as f:
        lines = f.readlines()

    return lines[-limit:]


# ---------------------------------------------------
# Report Retrieval Functions
# ---------------------------------------------------

def get_report_by_date(date_str):
    """Retrieve report archive by date (YYYYMMDD format)."""
    matching_dirs = []

    if not os.path.exists(ARCHIVE_DIR):
        return None

    for dir_name in os.listdir(ARCHIVE_DIR):
        if dir_name.startswith(date_str):
            archive_path = os.path.join(ARCHIVE_DIR, dir_name)
            matching_dirs.append({
                "timestamp": dir_name,
                "path": archive_path,
                "files": os.listdir(archive_path)
            })

    return matching_dirs if matching_dirs else None


def get_latest_report():
    """Retrieve latest scan report archive."""
    if not os.path.exists(ARCHIVE_DIR):
        return None

    archives = sorted(os.listdir(ARCHIVE_DIR), reverse=True)

    if not archives:
        return None

    latest = archives[0]
    latest_path = os.path.join(ARCHIVE_DIR, latest)

    return {
        "timestamp": latest,
        "path": latest_path,
        "files": os.listdir(latest_path)
    }


def get_report_metadata(archive_path):
    """Extract metadata from archived report."""
    consolidated_file = os.path.join(archive_path, "consolidated-ticket-report.json")

    if not os.path.exists(consolidated_file):
        return None

    with open(consolidated_file, "r") as f:
        report = json.load(f)

    return {
        "generated_at": report.get("generated_at"),
        "total_vulnerabilities": report.get("total_vulnerabilities"),
        "severity_breakdown": report.get("severity_breakdown"),
        "applications_scanned": report.get("applications_scanned")
    }


# ---------------------------------------------------
# Report Summary Function
# ---------------------------------------------------

def generate_management_summary():
    """Generate comprehensive report management summary."""
    history = get_scan_history()
    audit_lines = get_audit_log(10)

    summary = {
        "total_scans_recorded": history["total_scans"],
        "latest_scan": history["scans"][-1] if history["scans"] else None,
        "scan_trends": get_scan_trends(),
        "recent_audit_logs": [line.strip() for line in audit_lines],
        "archive_location": ARCHIVE_DIR
    }

    return summary


# ---------------------------------------------------
# Cleanup Functions
# ---------------------------------------------------

def cleanup_old_archives(days=90):
    """Remove archived reports older than N days."""
    from datetime import timedelta

    if not os.path.exists(ARCHIVE_DIR):
        return

    cutoff_date = datetime.now() - timedelta(days=days)

    for dir_name in os.listdir(ARCHIVE_DIR):
        dir_path = os.path.join(ARCHIVE_DIR, dir_name)

        if not os.path.isdir(dir_path):
            continue

        try:
            dir_datetime = datetime.strptime(dir_name, "%Y%m%d_%H%M%S")

            if dir_datetime < cutoff_date:
                shutil.rmtree(dir_path)
                log_audit(f"CLEANUP: Removed archive older than {days} days: {dir_name}")

        except ValueError:
            continue


# ---------------------------------------------------
# Initialize Report Management
# ---------------------------------------------------

def initialize_report_management():
    """Initialize all report management structures."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    initialize_history()
    log_audit("INIT: Report management system initialized")
