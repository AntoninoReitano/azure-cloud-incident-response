
import json
from collections import defaultdict
from pathlib import Path

# Step 1: Locate and load the Azure login logs
log_path = (
    Path(__file__).resolve().parent.parent
    / "sample_logs"
    / "azure_signins.json"
)

with open(log_path, "r") as file:
    logs = json.load(file)

# Step 2: Count failed logins for each user and IP
failed_attempts = defaultdict(int)

for log in logs:
    if log["status"] == "failure":
        key = (log["user"], log["ip"])
        failed_attempts[key] += 1


# Step 3: Detect suspicious activity and create reports
from datetime import datetime, timezone

report_folder = (
    Path(__file__).resolve().parent.parent
    / "incident_reports"
)
report_folder.mkdir(exist_ok=True)

for (user, ip), count in failed_attempts.items():
    if count >= 5:
        print("SECURITY ALERT DETECTED")
        print(f"User: {user}")
        print(f"IP Address: {ip}")
        print(f"Failed Attempts: {count}")
        print("Severity: HIGH")

        # Create incident report
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        report = f"""# Cloud Security Incident Report

## Incident Summary
- Detection Time: {timestamp}
- Affected User: {user}
- Source IP: {ip}
- Failed Login Attempts: {count}
- Severity: HIGH
- Status: Open - Requires Investigation

## Detection
Multiple failed login attempts were detected
from the same IP address targeting one user.

## Potential Threat
Possible brute-force authentication attack.

## Recommended Response
1. Review authentication logs.
2. Investigate successful logins.
3. Check for unusual account activity.
4. Verify MFA is enabled.
5. Escalate if compromise is suspected.

## Investigation Status
Pending analyst review.
"""

        report_path = (
            report_folder / "incident_report.md"
        )

        with open(report_path, "w") as file:
            file.write(report)

        print(f"Incident report saved: {report_path}")


# Step 4: Detect successful logins after repeated failures
for log in logs:
    if log["status"] == "success":
        user = log["user"]
        ip = log["ip"]

        key = (user, ip)

        if failed_attempts[key] >= 5:
            print("\nPOTENTIAL ACCOUNT COMPROMISE")
            print("----------------------------")
            print(f"User: {user}")
            print(f"Source IP: {ip}")
            print("Severity: CRITICAL")
            print("Reason: Successful login associated")
            print("with multiple failed attempts.")
            print("Action: Investigate immediately.")

