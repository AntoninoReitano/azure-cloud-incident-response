
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
from datetime import timedelta

# Sort events chronologically
sorted_logs = sorted(
    logs,
    key=lambda log: datetime.fromisoformat(
        log["time"].replace("Z", "+00:00")
    )
)

for log in sorted_logs:
    if log["status"] != "success":
        continue

    login_time = datetime.fromisoformat(
        log["time"].replace("Z", "+00:00")
    )

    window_start = login_time - timedelta(minutes=10)

    recent_failures = [
        event for event in sorted_logs
        if event["user"] == log["user"]
        and event["ip"] == log["ip"]
        and event["status"] == "failure"
        and window_start <= datetime.fromisoformat(
            event["time"].replace("Z", "+00:00")
        ) < login_time
    ]

    if len(recent_failures) >= 5:
        print("\nPOTENTIAL ACCOUNT COMPROMISE")
        print("----------------------------")
        print(f"User: {log['user']}")
        print(f"Source IP: {log['ip']}")
        print(f"Failed attempts: {len(recent_failures)}")
        print("Time window: 10 minutes")
        print("Severity: CRITICAL")
        print("Action: Investigate immediately.")


        # Generate a critical incident report
        incident_id = login_time.strftime("INC-%Y%m%d-%H%M%S")

        report = f"""# Cloud Security Incident Report

## Incident Information
- Incident ID: {incident_id}
- Severity: CRITICAL
- Status: Open - Investigation Required
- Affected Account: {log['user']}
- Source IP: {log['ip']}
- Successful Login: {log['time']}
- Failed Attempts: {len(recent_failures)}
- Detection Window: 10 minutes

## Incident Description
Five or more failed login attempts were followed
by a successful login from the same IP address
within a 10-minute period.

## Evidence
- Authentication failures: {len(recent_failures)}
- Successful authentication: 1
- Source IP: {log['ip']}

## Potential Impact
Possible unauthorized account access.
Actual compromise has not been confirmed.

## Recommended Response
1. Validate the login activity with the account owner.
2. Review MFA and authentication records.
3. Investigate additional suspicious account activity.
4. Revoke active sessions if compromise is confirmed.
5. Reset credentials if necessary.
6. Document findings and resolution.

## Investigation Status
Pending security analyst review.
"""

        report_path = report_folder / f"{incident_id}.md"

        with open(report_path, "w", encoding="utf-8") as file:
            file.write(report)

        print(f"Critical incident report saved: {report_path}")

