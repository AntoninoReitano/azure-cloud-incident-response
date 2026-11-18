# azure-cloud-incident-response

# Cloud Incident Response & Threat Detection

## Project Overview

A Python-based cloud security monitoring project
that analyzes simulated Azure authentication logs,
detects suspicious login patterns, and automatically
generates incident response reports.

This project demonstrates fundamental security
operations center (SOC) and incident response skills.

## Features

- Detects repeated failed login attempts
- Identifies potential brute-force attacks
- Detects successful logins following multiple failures
- Uses a 10-minute detection window
- Assigns HIGH and CRITICAL alert severity
- Automatically generates Markdown incident reports
- Tests suspicious and normal authentication activity

## Technologies

- Python 3
- JSON
- Git and GitHub
- GitHub Codespaces
- Simulated Azure authentication logs

## Detection Rules

### Rule 1: Repeated Failed Logins

Triggers a HIGH severity alert when five or more
failed authentication attempts originate from
the same IP address against the same account.

### Rule 2: Potential Account Compromise

Triggers a CRITICAL severity alert when five or
more failed login attempts are followed by a
successful login from the same IP address and
account within 10 minutes.

These alerts indicate suspicious patterns,
not confirmed account compromise.

## Running the Project

Run the following command:

```bash
python detection/suspicious_logins.py
```

## Incident Response

When suspicious authentication activity is detected,
the program generates a Markdown incident report.

Reports include:

- Incident ID
- Affected account
- Source IP address
- Detection severity
- Authentication evidence
- Potential impact
- Recommended response actions

## Testing

The project includes two simulated datasets:

- `azure_signins.json`: Suspicious authentication
  activity with repeated failures and a success.
- `normal_signins.json`: Normal authentication
  activity that should not trigger an alert.

## Limitations

- Uses simulated authentication logs, not live Azure data
- Does not currently integrate with Microsoft Sentinel
- HIGH detection counts failures across the full dataset
- CRITICAL detection uses a 10-minute lookback window
- Does not automatically contain or remediate threats

## Future Improvements

- Microsoft Sentinel integration
- KQL detection queries
- Automated unit tests
- Time-windowed brute-force detection
- Incident dashboard
- Automated response playbooks

## Disclaimer

This project is an educational security lab.
All authentication events, accounts, and IP
addresses are fictional.
