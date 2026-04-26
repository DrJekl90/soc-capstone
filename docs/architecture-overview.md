# Architecture Overview

## Summary

This project targets identity-based attack patterns in hybrid Azure AD environments.
The detection architecture spans two layers: cloud-native analytics in Microsoft
Sentinel and host-based detection through Wazuh agents on Linux and Windows endpoints.

## Cloud Layer - Microsoft Sentinel

Sentinel ingests sign-in and audit logs from Azure AD via Diagnostic Settings configured
at the tenant level. Logs land in a Log Analytics workspace with 90-day retention.

Ten analytic rules run against this data:

| Rule | Target Table | Frequency | ATT&CK Technique |
|---|---|---|---|
| Impossible Travel | SigninLogs | 1h | T1078 |
| MFA Fatigue | SigninLogs | 30m | T1621 |
| Token Replay | SigninLogs | 1h | T1550.001 |
| OAuth Consent Phishing | AuditLogs | 6h | T1550.001 |
| Privilege Escalation | AuditLogs | 15m | T1078.004 |
| Suspicious Inbox Rules | OfficeActivity | 6h | T1114.003 |
| Password Spray | SigninLogs | 1h | T1110.003 |
| Mass File Download | OfficeActivity | 1h | T1530 |
| Service Principal Abuse | AADServicePrincipalSignInLogs | 4h | T1078.004 |
| Conditional Access Bypass | SigninLogs | 1h | T1556.006 |

Each rule creates an incident in the Sentinel incident queue. Incidents are triaged
by severity, with enrichment scripts providing GeoIP and reputation data on demand.

## Endpoint Layer - Wazuh

Wazuh agents report to a central Wazuh Manager. Custom rules in the local rules file
extend the default ruleset across five detection categories:

- SSH brute force correlation (rule IDs 100100-100103)
- Suspicious PowerShell execution (rule IDs 100110-100113)
- Linux privilege escalation chains (rule IDs 100120-100124)
- Web shell detection (rule IDs 100130-100133)
- Ransomware behavior detection (rule IDs 100140-100143)

Agents forward Sysmon telemetry on Windows hosts and auditd/ossec data on Linux hosts.

## Enrichment Layer

Three scripts provide on-demand enrichment:

- **geoip-lookup.ps1** - resolves IPs to country, city, and ISP via ip-api.com
- **reputation-check.py** - queries AbuseIPDB and VirusTotal for threat intel
- **log-normalizer.py** - normalizes multi-source logs to a common schema for correlation

## Automation Layer

Four automation tools support SOC workflows beyond detection:

- **ioc-extractor.py** - pulls indicators out of raw text, emails, and threat reports
- **hash-lookup.py** - checks file hashes against VirusTotal during triage
- **triage-helper.py** - generates structured investigation worksheets from incidents
- **sigma-to-kql.py** - converts Sigma detection rules into KQL for Sentinel

## Hardening and Response Tools

- **ad-security-audit.ps1** - snapshots AD for stale accounts, weak passwords, privileged groups
- **firewall-audit.ps1** - flags risky Windows firewall inbound rules
- **linux-hardening-check.sh** - audits SSH config, file permissions, SUID binaries, firewall status
- **proc-monitor.sh** - snapshots processes and flags anything running from writable dirs
- **log-collector.sh** - packages logs and system state into a tarball for IR analysis

## Data Flow

```
Azure AD --> Diagnostic Settings --> Log Analytics --> Sentinel Rules --> Incidents
Endpoints --> Wazuh Agents --> Wazuh Manager --> Custom Rules --> Alerts
Incidents + Alerts --> Analyst Triage --> Enrichment/Automation --> Response
```

## Design Decisions

- **Separate detection layers** - cloud and endpoint detections are independent so a failure
  in one does not blind the other.
- **Conservative thresholds** - all rules start with higher thresholds and shorter lookback
  windows to minimize false positives. Tuning comes after baseline data collection.
- **ATT&CK mapping first** - every detection begins with a technique ID before any code is
  written. This keeps coverage measurable and gaps visible.
