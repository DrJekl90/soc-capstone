# Assignment 6 - Capstone Summary

## Project Title

SOC Capstone: Cloud Identity Threat Detection

## Objective

Design, build, and validate a detection engineering pipeline targeting identity-based
attacks in Azure AD environments. Deliver production-grade analytic rules, endpoint
detection rules, enrichment automation, and SOC tooling, all mapped to the MITRE
ATT&CK framework.

## Deliverables

### KQL Analytic Rules (10)

| Detection | Technique | Tactic |
|---|---|---|
| Impossible Travel | T1078 | Initial Access |
| MFA Fatigue | T1621 | Credential Access |
| Token Replay | T1550.001 | Defense Evasion |
| OAuth Consent Phishing | T1550.001 | Credential Access |
| Privilege Escalation | T1078.004 | Privilege Escalation |
| Suspicious Inbox Rules | T1114.003 | Collection |
| Password Spray | T1110.003 | Credential Access |
| Mass File Download | T1530 | Collection |
| Service Principal Abuse | T1078.004 | Persistence |
| Conditional Access Bypass | T1556.006 | Defense Evasion |

### Wazuh Custom Rules (5 rule files, 20 individual rules)

| Detection | Technique | Tactic |
|---|---|---|
| SSH Brute Force | T1110.001 | Credential Access |
| Suspicious PowerShell | T1059.001 | Execution |
| Linux Priv Escalation | T1548.003 | Privilege Escalation |
| Web Shell Detection | T1505.003 | Persistence |
| Ransomware Behavior | T1486 | Impact |

### Enrichment Scripts (3)

- geoip-lookup.ps1 - IP geolocation resolution
- reputation-check.py - multi-source threat intelligence lookup
- log-normalizer.py - cross-format log normalization

### Automation Tools (4)

- ioc-extractor.py - indicator extraction from raw text and reports
- hash-lookup.py - file hash reputation checking via VirusTotal
- triage-helper.py - automated triage worksheet generation
- sigma-to-kql.py - Sigma rule conversion to KQL for Sentinel

### Hardening and IR Scripts (5)

- ad-security-audit.ps1 - Active Directory security snapshot
- firewall-audit.ps1 - Windows firewall rule risk assessment
- linux-hardening-check.sh - Linux security configuration audit
- proc-monitor.sh - suspicious process detection snapshot
- log-collector.sh - incident response evidence collection

### Sample Logs (5)

Realistic, non-PII sample logs for Azure AD sign-ins, Sysmon events, MFA fatigue
sequences, token replay scenarios, and OAuth consent phishing campaigns.

## Methodology

1. Conducted threat research to identify prevalent identity attack vectors
2. Mapped each attack to a specific MITRE ATT&CK technique and tactic
3. Developed detection queries in KQL and Wazuh XML rule format
4. Generated realistic sample logs to validate each detection
5. Built enrichment and automation scripts to support analyst triage workflows
6. Created hardening and IR tools for proactive defense and response
7. Documented architecture, workflows, and triage procedures

## Key Findings

- MFA fatigue attacks leave a clear signal in Azure AD sign-in logs: clusters of
  MFA failure codes (50074, 50076, 500121) followed by a success within minutes.
- Token replay is detectable by correlating the same CorrelationId across different
  IPs and device fingerprints. Stolen tokens rarely match the original session context.
- OAuth consent phishing targets non-admin users because admin consent is harder to
  social-engineer. Monitoring AuditLogs for consent events with sensitive scopes from
  non-admin principals catches most campaigns.
- Password spray attacks are distinguishable from brute force by checking the ratio
  of targeted accounts to attempts per account. Sprays hit many accounts with few
  attempts each, while brute force hammers one account with many passwords.

## Tools Used

Microsoft Sentinel, Wazuh, KQL, Python 3, PowerShell 7, Bash, Azure AD, Sysmon,
MITRE ATT&CK Framework

## Author

Joseph Alsudani
