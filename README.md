# SOC Capstone - Cloud Identity Threat Detection

![SOC Analyst](https://img.shields.io/badge/SOC-Analyst-2D2D2D?style=flat-square&labelColor=B00020)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-2D2D2D?style=flat-square&labelColor=B00020)
![KQL](https://img.shields.io/badge/KQL-Detection-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Wazuh](https://img.shields.io/badge/Wazuh-HIDS-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Python](https://img.shields.io/badge/Python-Enrichment-2D2D2D?style=flat-square&labelColor=3A3A3A)
![PowerShell](https://img.shields.io/badge/PowerShell-Automation-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Azure](https://img.shields.io/badge/Azure-Cloud-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Bash](https://img.shields.io/badge/Bash-CLI-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Linux](https://img.shields.io/badge/Linux-Endpoint-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Windows](https://img.shields.io/badge/Windows-Endpoint-2D2D2D?style=flat-square&labelColor=3A3A3A)
![Zero Trust](https://img.shields.io/badge/Zero-Trust-2D2D2D?style=flat-square&labelColor=B00020)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-2D2D2D?style=flat-square&labelColor=3A3A3A)
![GitHub](https://img.shields.io/badge/GitHub-Version_Control-2D2D2D?style=flat-square&labelColor=3A3A3A)

---

This project is a practical detection engineering capstone focused on identity-based threats in Azure AD environments. It covers the full lifecycle: threat research, detection rule development, enrichment scripting, SOC automation tooling, sample log generation, and MITRE ATT&CK mapping.

The core deliverable is a set of ten KQL analytic rules built for Microsoft Sentinel, targeting attack patterns that SOC teams deal with regularly - impossible travel, MFA fatigue, token replay, OAuth consent phishing, privilege escalation, suspicious inbox rules, password spraying, mass file download, service principal abuse, and conditional access bypass. Each rule was written to be deployable in a production Sentinel workspace with minimal tuning.

On the endpoint side, five custom Wazuh rule sets cover SSH brute force correlation, suspicious PowerShell execution, Linux privilege escalation chains, web shell detection, and ransomware behavior patterns. Supporting the detection layer is a full automation toolkit: enrichment scripts for GeoIP resolution and IP reputation scoring, an IOC extractor for pulling indicators out of threat reports, a file hash reputation checker, an automated triage worksheet generator, and a lightweight Sigma-to-KQL converter. Additional hardening and incident response scripts round out the project with proactive defense capabilities. Every detection maps to a specific MITRE ATT&CK technique, and every script includes realistic sample logs for validation.

## Tools & Technologies

| Category | Tools |
|---|---|
| SIEM | Microsoft Sentinel, Wazuh |
| Query Language | Kusto Query Language (KQL) |
| Scripting | Python 3, PowerShell 7, Bash |
| Framework | MITRE ATT&CK |
| Cloud Platform | Microsoft Azure, Azure AD |
| Log Sources | Azure AD SigninLogs, AuditLogs, Sysmon |
| Architecture | Zero Trust |

## Repository Structure

```
docs/                  Architecture docs, workflow diagrams, assignment summary
scripts/kql/           Ten KQL analytic rules for Microsoft Sentinel
scripts/wazuh/         Five custom Wazuh detection rule sets
scripts/enrichment/    GeoIP lookup, reputation check, log normalizer
scripts/automation/    IOC extractor, hash lookup, triage helper, Sigma converter,
                       AD security audit, firewall audit
scripts/bash/          Linux hardening checker, process monitor, IR log collector
logs/                  Realistic sample logs for testing detections
research/              Notes and references from threat research phase
```

## Author

**Joseph Alsudani**
SOC Engineer | Detection Engineer | Security Operations

## Future Work

- Integrate SOAR playbook triggers for automated response on high-confidence alerts
- Add Sigma rule equivalents for cross-SIEM portability
- Build a Sentinel workbook for visual triage of identity-based detections
- Expand Wazuh ruleset to cover container escape and cloud API abuse
- Develop automated testing pipeline for detection rule validation
