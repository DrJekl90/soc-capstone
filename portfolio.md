# SOC Engineering Portfolio - Joseph Alsudani

## About

Security operations engineer focused on building detection logic that works in production.
I design analytic rules for Microsoft Sentinel, write custom Wazuh detection rules, and build
enrichment scripts that reduce analyst triage time. My work is grounded in the MITRE ATT&CK
framework and built around real-world SOC workflows.

## Core Competencies

- Threat detection and hunting across cloud and endpoint telemetry
- SIEM engineering in Microsoft Sentinel and Wazuh
- KQL query development for scheduled and NRT analytic rules
- Log analysis, normalization, and enrichment automation
- Incident response workflows aligned to NIST 800-61
- MITRE ATT&CK mapping and coverage analysis
- Zero Trust architecture principles

## Featured Project: SOC Capstone

**Cloud Identity Threat Detection**

End-to-end detection engineering project targeting identity-based attacks in Azure AD.
Six KQL analytic rules, three Wazuh custom rules, and three enrichment scripts, all
mapped to ATT&CK with realistic sample logs for validation.

Detections built:
- Impossible travel (T1078)
- MFA fatigue / push bombing (T1621)
- Token replay (T1550.001)
- OAuth consent phishing (T1550.001)
- Privilege escalation via role assignment (T1078.004)
- Suspicious inbox rule creation (T1114.003)
- SSH brute force correlation (T1110.001)
- Suspicious PowerShell execution (T1059.001)
- Linux privilege escalation chain (T1548.003)

## Engineering Philosophy

**Detection-First Thinking** - Every rule starts with a threat hypothesis mapped to ATT&CK.
If it does not have a clear detection use case, it does not ship.

**Operational Realism** - Detection logic is only useful if it works at scale with acceptable
false positive rates. I tune before I deploy.

**Documentation as Deliverable** - A detection rule without documentation is technical debt.
Every rule ships with context, triage steps, and known limitations.

## Contact

- GitHub: github.com/joseph-alsudani
- LinkedIn: linkedin.com/in/joseph-alsudani
- Email: joseph.alsudani@protonmail.com
