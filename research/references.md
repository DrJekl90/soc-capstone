# References

## MITRE ATT&CK

- T1078 - Valid Accounts: https://attack.mitre.org/techniques/T1078/
- T1078.004 - Valid Accounts: Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/
- T1110.001 - Brute Force: Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- T1110.003 - Brute Force: Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- T1059.001 - Command and Scripting Interpreter: PowerShell: https://attack.mitre.org/techniques/T1059/001/
- T1114.003 - Email Collection: Email Forwarding Rule: https://attack.mitre.org/techniques/T1114/003/
- T1550.001 - Use Alternate Authentication Material: Application Access Token: https://attack.mitre.org/techniques/T1550/001/
- T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching: https://attack.mitre.org/techniques/T1548/003/
- T1621 - Multi-Factor Authentication Request Generation: https://attack.mitre.org/techniques/T1621/
- T1547.006 - Boot or Logon Autostart Execution: Kernel Modules: https://attack.mitre.org/techniques/T1547/006/
- T1562.001 - Impair Defenses: Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- T1505.003 - Server Software Component: Web Shell: https://attack.mitre.org/techniques/T1505/003/
- T1486 - Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- T1490 - Inhibit System Recovery: https://attack.mitre.org/techniques/T1490/
- T1530 - Data from Cloud Storage Object: https://attack.mitre.org/techniques/T1530/
- T1556.006 - Modify Authentication Process: MFA: https://attack.mitre.org/techniques/T1556/006/

## Microsoft Documentation

- Azure AD Sign-in Logs schema: https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-log-schema
- Azure AD Audit Logs schema: https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities
- KQL reference: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
- Microsoft Sentinel analytic rule types: https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in
- Token protection (Proof of Possession): https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-token-protection
- Conditional Access policies: https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview

## Wazuh Documentation

- Custom rules: https://documentation.wazuh.com/current/user-manual/ruleset/custom.html
- Sysmon integration: https://documentation.wazuh.com/current/proof-of-concept-guide/monitoring-sysmon-events.html
- Rule syntax reference: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

## Incident References

- Uber breach (2022) - MFA fatigue attack: https://blog.cloudflare.com/2022-07-sms-phishing-attack/
- Microsoft token replay research: https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/
- OAuth consent phishing campaigns: https://www.microsoft.com/en-us/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/

## Tools

- AbuseIPDB API: https://docs.abuseipdb.com/
- VirusTotal API: https://docs.virustotal.com/reference/overview
- ip-api.com (GeoIP): https://ip-api.com/docs/api:json
- Sysmon configuration: https://github.com/SwiftOnSecurity/sysmon-config
- Sigma rule format: https://sigmahq.io/docs/guide/getting-started.html
