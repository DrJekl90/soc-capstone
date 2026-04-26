# Architecture Diagram

```
                        +---------------------------+
                        |      AZURE AD TENANT      |
                        |  SigninLogs | AuditLogs    |
                        +-------------+-------------+
                                      |
                            Log Ingestion (DCR)
                                      |
                        +-------------v-------------+
                        |   LOG ANALYTICS WORKSPACE  |
                        |   (Retention: 90 days)     |
                        +-------------+-------------+
                                      |
                    +-----------------+-----------------+
                    |                                   |
        +-----------v-----------+         +-------------v-----------+
        |  MICROSOFT SENTINEL   |         |     ENRICHMENT LAYER    |
        |                       |         |                         |
        |  Analytic Rules:      |         |  geoip-lookup.ps1       |
        |  - Impossible Travel  |         |  reputation-check.py    |
        |  - MFA Fatigue    [*] |         |  log-normalizer.py      |
        |  - Token Replay       |         +-------------+-----------+
        |  - OAuth Consent      |                       |
        |  - Priv Escalation    |              Enriched Context
        |  - Inbox Rules        |                       |
        +-----------+-----------+         +-------------v-----------+
                    |                     |    ANALYST WORKBENCH     |
              Alert Pipeline              |                         |
                    |                     |  Triage | Investigate    |
        +-----------v-----------+         |  Contain | Document     |
        |    INCIDENT QUEUE     |-------->|                         |
        |  (Auto-severity)      |         +-------------------------+
        +-----------------------+

        +---------------------------+
        |     WAZUH MANAGER         |
        |                           |
        |  Custom Rules:            |
        |  - SSH Brute Force    [*] |
        |  - Suspicious PS         |
        |  - Linux Priv Esc        |
        +-------------+------------+
                      |
            Agent Telemetry
                      |
        +-------------v------------+
        |   LINUX / WINDOWS AGENTS  |
        |   Sysmon | auditd | ossec |
        +---------------------------+

  [*] = MITRE ATT&CK Mapped
```

All detections feed into a unified incident queue. Enrichment scripts run on-demand
or via automation rules to add GeoIP context and reputation scores before analyst triage.
