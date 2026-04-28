# Workflow Diagrams

## Detection Rule Development Lifecycle

```mermaid
flowchart TD
    A[Threat Research] --> B[Hypothesis Formation\nATT&CK Technique ID]
    B --> C[Query Development\nKQL / Wazuh XML]
    C --> D[Sample Log Testing\nvalidate against /logs]
    D --> E[Threshold Tuning\nadjust frequency, timeframe]
    E --> F[Documentation\ntriage steps, known limitations]
    F --> G[Deployment]

    classDef blue fill:#d4eaf7,stroke:#5a9fd4,color:#1a3a5c
    class A,B,C,D,E,F,G blue
```

---

## Incident Triage Workflow

```mermaid
flowchart TD
    A[Alert Fires] --> B[Severity Assessment\nauto-assigned by rule]
    B --> C[Initial Enrichment]
    C --> C1[geoip-lookup.ps1\nlocation context]
    C --> C2[reputation-check.py\nthreat intel]
    C --> C3[hash-lookup.py\nfile reputation]
    C1 & C2 & C3 --> D[Analyst Investigation]
    D --> D1[Review raw logs\nin Log Analytics]
    D --> D2[Check user\nactivity timeline]
    D --> D3[Correlate with\nendpoint telemetry]
    D --> D4[Generate triage worksheet\nvia triage-helper.py]
    D1 & D2 & D3 & D4 --> E[Determination]
    E --> F[True Positive\nContainment + Response]
    E --> G[Benign True Positive\nTune Rule]
    E --> H[False Positive\nSuppress + Document]

    classDef green fill:#d4f0e2,stroke:#5ab882,color:#1a3d2b
    classDef tp fill:#d4f0e2,stroke:#5ab882,color:#1a3d2b
    classDef btp fill:#f5e8d4,stroke:#c89050,color:#3d2a1a
    classDef fp fill:#f5d4d4,stroke:#c85050,color:#7a2020
    class A,B,C,C1,C2,C3,D,D1,D2,D3,D4,E green
    class F tp
    class G btp
    class H fp
```

---

## Enrichment Pipeline

```mermaid
flowchart TD
    A[Raw IP Address] --> B[geoip-lookup.ps1\ncountry, city, ISP, lat/lon]
    B --> C[reputation-check.py\nAbuseIPDB score, VT detections]
    C --> D[Risk Classification\nLOW / MEDIUM / HIGH / CRITICAL]
    D --> E[Analyst Report\nenriched context attached to incident]

    classDef amber fill:#f5e8d4,stroke:#c89050,color:#3d2a1a
    class A,B,C,D,E amber
```

---

## Log Normalization Flow

```mermaid
flowchart TD
    A[Source Logs\nAzure AD, Sysmon, Generic] --> B[log-normalizer.py\nauto-detect source format]
    B --> C[Common Schema Output JSONL\ntimestamp, source, event_type, severity\nuser, src_ip, dst_ip, hostname, action, details]
    C --> D[Cross-Source Correlation\nmatch by user, IP, or timeframe]

    classDef purple fill:#f0d8f5,stroke:#b06ac0,color:#3a1a3d
    class A,B,C,D purple
```

---

## Incident Response Collection Flow

```mermaid
flowchart TD
    A[Suspected Compromise] --> B[log-collector.sh]
    B --> B1[System info\nuname, uptime, disk, memory]
    B --> B2[User info\npasswd, who, last logins]
    B --> B3[Process snapshot\nfull ps tree]
    B --> B4[Network state\nlisteners, connections, routes]
    B --> B5[Log files\nauth, syslog, audit, cron]
    B --> B6[Cron jobs]
    B1 & B2 & B3 & B4 & B5 & B6 --> C[Timestamped Tarball\nir-collect-HOSTNAME-TIMESTAMP.tar.gz]
    C --> D[Offline Analysis]

    classDef indigo fill:#d8d8f5,stroke:#7070c8,color:#1a1a3d
    class A,B,B1,B2,B3,B4,B5,B6,C,D indigo
```
