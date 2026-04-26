# Workflow Diagrams

## Detection Rule Development Lifecycle

```
  Threat Research
       |
       v
  Hypothesis Formation
  (ATT&CK Technique ID)
       |
       v
  Query Development
  (KQL / Wazuh XML)
       |
       v
  Sample Log Testing
  (validate against /logs)
       |
       v
  Threshold Tuning
  (adjust frequency, timeframe)
       |
       v
  Documentation
  (triage steps, known limitations)
       |
       v
  Deployment
```

## Incident Triage Workflow

```
  Alert Fires
       |
       v
  Severity Assessment
  (auto-assigned by rule)
       |
       v
  Initial Enrichment
  +--> geoip-lookup.ps1 (location context)
  +--> reputation-check.py (threat intel)
  +--> hash-lookup.py (file reputation)
       |
       v
  Analyst Investigation
  +--> Review raw logs in Log Analytics
  +--> Check user activity timeline
  +--> Correlate with endpoint telemetry
  +--> Generate triage worksheet (triage-helper.py)
       |
       v
  Determination
  +-- True Positive --> Containment + Response
  +-- Benign True Positive --> Tune Rule
  +-- False Positive --> Suppress + Document
```

## Enrichment Pipeline

```
  Raw IP Address
       |
       v
  geoip-lookup.ps1
  (country, city, ISP, lat/lon)
       |
       v
  reputation-check.py
  (AbuseIPDB score, VT detections)
       |
       v
  Risk Classification
  (LOW / MEDIUM / HIGH / CRITICAL)
       |
       v
  Analyst Report
  (enriched context attached to incident)
```

## Log Normalization Flow

```
  Source Logs (Azure AD, Sysmon, Generic)
       |
       v
  log-normalizer.py
  (auto-detect source format)
       |
       v
  Common Schema Output (JSONL)
  {timestamp, source, event_type, severity,
   user, src_ip, dst_ip, hostname, action, details}
       |
       v
  Cross-Source Correlation
  (match by user, IP, or timeframe)
```

## Incident Response Collection Flow

```
  Suspected Compromise
       |
       v
  log-collector.sh (Linux)
  +--> System info (uname, uptime, disk, memory)
  +--> User info (passwd, who, last logins)
  +--> Process snapshot (full ps tree)
  +--> Network state (listeners, connections, routes)
  +--> Log files (auth, syslog, audit, cron)
  +--> Cron jobs
       |
       v
  Timestamped Tarball
  (ir-collect-HOSTNAME-TIMESTAMP.tar.gz)
       |
       v
  Offline Analysis
```
