# Roadmap

Planned enhancements for this project, roughly ordered by priority.

## Near Term

- [ ] Add Sigma rule equivalents for all six KQL detections
- [ ] Build a Sentinel workbook with triage views for identity-based alerts
- [ ] Create a SOAR playbook stub for automated MFA fatigue response
- [ ] Add unit tests for enrichment scripts using mocked API responses

## Medium Term

- [ ] Expand Wazuh ruleset: container escape detection, cloud API abuse
- [ ] Write a log ingestion simulator that generates realistic Azure AD traffic
- [ ] Add threat intelligence feed integration to reputation-check.py
- [ ] Build CI pipeline to validate KQL syntax on commit

## Long Term

- [ ] Cross-SIEM detection parity (Splunk SPL, Elastic EQL)
- [ ] Detection-as-Code framework with version-controlled rule deployment
- [ ] Automated false positive benchmarking against baseline log sets
- [ ] Integration with MITRE ATT&CK Navigator for coverage visualization

## Completed

- [x] Six KQL analytic rules for Microsoft Sentinel
- [x] Three custom Wazuh detection rules
- [x] GeoIP, reputation, and normalization enrichment scripts
- [x] Realistic sample logs for all detection categories
- [x] Full MITRE ATT&CK mapping for every detection
