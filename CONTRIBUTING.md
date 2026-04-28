# Contributing

Contributions that improve detection coverage, fix bugs in enrichment scripts,
or add meaningful documentation are welcome.

## How to Contribute

1. Fork this repository
2. Create a feature branch (`git checkout -b detection/new-rule-name`)
3. Write your changes with clear, minimal comments
4. Test detection rules against the sample logs in `/logs`
5. Map every detection to a MITRE ATT&CK technique
6. Submit a pull request with a description of what you changed and why

## Standards

- KQL rules must include a header comment with the ATT&CK technique ID, tactic,
  and a one-line description of what the rule detects
- Wazuh rules must use rule IDs in the 100100+ range to avoid collisions
- Python scripts must run on Python 3.8+ without exotic dependencies
- PowerShell scripts must run on PowerShell 7+
- No real user data, credentials, or API keys in any file
- Keep comments minimal and meaningful, the code should be readable on its own

## What Not to Submit

- Detection rules without ATT&CK mapping
- Scripts that require paid API access with no free-tier alternative
- Large binary files or compiled artifacts
- Changes to sample logs that introduce PII or real infrastructure data

## Questions

Open an issue or reach out at shalnark90@outlook.com
