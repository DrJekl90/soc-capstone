"""
Alert Triage Helper
Reads a Sentinel incident export (JSON) and generates a structured
triage worksheet with enrichment recommendations and investigation
steps based on the alert type and ATT&CK technique.
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Maps ATT&CK technique IDs to triage checklists
TRIAGE_PLAYBOOKS = {
    "T1078": {
        "name": "Valid Accounts",
        "priority_questions": [
            "Is this a known user account or a service account?",
            "Has this user traveled recently?",
            "Does the source IP belong to a corporate VPN or known proxy?",
            "Were any Conditional Access policies bypassed?",
        ],
        "enrichment_steps": [
            "Run geoip-lookup.ps1 against the source IP",
            "Run reputation-check.py against the source IP",
            "Check Azure AD sign-in logs for the user in the past 24h",
            "Review the user's device registration status",
        ],
        "escalation_criteria": [
            "Source IP is in a high-risk country with no business justification",
            "Multiple accounts authenticated from the same anomalous IP",
            "User confirms they did not perform the sign-in",
        ],
    },
    "T1621": {
        "name": "MFA Fatigue",
        "priority_questions": [
            "How many MFA prompts did the user receive?",
            "Did the user eventually approve a prompt?",
            "Is the source IP consistent across all prompts?",
            "Has the user reported receiving unexpected push notifications?",
        ],
        "enrichment_steps": [
            "Pull full MFA audit log for the user in the past 1h",
            "Check if the user's password was recently changed",
            "Verify whether number-matching MFA is enabled for this user",
            "Review sign-in risk detections from Identity Protection",
        ],
        "escalation_criteria": [
            "User approved a prompt they did not initiate",
            "Post-approval activity includes mailbox rule changes or app consent",
            "Source IP does not match the user's normal location",
        ],
    },
    "T1110": {
        "name": "Brute Force",
        "priority_questions": [
            "Is the source IP internal or external?",
            "How many distinct accounts were targeted?",
            "Did any of the attempts succeed?",
            "Is the target a privileged account or service account?",
        ],
        "enrichment_steps": [
            "Run reputation-check.py on the source IP",
            "Check firewall logs for the source IP in the past 24h",
            "Review failed authentication events for targeted accounts",
            "Check if the source IP appears in any threat intel feeds",
        ],
        "escalation_criteria": [
            "A targeted account shows a successful login after the brute force window",
            "The source IP has a high abuse score on AbuseIPDB",
            "Multiple accounts were targeted from the same IP in a spray pattern",
        ],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "priority_questions": [
            "What was the full command line?",
            "Was the parent process expected (e.g., explorer.exe vs. svchost)?",
            "Did the process make any network connections?",
            "Were any files created or modified by the process?",
        ],
        "enrichment_steps": [
            "Pull Sysmon Event ID 1 for process details",
            "Check Sysmon Event ID 3 for outbound connections from this process",
            "Check Sysmon Event ID 11 for files created by this process",
            "Run hash-lookup.py on any dropped file hashes",
        ],
        "escalation_criteria": [
            "Process made outbound connections to non-corporate IPs",
            "Command line contains encoded content or download cradles",
            "Parent process chain is unusual for this host",
        ],
    },
}

# Fallback for techniques not in the playbook
DEFAULT_PLAYBOOK = {
    "name": "General Investigation",
    "priority_questions": [
        "What user or system is involved?",
        "What is the source IP and is it expected?",
        "What action was performed?",
        "Is this activity consistent with the user's normal behavior?",
    ],
    "enrichment_steps": [
        "Run geoip-lookup.ps1 on any involved IPs",
        "Run reputation-check.py on external IPs",
        "Review relevant log source for surrounding context",
    ],
    "escalation_criteria": [
        "Activity cannot be explained by normal business operations",
        "Multiple indicators align with known attack patterns",
    ],
}


def get_playbook(technique_id):
    """Match a technique ID to a triage playbook."""
    # Handle sub-techniques by checking the parent
    parent = technique_id.split(".")[0] if "." in technique_id else technique_id
    return TRIAGE_PLAYBOOKS.get(parent, DEFAULT_PLAYBOOK)


def generate_worksheet(incident):
    """Build a triage worksheet for a single incident."""
    title = incident.get("title", "Untitled Incident")
    severity = incident.get("severity", "Unknown")
    techniques = incident.get("techniques", [])
    timestamp = incident.get("createdTimeUtc", "Unknown")
    entities = incident.get("entities", [])

    worksheet = []
    worksheet.append(f"TRIAGE WORKSHEET")
    worksheet.append(f"================")
    worksheet.append(f"Incident:  {title}")
    worksheet.append(f"Severity:  {severity}")
    worksheet.append(f"Created:   {timestamp}")
    worksheet.append(f"Technique: {', '.join(techniques) if techniques else 'Not mapped'}")
    worksheet.append("")

    if entities:
        worksheet.append("ENTITIES:")
        for e in entities:
            etype = e.get("type", "unknown")
            value = e.get("value", "?")
            worksheet.append(f"  [{etype}] {value}")
        worksheet.append("")

    # Pick the first technique for the playbook (most specific)
    tech = techniques[0] if techniques else "GENERIC"
    playbook = get_playbook(tech)
    worksheet.append(f"PLAYBOOK: {playbook['name']}")
    worksheet.append("")

    worksheet.append("PRIORITY QUESTIONS:")
    for i, q in enumerate(playbook["priority_questions"], 1):
        worksheet.append(f"  {i}. [ ] {q}")
    worksheet.append("")

    worksheet.append("ENRICHMENT STEPS:")
    for i, s in enumerate(playbook["enrichment_steps"], 1):
        worksheet.append(f"  {i}. [ ] {s}")
    worksheet.append("")

    worksheet.append("ESCALATION CRITERIA:")
    for c in playbook["escalation_criteria"]:
        worksheet.append(f"  - {c}")
    worksheet.append("")

    worksheet.append("ANALYST NOTES:")
    worksheet.append("  (fill in during investigation)")
    worksheet.append("")
    worksheet.append("DISPOSITION: [ ] True Positive  [ ] Benign TP  [ ] False Positive")
    worksheet.append("")

    return "\n".join(worksheet)


def main():
    parser = argparse.ArgumentParser(description="Generate triage worksheets from Sentinel incidents")
    parser.add_argument("input", help="JSON file with incident data (single object or array)")
    parser.add_argument("-o", "--output", help="Output directory for worksheets", default="./worksheets")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"File not found: {args.input}")
        sys.exit(1)

    with open(input_path) as f:
        data = json.load(f)

    incidents = data if isinstance(data, list) else [data]
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    for i, incident in enumerate(incidents):
        worksheet = generate_worksheet(incident)
        filename = f"triage-{i+1:03d}.txt"
        filepath = output_dir / filename
        filepath.write_text(worksheet)
        print(f"[+] {filepath}")

    print(f"\nGenerated {len(incidents)} worksheet(s) in {output_dir}/")


if __name__ == "__main__":
    main()
