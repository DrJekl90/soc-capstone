"""
Sigma-to-KQL Converter (Lightweight)
Converts basic Sigma detection rules (YAML) into KQL queries that
can be pasted into Microsoft Sentinel. Handles common field mappings
for Windows Security and Sysmon log sources. Not a full replacement
for the official Sigma CLI, but useful for quick one-off conversions.
"""

import sys
import argparse
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Install PyYAML first: pip install pyyaml")
    sys.exit(1)


# Maps Sigma log sources to KQL tables
TABLE_MAP = {
    ("windows", "security"): "SecurityEvent",
    ("windows", "sysmon"): "SysmonEvent",
    ("windows", "powershell"): "Event",
    ("azure", "signinlogs"): "SigninLogs",
    ("azure", "auditlogs"): "AuditLogs",
}

# Maps common Sigma field names to KQL column names
FIELD_MAP = {
    "EventID": "EventID",
    "CommandLine": "CommandLine",
    "Image": "NewProcessName",
    "ParentImage": "ParentProcessName",
    "User": "TargetUserName",
    "SourceIP": "IpAddress",
    "DestinationIP": "DestinationIp",
    "TargetFilename": "ObjectName",
    "Hashes": "FileHash",
    "LogonType": "LogonType",
}


def resolve_table(logsource):
    """Pick the right KQL table based on the Sigma logsource block."""
    product = logsource.get("product", "").lower()
    service = logsource.get("service", "").lower()
    category = logsource.get("category", "").lower()

    # Try direct mapping
    key = (product, service)
    if key in TABLE_MAP:
        return TABLE_MAP[key]

    # Fallback for sysmon categories
    if product == "windows" and category.startswith("process"):
        return "SysmonEvent"
    if product == "windows":
        return "SecurityEvent"

    return "CommonSecurityLog"


def map_field(sigma_field):
    """Translate a Sigma field name to its KQL equivalent."""
    return FIELD_MAP.get(sigma_field, sigma_field)


def build_condition(key, value):
    """Turn a single Sigma key-value pair into a KQL where clause."""
    kql_field = map_field(key)

    if isinstance(value, list):
        # OR across list values
        quoted = [f'"{v}"' for v in value]
        return f'{kql_field} in ({", ".join(quoted)})'
    elif isinstance(value, str):
        if "*" in value:
            # Wildcard match
            pattern = value.replace("*", "")
            if value.startswith("*") and value.endswith("*"):
                return f'{kql_field} contains "{pattern}"'
            elif value.endswith("*"):
                return f'{kql_field} startswith "{pattern}"'
            elif value.startswith("*"):
                return f'{kql_field} endswith "{pattern}"'
        return f'{kql_field} == "{value}"'
    elif isinstance(value, int):
        return f"{kql_field} == {value}"

    return f'{kql_field} == "{value}"'


def convert_detection(detection):
    """Convert the Sigma detection block into KQL where clauses."""
    conditions = []
    condition_expr = detection.get("condition", "selection")

    for selection_name, selection in detection.items():
        if selection_name == "condition":
            continue
        if not isinstance(selection, dict):
            continue

        parts = []
        for field, value in selection.items():
            # Handle field modifiers (contains, endswith, etc.)
            if "|" in field:
                base_field, modifier = field.split("|", 1)
                kql_field = map_field(base_field)
                if modifier == "contains":
                    if isinstance(value, list):
                        clauses = [f'{kql_field} contains "{v}"' for v in value]
                        parts.append(f'({" or ".join(clauses)})')
                    else:
                        parts.append(f'{kql_field} contains "{value}"')
                elif modifier == "endswith":
                    parts.append(f'{kql_field} endswith "{value}"')
                elif modifier == "startswith":
                    parts.append(f'{kql_field} startswith "{value}"')
                else:
                    parts.append(build_condition(base_field, value))
            else:
                parts.append(build_condition(field, value))

        if parts:
            conditions.append((selection_name, parts))

    return conditions


def sigma_to_kql(sigma):
    """Main conversion: takes a parsed Sigma dict, returns KQL string."""
    title = sigma.get("title", "Untitled Rule")
    description = sigma.get("description", "")
    level = sigma.get("level", "medium")
    tags = sigma.get("tags", [])
    logsource = sigma.get("logsource", {})
    detection = sigma.get("detection", {})

    table = resolve_table(logsource)
    conditions = convert_detection(detection)

    lines = []
    lines.append(f"// {title}")
    if description:
        lines.append(f"// {description}")
    lines.append(f"// Severity: {level}")
    if tags:
        attack_tags = [t for t in tags if t.startswith("attack.")]
        if attack_tags:
            lines.append(f"// ATT&CK: {', '.join(attack_tags)}")
    lines.append("")
    lines.append(table)
    lines.append("| where TimeGenerated > ago(24h)")

    for name, parts in conditions:
        lines.append(f"// Selection: {name}")
        for p in parts:
            lines.append(f"| where {p}")

    lines.append("| project TimeGenerated, Computer, TargetUserName, NewProcessName, CommandLine")
    lines.append("| order by TimeGenerated desc")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Convert Sigma rules to KQL")
    parser.add_argument("input", help="Sigma YAML rule file")
    parser.add_argument("-o", "--output", help="Output KQL file")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        print(f"File not found: {args.input}")
        sys.exit(1)

    with open(path) as f:
        sigma = yaml.safe_load(f)

    kql = sigma_to_kql(sigma)
    print(kql)

    if args.output:
        Path(args.output).write_text(kql)
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
