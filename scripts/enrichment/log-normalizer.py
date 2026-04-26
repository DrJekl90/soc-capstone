"""
Log Normalizer
Reads raw JSON log files from multiple sources (Azure AD, Sysmon, generic),
normalizes them to a common schema, and outputs a unified JSONL file.
Useful for cross-source correlation and enrichment pipeline input.
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path


COMMON_SCHEMA = {
    "timestamp": None,
    "source": None,
    "event_type": None,
    "severity": None,
    "user": None,
    "src_ip": None,
    "dst_ip": None,
    "hostname": None,
    "action": None,
    "details": None,
}


def normalize_azuread(event):
    """Normalize an Azure AD sign-in log entry."""
    record = COMMON_SCHEMA.copy()
    record["timestamp"] = event.get("createdDateTime") or event.get("TimeGenerated")
    record["source"] = "azure_ad"
    record["event_type"] = "authentication"
    record["user"] = event.get("userPrincipalName")
    record["src_ip"] = event.get("ipAddress")
    record["hostname"] = event.get("deviceDetail", {}).get("displayName")
    record["action"] = "success" if event.get("status", {}).get("errorCode") == 0 else "failure"
    record["severity"] = classify_severity(event)
    record["details"] = {
        "app": event.get("appDisplayName"),
        "location": event.get("location", {}).get("city"),
        "error_code": event.get("status", {}).get("errorCode"),
        "risk_level": event.get("riskLevelDuringSignIn"),
    }
    return record


def normalize_sysmon(event):
    """Normalize a Sysmon event log entry."""
    record = COMMON_SCHEMA.copy()
    record["timestamp"] = event.get("UtcTime") or event.get("TimeCreated")
    record["source"] = "sysmon"
    record["event_type"] = map_sysmon_event(event.get("EventID"))
    record["user"] = event.get("User")
    record["src_ip"] = event.get("SourceIp")
    record["dst_ip"] = event.get("DestinationIp")
    record["hostname"] = event.get("Computer")
    record["action"] = event.get("Image", "unknown")
    record["severity"] = "medium"
    record["details"] = {
        "event_id": event.get("EventID"),
        "process": event.get("Image"),
        "command_line": event.get("CommandLine"),
        "parent_process": event.get("ParentImage"),
        "hashes": event.get("Hashes"),
    }
    return record


def normalize_generic(event):
    """Fallback normalizer for unrecognized log formats."""
    record = COMMON_SCHEMA.copy()
    record["timestamp"] = (
        event.get("timestamp")
        or event.get("TimeGenerated")
        or event.get("@timestamp")
        or datetime.utcnow().isoformat()
    )
    record["source"] = event.get("source", "unknown")
    record["event_type"] = event.get("event_type", "unknown")
    record["user"] = event.get("user") or event.get("username")
    record["src_ip"] = event.get("src_ip") or event.get("source_ip")
    record["severity"] = event.get("severity", "info")
    record["details"] = event
    return record


def map_sysmon_event(event_id):
    """Map Sysmon EventID to a readable category."""
    mapping = {
        1: "process_create",
        3: "network_connection",
        7: "image_loaded",
        8: "create_remote_thread",
        10: "process_access",
        11: "file_create",
        12: "registry_event",
        13: "registry_value_set",
        22: "dns_query",
    }
    return mapping.get(event_id, f"sysmon_event_{event_id}")


def classify_severity(azure_event):
    """Assign severity based on Azure AD risk signals."""
    risk = azure_event.get("riskLevelDuringSignIn", "none")
    if risk in ("high",):
        return "high"
    elif risk in ("medium",):
        return "medium"
    elif azure_event.get("status", {}).get("errorCode", 0) != 0:
        return "low"
    return "info"


def detect_log_type(events):
    """Determine log source from field presence."""
    sample = events[0] if events else {}
    if "userPrincipalName" in sample or "appDisplayName" in sample:
        return "azuread"
    elif "EventID" in sample or "Image" in sample:
        return "sysmon"
    return "generic"


def main():
    parser = argparse.ArgumentParser(description="Normalize JSON logs to a common schema")
    parser.add_argument("input", help="Input JSON log file")
    parser.add_argument("-o", "--output", help="Output JSONL file", default=None)
    parser.add_argument("-t", "--type", choices=["azuread", "sysmon", "generic"], help="Force log type")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"File not found: {args.input}")
        sys.exit(1)

    with open(input_path, "r") as f:
        raw = json.load(f)

    events = raw if isinstance(raw, list) else [raw]

    log_type = args.type or detect_log_type(events)
    normalizer = {
        "azuread": normalize_azuread,
        "sysmon": normalize_sysmon,
        "generic": normalize_generic,
    }[log_type]

    print(f"Detected log type: {log_type}")
    print(f"Processing {len(events)} event(s)...")

    output_path = args.output or f"normalized-{input_path.stem}.jsonl"
    count = 0

    with open(output_path, "w") as f:
        for event in events:
            normalized = normalizer(event)
            f.write(json.dumps(normalized) + "\n")
            count += 1

    print(f"Wrote {count} normalized record(s) to {output_path}")


if __name__ == "__main__":
    main()
