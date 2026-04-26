"""
IP Reputation Checker
Queries AbuseIPDB and VirusTotal for threat intelligence on a list of IPs.
Requires API keys set as environment variables:
    ABUSEIPDB_KEY
    VIRUSTOTAL_KEY
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests")
    sys.exit(1)


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def check_abuseipdb(ip, api_key):
    """Query AbuseIPDB for abuse confidence score."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", "N/A"),
        }
    except requests.RequestException as e:
        return {"source": "AbuseIPDB", "ip": ip, "error": str(e)}


def check_virustotal(ip, api_key):
    """Query VirusTotal for detection stats on an IP."""
    headers = {"x-apikey": api_key}
    url = f"{VIRUSTOTAL_URL}/{ip}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "as_owner": attrs.get("as_owner", "N/A"),
            "country": attrs.get("country", "N/A"),
        }
    except requests.RequestException as e:
        return {"source": "VirusTotal", "ip": ip, "error": str(e)}


def assess_risk(abuse_result, vt_result):
    """Simple risk assessment combining both sources."""
    score = 0

    if "error" not in abuse_result:
        score += abuse_result.get("abuse_score", 0)

    if "error" not in vt_result:
        score += vt_result.get("malicious", 0) * 10
        score += vt_result.get("suspicious", 0) * 5

    if score >= 80:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 15:
        return "MEDIUM"
    else:
        return "LOW"


def main():
    parser = argparse.ArgumentParser(description="Check IP reputation against AbuseIPDB and VirusTotal")
    parser.add_argument("ips", nargs="*", help="IP addresses to check")
    parser.add_argument("-f", "--file", help="File with one IP per line")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    args = parser.parse_args()

    abuseipdb_key = os.environ.get("ABUSEIPDB_KEY")
    virustotal_key = os.environ.get("VIRUSTOTAL_KEY")

    if not abuseipdb_key and not virustotal_key:
        print("Set at least one API key: ABUSEIPDB_KEY or VIRUSTOTAL_KEY")
        sys.exit(1)

    ip_list = list(args.ips) if args.ips else []

    if args.file:
        with open(args.file, "r") as f:
            ip_list.extend(line.strip() for line in f if line.strip())

    if not ip_list:
        print("No IPs provided. Use positional args or -f <file>.")
        sys.exit(1)

    results = []

    for ip in ip_list:
        print(f"\n--- Checking {ip} ---")
        entry = {"ip": ip, "checked_at": datetime.utcnow().isoformat()}

        if abuseipdb_key:
            abuse = check_abuseipdb(ip, abuseipdb_key)
            entry["abuseipdb"] = abuse
            if "error" not in abuse:
                print(f"  AbuseIPDB: score={abuse['abuse_score']}, reports={abuse['total_reports']}")
            time.sleep(1.2)

        if virustotal_key:
            vt = check_virustotal(ip, virustotal_key)
            entry["virustotal"] = vt
            if "error" not in vt:
                print(f"  VirusTotal: malicious={vt['malicious']}, suspicious={vt['suspicious']}")
            time.sleep(15)

        entry["risk_level"] = assess_risk(
            entry.get("abuseipdb", {}),
            entry.get("virustotal", {})
        )
        print(f"  Risk: {entry['risk_level']}")

        results.append(entry)

    output_path = args.output or f"reputation-results-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
