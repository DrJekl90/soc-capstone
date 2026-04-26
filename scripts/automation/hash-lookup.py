"""
File Hash Reputation Lookup
Takes MD5, SHA1, or SHA256 hashes and checks them against VirusTotal.
Useful during triage when you pull a hash from Sysmon logs or an
EDR alert and need to know if it has been seen before.
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
    print("Install requests first: pip install requests")
    sys.exit(1)

VT_URL = "https://www.virustotal.com/api/v3/files"


def identify_hash_type(h):
    """Figure out what kind of hash we are looking at."""
    length = len(h.strip())
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    return "unknown"


def lookup_hash(file_hash, api_key):
    """Hit VirusTotal and pull back detection stats for a hash."""
    headers = {"x-apikey": api_key}
    url = f"{VT_URL}/{file_hash}"

    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 404:
            return {"hash": file_hash, "status": "not_found"}

        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return {
            "hash": file_hash,
            "hash_type": identify_hash_type(file_hash),
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "file_type": attrs.get("type_description", "unknown"),
            "file_name": attrs.get("meaningful_name", "unknown"),
            "file_size": attrs.get("size", 0),
            "first_seen": attrs.get("first_submission_date", None),
            "last_seen": attrs.get("last_analysis_date", None),
            "tags": attrs.get("tags", []),
        }
    except requests.RequestException as e:
        return {"hash": file_hash, "status": "error", "error": str(e)}


def verdict(result):
    """Assign a plain-english verdict based on detection counts."""
    if result.get("status") != "found":
        return result.get("status", "unknown").upper()

    mal = result.get("malicious", 0)
    sus = result.get("suspicious", 0)

    if mal >= 10:
        return "MALICIOUS"
    elif mal >= 3 or sus >= 5:
        return "SUSPICIOUS"
    elif mal >= 1:
        return "LOW_CONFIDENCE"
    return "CLEAN"


def main():
    parser = argparse.ArgumentParser(description="Look up file hashes on VirusTotal")
    parser.add_argument("hashes", nargs="*", help="Hashes to check")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    api_key = os.environ.get("VIRUSTOTAL_KEY")
    if not api_key:
        print("Set VIRUSTOTAL_KEY environment variable first.")
        sys.exit(1)

    hash_list = list(args.hashes) if args.hashes else []
    if args.file:
        with open(args.file) as f:
            hash_list.extend(line.strip() for line in f if line.strip())

    if not hash_list:
        print("Provide hashes as arguments or with -f <file>.")
        sys.exit(1)

    results = []
    for h in hash_list:
        h = h.strip()
        htype = identify_hash_type(h)
        print(f"[{htype.upper()}] {h}")

        result = lookup_hash(h, api_key)
        result["verdict"] = verdict(result)
        results.append(result)

        v = result["verdict"]
        if result["status"] == "found":
            det = result["malicious"]
            name = result.get("file_name", "?")
            print(f"  -> {v} | {det} detections | {name}")
        else:
            print(f"  -> {v}")

        # VT free tier: 4 requests per minute
        time.sleep(16)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
