"""
IOC Extractor
Pulls indicators of compromise out of raw text, emails, or threat reports.
Handles IPv4, IPv6, domains, URLs, file hashes (MD5, SHA1, SHA256),
and email addresses. Defangs common obfuscation (hxxp, [.], etc).
"""

import re
import sys
import json
import argparse
from pathlib import Path


# Patterns tuned to catch real IOCs while ignoring common false positives
PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|xyz|ru|cn|top|info|biz|cc|tk|ml|ga|cf|gq|pw)\b"
    ),
    "url": re.compile(
        r"(?:https?|hxxps?|ftp)://[^\s\"'<>\]\)]{4,}"
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
}

# IPs to skip (private ranges, localhost, documentation ranges)
PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
]

# Domains that are almost always false positives
DOMAIN_ALLOWLIST = {
    "example.com", "example.org", "example.net",
    "microsoft.com", "google.com", "github.com",
    "schema.org", "w3.org",
}


def refang(text):
    """Undo common defanging in threat reports."""
    text = text.replace("hxxp", "http")
    text = text.replace("[.]", ".")
    text = text.replace("[:]", ":")
    text = text.replace("[@]", "@")
    text = text.replace("(dot)", ".")
    return text


def is_private_ip(ip):
    return any(p.match(ip) for p in PRIVATE_RANGES)


def extract(text, skip_private=True, skip_allowlist=True):
    """Extract all IOC types from text and return deduplicated results."""
    text = refang(text)
    results = {}

    for ioc_type, pattern in PATTERNS.items():
        matches = set(pattern.findall(text))

        if ioc_type == "ipv4" and skip_private:
            matches = {m for m in matches if not is_private_ip(m)}

        if ioc_type == "domain" and skip_allowlist:
            matches = {m for m in matches if m.lower() not in DOMAIN_ALLOWLIST}

        # Avoid hash collisions (an MD5 could also match as a substring of SHA256)
        if ioc_type == "md5":
            sha1s = set(PATTERNS["sha1"].findall(text))
            sha256s = set(PATTERNS["sha256"].findall(text))
            matches = matches - sha1s - sha256s
        if ioc_type == "sha1":
            sha256s = set(PATTERNS["sha256"].findall(text))
            matches = matches - sha256s

        if matches:
            results[ioc_type] = sorted(matches)

    return results


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from text or files")
    parser.add_argument("input", nargs="?", help="Input file path (reads stdin if omitted)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--include-private", action="store_true", help="Include private/reserved IPs")
    args = parser.parse_args()

    if args.input:
        path = Path(args.input)
        if not path.exists():
            print(f"File not found: {args.input}")
            sys.exit(1)
        text = path.read_text(encoding="utf-8", errors="ignore")
    else:
        text = sys.stdin.read()

    iocs = extract(text, skip_private=not args.include_private)

    total = sum(len(v) for v in iocs.values())
    print(f"Extracted {total} IOC(s) across {len(iocs)} type(s)\n")

    for ioc_type, values in iocs.items():
        print(f"  [{ioc_type.upper()}] ({len(values)})")
        for v in values[:10]:
            print(f"    {v}")
        if len(values) > 10:
            print(f"    ... and {len(values) - 10} more")
        print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(iocs, f, indent=2)
        print(f"Full results saved to {args.output}")


if __name__ == "__main__":
    main()
