#!/usr/bin/env python3
"""
phishtriage.py - Static triage tool for suspicious .eml files.

Parses a reported phishing email and produces a triage summary:
  - Sender and routing analysis (From vs Return-Path vs Reply-To mismatches)
  - SPF / DKIM / DMARC results pulled from Authentication-Results headers
  - Received-header hop chain and originating IP
  - Extracted URLs with display-text vs href mismatch detection
  - Attachment inventory with SHA-256 hashes
  - Optional VirusTotal reputation lookup for URLs, domains, and file hashes

Usage:
    python phishtriage.py sample.eml
    python phishtriage.py sample.eml --vt          # enable VirusTotal lookups
    python phishtriage.py sample.eml --json        # machine-readable output

VirusTotal requires an API key in the VT_API_KEY environment variable.
The public API is rate limited to 4 requests/minute, so lookups are throttled.
"""

import argparse
import email
import email.policy
import hashlib
import json
import os
import re
import sys
import time
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

VT_API_KEY = os.environ.get("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Domains that show up constantly in legitimate mail and add noise to triage.
URL_NOISE = {
    "schemas.microsoft.com",
    "www.w3.org",
    "purl.org",
    "aka.ms",
}

# Extensions that are executable or commonly abused as malware carriers.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
    ".jar", ".ps1", ".bat", ".cmd", ".com", ".pif", ".msi", ".lnk",
    ".iso", ".img", ".vhd", ".dll", ".cpl", ".reg",
}

# Archives can nest a risky payload, so they get flagged for manual detonation.
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace"}


class LinkExtractor(HTMLParser):
    """Pull (display_text, href) pairs out of the HTML body.

    A link whose visible text looks like one domain but whose href points
    somewhere else is one of the most reliable phishing indicators there is.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._current_href = None
        self._buffer = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._buffer = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._buffer).strip()
            self.links.append((text, self._current_href))
            self._current_href = None
            self._buffer = []


def domain_of(value):
    """Return the lowercase registrable-ish domain from a URL or address."""
    if not value:
        return None
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[-1].strip(">").lower()
    host = urlparse(value).netloc.lower()
    if "@" in host:            # strip userinfo, e.g. http://user@evil.com
        host = host.rsplit("@", 1)[-1]
    if ":" in host:            # strip port
        host = host.rsplit(":", 1)[0]
    return host or None


def parse_auth_results(msg):
    """Extract SPF, DKIM and DMARC verdicts from Authentication-Results headers.

    There can be several of these headers, one per hop that evaluated the
    message. The first one added is the closest to your own perimeter, so it
    is the one worth trusting; anything further out was written by a server
    you do not control and can be forged.
    """
    raw = msg.get_all("Authentication-Results") or []
    raw += msg.get_all("ARC-Authentication-Results") or []
    verdicts = {"spf": None, "dkim": None, "dmarc": None}
    details = []

    for header in raw:
        flat = " ".join(str(header).split())
        details.append(flat)
        for mech in verdicts:
            if verdicts[mech] is not None:
                continue
            match = re.search(rf"\b{mech}=(\w+)", flat, re.IGNORECASE)
            if match:
                verdicts[mech] = match.group(1).lower()

    # Microsoft 365 also stamps a compauth verdict inside its own header.
    if verdicts["dmarc"] is None:
        for header in raw:
            match = re.search(r"compauth=(\w+)", str(header), re.IGNORECASE)
            if match:
                verdicts["dmarc"] = f"compauth:{match.group(1).lower()}"
                break

    return verdicts, details


def received_chain(msg):
    """Return the Received hops oldest-first, with any public IPs called out."""
    hops = []
    received = msg.get_all("Received") or []
    for index, header in enumerate(reversed(received)):
        flat = " ".join(str(header).split())
        ips = [ip for ip in IP_RE.findall(flat) if not is_private(ip)]
        hops.append({"hop": index + 1, "raw": flat[:300], "public_ips": ips})
    return hops


def is_private(ip):
    try:
        octets = [int(part) for part in ip.split(".")]
    except ValueError:
        return True
    if len(octets) != 4 or any(o > 255 for o in octets):
        return True
    if octets[0] == 10:
        return True
    if octets[0] == 127:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False


def extract_bodies(msg):
    """Return (plain_text, html) decoded from the message."""
    plain, html = "", ""
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if ctype == "text/plain":
            plain += content
        elif ctype == "text/html":
            html += content
    return plain, html


def collect_urls(plain, html):
    """Build a deduplicated URL list with mismatch flags from the HTML links."""
    found = {}

    for url in URL_RE.findall(plain):
        url = url.rstrip(".,;:)")
        found.setdefault(url, {"url": url, "display_text": None, "mismatch": False})

    extractor = LinkExtractor()
    if html:
        try:
            extractor.feed(html)
        except Exception:
            pass

    for text, href in extractor.links:
        if not href.lower().startswith(("http://", "https://")):
            continue
        entry = found.setdefault(
            href, {"url": href, "display_text": None, "mismatch": False}
        )
        entry["display_text"] = text or None

        # If the visible text itself contains a domain, compare it to the href.
        text_urls = URL_RE.findall(text or "")
        text_domain = None
        if text_urls:
            text_domain = domain_of(text_urls[0])
        elif text and re.fullmatch(r"[\w.-]+\.[a-z]{2,}", text.strip(), re.I):
            text_domain = text.strip().lower()

        if text_domain and text_domain != domain_of(href):
            entry["mismatch"] = True

    for url in URL_RE.findall(html or ""):
        url = url.rstrip('.,;:)"\'')
        found.setdefault(url, {"url": url, "display_text": None, "mismatch": False})

    results = []
    for entry in found.values():
        host = domain_of(entry["url"])
        if host in URL_NOISE:
            continue
        entry["domain"] = host
        results.append(entry)
    return results


def collect_attachments(msg):
    """Hash every attachment and flag risky or archived file types."""
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        ext = os.path.splitext(filename)[1].lower()
        attachments.append(
            {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),
                "risky_extension": ext in RISKY_EXTENSIONS,
                "archive": ext in ARCHIVE_EXTENSIONS,
            }
        )
    return attachments


def vt_lookup(kind, identifier):
    """Query VirusTotal for a hash, domain, or URL. Returns detection counts."""
    import urllib.error
    import urllib.request
    import base64

    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    if kind == "url":
        encoded = base64.urlsafe_b64encode(identifier.encode()).decode().strip("=")
        endpoint = f"{VT_BASE}/urls/{encoded}"
    elif kind == "domain":
        endpoint = f"{VT_BASE}/domains/{identifier}"
    else:
        endpoint = f"{VT_BASE}/files/{identifier}"

    request = urllib.request.Request(endpoint, headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not found in VirusTotal"}
        return {"error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"error": str(exc)}

    stats = data.get("data", {}).get("attributes", {}).get(
        "last_analysis_stats", {}
    )
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def analyze(path, use_vt=False):
    with open(path, "rb") as handle:
        msg = email.message_from_binary_file(handle, policy=email.policy.default)

    from_header = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))

    from_addr = parseaddr(from_header)[1]
    from_display = parseaddr(from_header)[0]
    reply_addr = parseaddr(reply_to)[1] if reply_to else None
    return_addr = parseaddr(return_path)[1] if return_path else None

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_addr) if reply_addr else None
    return_domain = domain_of(return_addr) if return_addr else None

    verdicts, auth_details = parse_auth_results(msg)
    plain, html = extract_bodies(msg)
    urls = collect_urls(plain, html)
    attachments = collect_attachments(msg)

    findings = []
    if verdicts["spf"] in {"fail", "softfail", "permerror", "temperror"}:
        findings.append(f"SPF result is {verdicts['spf']}")
    if verdicts["dkim"] in {"fail", "permerror", "temperror", "none"}:
        findings.append(f"DKIM result is {verdicts['dkim']}")
    if verdicts["dmarc"] and "fail" in verdicts["dmarc"]:
        findings.append(f"DMARC result is {verdicts['dmarc']}")
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            f"Reply-To domain ({reply_domain}) does not match From ({from_domain})"
        )
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(
            f"Return-Path domain ({return_domain}) does not match From ({from_domain})"
        )
    if from_display and "@" in from_display:
        candidate = domain_of(from_display)
        if candidate and from_domain and candidate != from_domain:
            findings.append(
                f"Display name spoofs an address at {candidate} "
                f"but the real sender is {from_domain}"
            )
    for entry in urls:
        if entry["mismatch"]:
            findings.append(
                f"Link text points at a different domain than its href: "
                f"{entry['display_text']} -> {entry['url'][:80]}"
            )
    for item in attachments:
        if item["risky_extension"]:
            findings.append(f"Attachment has an executable extension: {item['filename']}")
        elif item["archive"]:
            findings.append(f"Archive attachment needs detonation: {item['filename']}")

    report = {
        "file": os.path.basename(path),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "from": {"display_name": from_display, "address": from_addr, "domain": from_domain},
        "reply_to": reply_addr,
        "return_path": return_addr,
        "authentication": verdicts,
        "authentication_raw": auth_details,
        "hops": received_chain(msg),
        "urls": urls,
        "attachments": attachments,
        "findings": findings,
    }

    if use_vt:
        report["virustotal"] = {"domains": {}, "files": {}}
        seen_domains = {entry["domain"] for entry in urls if entry["domain"]}
        for index, dom in enumerate(sorted(seen_domains)):
            if index:
                time.sleep(15)  # public API allows 4 requests per minute
            report["virustotal"]["domains"][dom] = vt_lookup("domain", dom)
        for item in attachments:
            time.sleep(15)
            report["virustotal"]["files"][item["filename"]] = vt_lookup(
                "file", item["sha256"]
            )

    return report


def print_report(report):
    line = "-" * 68
    print(line)
    print(f"PHISHING TRIAGE REPORT - {report['file']}")
    print(line)
    print(f"Subject      : {report['subject']}")
    print(f"Date         : {report['date']}")
    print(f"From         : {report['from']['display_name']} <{report['from']['address']}>")
    print(f"From domain  : {report['from']['domain']}")
    print(f"Reply-To     : {report['reply_to'] or '(none)'}")
    print(f"Return-Path  : {report['return_path'] or '(none)'}")
    print()

    auth = report["authentication"]
    print("AUTHENTICATION")
    print(f"  SPF   : {auth['spf'] or 'not present'}")
    print(f"  DKIM  : {auth['dkim'] or 'not present'}")
    print(f"  DMARC : {auth['dmarc'] or 'not present'}")
    print()

    print(f"ROUTING ({len(report['hops'])} hops, oldest first)")
    for hop in report["hops"]:
        ips = ", ".join(hop["public_ips"]) or "no public IP"
        print(f"  {hop['hop']}. {ips}")
    print()

    print(f"URLS ({len(report['urls'])})")
    for entry in report["urls"]:
        flag = "  [TEXT/HREF MISMATCH]" if entry["mismatch"] else ""
        print(f"  - {entry['url'][:100]}{flag}")
        if entry["display_text"]:
            print(f"      shown as: {entry['display_text'][:80]}")
    if not report["urls"]:
        print("  none")
    print()

    print(f"ATTACHMENTS ({len(report['attachments'])})")
    for item in report["attachments"]:
        marker = ""
        if item["risky_extension"]:
            marker = "  [RISKY EXTENSION]"
        elif item["archive"]:
            marker = "  [ARCHIVE]"
        print(f"  - {item['filename']} ({item['size_bytes']} bytes){marker}")
        print(f"      sha256: {item['sha256']}")
    if not report["attachments"]:
        print("  none")
    print()

    if "virustotal" in report:
        print("VIRUSTOTAL")
        for dom, stats in report["virustotal"]["domains"].items():
            print(f"  domain {dom}: {stats}")
        for name, stats in report["virustotal"]["files"].items():
            print(f"  file {name}: {stats}")
        print()

    print(f"FINDINGS ({len(report['findings'])})")
    if report["findings"]:
        for finding in report["findings"]:
            print(f"  ! {finding}")
    else:
        print("  No static indicators triggered. Does not mean the message is clean.")
    print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Static triage for suspicious .eml files."
    )
    parser.add_argument("eml", nargs="+", help="one or more .eml files")
    parser.add_argument("--vt", action="store_true", help="enable VirusTotal lookups")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    reports = []
    for path in args.eml:
        if not os.path.isfile(path):
            print(f"skipping {path}: not a file", file=sys.stderr)
            continue
        report = analyze(path, use_vt=args.vt)
        reports.append(report)
        if not args.json:
            print_report(report)

    if args.json:
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))


if __name__ == "__main__":
    main()
