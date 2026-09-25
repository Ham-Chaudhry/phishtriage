# phishtriage

A command-line triage tool for user-reported phishing emails. Point it at a
`.eml` file and it produces the same static analysis a Tier 1 analyst performs
by hand before deciding whether a message needs sandbox detonation.

Built to compress the repetitive part of phishing queue work: pulling
authentication results out of the headers, comparing the sender fields against
each other, extracting every URL, and hashing attachments for reputation
lookup.

## What it checks

**Sender consistency.** Compares the `From` domain against `Reply-To` and
`Return-Path`. A legitimate sender is usually consistent across all three.
Attackers frequently set a display name to a trusted brand while the actual
envelope sender is disposable infrastructure, so the display name is also
parsed for embedded addresses that contradict the real one.

**Email authentication.** Extracts SPF, DKIM and DMARC verdicts from the
`Authentication-Results` headers. Only the header added by the receiving
perimeter is trustworthy; headers added further upstream were written by
servers outside your control and can be forged, so the first one parsed is
treated as authoritative.

**Routing.** Walks the `Received` chain oldest-first and surfaces public IP
addresses, which identifies the originating infrastructure.

**URLs.** Extracts links from both the plain text and HTML bodies. Anchor tags
are compared against their visible text, flagging cases where a link displays
one domain but points to another. Common schema and namespace URLs are
filtered out to reduce noise.

**Attachments.** Inventories every attachment with SHA-256 and MD5 hashes,
flagging executable extensions and archives that require manual detonation.

**Reputation.** With `--vt`, queries the VirusTotal API for domain and file
hash reputation. Lookups are throttled to stay within the public API's rate
limit of four requests per minute.

## Usage

```
python phishtriage.py samples/sample_phish.eml
python phishtriage.py samples/sample_phish.eml --vt
python phishtriage.py *.eml --json > triage.json
```

VirusTotal lookups require an API key:

```
export VT_API_KEY=your_key_here
```

The `--json` output is structured for piping into a ticketing system or
enrichment pipeline.

## Example

```
FINDINGS (8)
  ! SPF result is fail
  ! DKIM result is none
  ! DMARC result is fail
  ! Reply-To domain (m365-secure-notice.ru) does not match From (m365-secure-notice.com)
  ! Return-Path domain (mail-relay-77.ru) does not match From (m365-secure-notice.com)
  ! Display name spoofs an address at microsoft.com but the real sender is m365-secure-notice.com
  ! Link text points at a different domain than its href: login.microsoftonline.com -> https://login.microsoftonline.com.account-verify.m365-secure-notice.com/auth
  ! Attachment has an executable extension: Password_Reset_Form.exe
```

## Limitations

Static analysis only. It does not follow redirects, resolve DNS, or detonate
anything. An empty findings list means no static indicator triggered, not that
the message is safe. URL shorteners and redirect chains in particular will
hide the real destination from this tool, and those still require sandbox
analysis.

Only standard library dependencies. Python 3.8+.
