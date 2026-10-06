# SAQRIntel

**SAQRIntel - OSINT and reconnaissance framework** with a browser dashboard — built for Kali Linux.

SAQRIntel consolidates domain/DNS recon, email OSINT, network mapping, and web fuzzing/crawling into one tool. Findings live in **workspaces** (like Recon-ng) so engagements stay separated, and everything exports to a single PDF or JSON report.

---

## Authorized Use Only

> **SAQRIntel is for authorized security testing and OSINT research only.**
>
> You must have explicit permission before running active modules (port scanning, crawling, directory fuzzing) against any system you do not own or administer. Unauthorized scanning, fuzzing, or access attempts may be illegal and unethical.
>
> Passive OSINT (public WHOIS, DNS, certificate transparency) still requires responsible use and compliance with applicable laws and terms of service.
>
> The authors accept no liability for misuse.

Active modules (**Network Mapping**, **Web Recon / Fuzzer**) require an in-app authorization confirmation checkbox before a scan will start.

---

## Features

| Module | What it does |
|--------|----------------|
| **Domain / DNS** | WHOIS against the *registrable* domain via tldextract (e.g. `demo.testfire.net` → `testfire.net`), A/AAAA/MX/NS/TXT/SOA, crt.sh subdomains, optional DNS brute-force, PTR, AXFR attempts, DNSSEC (DNSKEY) |
| **Email OSINT** | Unverified format guesses, email scrape, SPF/DMARC with strength ratings. **MX-aware severity**: no MX + missing SPF/DMARC → Medium; MX present + missing policy → High. Optional HIBP *password* k-anonymity check |
| **Network Mapping** | nmap port/service scan, ASN/CIDR WHOIS, interactive vis-network graph |
| **Web Recon / Fuzzer** | Tech fingerprinting, depth-limited crawler, path fuzzer with live WebSocket progress |
| **Reporting** | Findings with editable severity → PDF (fpdf2) + JSON; audit log appendix |

---

## Requirements

- Kali Linux (or similar) with Python 3.10+
- `nmap` and `whois` on `PATH` (standard on Kali)
- Network access for DNS / crt.sh / HTTP targets

## Setup

```bash
cd SAQRIntel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

From the project root:

```bash
source .venv/bin/activate
python backend/main.py
```

Open **http://127.0.0.1:8000**

Alternatively:

```bash
python -m backend.main
# or
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

## Usage walkthrough

1. **Create a workspace** on the landing page (e.g. `lab-engagement-01`).
2. Enter a **target** (domain, IP, or URL).
3. Tick modules. Passive modules show a warning badge and open an **authorization** dialog.
4. Click **Run Scan** — live log lines stream over WebSocket.
5. Review **Results** (by module), **Network Graph**, and **Findings** (edit severities).
6. On **Report**, generate PDF or JSON and download.

### Settings

Gear icon → rate limit (req/s), thread count, nmap port expression (`--top-ports 100` or `1-65535` with the UI warning), wordlist paths, crawl depth/pages.

### CLI module tests (no GUI)

```bash
python scripts/smoke_test.py example.com
python scripts/smoke_test.py scanme.nmap.org --with-nmap
python scripts/smoke_test.py https://example.com --with-web
```

Individual modules are also runnable:

```bash
python -m backend.modules.dns_recon example.com
python -m backend.modules.email_osint example.com
```

---

## Project layout

```
SAQRIntel/
  backend/
    main.py              # FastAPI + WebSocket entrypoint
    schemas.py
    modules/             # Plain, testable recon modules
    db/                  # SQLAlchemy models (SQLite)
    core/                # config, rate limiter, HTTP helpers
  frontend/              # Bootstrap SPA (no build step)
  wordlists/
  reports/               # Generated PDF/JSON
  data/                  # SQLite DB (created at runtime)
  scripts/smoke_test.py
  requirements.txt
  README.md
```

---

## Design notes

- **Workspaces** isolate targets, findings, and audit logs in SQLite.
- **Rate limiter** is shared across HTTP-heavy modules.
- **Scans run in a thread pool**; progress is pushed to the browser via WebSocket so the event loop stays responsive.
- **PDF** uses `fpdf2` (pure Python) to avoid WeasyPrint’s Cairo/Pango system packages on Kali.
- **HIBP** integration only supports the Pwned Passwords *k-anonymity* range API for a password you supply — never bulk email breach lookups.

---

## Disclaimer

This software is provided as-is for educational and authorized professional use. Always obtain written authorization before active testing. Respect rate limits, robots policies where applicable, and local law.
