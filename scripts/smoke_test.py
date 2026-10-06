#!/usr/bin/env python3
"""
Quick CLI smoke tests for SAQRIntel modules (no web server required).

Usage (from project root):
    python scripts/smoke_test.py example.com
    python scripts/smoke_test.py example.com --with-nmap   # needs authorization & nmap
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="SAQRIntel module smoke tests")
    parser.add_argument("target", nargs="?", default="example.com")
    parser.add_argument("--with-nmap", action="store_true", help="Also run a tiny nmap scan")
    parser.add_argument("--with-web", action="store_true", help="Also fingerprint + shallow crawl")
    args = parser.parse_args()

    from backend.modules import dns_recon, email_osint, network_map, web_fuzzer, report_gen

    print("=== DNS (no brute) ===")
    dns = dns_recon.run_dns_recon(args.target, do_brute=False, on_progress=print)
    print("A records:", dns["records"].get("A"))
    print("NS:", dns["nameservers"][:5])

    print("\n=== EMAIL (SPF/DMARC + guesses) ===")
    email = email_osint.run_email_osint(args.target, urls=[], on_progress=print)
    # re-run without auto seed scrape noise for example.com — module seeds https://
    print("SPF:", email["spf"].get("strength"), email["spf"].get("summary", "")[:120])
    print("DMARC:", email["dmarc"].get("strength"), email["dmarc"].get("policy"))

    if args.with_nmap:
        print("\n=== NETWORK (ports 80,443) ===")
        net = network_map.run_network_map(
            args.target, ports="80,443", host_map=dns.get("host_map"), on_progress=print
        )
        print("Open:", net["scan"].get("ports"))
        print("Graph nodes:", len(net["graph"]["nodes"]))

    if args.with_web:
        print("\n=== WEB fingerprint ===")
        url = args.target if args.target.startswith("http") else f"https://{args.target}"
        fp = web_fuzzer.fingerprint(url, on_progress=print)
        print(json.dumps(fp.get("technologies"), indent=2))

    print("\n=== REPORT (JSON sample) ===")
    findings = [
        {
            "id": 1,
            "module": "dns",
            "title": "Smoke test finding",
            "severity": "Info",
            "data_json": {"a": dns["records"].get("A")},
        }
    ]
    path = report_gen.generate_json_report("smoke", args.target, findings, [])
    print("Wrote", path)

    pdf = report_gen.generate_pdf_report("smoke", args.target, findings, [{"module": "system", "message": "smoke", "created_at": "now"}])
    print("Wrote", pdf)
    print("\nOK — modules import and run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
