"""
Domain / DNS reconnaissance module.

Capabilities:
  - WHOIS (python-whois, with system `whois` fallback)
  - Per-type DNS queries: A, AAAA, MX, NS, TXT, SOA (no ANY)
  - Subdomain enum via crt.sh + optional wordlist brute-force
  - Reverse DNS for resolved IPs
  - AXFR attempt against each nameserver
  - DNSSEC presence (DNSKEY)
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any, Dict, List, Optional, Set

import dns.query
import dns.resolver
import dns.zone
import whois

from backend.core.audit_log import ProgressCallback, emit
from backend.core.domain import apex_domain, clean_host
from backend.core.http_client import http_get
from backend.core.rate_limiter import RateLimiter, default_limiter

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA")


def _clean_domain(domain: str) -> str:
    """Normalize to registrable domain (tldextract eTLD+1) for WHOIS / policy DNS."""
    return apex_domain(domain)


def whois_lookup(domain: str, on_progress: ProgressCallback = None) -> Dict[str, Any]:
    """
    Return registrar, dates, and nameservers for a domain.

    Always queries the *registrable* domain (eTLD+1 via tldextract). WHOIS
    databases have records for testfire.net, not for demo.testfire.net.
    """
    input_host = clean_host(domain)
    queried = _clean_domain(domain)
    if input_host and input_host != queried:
        emit(on_progress, f"[DNS] WHOIS: normalized hostname {input_host} -> registrable {queried}")
    else:
        emit(on_progress, f"[DNS] WHOIS lookup for {queried}")

    result: Dict[str, Any] = {
        "domain": queried,
        "input_host": input_host,
        "queried_domain": queried,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "raw": None,
        "error": None,
    }
    try:
        w = whois.whois(queried)
        result["registrar"] = getattr(w, "registrar", None)
        created = getattr(w, "creation_date", None)
        expires = getattr(w, "expiration_date", None)
        # python-whois may return lists for multi-record fields
        if isinstance(created, list):
            created = created[0] if created else None
        if isinstance(expires, list):
            expires = expires[0] if expires else None
        result["creation_date"] = str(created) if created else None
        result["expiration_date"] = str(expires) if expires else None
        ns = getattr(w, "name_servers", None) or []
        if isinstance(ns, str):
            ns = [ns]
        result["name_servers"] = sorted({n.lower().rstrip(".") for n in ns if n})
        result["raw"] = str(w.text) if getattr(w, "text", None) else None
    except Exception as exc:  # noqa: BLE001 — surface WHOIS failures cleanly
        result["error"] = str(exc)
        emit(on_progress, f"[DNS] WHOIS error: {exc}")
    return result


def query_dns_records(
    domain: str,
    on_progress: ProgressCallback = None,
) -> Dict[str, List[str]]:
    """Query each record type individually (ANY is deprecated/often blocked)."""
    domain = _clean_domain(domain)
    emit(on_progress, f"[DNS] Pulling DNS records for {domain}")
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    out: Dict[str, List[str]] = {t: [] for t in RECORD_TYPES}

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                out[rtype].append(rdata.to_text())
            emit(on_progress, f"[DNS] {rtype}: {len(out[rtype])} record(s)")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            emit(on_progress, f"[DNS] {rtype}: none")
        except Exception as exc:  # noqa: BLE001
            emit(on_progress, f"[DNS] {rtype} error: {exc}")
    return out


def crtsh_subdomains(
    domain: str,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> List[str]:
    """Enumerate subdomains via certificate transparency (crt.sh JSON API)."""
    domain = _clean_domain(domain)
    emit(on_progress, f"[DNS] Querying crt.sh for %.{domain}")
    # crt.sh is occasionally flaky (404/429/timeouts) — retry a few times
    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    found: Set[str] = set()
    last_err = None
    for url in urls:
        for attempt in range(1, 4):
            try:
                resp = http_get(url, timeout=45.0, limiter=limiter or default_limiter)
                if resp.status_code in (404, 429, 502, 503):
                    last_err = f"HTTP {resp.status_code}"
                    emit(on_progress, f"[DNS] crt.sh {last_err} (attempt {attempt}) — retrying")
                    continue
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list):
                    last_err = "unexpected JSON shape"
                    continue
                for entry in data:
                    name = entry.get("name_value") or entry.get("common_name") or ""
                    for line in str(name).splitlines():
                        host = line.strip().lower().lstrip("*.")
                        if host.endswith(domain) or host == domain:
                            found.add(host)
                emit(on_progress, f"[DNS] crt.sh returned {len(found)} unique name(s)")
                return sorted(found)
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                emit(on_progress, f"[DNS] crt.sh error (attempt {attempt}): {exc}")
    emit(on_progress, f"[DNS] crt.sh gave up: {last_err}")
    return sorted(found)


def _resolve_a(hostname: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return [r.to_text() for r in answers]
    except Exception:  # noqa: BLE001
        return []


def brute_subdomains(
    domain: str,
    wordlist_path: str,
    threads: int = 20,
    on_progress: ProgressCallback = None,
) -> List[Dict[str, Any]]:
    """
    DNS brute-force against a wordlist using a thread pool.
    Only returns names that resolve to at least one A record.
    """
    domain = _clean_domain(domain)
    emit(on_progress, f"[DNS] Brute-forcing subdomains ({threads} threads)")
    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
            words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    except OSError as exc:
        emit(on_progress, f"[DNS] Wordlist error: {exc}")
        return []

    results: List[Dict[str, Any]] = []
    lock_progress = 0

    def check(word: str) -> Optional[Dict[str, Any]]:
        host = f"{word}.{domain}"
        ips = _resolve_a(host)
        if ips:
            return {"host": host, "ips": ips}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(check, w): w for w in words}
        for fut in concurrent.futures.as_completed(futures):
            hit = fut.result()
            lock_progress += 1
            if hit:
                results.append(hit)
                emit(on_progress, f"[DNS] Hit: {hit['host']} -> {', '.join(hit['ips'])}")
            elif lock_progress % 50 == 0:
                emit(on_progress, f"[DNS] Brute progress: {lock_progress}/{len(words)}")

    emit(on_progress, f"[DNS] Brute complete: {len(results)} resolved")
    return sorted(results, key=lambda x: x["host"])


def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for a single IP."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.rstrip(".")
    except Exception:  # noqa: BLE001
        return None


def reverse_dns_many(
    ips: List[str],
    on_progress: ProgressCallback = None,
) -> Dict[str, Optional[str]]:
    emit(on_progress, f"[DNS] Reverse DNS for {len(ips)} IP(s)")
    out: Dict[str, Optional[str]] = {}
    for ip in sorted(set(ips)):
        ptr = reverse_dns(ip)
        out[ip] = ptr
        emit(on_progress, f"[DNS] PTR {ip} -> {ptr or '(none)'}")
    return out


def attempt_axfr(
    domain: str,
    nameservers: List[str],
    on_progress: ProgressCallback = None,
) -> List[Dict[str, Any]]:
    """
    Attempt zone transfer against each NS.
    Success is rare and should be reported as High severity by the orchestrator.
    """
    domain = _clean_domain(domain)
    results = []
    for ns in nameservers:
        ns_host = ns.rstrip(".")
        emit(on_progress, f"[DNS] AXFR attempt vs {ns_host}")
        entry: Dict[str, Any] = {
            "nameserver": ns_host,
            "vulnerable": False,
            "records": [],
            "message": "",
        }
        try:
            # Resolve NS to IP first
            ns_ips = _resolve_a(ns_host)
            if not ns_ips:
                entry["message"] = "Could not resolve nameserver"
                results.append(entry)
                continue
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ips[0], domain, lifetime=8))
            names = [n.to_text() for n in zone.nodes.keys()]
            entry["vulnerable"] = True
            entry["records"] = names[:200]  # cap for storage
            entry["message"] = f"AXFR succeeded — {len(names)} names (zone transfer open)"
            emit(on_progress, f"[DNS] VULNERABLE: AXFR open on {ns_host}")
        except Exception as exc:  # noqa: BLE001 — refused/timeout is expected
            entry["message"] = f"Refused/failed (expected/secure): {exc}"
            emit(on_progress, f"[DNS] AXFR refused on {ns_host} (secure)")
        results.append(entry)
    return results


def check_dnssec(domain: str, on_progress: ProgressCallback = None) -> Dict[str, Any]:
    """Check for DNSKEY records as a simple DNSSEC presence signal."""
    domain = _clean_domain(domain)
    emit(on_progress, f"[DNS] Checking DNSSEC (DNSKEY) for {domain}")
    out = {"domain": domain, "dnssec_present": False, "dnskey_count": 0, "records": []}
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY")
        recs = [r.to_text() for r in answers]
        out["dnssec_present"] = bool(recs)
        out["dnskey_count"] = len(recs)
        out["records"] = recs
        emit(on_progress, f"[DNS] DNSKEY found: {len(recs)}")
    except Exception:  # noqa: BLE001
        emit(on_progress, "[DNS] No DNSKEY (DNSSEC not detected via this check)")
    return out


def run_dns_recon(
    domain: str,
    *,
    wordlist_path: Optional[str] = None,
    threads: int = 20,
    do_brute: bool = True,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """
    Full DNS module pipeline. Returns a structured dict suitable for
    Finding rows + network graph construction.

    Policy lookups (WHOIS, NS, DNSSEC, crt.sh) always use the registrable
    domain via tldextract so demo.testfire.net becomes testfire.net — WHOIS
    only exists for the registered name, not arbitrary host labels.
    """
    original_host = clean_host(domain)
    domain = _clean_domain(domain)
    emit(on_progress, f"[DNS] === Starting DNS recon for {domain} ===")
    if original_host and original_host != domain:
        emit(on_progress, f"[DNS] Normalized hostname {original_host} -> registrable {domain}")

    whois_data = whois_lookup(domain, on_progress)
    records = query_dns_records(domain, on_progress)

    # Nameservers from DNS NS records (preferred) or WHOIS
    ns_from_dns = [n.rstrip(".") for n in records.get("NS", [])]
    nameservers = ns_from_dns or whois_data.get("name_servers") or []

    # A/AAAA for apex
    apex_ips = records.get("A", []) + records.get("AAAA", [])

    ct_subs = crtsh_subdomains(domain, on_progress, limiter=limiter)
    brute_hits: List[Dict[str, Any]] = []
    if do_brute and wordlist_path:
        brute_hits = brute_subdomains(domain, wordlist_path, threads, on_progress)

    # Merge subdomain set and resolve A records
    all_hosts: Set[str] = set(ct_subs)
    for hit in brute_hits:
        all_hosts.add(hit["host"])
    all_hosts.add(domain)
    if original_host:
        all_hosts.add(original_host)

    host_map: Dict[str, List[str]] = {}
    for host in sorted(all_hosts):
        ips = _resolve_a(host)
        if ips:
            host_map[host] = ips
        elif host == domain and apex_ips:
            host_map[host] = [ip for ip in apex_ips if ":" not in ip] or apex_ips

    all_ips: List[str] = []
    for ips in host_map.values():
        all_ips.extend(ips)
    all_ips.extend(apex_ips)
    ptrs = reverse_dns_many(all_ips, on_progress)

    axfr = attempt_axfr(domain, nameservers, on_progress)
    dnssec = check_dnssec(domain, on_progress)

    emit(on_progress, f"[DNS] === DNS recon complete for {domain} ===")
    return {
        "domain": domain,
        "original_host": original_host,
        "whois": whois_data,
        "records": records,
        "nameservers": nameservers,
        "subdomains_ct": ct_subs,
        "subdomains_brute": brute_hits,
        "host_map": host_map,
        "reverse_dns": ptrs,
        "axfr": axfr,
        "dnssec": dnssec,
    }


# CLI smoke test
if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    data = run_dns_recon(target, do_brute=False, on_progress=print)
    print(json.dumps({k: data[k] for k in ("domain", "records", "dnssec")}, indent=2, default=str))
