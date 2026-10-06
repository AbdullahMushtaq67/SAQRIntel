"""
Email OSINT module.

- Corporate email format guesses (labeled unverified)
- Email extraction from page HTML / URL lists
- SPF + DMARC parsers with plain-English strength ratings
- Optional HaveIBeenPwned Pwned Passwords k-anonymity check (password only)
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set

import dns.resolver

from backend.core.audit_log import ProgressCallback, emit
from backend.core.domain import apex_domain
from backend.core.http_client import http_get
from backend.core.rate_limiter import RateLimiter, default_limiter

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

# first, last samples used only to illustrate formats — not real people
SAMPLE_FIRST = "jane"
SAMPLE_LAST = "doe"


def _clean_domain(domain: str) -> str:
    """Always use registrable domain so SPF/DMARC/WHOIS are not checked on host labels."""
    return apex_domain(domain)


def _mx_records(domain: str) -> List[str]:
    """
    Return MX exchange hostnames for the domain.

    RFC 7505 null MX (exchange '.') means the domain explicitly accepts no mail;
    we treat that as an empty list so severity logic does not inflate risk.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
        exchanges = []
        for rdata in answers:
            ex = rdata.exchange.to_text().rstrip(".")
            if not ex:
                # Null MX — domain publishes "no mail service"
                continue
            exchanges.append(ex)
        return sorted(set(exchanges))
    except Exception:  # noqa: BLE001
        return []


def mail_policy_severity(strength: str, has_mx: bool) -> str:
    """
    Map policy strength to finding severity, conditioned on MX presence.

    A domain with no MX is not actively sending/receiving via published mail
    infrastructure — missing SPF/DMARC is still worth noting (spoofing risk)
    but Medium rather than High. Active mail (MX present) without protection
    remains High.
    """
    base = {
        "Strict": "Info",
        "Moderate": "Low",
        "Permissive": "Medium",
        "Missing": "High" if has_mx else "Medium",
    }.get(strength, "Info")
    # Permissive on a non-mail domain is less urgent than on an MX domain
    if strength == "Permissive" and not has_mx:
        return "Low"
    return base


def guess_email_formats(domain: str, on_progress: ProgressCallback = None) -> List[Dict[str, str]]:
    """
    Generate likely corporate email patterns.
    Clearly labeled as unverified guesses — not confirmed addresses.
    """
    domain = _clean_domain(domain)
    emit(on_progress, f"[EMAIL] Generating unverified format guesses for @{domain}")
    f, l = SAMPLE_FIRST, SAMPLE_LAST
    patterns = [
        ("first.last", f"{f}.{l}@{domain}"),
        ("firstlast", f"{f}{l}@{domain}"),
        ("flast", f"{f[0]}{l}@{domain}"),
        ("first", f"{f}@{domain}"),
        ("first_last", f"{f}_{l}@{domain}"),
        ("last.first", f"{l}.{f}@{domain}"),
    ]
    out = [
        {
            "pattern": name,
            "example": example,
            "status": "unverified_guess",
            "note": "Illustrative only — not a confirmed mailbox",
        }
        for name, example in patterns
    ]
    emit(on_progress, f"[EMAIL] Produced {len(out)} unverified guess pattern(s)")
    return out


def extract_emails_from_text(text: str) -> List[str]:
    """Regex-extract emails; filter obvious false positives."""
    found: Set[str] = set()
    for match in EMAIL_RE.findall(text or ""):
        email = match.lower().rstrip(".")
        # Skip image/font extensions mistaken as TLDs in some paths
        if any(email.endswith(ext) for ext in (".png", ".jpg", ".gif", ".css", ".js")):
            continue
        found.add(email)
    return sorted(found)


def scrape_emails_from_urls(
    urls: List[str],
    *,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """Fetch each URL and extract emails from response bodies."""
    emit(on_progress, f"[EMAIL] Scraping emails from {len(urls)} URL(s)")
    all_emails: Set[str] = set()
    per_url: Dict[str, List[str]] = {}
    lim = limiter or default_limiter

    for url in urls:
        try:
            resp = http_get(url, limiter=lim, verify=False)
            emails = extract_emails_from_text(resp.text)
            per_url[url] = emails
            all_emails.update(emails)
            emit(on_progress, f"[EMAIL] {url} -> {len(emails)} email(s)")
        except Exception as exc:  # noqa: BLE001
            per_url[url] = []
            emit(on_progress, f"[EMAIL] Failed {url}: {exc}")

    return {
        "emails": sorted(all_emails),
        "by_url": per_url,
        "count": len(all_emails),
    }


def _txt_records(name: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
        out: List[str] = []
        for rdata in answers:
            if hasattr(rdata, "strings"):
                parts = [
                    s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                ]
                out.append("".join(parts))
            else:
                # Fallback: strip surrounding quotes from to_text()
                out.append(rdata.to_text().strip('"'))
        return out
    except Exception:  # noqa: BLE001
        return []


def parse_spf(
    domain: str,
    on_progress: ProgressCallback = None,
    *,
    has_mx: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Fetch SPF from TXT, parse mechanisms, and rate strength by `all` qualifier:
      -all  -> Strict
      ~all  -> Moderate
      ?all / +all / missing all -> Permissive

    Severity for Missing/Permissive accounts for whether MX exists (see
    mail_policy_severity).
    """
    domain = _clean_domain(domain)
    emit(on_progress, f"[EMAIL] Parsing SPF for {domain}")
    txts = _txt_records(domain)
    spf_raw = next((t for t in txts if t.lower().startswith("v=spf1")), None)

    if has_mx is None:
        has_mx = bool(_mx_records(domain))

    result: Dict[str, Any] = {
        "domain": domain,
        "present": bool(spf_raw),
        "raw": spf_raw,
        "mechanisms": [],
        "all_qualifier": None,
        "strength": "Missing",
        "has_mx": has_mx,
        "summary": "",
        "severity": "Info",
    }
    if not spf_raw:
        if has_mx:
            result["summary"] = (
                "No SPF record found on a domain that publishes MX — real mail flow "
                "has no sender authentication. Spoofed mail can more easily claim this domain."
            )
        else:
            result["summary"] = (
                "No MX records and no SPF. This domain does not appear to send mail, but "
                "there is still no explicit anti-spoofing record — a defensive "
                "'v=spf1 -all' is still recommended."
            )
        result["severity"] = mail_policy_severity("Missing", has_mx)
        emit(on_progress, f"[EMAIL] No SPF record (severity={result['severity']}, has_mx={has_mx})")
        return result

    tokens = spf_raw.split()
    mechs = []
    all_q = None
    for tok in tokens[1:]:  # skip v=spf1
        lower = tok.lower()
        if lower.endswith("all") and lower in ("-all", "~all", "?all", "+all", "all"):
            all_q = lower if lower != "all" else "+all"
        mechs.append(tok)
    result["mechanisms"] = mechs
    result["all_qualifier"] = all_q

    if all_q == "-all":
        result["strength"] = "Strict"
        result["summary"] = (
            "SPF ends with -all (fail). Mail not matching SPF should be rejected. "
            f"Mechanisms: {', '.join(mechs)}."
        )
    elif all_q == "~all":
        result["strength"] = "Moderate"
        result["summary"] = (
            "SPF ends with ~all (softfail). Non-matching mail is marked but often still delivered. "
            f"Mechanisms: {', '.join(mechs)}."
        )
    else:
        result["strength"] = "Permissive"
        result["summary"] = (
            f"SPF uses {all_q or 'no explicit all'} - spoofing protection is weak. "
            f"Mechanisms: {', '.join(mechs)}."
        )

    result["severity"] = mail_policy_severity(result["strength"], has_mx)
    emit(on_progress, f"[EMAIL] SPF strength: {result['strength']} (severity={result['severity']})")
    return result


def parse_dmarc(
    domain: str,
    on_progress: ProgressCallback = None,
    *,
    has_mx: Optional[bool] = None,
) -> Dict[str, Any]:
    """Check _dmarc.DOMAIN TXT and rate policy strength (MX-aware severity)."""
    domain = _clean_domain(domain)
    emit(on_progress, f"[EMAIL] Checking DMARC for {domain}")
    name = f"_dmarc.{domain}"
    txts = _txt_records(name)
    raw = next((t for t in txts if "v=DMARC1" in t.upper() or t.lower().startswith("v=dmarc1")), None)

    if has_mx is None:
        has_mx = bool(_mx_records(domain))

    result: Dict[str, Any] = {
        "domain": domain,
        "present": bool(raw),
        "raw": raw,
        "policy": None,
        "pct": None,
        "rua": None,
        "strength": "Missing",
        "has_mx": has_mx,
        "summary": "",
        "severity": "Info",
    }
    if not raw:
        if has_mx:
            result["summary"] = (
                "No DMARC record on a domain that publishes MX — receivers have no policy "
                "guidance for handling spoofed mail claiming this domain."
            )
        else:
            result["summary"] = (
                "No MX records and no DMARC. Lower urgency than for active mail domains, but "
                "publishing a DMARC record (even p=none for monitoring) is still good hygiene."
            )
        result["severity"] = mail_policy_severity("Missing", has_mx)
        emit(on_progress, f"[EMAIL] No DMARC record (severity={result['severity']}, has_mx={has_mx})")
        return result

    tags = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()
    result["policy"] = policy
    result["pct"] = tags.get("pct", "100")
    result["rua"] = tags.get("rua")

    if policy == "reject":
        result["strength"] = "Strict"
        result["summary"] = (
            f"DMARC p=reject - spoofed mail should be rejected. pct={result['pct']}."
        )
    elif policy == "quarantine":
        result["strength"] = "Moderate"
        result["summary"] = (
            f"DMARC p=quarantine - spoofed mail should go to spam. pct={result['pct']}."
        )
    else:
        result["strength"] = "Permissive"
        result["summary"] = (
            f"DMARC p={policy} - monitoring only; spoofed mail is still delivered. "
            f"pct={result['pct']}."
        )

    result["severity"] = mail_policy_severity(result["strength"], has_mx)
    emit(on_progress, f"[EMAIL] DMARC strength: {result['strength']} (p={policy}, severity={result['severity']})")
    return result


def hibp_pwned_password_check(
    password: str,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """
    HaveIBeenPwned Pwned Passwords k-anonymity API.
    Only the first 5 hex chars of the SHA-1 hash are sent - never the full password.
    This is intentionally NOT an email breach lookup.
    """
    emit(on_progress, "[EMAIL] HIBP k-anonymity password check (hash prefix only)")
    if not password:
        return {"error": "empty password", "pwned": False, "count": 0}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        resp = http_get(
            url,
            headers={"Add-Padding": "true"},
            limiter=limiter or default_limiter,
            timeout=15.0,
        )
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = int(parts[1])
                break
        emit(on_progress, f"[EMAIL] Password appears in breaches: {count} time(s)" if count else "[EMAIL] Password not found in HIBP corpus")
        return {
            "pwned": count > 0,
            "count": count,
            "hash_prefix": prefix,
            "note": "Only SHA-1 prefix sent to HIBP (k-anonymity). Not an email breach lookup.",
        }
    except Exception as exc:  # noqa: BLE001
        emit(on_progress, f"[EMAIL] HIBP error: {exc}")
        return {"error": str(exc), "pwned": False, "count": 0}


def run_email_osint(
    domain: str,
    *,
    urls: Optional[List[str]] = None,
    password_to_check: Optional[str] = None,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """Full email OSINT pipeline for a domain (+ optional crawl URLs)."""
    domain = _clean_domain(domain)
    emit(on_progress, f"[EMAIL] === Starting email OSINT for {domain} ===")

    mx = _mx_records(domain)
    has_mx = bool(mx)
    emit(
        on_progress,
        f"[EMAIL] MX check: {len(mx)} record(s) — "
        + (", ".join(mx[:5]) if mx else "none (no published mail infrastructure)"),
    )

    guesses = guess_email_formats(domain, on_progress)
    scraped = scrape_emails_from_urls(urls or [], on_progress=on_progress, limiter=limiter)
    # Also try common public pages if no URLs provided
    if not urls:
        seed = [f"https://{domain}/", f"http://{domain}/"]
        scraped = scrape_emails_from_urls(seed, on_progress=on_progress, limiter=limiter)

    spf = parse_spf(domain, on_progress, has_mx=has_mx)
    dmarc = parse_dmarc(domain, on_progress, has_mx=has_mx)
    hibp = None
    if password_to_check:
        hibp = hibp_pwned_password_check(password_to_check, on_progress, limiter)

    emit(on_progress, f"[EMAIL] === Email OSINT complete for {domain} ===")
    return {
        "domain": domain,
        "mx_records": mx,
        "has_mx": has_mx,
        "format_guesses": guesses,
        "scraped_emails": scraped,
        "spf": spf,
        "dmarc": dmarc,
        "hibp_password": hibp,
    }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(run_email_osint(target, on_progress=print), indent=2, default=str))
