"""
Domain / hostname normalization shared across modules.

WHOIS, SPF/DMARC, DNSSEC, and certificate-transparency queries belong on the
*registrable* (apex) domain — not on arbitrary hostnames like demo.testfire.net
or www.example.com. We use tldextract for Public Suffix List–aware parsing.
"""

from __future__ import annotations

import tldextract

# Cache PSL lookups in-process; do not fetch updates at import time in air-gapped labs
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def clean_host(value: str) -> str:
    """Strip scheme/path/port; lowercase; no trailing dot."""
    d = (value or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix) :]
    # Drop credentials / IPv6 brackets edge cases lightly
    d = d.split("@")[-1]
    return d.split("/")[0].split(":")[0].rstrip(".")


def registrable_domain(value: str) -> str:
    """
    Return the registrable domain (eTLD+1) for registry/WHOIS/mail-policy lookups.

    Examples:
      demo.testfire.net     -> testfire.net
      www.cheezious.com     -> cheezious.com
      https://a.b.example.co.uk/x -> example.co.uk
      1.2.3.4               -> 1.2.3.4  (IPs unchanged)
    """
    host = clean_host(value)
    if not host:
        return host

    # Literal IPv4 — WHOIS/ASN paths handle IPs separately; do not tldextract
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return host

    ext = _EXTRACTOR(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    # Fallback: if PSL misses, return cleaned host rather than empty
    return host


# Backwards-compatible alias used across modules
def apex_domain(value: str) -> str:
    """Alias for registrable_domain (historically named apex_domain)."""
    return registrable_domain(value)
