"""
Compliance mapping and risk scoring for SAQRIntel findings.
Mappings are at control-family level. Review them against the official
ISO 27001:2022 and NCA ECC documents before using them in client work.
"""

from __future__ import annotations

import math
from typing import Dict, List

ISO = "ISO 27001:2022"
NCA = "NCA ECC"


def _c(framework: str, control: str, name: str) -> Dict[str, str]:
    return {"framework": framework, "control": control, "name": name}


EMAIL_AUTH = [
    _c(ISO, "A.5.14", "Information transfer"),
    _c(ISO, "A.8.9", "Configuration management"),
    _c(NCA, "2-4", "Email Protection"),
]
PII_EXPOSURE = [
    _c(ISO, "A.5.34", "Privacy and protection of PII"),
    _c(ISO, "A.8.12", "Data leakage prevention"),
    _c(NCA, "2-7", "Data and Information Protection"),
]
CREDENTIALS = [
    _c(ISO, "A.5.17", "Authentication information"),
    _c(ISO, "A.8.5", "Secure authentication"),
    _c(NCA, "2-2", "Identity and Access Management"),
]
ZONE_TRANSFER = [
    _c(ISO, "A.8.20", "Networks security"),
    _c(ISO, "A.8.9", "Configuration management"),
    _c(NCA, "2-5", "Network Security Management"),
]
DNSSEC = [
    _c(ISO, "A.8.20", "Networks security"),
    _c(ISO, "A.8.24", "Use of cryptography"),
    _c(NCA, "2-5", "Network Security Management"),
    _c(NCA, "2-8", "Cryptography"),
]
ATTACK_SURFACE = [
    _c(ISO, "A.5.9", "Inventory of information and other associated assets"),
    _c(ISO, "A.8.8", "Management of technical vulnerabilities"),
    _c(NCA, "2-1", "Asset Management"),
    _c(NCA, "2-10", "Vulnerabilities Management"),
]
OPEN_PORTS = [
    _c(ISO, "A.8.20", "Networks security"),
    _c(ISO, "A.8.9", "Configuration management"),
    _c(ISO, "A.8.8", "Management of technical vulnerabilities"),
    _c(NCA, "2-5", "Network Security Management"),
    _c(NCA, "2-10", "Vulnerabilities Management"),
]
WEB_APP = [
    _c(ISO, "A.8.26", "Application security requirements"),
    _c(ISO, "A.8.8", "Management of technical vulnerabilities"),
    _c(NCA, "2-15", "Web Application Security"),
]

WEB_HEADERS = [
    _c(ISO, "A.8.9", "Configuration management"),
    _c(ISO, "A.8.26", "Application security requirements"),
    _c(NCA, "2-15", "Web Application Security"),
]
TLS_CONTROLS = [
    _c(ISO, "A.8.24", "Use of cryptography"),
    _c(ISO, "A.8.20", "Networks security"),
    _c(NCA, "2-8", "Cryptography"),
    _c(NCA, "2-5", "Network Security Management"),
]
EXPOSED_FILES = [
    _c(ISO, "A.8.3", "Information access restriction"),
    _c(ISO, "A.8.12", "Data leakage prevention"),
    _c(ISO, "A.8.9", "Configuration management"),
    _c(NCA, "2-7", "Data and Information Protection"),
    _c(NCA, "2-15", "Web Application Security"),
]

# (module, keywords - any match, controls). First match wins.
RULES = [
    ("email", ("spf", "dmarc"), EMAIL_AUTH),
    ("email", ("emails extracted",), PII_EXPOSURE),
    ("email", ("hibp",), CREDENTIALS),
    ("dns", ("zone transfer",), ZONE_TRANSFER),
    ("dns", ("dnssec",), DNSSEC),
    ("dns", ("subdomain",), ATTACK_SURFACE),
    ("network", ("open",), OPEN_PORTS),
    ("web", ("emails found",), PII_EXPOSURE),
    ("web", ("crawl", "fuzzer"), WEB_APP),
    ("webcheck", ("security header", "disclosure"), WEB_HEADERS),
    ("webcheck", ("tls", "https"), TLS_CONTROLS),
    ("webcheck", ("exposed file",), EXPOSED_FILES),
]


def map_finding(module: str, title: str, severity: str = "Info") -> List[Dict[str, str]]:
    """Return mapped controls. Info findings are not mapped (nothing to fix)."""
    if severity == "Info":
        return []
    t = (title or "").lower()
    for mod, keywords, controls in RULES:
        if mod == module and any(k in t for k in keywords):
            return [dict(c) for c in controls]
    return []


WEIGHTS = {"High": 10, "Medium": 4, "Low": 1}


def calculate_risk(severities: List[str]) -> Dict:
    """
    0-100 risk score (higher = riskier).
    Weighted points with diminishing returns, so many Low findings
    cannot reach 100 on their own.
    """
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for s in severities:
        counts[s if s in counts else "Info"] += 1
    points = sum(WEIGHTS[k] * counts[k] for k in WEIGHTS)
    score = round(100 * (1 - math.exp(-points / 30)))
    if score >= 75:
        rating = "Critical"
    elif score >= 50:
        rating = "High"
    elif score >= 25:
        rating = "Moderate"
    else:
        rating = "Low"
    return {"score": score, "rating": rating, "counts": counts, "points": points}
