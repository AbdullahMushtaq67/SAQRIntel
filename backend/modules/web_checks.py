"""
Web security checks for SAQRIntel.

- Security headers (HSTS, CSP, X-Frame-Options, ...)
- TLS certificate and protocol check
- Exposed sensitive files (.git, .env, backups, ...)

ACTIVE module: it sends a small number of requests to the target.
Use it only on systems you own or have written permission to test.
File contents are never stored - only whether a file looks exposed.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from backend.core.audit_log import ProgressCallback, emit
from backend.core.config import settings
from backend.core.http_client import http_get
from backend.core.rate_limiter import RateLimiter, default_limiter

# (header, severity if missing, why it matters)
HEADER_RULES = [
    ("Strict-Transport-Security", "Medium", "Browsers are not told to always use HTTPS."),
    ("Content-Security-Policy", "Medium", "No policy limits which scripts can run, so XSS is easier."),
    ("X-Frame-Options", "Low", "Other sites may put this page in a frame (clickjacking)."),
    ("X-Content-Type-Options", "Low", "Browsers may guess content types (MIME sniffing)."),
    ("Referrer-Policy", "Low", "Full page addresses may leak to other sites."),
    ("Permissions-Policy", "Low", "Browser features such as camera are not restricted."),
]


def _base_url(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    p = urlparse(t)
    return f"{p.scheme}://{p.netloc}"


def _is_html(chunk: bytes, ctype: str) -> bool:
    low = chunk[:300].lower()
    return "text/html" in (ctype or "").lower() or b"<html" in low or b"<!doctype" in low


# ---------------- Security headers ----------------

def check_security_headers(
    base: str,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    emit(on_progress, f"[WEBCHECK] Checking security headers on {base}")
    out: Dict[str, Any] = {
        "url": base,
        "final_url": None,
        "status": None,
        "present": [],
        "issues": [],
        "disclosure": [],
        "error": None,
    }
    try:
        resp = http_get(base, limiter=limiter or default_limiter, verify=False, timeout=15.0)
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
        emit(on_progress, f"[WEBCHECK] Header check failed: {exc}")
        return out

    headers = {k.lower(): v for k, v in resp.headers.items()}
    out["status"] = resp.status_code
    out["final_url"] = resp.url
    is_https = resp.url.lower().startswith("https://")
    csp = headers.get("content-security-policy", "").lower()

    for name, sev, why in HEADER_RULES:
        key = name.lower()
        if key == "strict-transport-security" and not is_https:
            continue
        present = key in headers
        if key == "x-frame-options" and "frame-ancestors" in csp:
            present = True
        if present:
            out["present"].append(name)
        else:
            out["issues"].append({"header": name, "severity": sev, "why": why})

    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = headers.get(name.lower())
        if val and any(ch.isdigit() for ch in val):
            out["disclosure"].append({"header": name, "value": val[:120]})

    emit(
        on_progress,
        f"[WEBCHECK] Headers: {len(out['present'])} present, {len(out['issues'])} missing, "
        f"{len(out['disclosure'])} version disclosure(s)",
    )
    return out


# ---------------- TLS ----------------

def _fill_cert(out: Dict[str, Any], cert: Dict[str, Any]) -> None:
    if not cert:
        return
    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        out["not_after"] = expires.strftime("%Y-%m-%d")
        out["days_left"] = (expires - datetime.now(timezone.utc)).days

    def flat(name: str) -> str:
        parts = []
        for rdn in cert.get(name, ()):
            for key, value in rdn:
                if key in ("commonName", "organizationName"):
                    parts.append(value)
        return ", ".join(parts)

    out["issuer"] = flat("issuer")
    out["subject"] = flat("subject")


def check_tls(base: str, on_progress: ProgressCallback = None) -> Dict[str, Any]:
    p = urlparse(base)
    host = p.hostname
    port = p.port or 443
    out: Dict[str, Any] = {
        "host": host,
        "port": port,
        "reachable": False,
        "trusted": None,
        "expired": False,
        "verify_error": None,
        "protocol": None,
        "cipher": None,
        "not_after": None,
        "days_left": None,
        "issuer": None,
        "subject": None,
        "error": None,
    }
    if not host:
        out["error"] = "no host"
        return out
    emit(on_progress, f"[WEBCHECK] Checking TLS on {host}:{port}")

    # 1) Normal connection - the certificate must be valid and trusted
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["reachable"] = True
                out["trusted"] = True
                out["protocol"] = ssock.version()
                cipher = ssock.cipher()
                out["cipher"] = cipher[0] if cipher else None
                _fill_cert(out, ssock.getpeercert())
        emit(on_progress, f"[WEBCHECK] TLS ok: {out['protocol']}, {out['days_left']} day(s) left")
        return out
    except ssl.SSLCertVerificationError as exc:
        out["trusted"] = False
        out["verify_error"] = getattr(exc, "verify_message", None) or str(exc)
        out["expired"] = "expired" in out["verify_error"].lower()
    except (OSError, ssl.SSLError) as exc:
        out["error"] = str(exc)
        emit(on_progress, f"[WEBCHECK] TLS connection failed: {exc}")
        return out

    # 2) Certificate failed verification - connect again without checks to read the protocol
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["reachable"] = True
                out["protocol"] = ssock.version()
                cipher = ssock.cipher()
                out["cipher"] = cipher[0] if cipher else None
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    emit(on_progress, f"[WEBCHECK] TLS certificate problem: {out['verify_error']}")
    return out


# ---------------- Exposed files ----------------

def _v_git_head(b: bytes, c: str) -> bool:
    return b.startswith(b"ref:")


def _v_git_config(b: bytes, c: str) -> bool:
    return b"[core]" in b


def _v_env(b: bytes, c: str) -> bool:
    return (not _is_html(b, c)) and b"=" in b


def _v_zip(b: bytes, c: str) -> bool:
    return b.startswith(b"PK")


def _v_sql(b: bytes, c: str) -> bool:
    low = b.lower()
    return (not _is_html(b, c)) and any(
        k in low for k in (b"create table", b"insert into", b"mysql dump", b"-- dump")
    )


def _v_phpinfo(b: bytes, c: str) -> bool:
    low = b.lower()
    return b"phpinfo" in low or b"php version" in low


def _v_status(b: bytes, c: str) -> bool:
    return b"apache server status" in b.lower()


def _v_dsstore(b: bytes, c: str) -> bool:
    return b.startswith(b"\x00\x00\x00\x01Bud1")


def _v_wpconfig(b: bytes, c: str) -> bool:
    return b"DB_PASSWORD" in b or b"DB_NAME" in b


def _v_php(b: bytes, c: str) -> bool:
    return b"<?php" in b.lower()


# (path, severity, label, validator). A hit needs HTTP 200 AND matching content,
# so sites that answer 200 for every URL do not create false alarms.
EXPOSED_CHECKS = [
    ("/.git/HEAD", "High", "Git repository metadata", _v_git_head),
    ("/.git/config", "High", "Git configuration", _v_git_config),
    ("/.env", "High", "Environment file", _v_env),
    ("/backup.zip", "High", "Backup archive", _v_zip),
    ("/backup.sql", "High", "Database dump", _v_sql),
    ("/db.sql", "High", "Database dump", _v_sql),
    ("/wp-config.php.bak", "High", "WordPress config backup", _v_wpconfig),
    ("/config.php.bak", "High", "PHP config backup", _v_php),
    ("/phpinfo.php", "Medium", "PHP info page", _v_phpinfo),
    ("/server-status", "Medium", "Apache status page", _v_status),
    ("/.DS_Store", "Low", "macOS folder metadata", _v_dsstore),
]


def _probe(base: str, path: str, limiter: Optional[RateLimiter]) -> Tuple[int, str, bytes]:
    """GET a path and read at most 2 KB. Redirects are not followed."""
    (limiter or default_limiter).wait()
    resp = requests.get(
        base + path,
        headers={"User-Agent": settings.user_agent, "Accept": "*/*"},
        timeout=settings.http_timeout,
        verify=False,
        allow_redirects=False,
        stream=True,
    )
    try:
        status = resp.status_code
        ctype = resp.headers.get("Content-Type", "")
        chunk = b""
        if status == 200:
            chunk = next(resp.iter_content(2048), b"") or b""
        return status, ctype, chunk
    finally:
        resp.close()


def check_exposed_files(
    base: str,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    emit(on_progress, f"[WEBCHECK] Checking {len(EXPOSED_CHECKS)} common sensitive paths on {base}")
    out: Dict[str, Any] = {
        "exposed": [],
        "checked": 0,
        "robots_txt": False,
        "security_txt": False,
        "errors": 0,
    }
    for path, sev, label, validator in EXPOSED_CHECKS:
        try:
            status, ctype, chunk = _probe(base, path, limiter)
        except Exception:  # noqa: BLE001
            out["errors"] += 1
            continue
        out["checked"] += 1
        if status == 200 and validator(chunk, ctype):
            out["exposed"].append(
                {"path": path, "severity": sev, "label": label, "status": status, "content_type": ctype[:60]}
            )
            emit(on_progress, f"[WEBCHECK] EXPOSED: {path} ({label})")

    for path, key in (("/robots.txt", "robots_txt"), ("/.well-known/security.txt", "security_txt")):
        try:
            status, ctype, chunk = _probe(base, path, limiter)
            out[key] = status == 200 and len(chunk) > 0 and not _is_html(chunk, ctype)
        except Exception:  # noqa: BLE001
            out["errors"] += 1

    emit(on_progress, f"[WEBCHECK] Exposed files found: {len(out['exposed'])}")
    return out


# ---------------- Orchestration ----------------

def run_web_checks(
    target: str,
    *,
    do_exposed: bool = True,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    base = _base_url(target)
    emit(on_progress, f"[WEBCHECK] === Starting web security checks for {base} ===")

    headers = check_security_headers(base, on_progress, limiter)
    if headers.get("error") and base.startswith("https://"):
        alt = "http://" + base[len("https://"):]
        emit(on_progress, "[WEBCHECK] HTTPS failed, trying plain HTTP")
        retry = check_security_headers(alt, on_progress, limiter)
        if not retry.get("error"):
            headers = retry
            base = alt

    tls = check_tls("https://" + urlparse(base).netloc, on_progress)
    exposed = check_exposed_files(base, on_progress, limiter) if do_exposed else None

    summary = {
        "missing_headers": len(headers.get("issues") or []),
        "tls_trusted": tls.get("trusted"),
        "tls_days_left": tls.get("days_left"),
        "exposed_files": len((exposed or {}).get("exposed") or []),
    }
    emit(on_progress, f"[WEBCHECK] === Web security checks complete for {base} ===")
    return {"base_url": base, "headers": headers, "tls": tls, "exposed": exposed, "summary": summary}


def build_findings(data: Dict[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Turn results into (title, severity, data) tuples for the scanner to save."""
    items: List[Tuple[str, str, Dict[str, Any]]] = []

    hdr = data.get("headers") or {}
    if hdr.get("error"):
        items.append(("Security headers: site not reachable", "Info", hdr))
    else:
        for issue in hdr.get("issues") or []:
            items.append(
                (f"Missing security header: {issue['header']}", issue["severity"],
                 {**issue, "url": hdr.get("final_url")})
            )
        if hdr.get("present"):
            items.append(
                (f"Security headers present ({len(hdr['present'])})", "Info",
                 {"present": hdr["present"], "url": hdr.get("final_url")})
            )
        for d in hdr.get("disclosure") or []:
            items.append((f"Version disclosure in {d['header']} header", "Low", d))

    tls = data.get("tls") or {}
    days = tls.get("days_left")
    if not tls.get("reachable"):
        items.append(("HTTPS (port 443) not reachable", "Medium", tls))
    elif tls.get("expired"):
        items.append(("TLS certificate expired", "High", tls))
    elif tls.get("trusted") is False:
        items.append(("TLS certificate not trusted", "Medium", tls))
    elif days is not None and days <= 30:
        items.append((f"TLS certificate expires in {days} days", "Medium", tls))
    else:
        items.append((f"TLS certificate valid ({days} days left)", "Info", tls))
    if tls.get("protocol") in ("SSLv3", "TLSv1", "TLSv1.1"):
        items.append((f"Weak TLS protocol negotiated: {tls['protocol']}", "High", tls))

    ex = data.get("exposed")
    if ex is not None:
        for item in ex.get("exposed") or []:
            items.append((f"Exposed file: {item['path']} ({item['label']})", item["severity"], item))
        if not ex.get("exposed"):
            items.append(
                (f"No common sensitive files exposed ({ex.get('checked', 0)} paths checked)", "Info",
                 {"checked": ex.get("checked")})
            )
        items.append(
            ("security.txt found" if ex.get("security_txt") else "security.txt not found", "Info",
             {"security_txt": ex.get("security_txt")})
        )
        if ex.get("robots_txt"):
            items.append(("robots.txt found", "Info", {"robots_txt": True}))

    return items


if __name__ == "__main__":
    import json
    import sys

    tgt = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = run_web_checks(tgt, on_progress=print)
    print(json.dumps(result, indent=2, default=str))
    for t, s, _ in build_findings(result):
        print(f"[{s}] {t}")
