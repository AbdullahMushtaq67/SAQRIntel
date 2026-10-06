"""
Web reconnaissance / fuzzer module.

- Technology fingerprinting (headers, cookies, meta generator)
- Bounded-depth crawler with sensitive-extension detection + email harvest
- Directory/file fuzzer with live progress callbacks
"""

from __future__ import annotations

import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from backend.core.audit_log import ProgressCallback, emit
from backend.core.http_client import http_get
from backend.core.rate_limiter import RateLimiter, default_limiter
from backend.modules.email_osint import extract_emails_from_text

SENSITIVE_EXTS = (".pdf", ".xls", ".xlsx", ".sql", ".bak", ".env", ".zip", ".tar", ".gz", ".cfg", ".ini", ".yml")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def _normalize_base(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/") + "/"


def fingerprint(
    url: str,
    *,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """WhatWeb-style summary from headers + HTML."""
    url = _normalize_base(url).rstrip("/")
    emit(on_progress, f"[WEB] Fingerprinting {url}")
    result: Dict[str, Any] = {
        "url": url,
        "status": None,
        "server": None,
        "x_powered_by": None,
        "cookies": [],
        "generator": None,
        "technologies": [],
        "headers": {},
        "error": None,
    }
    try:
        resp = http_get(url, limiter=limiter or default_limiter, verify=False, timeout=15.0)
        result["status"] = resp.status_code
        headers = {k: v for k, v in resp.headers.items()}
        result["headers"] = headers
        result["server"] = headers.get("Server") or headers.get("server")
        result["x_powered_by"] = headers.get("X-Powered-By") or headers.get("x-powered-by")
        # Cookies
        if resp.cookies:
            result["cookies"] = [f"{c.name}" for c in resp.cookies]
        elif "Set-Cookie" in headers:
            result["cookies"] = [headers["Set-Cookie"][:120]]

        soup = BeautifulSoup(resp.text, "lxml")
        gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if gen and gen.get("content"):
            result["generator"] = gen["content"]

        techs = []
        if result["server"]:
            techs.append(f"Server: {result['server']}")
        if result["x_powered_by"]:
            techs.append(f"X-Powered-By: {result['x_powered_by']}")
        if result["generator"]:
            techs.append(f"Generator: {result['generator']}")
        # Simple body hints
        body = resp.text.lower()
        hints = [
            ("wp-content", "WordPress"),
            ("Drupal.settings", "Drupal"),
            ("cdn.shopify.com", "Shopify"),
            ("__next", "Next.js"),
            ("react", "React (hint)"),
            ("laravel", "Laravel (hint)"),
            ("csrf-token", "CSRF token present"),
        ]
        for needle, label in hints:
            if needle.lower() in body or needle in resp.text:
                techs.append(label)
        result["technologies"] = sorted(set(techs))
        emit(on_progress, f"[WEB] Tech: {', '.join(result['technologies']) or 'unknown'}")
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        emit(on_progress, f"[WEB] Fingerprint error: {exc}")
    return result


def crawl(
    start_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 50,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """BFS crawl of same-host links up to max_depth / max_pages."""
    start_url = _normalize_base(start_url).rstrip("/")
    parsed_start = urlparse(start_url)
    origin = f"{parsed_start.scheme}://{parsed_start.netloc}"
    emit(on_progress, f"[WEB] Crawling {start_url} (depth={max_depth}, max_pages={max_pages})")

    visited: Set[str] = set()
    internal: Set[str] = set()
    external: Set[str] = set()
    js_files: Set[str] = set()
    sensitive: Set[str] = set()
    emails: Set[str] = set()

    queue: deque = deque([(start_url, 0)])
    lim = limiter or default_limiter

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        emit(on_progress, f"[WEB] Crawl [{depth}] {url}")
        try:
            resp = http_get(url, limiter=lim, verify=False, timeout=12.0)
            emails.update(extract_emails_from_text(resp.text))
            soup = BeautifulSoup(resp.text, "lxml")

            # Scripts
            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                js_files.add(src)

            for tag, attr in (("a", "href"), ("link", "href"), ("iframe", "src")):
                for el in soup.find_all(tag):
                    href = el.get(attr)
                    if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                        continue
                    absolute = urljoin(url, href).split("#")[0]
                    lower = absolute.lower()
                    if any(lower.endswith(ext) for ext in SENSITIVE_EXTS):
                        sensitive.add(absolute)
                    p = urlparse(absolute)
                    if p.netloc == parsed_start.netloc:
                        internal.add(absolute)
                        if depth < max_depth and absolute not in visited:
                            # Only enqueue HTML-ish paths
                            if not any(lower.endswith(ext) for ext in (".png", ".jpg", ".gif", ".css", ".woff", ".ico")):
                                queue.append((absolute, depth + 1))
                    elif p.scheme in ("http", "https"):
                        external.add(absolute)
        except Exception as exc:  # noqa: BLE001
            emit(on_progress, f"[WEB] Crawl error {url}: {exc}")

    emit(
        on_progress,
        f"[WEB] Crawl done: {len(visited)} pages, {len(internal)} internal, "
        f"{len(sensitive)} sensitive, {len(emails)} emails",
    )
    return {
        "start_url": start_url,
        "pages_visited": sorted(visited),
        "internal_urls": sorted(internal),
        "external_urls": sorted(external)[:200],
        "js_files": sorted(js_files),
        "sensitive_files": sorted(sensitive),
        "emails": sorted(emails),
        "stats": {
            "visited": len(visited),
            "internal": len(internal),
            "external": len(external),
            "js": len(js_files),
            "sensitive": len(sensitive),
            "emails": len(emails),
        },
    }


def fuzz_paths(
    base_url: str,
    wordlist_path: str,
    *,
    threads: int = 10,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """
    Directory/file fuzzer. Reports non-404 responses with status + length.
    Progress is streamed via on_progress for WebSocket live updates.
    """
    base = _normalize_base(base_url)
    emit(on_progress, f"[WEB] Fuzzing {base} with {wordlist_path}")
    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
            words = [w.strip().lstrip("/") for w in fh if w.strip() and not w.startswith("#")]
    except OSError as exc:
        emit(on_progress, f"[WEB] Wordlist error: {exc}")
        return {"base_url": base, "hits": [], "error": str(exc)}

    hits: List[Dict[str, Any]] = []
    lim = limiter or default_limiter
    total = len(words)
    done = 0

    def probe(path: str) -> Optional[Dict[str, Any]]:
        url = urljoin(base, path)
        try:
            resp = http_get(url, limiter=lim, verify=False, timeout=8.0, allow_redirects=False)
            code = resp.status_code
            # Misses: 404 and soft-404-ish empty redirects
            if code == 404:
                return None
            # CDN catch-alls often 301/302/307/308 every unknown path — not real finds
            if 300 <= code < 400:
                return None
            return {
                "path": path,
                "url": url,
                "status": code,
                "length": len(resp.content),
            }
        except Exception:  # noqa: BLE001
            return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(probe, w): w for w in words}
        for fut in as_completed(futures):
            done += 1
            hit = fut.result()
            if hit:
                hits.append(hit)
                emit(
                    on_progress,
                    f"[WEB] Fuzz hit [{done}/{total}] {hit['status']} {hit['path']} ({hit['length']}b)",
                )
            elif done % 25 == 0 or done == total:
                emit(on_progress, f"[WEB] Fuzz progress {done}/{total}")

    hits.sort(key=lambda h: (h["status"], h["path"]))
    emit(on_progress, f"[WEB] Fuzz complete: {len(hits)} interesting (non-404/non-3xx) response(s)")
    return {"base_url": base, "tested": total, "hits": hits}


def run_web_recon(
    url: str,
    *,
    wordlist_path: Optional[str] = None,
    max_depth: int = 2,
    max_pages: int = 50,
    threads: int = 10,
    do_fuzz: bool = True,
    on_progress: ProgressCallback = None,
    limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """Full web module pipeline."""
    emit(on_progress, f"[WEB] === Starting web recon for {url} ===")
    fp = fingerprint(url, on_progress=on_progress, limiter=limiter)
    crawled = crawl(
        url,
        max_depth=max_depth,
        max_pages=max_pages,
        on_progress=on_progress,
        limiter=limiter,
    )
    fuzz = None
    if do_fuzz and wordlist_path:
        fuzz = fuzz_paths(
            url,
            wordlist_path,
            threads=threads,
            on_progress=on_progress,
            limiter=limiter,
        )
    emit(on_progress, "[WEB] === Web recon complete ===")
    return {"fingerprint": fp, "crawl": crawled, "fuzz": fuzz}


if __name__ == "__main__":
    import json
    import sys

    u = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(fingerprint(u, on_progress=print), indent=2, default=str))
