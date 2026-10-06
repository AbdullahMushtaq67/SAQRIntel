"""
Scan orchestrator — runs selected modules, persists findings/logs, streams progress.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.rate_limiter import RateLimiter
from backend.db import models
from backend.modules import compliance, dns_recon, email_osint, network_map, web_checks, web_fuzzer

# Modules that actively probe the target (need explicit authorization)
ACTIVE_MODULES = {"network", "web", "webcheck"}


def _add_finding(
    db: Session,
    workspace_id: int,
    target_id: Optional[int],
    scan_id: int,
    module: str,
    title: str,
    severity: str,
    data: Dict[str, Any],
) -> models.Finding:
    controls = compliance.map_finding(module, title, severity)
    if controls and isinstance(data, dict):
        data = {**data, "compliance": controls}
    f = models.Finding(
        workspace_id=workspace_id,
        target_id=target_id,
        scan_id=scan_id,
        module=module,
        title=title,
        severity=severity,
        data_json=data,
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def _add_log(
    db: Session,
    workspace_id: int,
    scan_id: int,
    module: str,
    message: str,
    on_progress: Optional[Callable[[str], None]] = None,
) -> None:
    if on_progress:
        on_progress(message)
    db.add(
        models.ScanLog(
            workspace_id=workspace_id,
            scan_id=scan_id,
            module=module,
            message=message,
        )
    )
    db.commit()


def persist_dns_findings(db, workspace_id, target_id, scan_id, data: Dict[str, Any]) -> None:
    whois = data.get("whois") or {}
    _add_finding(
        db, workspace_id, target_id, scan_id, "dns",
        f"WHOIS: {data.get('domain')}",
        "Info",
        whois,
    )
    _add_finding(
        db, workspace_id, target_id, scan_id, "dns",
        f"DNS records for {data.get('domain')}",
        "Info",
        data.get("records") or {},
    )
    if data.get("subdomains_ct"):
        _add_finding(
            db, workspace_id, target_id, scan_id, "dns",
            f"Certificate transparency subdomains ({len(data['subdomains_ct'])})",
            "Low",
            {"subdomains": data["subdomains_ct"]},
        )
    if data.get("subdomains_brute"):
        _add_finding(
            db, workspace_id, target_id, scan_id, "dns",
            f"Brute-forced subdomains ({len(data['subdomains_brute'])})",
            "Low",
            {"hits": data["subdomains_brute"]},
        )
    for ax in data.get("axfr") or []:
        sev = "High" if ax.get("vulnerable") else "Info"
        title = (
            f"Zone transfer OPEN on {ax.get('nameserver')}"
            if ax.get("vulnerable")
            else f"Zone transfer refused on {ax.get('nameserver')} (secure)"
        )
        _add_finding(db, workspace_id, target_id, scan_id, "dns", title, sev, ax)
    dnssec = data.get("dnssec") or {}
    _add_finding(
        db, workspace_id, target_id, scan_id, "dns",
        "DNSSEC present" if dnssec.get("dnssec_present") else "DNSSEC not detected",
        "Info" if dnssec.get("dnssec_present") else "Low",
        dnssec,
    )
    if data.get("reverse_dns"):
        _add_finding(
            db, workspace_id, target_id, scan_id, "dns",
            "Reverse DNS (PTR) map",
            "Info",
            data["reverse_dns"],
        )


def persist_email_findings(db, workspace_id, target_id, scan_id, data: Dict[str, Any]) -> None:
    _add_finding(
        db, workspace_id, target_id, scan_id, "email",
        "Unverified corporate email format guesses",
        "Info",
        {"guesses": data.get("format_guesses"), "note": "Unverified — not confirmed mailboxes"},
    )
    scraped = data.get("scraped_emails") or {}
    if scraped.get("emails"):
        _add_finding(
            db, workspace_id, target_id, scan_id, "email",
            f"Emails extracted from pages ({scraped.get('count', 0)})",
            "Medium",
            scraped,
        )

    has_mx = bool(data.get("has_mx"))
    mx_records = data.get("mx_records") or []
    _add_finding(
        db, workspace_id, target_id, scan_id, "email",
        f"MX records: {len(mx_records)} published" if has_mx else "No MX records published",
        "Info",
        {"has_mx": has_mx, "mx_records": mx_records},
    )

    spf = data.get("spf") or {}
    # Prefer module-computed MX-aware severity; fall back to legacy map
    sev = spf.get("severity") or {
        "Strict": "Info",
        "Moderate": "Low",
        "Permissive": "Medium",
        "Missing": "High" if has_mx else "Medium",
    }.get(spf.get("strength"), "Info")
    _add_finding(
        db, workspace_id, target_id, scan_id, "email",
        f"SPF: {spf.get('strength', 'unknown')}",
        sev,
        spf,
    )
    dmarc = data.get("dmarc") or {}
    sev = dmarc.get("severity") or {
        "Strict": "Info",
        "Moderate": "Low",
        "Permissive": "Medium",
        "Missing": "High" if has_mx else "Medium",
    }.get(dmarc.get("strength"), "Info")
    _add_finding(
        db, workspace_id, target_id, scan_id, "email",
        f"DMARC: {dmarc.get('strength', 'unknown')} (p={dmarc.get('policy')})",
        sev,
        dmarc,
    )
    hibp = data.get("hibp_password")
    if hibp:
        sev = "High" if hibp.get("pwned") else "Info"
        _add_finding(
            db, workspace_id, target_id, scan_id, "email",
            "HIBP pwned password check (k-anonymity)",
            sev,
            hibp,
        )


def persist_network_findings(db, workspace_id, target_id, scan_id, data: Dict[str, Any]) -> None:
    scan = data.get("scan") or {}
    ports = scan.get("ports") or []
    _add_finding(
        db, workspace_id, target_id, scan_id, "network",
        f"Open ports on {scan.get('ip')} ({len(ports)})",
        "Medium" if ports else "Info",
        scan,
    )
    for p in ports:
        _add_finding(
            db, workspace_id, target_id, scan_id, "network",
            f"Open {p.get('port')}/{p.get('protocol')} — {p.get('service')} {p.get('banner')}".strip(),
            "Low",
            p,
        )
    asn = data.get("asn") or {}
    if asn:
        _add_finding(
            db, workspace_id, target_id, scan_id, "network",
            f"ASN/Org: {asn.get('orgname') or asn.get('asn') or 'unknown'}",
            "Info",
            asn,
        )
    if data.get("graph"):
        _add_finding(
            db, workspace_id, target_id, scan_id, "network",
            "Network graph snapshot",
            "Info",
            data["graph"],
        )


def persist_web_findings(db, workspace_id, target_id, scan_id, data: Dict[str, Any]) -> None:
    fp = data.get("fingerprint") or {}
    _add_finding(
        db, workspace_id, target_id, scan_id, "web",
        f"Technology fingerprint: {', '.join(fp.get('technologies') or []) or 'n/a'}",
        "Info",
        fp,
    )
    crawl = data.get("crawl") or {}
    stats = crawl.get("stats") or {}
    _add_finding(
        db, workspace_id, target_id, scan_id, "web",
        f"Crawl: {stats.get('visited', 0)} pages, {stats.get('sensitive', 0)} sensitive files",
        "Medium" if stats.get("sensitive") else "Info",
        crawl,
    )
    if crawl.get("emails"):
        _add_finding(
            db, workspace_id, target_id, scan_id, "web",
            f"Emails found while crawling ({len(crawl['emails'])})",
            "Medium",
            {"emails": crawl["emails"]},
        )
    fuzz = data.get("fuzz")
    if fuzz:
        hits = fuzz.get("hits") or []
        _add_finding(
            db, workspace_id, target_id, scan_id, "web",
            f"Fuzzer hits: {len(hits)} non-404 path(s)",
            "Medium" if hits else "Info",
            fuzz,
        )


def run_scan(
    db: Session,
    workspace_id: int,
    target_value: str,
    modules: List[str],
    *,
    authorized: bool = False,
    options: Optional[Dict[str, Any]] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> models.Scan:
    """
    Execute selected modules sequentially and stream progress.
    Active modules (network, web) require authorized=True.
    """
    options = options or {}
    mods = [m.lower() for m in modules]

    # Authorization gate
    needs_auth = sorted(set(mods) & ACTIVE_MODULES)
    if needs_auth and not authorized:
        raise PermissionError(
            f"Authorization required for active modules: {', '.join(needs_auth)}. "
            "Confirm you have permission to test this target."
        )

    # Ensure target row
    target = (
        db.query(models.Target)
        .filter_by(workspace_id=workspace_id, value=target_value)
        .first()
    )
    if not target:
        ttype = "url" if target_value.startswith("http") else (
            "ip" if target_value.replace(".", "").isdigit() else "domain"
        )
        target = models.Target(workspace_id=workspace_id, value=target_value, target_type=ttype)
        db.add(target)
        db.commit()
        db.refresh(target)

    scan = models.Scan(
        workspace_id=workspace_id,
        target_value=target_value,
        modules=mods,
        status="running",
        authorized=authorized,
        started_at=datetime.now(timezone.utc),
        summary_json={},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    rate = float(options.get("rate_limit_rps", settings.rate_limit_rps))
    threads = int(options.get("thread_count", settings.thread_count))
    limiter = RateLimiter(rate)
    host_map: Dict[str, List[str]] = {}
    summary: Dict[str, Any] = {}

    def log(module: str, msg: str) -> None:
        _add_log(db, workspace_id, scan.id, module, msg, on_progress)

    try:
        log("system", f"Scan #{scan.id} started for {target_value} modules={mods}")

        if "dns" in mods:
            log("dns", "Running DNS reconnaissance module")
            dns_data = dns_recon.run_dns_recon(
                target_value,
                wordlist_path=options.get("subdomain_wordlist", settings.subdomain_wordlist),
                threads=threads,
                do_brute=bool(options.get("dns_brute", True)),
                on_progress=lambda m: log("dns", m),
                limiter=limiter,
            )
            host_map = dns_data.get("host_map") or {}
            persist_dns_findings(db, workspace_id, target.id, scan.id, dns_data)
            summary["dns"] = {
                "subdomains": len(dns_data.get("subdomains_ct") or []),
                "hosts_resolved": len(host_map),
            }

        if "email" in mods:
            log("email", "Running email OSINT module")
            urls = options.get("urls") or []
            email_data = email_osint.run_email_osint(
                target_value,
                urls=urls,
                password_to_check=options.get("password_check"),
                on_progress=lambda m: log("email", m),
                limiter=limiter,
            )
            persist_email_findings(db, workspace_id, target.id, scan.id, email_data)
            summary["email"] = {
                "scraped": (email_data.get("scraped_emails") or {}).get("count", 0),
                "spf": (email_data.get("spf") or {}).get("strength"),
                "dmarc": (email_data.get("dmarc") or {}).get("strength"),
            }

        if "network" in mods:
            log("network", "Running network mapping module (authorized)")
            net_data = network_map.run_network_map(
                target_value,
                ports=options.get("nmap_ports", settings.nmap_ports),
                timing=options.get("nmap_timing", settings.nmap_timing),
                host_map=host_map or None,
                on_progress=lambda m: log("network", m),
            )
            persist_network_findings(db, workspace_id, target.id, scan.id, net_data)
            summary["network"] = {
                "ip": (net_data.get("scan") or {}).get("ip"),
                "open_ports": len((net_data.get("scan") or {}).get("ports") or []),
                "graph_nodes": len((net_data.get("graph") or {}).get("nodes") or []),
            }

        if "web" in mods:
            log("web", "Running web recon / fuzzer module (authorized)")
            web_url = target_value if target_value.startswith("http") else f"https://{target_value}"
            web_data = web_fuzzer.run_web_recon(
                web_url,
                wordlist_path=options.get("fuzzer_wordlist", settings.fuzzer_wordlist),
                max_depth=int(options.get("crawl_max_depth", settings.crawl_max_depth)),
                max_pages=int(options.get("crawl_max_pages", settings.crawl_max_pages)),
                threads=threads,
                do_fuzz=bool(options.get("do_fuzz", True)),
                on_progress=lambda m: log("web", m),
                limiter=limiter,
            )
            persist_web_findings(db, workspace_id, target.id, scan.id, web_data)
            # Feed crawl URLs back for email if both ran — already handled separately
            summary["web"] = (web_data.get("crawl") or {}).get("stats") or {}

        if "webcheck" in mods:
            log("webcheck", "Running web security checks (authorized)")
            wc_data = web_checks.run_web_checks(
                target_value,
                do_exposed=bool(options.get("do_exposed", True)),
                on_progress=lambda m: log("webcheck", m),
                limiter=limiter,
            )
            for w_title, w_sev, w_data in web_checks.build_findings(wc_data):
                _add_finding(db, workspace_id, target.id, scan.id, "webcheck", w_title, w_sev, w_data)
            summary["webcheck"] = wc_data.get("summary") or {}

        scan_findings = db.query(models.Finding).filter_by(scan_id=scan.id).all()
        summary["risk"] = compliance.calculate_risk([f.severity for f in scan_findings])
        scan.status = "completed"
        scan.finished_at = datetime.now(timezone.utc)
        scan.summary_json = summary
        db.commit()
        log("system", f"Scan #{scan.id} completed successfully")
    except Exception as exc:  # noqa: BLE001
        scan.status = "failed"
        scan.finished_at = datetime.now(timezone.utc)
        scan.summary_json = {**summary, "error": str(exc)}
        db.commit()
        log("system", f"Scan #{scan.id} failed: {exc}")
        raise

    db.refresh(scan)
    return scan
