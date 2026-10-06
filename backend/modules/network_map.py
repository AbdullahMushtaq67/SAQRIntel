"""
Network mapping module.

- nmap port scan (subprocess / python-nmap) with top-100 default
- Service/version banners when available
- ASN/CIDR WHOIS via IP whois (ARIN/RIPE/APNIC as routed)
- Graph data builder: domain -> subdomain -> IP -> port nodes
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

import whois

from backend.core.audit_log import ProgressCallback, emit

try:
    import nmap as nmap_lib
except ImportError:  # pragma: no cover
    nmap_lib = None


def resolve_target_ip(target: str) -> Optional[str]:
    """Resolve hostname to first IPv4, or return IP if already numeric."""
    target = target.strip()
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        import socket

        return socket.gethostbyname(target)
    except Exception:  # noqa: BLE001
        return None


def port_scan(
    target: str,
    *,
    ports: str = "--top-ports 100",
    timing: str = "T3",
    on_progress: ProgressCallback = None,
) -> Dict[str, Any]:
    """
    Run nmap against target.
    `ports` may be '--top-ports 100', '1-1024', or '22,80,443'.
    Full 1-65535 is allowed but callers should warn about duration.
    """
    emit(on_progress, f"[NET] Port scan starting on {target} ({ports})")
    ip = resolve_target_ip(target)
    if not ip:
        emit(on_progress, f"[NET] Could not resolve {target}")
        return {"target": target, "ip": None, "ports": [], "error": "unresolvable"}

    # Build argument string for python-nmap / subprocess
    if ports.startswith("--"):
        port_args = ports
        port_spec = None
    else:
        port_args = f"-p {ports}"
        port_spec = ports

    open_ports: List[Dict[str, Any]] = []
    raw = ""
    error = None

    if nmap_lib and shutil.which("nmap"):
        try:
            nm = nmap_lib.PortScanner()
            args = f"-sV --version-light -{timing} {port_args}".replace("  ", " ").strip()
            # python-nmap: scan(hosts, ports=None, arguments='-sV')
            if port_spec:
                nm.scan(ip, ports=port_spec, arguments=f"-sV --version-light -{timing}")
            else:
                # top-ports must go in arguments
                nm.scan(ip, arguments=f"-sV --version-light -{timing} {ports}")
            raw = nm.csv() if hasattr(nm, "csv") else ""
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    for port in sorted(nm[ip][proto].keys()):
                        info = nm[ip][proto][port]
                        if info.get("state") == "open":
                            entry = {
                                "port": port,
                                "protocol": proto,
                                "state": "open",
                                "service": info.get("name") or "",
                                "product": info.get("product") or "",
                                "version": info.get("version") or "",
                                "banner": " ".join(
                                    x for x in [info.get("product"), info.get("version"), info.get("extrainfo")] if x
                                ).strip(),
                            }
                            open_ports.append(entry)
                            emit(
                                on_progress,
                                f"[NET] Open {port}/{proto} {entry['service']} {entry['banner']}".strip(),
                            )
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            emit(on_progress, f"[NET] python-nmap error, trying subprocess: {exc}")

    if not open_ports and shutil.which("nmap"):
        # Subprocess fallback
        cmd = ["nmap", "-sV", "--version-light", f"-{timing}"]
        if port_spec:
            cmd += ["-p", port_spec]
        else:
            # ports like "--top-ports 100"
            cmd += ports.split()
        cmd += ["-oG", "-", ip]
        emit(on_progress, f"[NET] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
            raw = proc.stdout
            # Parse greppable: Ports: 22/open/tcp//ssh//, 80/open/tcp//http//
            for line in raw.splitlines():
                if "Ports:" not in line:
                    continue
                ports_part = line.split("Ports:")[-1]
                for chunk in ports_part.split(","):
                    chunk = chunk.strip()
                    m = re.match(
                        r"(\d+)/(open)/(\w+)/.*?/([^/]*)/([^/]*)/",
                        chunk,
                    )
                    if m:
                        port, _state, proto, service, version = m.groups()
                        open_ports.append(
                            {
                                "port": int(port),
                                "protocol": proto,
                                "state": "open",
                                "service": service,
                                "product": "",
                                "version": version,
                                "banner": version,
                            }
                        )
                        emit(on_progress, f"[NET] Open {port}/{proto} {service}")
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            emit(on_progress, f"[NET] nmap subprocess error: {exc}")
    elif not shutil.which("nmap"):
        error = "nmap binary not found on PATH"
        emit(on_progress, f"[NET] {error}")

    emit(on_progress, f"[NET] Scan complete: {len(open_ports)} open port(s) on {ip}")
    return {
        "target": target,
        "ip": ip,
        "ports": open_ports,
        "raw": raw[:5000],
        "error": error,
    }


def asn_whois_lookup(ip: str, on_progress: ProgressCallback = None) -> Dict[str, Any]:
    """
    Query IP WHOIS for NetRange / CIDR / OrgName.
    python-whois talks to the appropriate RIR based on routing.
    """
    emit(on_progress, f"[NET] ASN/CIDR WHOIS for {ip}")
    result: Dict[str, Any] = {
        "ip": ip,
        "netrange": None,
        "cidr": None,
        "orgname": None,
        "asn": None,
        "raw": None,
        "error": None,
    }
    try:
        # Prefer system whois for IP objects — more reliable for RIRs
        if shutil.which("whois"):
            proc = subprocess.run(
                ["whois", ip],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            text = proc.stdout or proc.stderr or ""
            result["raw"] = text[:8000]
            patterns = {
                "netrange": re.compile(r"(?i)^(NetRange|inetnum):\s*(.+)$", re.M),
                "cidr": re.compile(r"(?i)^(CIDR|route|route6):\s*(.+)$", re.M),
                "orgname": re.compile(r"(?i)^(OrgName|org-name|organization|descr):\s*(.+)$", re.M),
                "asn": re.compile(r"(?i)^(OriginAS|origin|aut-num):\s*(.+)$", re.M),
            }
            for key, cre in patterns.items():
                m = cre.search(text)
                if m:
                    result[key] = m.group(2).strip()
            emit(
                on_progress,
                f"[NET] Org={result['orgname'] or '?'} CIDR={result['cidr'] or result['netrange'] or '?'}",
            )
        else:
            w = whois.whois(ip)
            result["raw"] = str(getattr(w, "text", w))[:8000]
            result["orgname"] = getattr(w, "org", None) or getattr(w, "organization", None)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        emit(on_progress, f"[NET] WHOIS error: {exc}")
    return result


def build_network_graph(
    domain: str,
    host_map: Dict[str, List[str]],
    port_results: Optional[Dict[str, Any]] = None,
    asn_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build vis-network compatible {nodes, edges} structure.

    Node types / colors:
      domain    — #1f77b4 (blue)
      subdomain — #2ca02c (green)
      ip        — #ff7f0e (orange)
      port      — #d62728 (red)
      asn       — #9467bd (purple)
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen = set()

    def add_node(nid: str, label: str, group: str, title: str = "") -> None:
        if nid in seen:
            return
        seen.add(nid)
        color = {
            "domain": "#c0392b",
            "subdomain": "#e74c3c",
            "ip": "#f39c12",
            "port": "#922b21",
            "asn": "#a93226",
        }.get(group, "#7f7f7f")
        nodes.append(
            {
                "id": nid,
                "label": label,
                "group": group,
                "title": title or label,
                "color": color,
            }
        )

    root_id = f"domain:{domain}"
    add_node(root_id, domain, "domain", f"Domain: {domain}")

    ip_to_hosts: Dict[str, List[str]] = {}
    for host, ips in (host_map or {}).items():
        host_id = f"host:{host}"
        group = "domain" if host == domain else "subdomain"
        add_node(host_id, host, group, f"Host: {host}")
        if host != domain:
            edges.append({"from": root_id, "to": host_id})
        for ip in ips:
            ip_id = f"ip:{ip}"
            add_node(ip_id, ip, "ip", f"IP: {ip}")
            edges.append({"from": host_id, "to": ip_id})
            ip_to_hosts.setdefault(ip, []).append(host)

    # Attach open ports to the scanned IP
    if port_results and port_results.get("ip"):
        ip = port_results["ip"]
        ip_id = f"ip:{ip}"
        add_node(ip_id, ip, "ip", f"IP: {ip}")
        # Link apex domain if not already
        if ip_id not in {e["to"] for e in edges if e["from"] == root_id}:
            edges.append({"from": root_id, "to": ip_id})
        for p in port_results.get("ports") or []:
            pid = f"port:{ip}:{p['port']}/{p.get('protocol', 'tcp')}"
            label = f"{p['port']}/{p.get('protocol', 'tcp')}"
            title = f"{label} {p.get('service', '')} {p.get('banner', '')}".strip()
            add_node(pid, label, "port", title)
            edges.append({"from": ip_id, "to": pid})

    if asn_info and (asn_info.get("cidr") or asn_info.get("orgname")):
        asn_label = asn_info.get("asn") or asn_info.get("cidr") or "ASN"
        asn_id = f"asn:{asn_label}"
        title = (
            f"Org: {asn_info.get('orgname')}\n"
            f"CIDR: {asn_info.get('cidr')}\n"
            f"NetRange: {asn_info.get('netrange')}"
        )
        add_node(asn_id, str(asn_label)[:40], "asn", title)
        if port_results and port_results.get("ip"):
            edges.append({"from": f"ip:{port_results['ip']}", "to": asn_id})

    return {"nodes": nodes, "edges": edges}


def run_network_map(
    target: str,
    *,
    ports: str = "--top-ports 100",
    timing: str = "T3",
    host_map: Optional[Dict[str, List[str]]] = None,
    on_progress: ProgressCallback = None,
) -> Dict[str, Any]:
    """Full network module: scan + ASN + graph payload."""
    emit(on_progress, f"[NET] === Starting network mapping for {target} ===")
    scan = port_scan(target, ports=ports, timing=timing, on_progress=on_progress)
    asn = asn_whois_lookup(scan["ip"], on_progress) if scan.get("ip") else {}
    domain = target
    # Strip URL bits if a URL was passed
    for p in ("https://", "http://"):
        if domain.startswith(p):
            domain = domain[len(p) :]
    domain = domain.split("/")[0].split(":")[0]

    hm = host_map or ({domain: [scan["ip"]]} if scan.get("ip") else {domain: []})
    graph = build_network_graph(domain, hm, scan, asn)
    emit(on_progress, f"[NET] === Network mapping complete ({len(graph['nodes'])} nodes) ===")
    return {"scan": scan, "asn": asn, "graph": graph}


if __name__ == "__main__":
    import json
    import sys

    t = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    # Lightweight smoke: ASN only if --asn-only
    if "--asn-only" in sys.argv:
        ip = resolve_target_ip(t)
        print(json.dumps(asn_whois_lookup(ip or t, print), indent=2, default=str))
    else:
        print(json.dumps(run_network_map(t, ports="22,80,443", on_progress=print), indent=2, default=str))
