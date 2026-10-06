"""
Reporting module — aggregate findings into PDF (fpdf2) and JSON.

fpdf2 is used instead of WeasyPrint to avoid system Cairo/Pango deps on Kali.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fpdf import FPDF

from backend.core.audit_log import ProgressCallback, emit
from backend.core.config import REPORTS_DIR, ensure_directories
from backend.modules import compliance


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


class SAQRIntelPDF(FPDF):
    """Simple branded PDF with page numbers."""

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "SAQRIntel OSINT Report - Authorized Use Only", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def _safe(text: Any, limit: int = 200) -> str:
    s = str(text) if text is not None else ""
    # Normalize common Unicode punctuation so Helvetica (latin-1) can render it
    replacements = {
        "\u2014": "-",  # em dash
        "\u2013": "-",  # en dash
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
    }
    for src, dst in replacements.items():
        s = s.replace(src, dst)
    # Collapse json.dumps unicode escapes that already used ASCII-safe form
    s = s.replace("\\u2014", "-").replace("\\u2013", "-")
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _wrap_pdf(text: str, max_token: int = 72) -> str:
    """
    Soft-wrap only unbroken tokens longer than max_token.
    Do NOT slice the whole string every N chars (that garbled Cheezious PDFs).
    """
    parts: List[str] = []
    for token in text.split(" "):
        if len(token) <= max_token:
            parts.append(token)
            continue
        chunks = [token[i : i + max_token] for i in range(0, len(token), max_token)]
        parts.append(" ".join(chunks))
    return " ".join(parts)


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def generate_json_report(
    workspace_name: str,
    target: str,
    findings: List[Dict[str, Any]],
    scan_logs: List[Dict[str, Any]],
    out_path: Optional[Path] = None,
) -> Path:
    ensure_directories()
    payload = {
        "tool": "SAQRIntel",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": workspace_name,
        "target": target,
        "severity_counts": severity_counts(findings),
        "risk": compliance.calculate_risk([f.get("severity", "Info") for f in findings]),
        "findings": findings,
        "audit_log": scan_logs,
        "disclaimer": "Authorized security testing and OSINT research only.",
    }
    if out_path is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_ws = "".join(c if c.isalnum() or c in "-_" else "_" for c in workspace_name)
        out_path = REPORTS_DIR / f"saqrintel_{safe_ws}_{stamp}.json"
    out_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return out_path


def generate_pdf_report(
    workspace_name: str,
    target: str,
    findings: List[Dict[str, Any]],
    scan_logs: List[Dict[str, Any]],
    *,
    out_path: Optional[Path] = None,
    on_progress: ProgressCallback = None,
) -> Path:
    """
    PDF structure:
      1. Cover (target, date, workspace)
      2. Executive summary (counts by severity)
      3. One section per module with findings table
      4. Audit log appendix
    """
    emit(on_progress, "[REPORT] Generating PDF")
    ensure_directories()
    if out_path is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_ws = "".join(c if c.isalnum() or c in "-_" else "_" for c in workspace_name)
        out_path = REPORTS_DIR / f"saqrintel_{safe_ws}_{stamp}.pdf"

    pdf = SAQRIntelPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)

    # --- Cover ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(160, 30, 35)
    pdf.ln(40)
    pdf.cell(0, 14, "SAQRINTEL", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(60, 40, 40)
    pdf.cell(0, 10, "OSINT & Reconnaissance Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(0, 0, 0)
    for label, value in (
        ("Workspace", workspace_name),
        ("Target", target),
        ("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
    ):
        pdf.cell(0, 9, f"{label}: {_safe(value, 80)}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(30)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(150, 40, 40)
    pdf.multi_cell(
        0,
        6,
        _safe(
            "AUTHORIZED USE ONLY - This report was produced for authorized security "
            "testing and OSINT research. Unauthorized scanning may be illegal."
        ),
        align="C",
    )

    # --- Executive summary ---
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "1. Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    counts = severity_counts(findings)
    pdf.ln(4)
    pdf.multi_cell(
        0,
        7,
        f"Total findings: {len(findings)}.  "
        f"High: {counts.get('High', 0)}  |  Medium: {counts.get('Medium', 0)}  |  "
        f"Low: {counts.get('Low', 0)}  |  Info: {counts.get('Info', 0)}",
    )
    pdf.ln(4)
    # Simple bar-like lines
    for sev, color in (("High", (180, 40, 40)), ("Medium", (200, 120, 30)), ("Low", (60, 100, 160)), ("Info", (80, 80, 80))):
        pdf.set_text_color(*color)
        pdf.cell(0, 7, f"  {sev}: {counts.get(sev, 0)}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    # --- Risk and compliance ---
    risk = compliance.calculate_risk([f.get("severity", "Info") for f in findings])
    risk_score = risk["score"]
    risk_rating = risk["rating"]
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "2. Risk Score and Compliance Mapping", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    risk_colors = {
        "Critical": (160, 20, 30),
        "High": (190, 60, 40),
        "Moderate": (200, 130, 30),
        "Low": (40, 130, 70),
    }
    bar_color = risk_colors.get(risk_rating, (0, 0, 0))
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*bar_color)
    pdf.cell(0, 9, f"Overall risk score: {risk_score}/100 ({risk_rating})", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(
        0,
        5,
        "The score runs from 0 (lowest risk) to 100 (highest risk). It is based on the "
        "number and severity of findings. Severity changes made in the dashboard are included.",
    )
    pdf.set_x(pdf.l_margin)
    pdf.ln(3)
    bar_y = pdf.get_y()
    pdf.set_fill_color(225, 225, 225)
    pdf.rect(pdf.l_margin, bar_y, 150, 6, "F")
    pdf.set_fill_color(*bar_color)
    pdf.rect(pdf.l_margin, bar_y, 150 * risk_score / 100, 6, "F")
    pdf.ln(12)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Controls affected by findings", new_x="LMARGIN", new_y="NEXT")
    control_map = {}
    for f in findings:
        if f.get("severity", "Info") == "Info":
            continue
        d = f.get("data_json") or {}
        if not isinstance(d, dict):
            continue
        for c in d.get("compliance") or []:
            key = (c.get("framework", ""), c.get("control", ""), c.get("name", ""))
            control_map.setdefault(key, []).append(f)
    if not control_map:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, "No findings were mapped to controls.", new_x="LMARGIN", new_y="NEXT")
    else:
        comp_w = (30, 16, 62, 82)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(140, 30, 35)
        pdf.set_text_color(255, 255, 255)
        for w, h in zip(comp_w, ("Framework", "Control", "Control name", "Findings")):
            pdf.cell(w, 8, h, border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 8)
        for (fw, ctl, name), items in sorted(control_map.items()):
            first = _safe(items[0].get("title", ""), 40)
            extra = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
            row = (_safe(fw, 22), _safe(ctl, 10), _safe(name, 42), _safe(first + extra, 58))
            for w, cell in zip(comp_w, row):
                pdf.cell(w, 7, cell, border=1)
            pdf.ln()

    # --- Per-module sections ---
    by_module: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_module.setdefault(f.get("module", "unknown"), []).append(f)

    section_num = 3
    for module, items in sorted(by_module.items()):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"{section_num}. Module: {_safe(module, 40)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        items_sorted = sorted(items, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "Info"), 9))

        # Table header
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(140, 30, 35)
        pdf.set_text_color(255, 255, 255)
        col_w = (28, 95, 25, 42)
        for w, h in zip(col_w, ("ID", "Title", "Severity", "Key Data")):
            pdf.cell(w, 8, h, border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 8)

        for item in items_sorted:
            data_preview = item.get("data_json") or item.get("data") or {}
            if isinstance(data_preview, dict):
                preview = _safe(json.dumps(data_preview, default=str), 55)
            else:
                preview = _safe(data_preview, 55)
            row = (
                _safe(item.get("id", ""), 10),
                _safe(item.get("title", ""), 50),
                _safe(item.get("severity", "Info"), 10),
                preview,
            )
            # Alternate row fill
            for w, cell in zip(col_w, row):
                pdf.cell(w, 7, cell, border=1)
            pdf.ln()
            # Detail paragraph — reset X so multi_cell has full width
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "I", 7)
            detail = _wrap_pdf(_safe(json.dumps(data_preview, default=str, ensure_ascii=True), 400))
            pdf.multi_cell(0, 4, detail)
            pdf.set_font("Helvetica", "", 8)
            pdf.ln(1)
        section_num += 1

    # --- Audit log ---
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(140, 30, 30)
    pdf.cell(0, 10, f"{section_num}. Audit Log Appendix", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 8)
    pdf.ln(2)
    for log in scan_logs[-400:]:  # cap appendix size
        ts = log.get("created_at") or log.get("timestamp") or ""
        msg = log.get("message", "")
        mod = log.get("module", "")
        line = _wrap_pdf(_safe(f"[{ts}] ({mod}) {msg}", 280), max_token=90)
        pdf.set_x(pdf.l_margin)
        try:
            pdf.multi_cell(0, 4, line)
        except Exception:  # noqa: BLE001 — never fail the whole report on one log line
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 4, _safe(line, 100), new_x="LMARGIN", new_y="NEXT")

    pdf.output(str(out_path))
    emit(on_progress, f"[REPORT] PDF written to {out_path}")
    return out_path


def findings_to_dicts(finding_rows: list) -> List[Dict[str, Any]]:
    """Convert SQLAlchemy Finding objects (or dicts) to plain dicts."""
    out = []
    for f in finding_rows:
        if isinstance(f, dict):
            out.append(f)
            continue
        out.append(
            {
                "id": f.id,
                "module": f.module,
                "title": f.title,
                "severity": f.severity,
                "data_json": f.data_json,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
        )
    return out


def logs_to_dicts(log_rows: list) -> List[Dict[str, Any]]:
    out = []
    for log in log_rows:
        if isinstance(log, dict):
            out.append(log)
            continue
        out.append(
            {
                "id": log.id,
                "module": log.module,
                "message": log.message,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
        )
    return out
