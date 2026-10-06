"""
SAQRIntel FastAPI entrypoint.

Start with:
    cd /path/to/SAQRIntel
    python -m backend.main
or:
    python backend/main.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path when launched as `python backend/main.py`
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from backend.core.config import FRONTEND_DIR, REPORTS_DIR, ensure_directories, settings
from backend.db.database import SessionLocal, get_db, init_db
from backend.db import models
from backend.modules import compliance, report_gen, scanner
from backend.schemas import (
    AUTHORIZATION_ACK,
    FindingOut,
    FindingSeverityUpdate,
    ReportRequest,
    ScanLogOut,
    ScanRequest,
    SettingsUpdate,
    TargetCreate,
    TargetOut,
    WorkspaceCreate,
    WorkspaceOut,
)

# ---------- Settings helpers ----------

DEFAULT_SETTING_KEYS = {
    "rate_limit_rps": str(settings.rate_limit_rps),
    "thread_count": str(settings.thread_count),
    "nmap_ports": settings.nmap_ports,
    "subdomain_wordlist": settings.subdomain_wordlist,
    "fuzzer_wordlist": settings.fuzzer_wordlist,
    "crawl_max_depth": str(settings.crawl_max_depth),
    "crawl_max_pages": str(settings.crawl_max_pages),
    "http_timeout": str(settings.http_timeout),
}


def _load_settings(db: Session) -> Dict[str, str]:
    rows = {r.key: r.value for r in db.query(models.AppSetting).all()}
    merged = dict(DEFAULT_SETTING_KEYS)
    merged.update(rows)
    return merged


def _settings_as_options(db: Session) -> Dict[str, Any]:
    raw = _load_settings(db)
    return {
        "rate_limit_rps": float(raw["rate_limit_rps"]),
        "thread_count": int(raw["thread_count"]),
        "nmap_ports": raw["nmap_ports"],
        "subdomain_wordlist": raw["subdomain_wordlist"],
        "fuzzer_wordlist": raw["fuzzer_wordlist"],
        "crawl_max_depth": int(raw["crawl_max_depth"]),
        "crawl_max_pages": int(raw["crawl_max_pages"]),
        "http_timeout": float(raw["http_timeout"]),
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_directories()
    init_db()
    db = SessionLocal()
    try:
        for k, v in DEFAULT_SETTING_KEYS.items():
            if not db.get(models.AppSetting, k):
                db.add(models.AppSetting(key=k, value=v))
        db.commit()
    finally:
        db.close()
    yield


app = FastAPI(
    title="SAQRIntel",
    description="SAQRIntel - OSINT & reconnaissance framework (authorized use only).",
    version="1.0.0",
    lifespan=lifespan,
)

# ---------- Workspaces ----------

@app.get("/api/workspaces", response_model=List[WorkspaceOut])
def list_workspaces(db: Session = Depends(get_db)):
    return db.query(models.Workspace).order_by(models.Workspace.created_at.desc()).all()


@app.post("/api/workspaces", response_model=WorkspaceOut)
def create_workspace(body: WorkspaceCreate, db: Session = Depends(get_db)):
    if db.query(models.Workspace).filter_by(name=body.name).first():
        raise HTTPException(400, "Workspace name already exists")
    ws = models.Workspace(name=body.name, description=body.description)
    db.add(ws)
    db.commit()
    db.refresh(ws)
    return ws


@app.delete("/api/workspaces/{workspace_id}")
def delete_workspace(workspace_id: int, db: Session = Depends(get_db)):
    ws = db.get(models.Workspace, workspace_id)
    if not ws:
        raise HTTPException(404, "Workspace not found")
    db.delete(ws)
    db.commit()
    return {"ok": True}


@app.get("/api/workspaces/{workspace_id}", response_model=WorkspaceOut)
def get_workspace(workspace_id: int, db: Session = Depends(get_db)):
    ws = db.get(models.Workspace, workspace_id)
    if not ws:
        raise HTTPException(404, "Workspace not found")
    return ws


# ---------- Targets ----------

@app.get("/api/workspaces/{workspace_id}/targets", response_model=List[TargetOut])
def list_targets(workspace_id: int, db: Session = Depends(get_db)):
    return (
        db.query(models.Target)
        .filter_by(workspace_id=workspace_id)
        .order_by(models.Target.created_at.desc())
        .all()
    )


@app.post("/api/workspaces/{workspace_id}/targets", response_model=TargetOut)
def add_target(workspace_id: int, body: TargetCreate, db: Session = Depends(get_db)):
    if not db.get(models.Workspace, workspace_id):
        raise HTTPException(404, "Workspace not found")
    t = models.Target(workspace_id=workspace_id, value=body.value, target_type=body.target_type)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


# ---------- Findings ----------

@app.get("/api/workspaces/{workspace_id}/findings", response_model=List[FindingOut])
def list_findings(workspace_id: int, module: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(models.Finding).filter_by(workspace_id=workspace_id)
    if module:
        q = q.filter_by(module=module)
    return q.order_by(models.Finding.created_at.desc()).all()


@app.patch("/api/findings/{finding_id}", response_model=FindingOut)
def update_finding_severity(finding_id: int, body: FindingSeverityUpdate, db: Session = Depends(get_db)):
    if body.severity not in ("Info", "Low", "Medium", "High"):
        raise HTTPException(400, "severity must be Info|Low|Medium|High")
    f = db.get(models.Finding, finding_id)
    if not f or f.workspace_id != body.workspace_id:
        raise HTTPException(404, "Finding not found in this workspace")
    f.severity = body.severity
    db.commit()
    db.refresh(f)
    return f


@app.get("/api/workspaces/{workspace_id}/logs", response_model=List[ScanLogOut])
def list_logs(workspace_id: int, limit: int = 500, db: Session = Depends(get_db)):
    return (
        db.query(models.ScanLog)
        .filter_by(workspace_id=workspace_id)
        .order_by(models.ScanLog.created_at.desc())
        .limit(limit)
        .all()
    )


@app.get("/api/workspaces/{workspace_id}/graph")
def get_graph(workspace_id: int, db: Session = Depends(get_db)):
    """Return the most recent network graph finding for the workspace."""
    finding = (
        db.query(models.Finding)
        .filter_by(workspace_id=workspace_id, module="network")
        .order_by(models.Finding.created_at.desc())
        .all()
    )
    for f in finding:
        if f.title.startswith("Network graph") or (
            isinstance(f.data_json, dict) and "nodes" in f.data_json and "edges" in f.data_json
        ):
            return f.data_json
    # Fallback: empty graph
    return {"nodes": [], "edges": []}


# ---------- Settings ----------

@app.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    return _load_settings(db)


@app.put("/api/settings")
def put_settings(body: SettingsUpdate, db: Session = Depends(get_db)):
    data = body.model_dump(exclude_none=True)
    for k, v in data.items():
        row = db.get(models.AppSetting, k)
        if row:
            row.value = str(v)
        else:
            db.add(models.AppSetting(key=k, value=str(v)))
        # Mirror into live settings object where applicable
        if hasattr(settings, k):
            coerce = type(getattr(settings, k))
            try:
                setattr(settings, k, coerce(v))
            except Exception:  # noqa: BLE001
                setattr(settings, k, v)
    db.commit()
    return _load_settings(db)


# ---------- Reports ----------

@app.post("/api/reports")
def create_report(body: ReportRequest, db: Session = Depends(get_db)):
    ws = db.get(models.Workspace, body.workspace_id)
    if not ws:
        raise HTTPException(404, "Workspace not found")

    # Scope to one scan by default so re-runs against other targets don't blend
    scan = None
    if body.scan_id:
        scan = db.get(models.Scan, body.scan_id)
        if not scan or scan.workspace_id != body.workspace_id:
            raise HTTPException(404, "Scan not found in this workspace")
    elif not body.include_all:
        q = db.query(models.Scan).filter_by(workspace_id=body.workspace_id)
        if body.target:
            q = q.filter_by(target_value=body.target)
        scan = q.order_by(models.Scan.started_at.desc()).first()

    findings_q = db.query(models.Finding).filter_by(workspace_id=body.workspace_id)
    logs_q = db.query(models.ScanLog).filter_by(workspace_id=body.workspace_id)
    if scan and not body.include_all:
        findings_q = findings_q.filter_by(scan_id=scan.id)
        logs_q = logs_q.filter_by(scan_id=scan.id)

    findings = findings_q.order_by(models.Finding.created_at.asc()).all()
    logs = logs_q.order_by(models.ScanLog.created_at.asc()).all()
    fdicts = report_gen.findings_to_dicts(findings)
    ldicts = report_gen.logs_to_dicts(logs)

    target = body.target
    if not target and scan:
        target = scan.target_value
    if not target:
        target = ws.name

    if body.format == "json":
        path = report_gen.generate_json_report(ws.name, target, fdicts, ldicts)
    else:
        path = report_gen.generate_pdf_report(ws.name, target, fdicts, ldicts)
    return {
        "path": str(path),
        "filename": path.name,
        "url": f"/api/reports/download/{path.name}",
        "scan_id": scan.id if scan else None,
        "finding_count": len(fdicts),
    }


@app.get("/api/reports/download/{filename}")
def download_report(filename: str):
    # Prevent path traversal
    safe = Path(filename).name
    path = REPORTS_DIR / safe
    if not path.exists():
        raise HTTPException(404, "Report not found")
    media = "application/pdf" if safe.endswith(".pdf") else "application/json"
    return FileResponse(path, media_type=media, filename=safe)


@app.get("/api/reports")
def list_reports(workspace_id: Optional[int] = None, db: Session = Depends(get_db)):
    """List reports; when workspace_id is set, only that workspace's filenames."""
    ensure_directories()
    files = sorted(REPORTS_DIR.glob("saqrintel_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if workspace_id is not None:
        ws = db.get(models.Workspace, workspace_id)
        if not ws:
            raise HTTPException(404, "Workspace not found")
        safe_ws = "".join(c if c.isalnum() or c in "-_" else "_" for c in ws.name)
        prefix = f"saqrintel_{safe_ws}_"
        files = [f for f in files if f.name.startswith(prefix)]
    return [
        {"filename": f.name, "url": f"/api/reports/download/{f.name}", "size": f.stat().st_size}
        for f in files
    ]


def _require_active_auth(modules: List[str], authorized: bool, ack: Optional[str]) -> None:
    from backend.modules.scanner import ACTIVE_MODULES

    needs = sorted(set(m.lower() for m in modules) & ACTIVE_MODULES)
    if not needs:
        return
    if not authorized or ack != AUTHORIZATION_ACK:
        raise PermissionError(
            f"Authorization required for active modules: {', '.join(needs)}. "
            "Confirm permission in the UI (authorized + authorization_ack)."
        )


# ---------- Sync scan kickoff (also available; WS preferred) ----------

@app.post("/api/scan")
def start_scan_sync(body: ScanRequest, db: Session = Depends(get_db)):
    if not db.get(models.Workspace, body.workspace_id):
        raise HTTPException(404, "Workspace not found")
    opts = _settings_as_options(db)
    opts.update(body.options or {})
    try:
        _require_active_auth(body.modules, body.authorized, body.authorization_ack)
        logs: List[str] = []
        scan = scanner.run_scan(
            db,
            body.workspace_id,
            body.target,
            body.modules,
            authorized=body.authorized and body.authorization_ack == AUTHORIZATION_ACK,
            options=opts,
            on_progress=logs.append,
        )
        return {"scan_id": scan.id, "status": scan.status, "summary": scan.summary_json, "log_tail": logs[-50:]}
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, str(exc)) from exc


# ---------- WebSocket live scan ----------

@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        payload = json.loads(raw)
        workspace_id = int(payload["workspace_id"])
        target = payload["target"]
        modules = payload.get("modules") or ["dns"]
        authorized = bool(payload.get("authorized", False))
        auth_ack = payload.get("authorization_ack")
        extra_opts = payload.get("options") or {}

        try:
            _require_active_auth(modules, authorized, auth_ack)
        except PermissionError as exc:
            await websocket.send_json({"type": "error", "message": str(exc), "code": 403})
            await websocket.close()
            return

        await websocket.send_json({"type": "status", "message": "Scan accepted - starting modules..."})

        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def progress(msg: str) -> None:
            # Thread-safe schedule onto the event loop
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "log", "message": msg})

        def worker() -> Dict[str, Any]:
            db = SessionLocal()
            try:
                opts = _settings_as_options(db)
                opts.update(extra_opts)
                scan = scanner.run_scan(
                    db,
                    workspace_id,
                    target,
                    modules,
                    authorized=authorized and auth_ack == AUTHORIZATION_ACK,
                    options=opts,
                    on_progress=progress,
                )
                return {
                    "type": "done",
                    "scan_id": scan.id,
                    "status": scan.status,
                    "summary": scan.summary_json,
                }
            except PermissionError as exc:
                return {"type": "error", "message": str(exc), "code": 403}
            except Exception as exc:  # noqa: BLE001
                return {"type": "error", "message": str(exc), "code": 500}
            finally:
                db.close()

        fut = loop.run_in_executor(None, worker)

        while True:
            if fut.done() and queue.empty():
                break
            try:
                item = await asyncio.wait_for(queue.get(), timeout=0.25)
                await websocket.send_json(item)
            except asyncio.TimeoutError:
                if fut.done():
                    # Drain remaining
                    while not queue.empty():
                        await websocket.send_json(queue.get_nowait())
                    break

        result = fut.result()
        await websocket.send_json(result)
    except WebSocketDisconnect:
        return
    except Exception as exc:  # noqa: BLE001
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass


@app.get("/api/workspaces/{workspace_id}/risk")
def workspace_risk(workspace_id: int, scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Risk score for a scan (latest scan by default)."""
    if scan_id is None:
        last = (
            db.query(models.Scan)
            .filter_by(workspace_id=workspace_id)
            .order_by(models.Scan.id.desc())
            .first()
        )
        if not last:
            return compliance.calculate_risk([])
        scan_id = last.id
    rows = db.query(models.Finding).filter_by(workspace_id=workspace_id, scan_id=scan_id).all()
    result = compliance.calculate_risk([f.severity for f in rows])
    result["scan_id"] = scan_id
    return result


@app.get("/api/health")
def health():
    return {"status": "ok", "app": "SAQRIntel", "version": "1.0.0"}


# Serve frontend SPA assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")

    @app.get("/")
    def index():
        return FileResponse(FRONTEND_DIR / "index.html")


def main() -> None:
    import uvicorn

    ensure_directories()
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
