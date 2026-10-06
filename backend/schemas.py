"""Pydantic request/response schemas for the SAQRIntel API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str = ""


class WorkspaceOut(BaseModel):
    id: int
    name: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


class TargetCreate(BaseModel):
    value: str
    target_type: str = "domain"


class TargetOut(BaseModel):
    id: int
    value: str
    target_type: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanRequest(BaseModel):
    workspace_id: int
    target: str
    modules: List[str] = Field(default_factory=lambda: ["dns", "email"])
    authorized: bool = False
    # Must equal AUTHORIZATION_ACK when active modules are selected
    authorization_ack: Optional[str] = None
    options: Dict[str, Any] = Field(default_factory=dict)


class FindingOut(BaseModel):
    id: int
    module: str
    title: str
    severity: str
    data_json: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class FindingSeverityUpdate(BaseModel):
    severity: str
    workspace_id: int


class ScanLogOut(BaseModel):
    id: int
    module: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True


class SettingsUpdate(BaseModel):
    rate_limit_rps: Optional[float] = None
    thread_count: Optional[int] = None
    nmap_ports: Optional[str] = None
    subdomain_wordlist: Optional[str] = None
    fuzzer_wordlist: Optional[str] = None
    crawl_max_depth: Optional[int] = None
    crawl_max_pages: Optional[int] = None
    http_timeout: Optional[float] = None


class ReportRequest(BaseModel):
    workspace_id: int
    target: Optional[str] = None
    format: str = "pdf"  # pdf|json
    scan_id: Optional[int] = None
    include_all: bool = False  # if True, dump entire workspace history


# Client must send this string (plus authorized=True) for active modules
AUTHORIZATION_ACK = "I_CONFIRM_AUTHORIZATION"