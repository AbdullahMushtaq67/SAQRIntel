"""
SQLAlchemy models for workspaces, targets, findings, and scan logs.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Workspace(Base):
    """A Recon-ng-style engagement container — findings never mix across workspaces."""

    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    # Persisted settings overrides (rate limit, threads, wordlists, nmap ports)
    settings_json: Mapped[dict] = mapped_column(JSON, default=dict)

    targets: Mapped[list["Target"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )
    scan_logs: Mapped[list["ScanLog"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )


class Target(Base):
    """A domain, URL, or IP belonging to a workspace."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), default="domain")  # domain|ip|url
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    workspace: Mapped["Workspace"] = relationship(back_populates="targets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="target")


class Scan(Base):
    """One scan run (may include multiple modules)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    target_value: Mapped[str] = mapped_column(String(512), nullable=False)
    modules: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)

    workspace: Mapped["Workspace"] = relationship(back_populates="scans")


class Finding(Base):
    """A single reportable finding produced by a module."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="Info")  # Info|Low|Medium|High
    data_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    workspace: Mapped["Workspace"] = relationship(back_populates="findings")
    target: Mapped["Target | None"] = relationship(back_populates="findings")


class ScanLog(Base):
    """Audit trail line for PDF appendix + live UI history."""

    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    module: Mapped[str] = mapped_column(String(64), default="system")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    workspace: Mapped["Workspace"] = relationship(back_populates="scan_logs")


class AppSetting(Base):
    """Key/value global settings (rate limit, wordlists, etc.)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
