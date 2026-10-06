"""
SQLAlchemy engine and session factory for SAQRIntel (SQLite).
"""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.core.config import DB_PATH, ensure_directories, settings


class Base(DeclarativeBase):
    pass


ensure_directories()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:  # noqa: ARG001
    """Enable foreign keys on every SQLite connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency: yield a DB session then close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Import models first so metadata is registered."""
    from backend.db import models  # noqa: F401

    ensure_directories()
    Base.metadata.create_all(bind=engine)
    # Touch the DB file path so operators can find it easily
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
