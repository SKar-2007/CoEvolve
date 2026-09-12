"""Database engine, session, and base classes."""

from __future__ import annotations

import logging
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None


def reset_engine() -> None:
    """Reset cached database engine and sessionmaker (for testing)."""
    global _engine, _session_factory
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
    _engine = None
    _session_factory = None


def _build_url(raw_url: str) -> str:
    """Ensure PostgreSQL URLs have sslmode=require; keep SQLite URLs unchanged."""
    if not raw_url or "sqlite" in raw_url:
        return raw_url
    if "sslmode" in raw_url:
        return raw_url
    separator = "&" if "?" in raw_url else "?"
    return f"{raw_url}{separator}sslmode=require"


def get_engine():
    global _engine
    if _engine is None:
        from .config import get_settings

        raw = get_settings().database_url
        url = _build_url(raw)
        logger.info("Connecting to database: %s...", url[:60])
        if "sqlite" in url:
            _engine = create_engine(
                url,
                connect_args={"check_same_thread": False},
            )
        else:
            _engine = create_engine(
                url,
                pool_pre_ping=True,
                pool_size=1,
                max_overflow=2,
                connect_args={"connect_timeout": 10},
            )
    return _engine


def get_session_factory() -> sessionmaker:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _session_factory


def get_db():
    """FastAPI dependency yielding a scoped session."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()
