"""Database engine, session, and base classes."""

from __future__ import annotations

import logging
import os
import threading

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None
_engine_lock = threading.Lock()


def _build_url(raw_url: str) -> str:
    """Ensure the URL has sslmode=require for Supabase/external Postgres."""
    if not raw_url:
        return raw_url
    if "sslmode" in raw_url:
        return raw_url
    separator = "&" if "?" in raw_url else "?"
    return f"{raw_url}{separator}sslmode=require"


def get_engine():
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                from .config import get_settings

                raw = get_settings().database_url
                url = _build_url(raw)
                logger.info("Connecting to database: %s...", url[:60])
                connect_args: dict = {}
                if url.startswith("sqlite"):
                    # SQLite uses SingletonThreadPool; pool_size/max_overflow
                    # are not supported. check_same_thread=False allows
                    # FastAPI's threadpool + tests to share the engine.
                    connect_args["check_same_thread"] = False
                    _engine = create_engine(
                        url,
                        pool_pre_ping=True,
                        connect_args=connect_args,
                    )
                else:
                    connect_args["connect_timeout"] = 10
                    pool_size = int(os.getenv("DB_POOL_SIZE", "5"))
                    max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "10"))
                    _engine = create_engine(
                        url,
                        pool_pre_ping=True,
                        pool_size=pool_size,
                        max_overflow=max_overflow,
                        connect_args=connect_args,
                    )
    return _engine


def get_session_factory() -> sessionmaker:
    global _session_factory
    if _session_factory is None:
        with _engine_lock:
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


def reset_engine():
    """Reset the global engine and session factory (for testing)."""
    global _engine, _session_factory
    with _engine_lock:
        if _engine is not None:
            try:
                _engine.dispose()
            except Exception:
                pass
        _engine = None
        _session_factory = None
