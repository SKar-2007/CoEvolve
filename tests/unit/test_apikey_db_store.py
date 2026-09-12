"""Tests for the DB-backed API key store (P0: survives restarts, shared workers)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///test_coevolve.db")

from packages.api.auth import (  # noqa: E402
    APIKeyStore,
    DBAPIKeyStore,
    get_key_store,
    reset_key_store,
)
from packages.api.config import get_settings  # noqa: E402
from packages.api.database import (  # noqa: E402
    Base,
    get_engine,
    get_session_factory,
    reset_engine,
)


@pytest.fixture
def db_factory():
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield get_session_factory()
    reset_engine()


class TestDBStore:
    def test_create_validate_disable(self, db_factory):
        store = DBAPIKeyStore(session_factory=db_factory)
        created = store.create_key("ops", tier="admin")
        assert created.key.startswith("cov_")

        validated = store.validate(created.key)
        assert validated is not None
        assert validated.name == "ops"
        assert validated.tier == "admin"

        assert store.validate("cov_bogus") is None
        assert store.disable(created.key) is True
        assert store.validate(created.key) is None

    def test_keys_survive_new_store_instance(self, db_factory):
        s1 = DBAPIKeyStore(session_factory=db_factory)
        created = s1.create_key("persistent")
        # New instance against the same DB (simulates restart / new worker)
        s2 = DBAPIKeyStore(session_factory=db_factory)
        assert s2.validate(created.key) is not None

    def test_list_redacts_raw_keys(self, db_factory):
        store = DBAPIKeyStore(session_factory=db_factory)
        store.create_key("a")
        listed = store.list_keys()
        assert len(listed) == 1
        assert listed[0].key == ""  # raw values are unrecoverable by design

    def test_bootstrap_key(self, db_factory):
        store = DBAPIKeyStore(session_factory=db_factory)
        store.ensure_bootstrap_key("cov_bootstrap123", name="admin-env")
        assert store.validate("cov_bootstrap123") is not None
        # Idempotent
        store.ensure_bootstrap_key("cov_bootstrap123", name="admin-env")
        assert len(store.list_keys()) == 1


class TestBackendSelection:
    def test_memory_default(self, monkeypatch):
        monkeypatch.setenv("API_KEY_STORE", "memory")
        monkeypatch.setenv("ADMIN_API_KEY", "")
        get_settings.cache_clear()
        reset_key_store()
        try:
            assert isinstance(get_key_store(), APIKeyStore)
        finally:
            reset_key_store()
            get_settings.cache_clear()

    def test_db_backend_with_bootstrap(self, monkeypatch, db_factory):
        monkeypatch.setenv("API_KEY_STORE", "db")
        monkeypatch.setenv("ADMIN_API_KEY", "cov_envbootstrap")
        get_settings.cache_clear()
        reset_engine()
        reset_key_store()
        try:
            store = get_key_store()
            assert isinstance(store, DBAPIKeyStore)
            assert store.validate("cov_envbootstrap") is not None
        finally:
            monkeypatch.undo()
            reset_key_store()
            get_settings.cache_clear()
            reset_engine()
