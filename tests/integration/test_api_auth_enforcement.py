"""Integration tests for auth wiring + mutating endpoints."""

from __future__ import annotations

import os

os.environ["DATABASE_URL"] = "sqlite:///test_coevolve.db"

from fastapi.testclient import TestClient  # noqa: E402
from packages.api.config import get_settings  # noqa: E402
from packages.api.database import Base, get_engine, reset_engine  # noqa: E402
from packages.api.main import app  # noqa: E402

get_settings.cache_clear()
reset_engine()


def _client():
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return TestClient(app)


class TestMutatingEndpointsOpenByDefault:
    def test_config_open_when_auth_disabled(self):
        os.environ["REQUIRE_AUTH"] = "false"
        get_settings.cache_clear()
        reset_engine()
        c = _client()
        r = c.post("/config", json={"llm_model": "x"})
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_stop_404(self):
        os.environ["REQUIRE_AUTH"] = "false"
        get_settings.cache_clear()
        reset_engine()
        c = _client()
        r = c.post("/episodes/does-not-exist/stop")
        assert r.status_code == 404


class TestAuthRequired:
    def test_config_401_when_enabled(self):
        os.environ["REQUIRE_AUTH"] = "true"
        get_settings.cache_clear()
        reset_engine()
        c = _client()
        r = c.post("/config", json={"llm_model": "x"})
        assert r.status_code == 401
        # cleanup
        os.environ["REQUIRE_AUTH"] = "false"
        get_settings.cache_clear()
        reset_engine()
