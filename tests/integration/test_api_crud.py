"""Integration tests for the FastAPI CRUD endpoints."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Force SQLite before any package imports
os.environ["DATABASE_URL"] = "sqlite:///test_coevolve.db"

# Clear any cached settings/engine
from packages.api.config import get_settings
from packages.api.database import get_engine, reset_engine

get_settings.cache_clear()
reset_engine()

from packages.api.database import Base
from packages.api.main import app

# Re-override after clearing caches
os.environ["DATABASE_URL"] = "sqlite:///test_coevolve.db"
get_settings.cache_clear()
reset_engine()


@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test, drop after."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    # Reset rate limiter between tests
    from packages.api.auth import get_rate_limiter

    get_rate_limiter()._windows.clear()
    yield
    Base.metadata.drop_all(engine)
    reset_engine()


@pytest.fixture
def client():
    return TestClient(app)


class TestHealth:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestEpisodes:
    def test_list_episodes_empty(self, client):
        resp = client.get("/episodes")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_episodes_limit_offset(self, client):
        resp = client.get("/episodes?limit=2&offset=0")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestElo:
    def test_elo_defaults(self, client):
        resp = client.get("/elo")
        assert resp.status_code == 200
        data = resp.json()
        assert data["attacker"] == 1500.0
        assert data["developer"] == 1500.0


class TestPrompts:
    def test_no_prompts_initially(self, client):
        resp = client.get("/prompts/current")
        assert resp.status_code == 404

    def test_prompt_history_empty(self, client):
        resp = client.get("/prompts/history")
        assert resp.status_code == 200
        assert resp.json() == []


class TestRules:
    def test_rules_empty(self, client):
        resp = client.get("/rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_rules_filter_by_class(self, client):
        resp = client.get("/rules?vuln_class=SQLi")
        assert resp.status_code == 200
        assert resp.json() == []


class TestMetrics:
    def test_metrics_empty(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_episodes"] == 0
        assert data["secure_rate"] == 0.0
        assert data["rules_count"] == 0
