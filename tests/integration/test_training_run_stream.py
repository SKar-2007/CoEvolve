"""Integration tests for POST /training/run and GET /training/stream."""

from __future__ import annotations

import json
import os
import types

os.environ["DATABASE_URL"] = "sqlite:///test_coevolve.db"
os.environ["REQUIRE_AUTH"] = "false"

from fastapi.testclient import TestClient  # noqa: E402
from packages.api.config import get_settings  # noqa: E402
from packages.api.database import Base, get_engine, reset_engine  # noqa: E402
from packages.api.main import app  # noqa: E402

get_settings.cache_clear()
reset_engine()


def _client() -> TestClient:
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return TestClient(app)


def _fake_trace(**overrides):
    base = {
        "episode_id": "ep-sync-1",
        "error": "",
        "difficulty_tier": 4,
        "judge_outcome": 0,
        "task": types.SimpleNamespace(task_description="do the thing"),
        "patch_text": "patch-bytes",
        "judge_verdict": {"verdict": "secure"},
        "elo_before": {"attacker": 1500.0, "developer": 1500.0},
        "elo_after": {"attacker": 1490.0, "developer": 1510.0},
        "prompt_version": 0,
        "distilled_rule": None,
        "regression_passed": True,
        "duration_s": 1.5,
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _fake_rule():
    return types.SimpleNamespace(
        rule_text="never interpolate SQL",
        vulnerability_class="SQLi",
        source_pattern="f'...{x}...'",
        recommended_fix="parameterize",
        source_trace_id="t1",
    )


class TestTrainingRun:
    def test_full_response_and_persistence(self, monkeypatch):
        monkeypatch.setattr(
            "packages.agents.training_loop.TrainingLoop.run_episode",
            lambda self, config, current_ratings=(1500.0, 1500.0): _fake_trace(),
        )
        c = _client()
        r = c.post("/training/run", json={"vulnerability_class": "SQLi", "language": "python"})
        assert r.status_code == 200
        body = r.json()
        assert body["episode_id"] == "ep-sync-1"
        assert body["status"] == "completed"
        assert body["difficulty_tier"] == 4
        assert body["judge_outcome"] == 0
        assert body["rule_distilled"] is False
        assert body["elo_after"] == {"attacker": 1490.0, "developer": 1510.0}

        # Persisted + Elo updated
        assert c.get("/elo").json() == {"attacker": 1490.0, "developer": 1510.0}
        eps = c.get("/episodes").json()
        assert any(e["episode_id"] == "ep-sync-1" for e in eps)

    def test_rule_distilled_path(self, monkeypatch):
        monkeypatch.setattr(
            "packages.agents.training_loop.TrainingLoop.run_episode",
            lambda self, config, current_ratings=(1500.0, 1500.0): _fake_trace(
                judge_outcome=1, distilled_rule=_fake_rule()
            ),
        )
        c = _client()
        body = c.post("/training/run", json={}).json()
        assert body["rule_distilled"] is True
        assert body["rule_text"] == "never interpolate SQL"
        rules = c.get("/rules").json()
        assert any(r["rule_text"] == "never interpolate SQL" for r in rules)

    def test_error_path(self, monkeypatch):
        monkeypatch.setattr(
            "packages.agents.training_loop.TrainingLoop.run_episode",
            lambda self, config, current_ratings=(1500.0, 1500.0): _fake_trace(
                error="llm exploded"
            ),
        )
        c = _client()
        body = c.post("/training/run", json={}).json()
        assert body["status"] == "failed"
        assert body["error"] == "llm exploded"

    def test_auth_enforced_when_enabled(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        get_settings.cache_clear()
        reset_engine()
        try:
            assert TestClient(app).post("/training/run", json={}).status_code == 401
        finally:
            monkeypatch.undo()
            os.environ["REQUIRE_AUTH"] = "false"
            get_settings.cache_clear()
            reset_engine()


class TestTrainingStream:
    def test_sse_event_sequence(self, monkeypatch):
        monkeypatch.setattr(
            "packages.agents.training_loop.TrainingLoop.run_episode",
            lambda self, config, current_ratings=(1500.0, 1500.0): _fake_trace(),
        )
        c = _client()
        r = c.get("/training/stream?vulnerability_class=SQLi&language=python")
        assert r.status_code == 200
        events = [
            json.loads(line[len("data: ") :])
            for line in r.text.splitlines()
            if line.startswith("data: ")
        ]
        kinds = [
            e.get("type") if e.get("type") in ("start", "elo", "complete", "error") else "agent"
            for e in events
        ]
        assert kinds[0] == "start"
        assert kinds[-1] == "complete"
        assert "elo" in kinds
        complete = events[-1]
        assert complete["episode_id"] == "ep-sync-1"
        assert complete["outcome"] == 0

        # Stream persists too
        assert any(e["episode_id"] == "ep-sync-1" for e in c.get("/episodes").json())
