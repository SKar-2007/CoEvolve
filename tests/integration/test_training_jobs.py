"""Integration tests for the async training-jobs API and worker path."""

from __future__ import annotations

import os
import types

os.environ["DATABASE_URL"] = "sqlite:///test_coevolve.db"
os.environ["REQUIRE_AUTH"] = "false"

from fastapi.testclient import TestClient  # noqa: E402
from packages.agents.llm import MockClient  # noqa: E402
from packages.api.config import get_settings  # noqa: E402
from packages.api.database import Base, get_engine, reset_engine  # noqa: E402
from packages.api.main import app  # noqa: E402
from packages.api.task_queue import get_task_queue, reset_task_queue  # noqa: E402
from packages.api.worker import TrainingWorker  # noqa: E402

get_settings.cache_clear()
reset_engine()
reset_task_queue()


def _client() -> TestClient:
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    reset_task_queue()
    return TestClient(app)


def _fake_trace():
    return types.SimpleNamespace(
        episode_id="ep-worker-1",
        error="",
        difficulty_tier=3,
        judge_outcome=0,
        task=types.SimpleNamespace(task_description="t"),
        patch_text="p",
        judge_verdict={},
        elo_before={"attacker": 1500.0, "developer": 1500.0},
        elo_after={"attacker": 1495.0, "developer": 1505.0},
        prompt_version=0,
        distilled_rule=None,
        regression_passed=True,
        duration_s=0.1,
    )


class TestJobsAPI:
    def test_enqueue_returns_202(self):
        c = _client()
        r = c.post("/training/jobs", json={"vulnerability_class": "SQLi"})
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "pending"
        assert body["job_id"]
        assert body["queue_position"] == 1

    def test_get_and_list(self):
        c = _client()
        r = c.post("/training/jobs", json={"vulnerability_class": "XSS", "use_react": True})
        job_id = r.json()["job_id"]

        got = c.get(f"/training/jobs/{job_id}")
        assert got.status_code == 200
        assert got.json()["vulnerability_class"] == "XSS"
        assert got.json()["use_react"] is True

        listed = c.get("/training/jobs")
        assert listed.status_code == 200
        assert any(j["job_id"] == job_id for j in listed.json())

    def test_get_missing_404(self):
        c = _client()
        assert c.get("/training/jobs/does-not-exist").status_code == 404


class TestWorkerPath:
    def _worker(self) -> TrainingWorker:
        w = TrainingWorker()
        w._queue = get_task_queue()  # same in-memory queue the API enqueued to
        w._llm = MockClient()

        def _already_initialized() -> None:
            return None

        w._ensure_initialized = _already_initialized
        return w

    def test_worker_processes_enqueued_job(self, monkeypatch):
        c = _client()
        job_id = c.post("/training/jobs", json={"vulnerability_class": "SQLi"}).json()["job_id"]

        # Stub the heavy TrainingLoop: worker must still dequeue, persist
        # the episode via the shared helper, and complete the job.
        def fake_run_episode(self, config, current_ratings=(1500.0, 1500.0)):
            return _fake_trace()

        monkeypatch.setattr(
            "packages.agents.training_loop.TrainingLoop.run_episode",
            fake_run_episode,
        )
        assert self._worker().run_once() is True

        job = get_task_queue().get_job(job_id)
        assert job is not None
        assert job.status.value == "completed"
        assert job.result["episode_id"] == "ep-worker-1"

        # Episode persisted to the DB
        eps = c.get("/episodes")
        assert eps.status_code == 200
        assert any(e["episode_id"] == "ep-worker-1" for e in eps.json())

    def test_use_react_flows_to_loop(self, monkeypatch):
        c = _client()
        c.post("/training/jobs", json={"use_react": True})

        seen: dict = {}

        def fake_run_episode(self, config, current_ratings=(1500.0, 1500.0)):
            return _fake_trace()

        # Capture the flag via the loop constructor
        import packages.agents.training_loop as loop_module

        real_loop = loop_module.TrainingLoop

        def spy_loop(*args, **kwargs):
            seen.update(kwargs)
            return real_loop(*args, **kwargs)

        monkeypatch.setattr(loop_module, "TrainingLoop", spy_loop)
        monkeypatch.setattr(real_loop, "run_episode", fake_run_episode)
        assert self._worker().run_once() is True
        assert seen.get("use_react") is True

    def test_worker_no_job_returns_false(self):
        _client()
        assert self._worker().run_once() is False

    def test_failed_job_marks_failed_and_alerts(self, monkeypatch):
        import packages.api.worker as worker_module

        c = _client()
        job_id = c.post("/training/jobs", json={}).json()["job_id"]

        def boom(self, config, current_ratings=(1500.0, 1500.0)):
            raise RuntimeError("loop exploded")

        monkeypatch.setattr("packages.agents.training_loop.TrainingLoop.run_episode", boom)
        notified = []

        class StubManager:
            def notify_error(self, message, context=""):
                notified.append((message, context))
                return {"LogChannel": True}

        monkeypatch.setattr(worker_module, "_build_alerter", lambda: StubManager())
        assert self._worker().run_once() is True

        job = get_task_queue().get_job(job_id)
        assert job is not None
        assert job.status.value == "failed"
        assert "loop exploded" in job.error
        assert notified and "loop exploded" in notified[0][0]

    def test_auth_enforced_when_enabled(self, monkeypatch):
        monkeypatch.setenv("REQUIRE_AUTH", "true")
        get_settings.cache_clear()
        reset_engine()
        reset_task_queue()
        try:
            c = TestClient(app)
            assert c.post("/training/jobs", json={}).status_code == 401
        finally:
            monkeypatch.undo()
            os.environ["REQUIRE_AUTH"] = "false"
            get_settings.cache_clear()
            reset_engine()
            reset_task_queue()
