"""Tests for shared training helpers (provider resolution + persistence)."""

from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///test_coevolve.db")

from packages.api.config import get_settings
from packages.api.database import Base, get_engine, get_session_factory, reset_engine
from packages.api.training_service import (
    get_current_ratings,
    get_prompt_version,
    persist_episode,
    resolve_llm_provider,
)


def _fresh_db():
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return get_session_factory()()


class TestResolveProvider:
    def test_mock_when_no_keys(self):
        s = get_settings()
        # Ensure no keys
        s.groq_api_key = ""
        s.anthropic_api_key = ""
        s.openai_api_key = ""
        s.huggingface_api_key = ""
        s.openrouter_api_key = ""
        s.gemini_api_key = ""
        s.modelscope_api_key = ""
        provider, key, _model = resolve_llm_provider(s)
        assert provider == "mock"
        assert key is None

    def test_groq_preferred(self):
        s = get_settings()
        s.groq_api_key = "gsk_test"
        s.anthropic_api_key = "sk_test"
        provider, key, _ = resolve_llm_provider(s)
        assert provider == "groq"
        assert key == "gsk_test"


class TestPersistence:
    def test_defaults_and_persist(self):
        db = _fresh_db()
        try:
            assert get_current_ratings(db) == (1500.0, 1500.0)
            assert get_prompt_version(db) == 0

            class FakeTask:
                task_description = "do thing"

            class FakeRule:
                rule_text = "r"
                vulnerability_class = "SQLi"
                source_pattern = "p"
                recommended_fix = "f"
                source_trace_id = "t"

            class FakeTrace:
                episode_id = "ep123"
                error = ""
                difficulty_tier = 3
                judge_outcome = 1
                task = FakeTask()
                patch_text = "patch"
                judge_verdict = {}
                elo_after = {"attacker": 1510.0, "developer": 1490.0}
                prompt_version = 0
                distilled_rule = FakeRule()
                regression_passed = True

            ep = persist_episode(
                db, trace=FakeTrace(), vulnerability_class="SQLi", current_ratings=(1500.0, 1500.0)
            )
            assert ep.id == "ep123"
            assert get_current_ratings(db) == (1510.0, 1490.0)
        finally:
            db.close()
            reset_engine()
