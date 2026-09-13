"""Tests for LLM client factory and MockClient (critical path)."""

from __future__ import annotations

import pytest
from packages.agents.llm import (
    LLMError,
    MockClient,
    build_client,
)


class TestBuildClient:
    def test_mock(self):
        c = build_client("mock", "mock")
        assert isinstance(c, MockClient)

    def test_unknown_provider(self):
        with pytest.raises(LLMError):
            build_client("nosuchprovider", "x")

    def test_missing_keys_raise(self):
        # No env keys set in CI — each real client must raise LLMError
        import os

        for provider, env in [
            ("anthropic", "ANTHROPIC_API_KEY"),
            ("openai", "OPENAI_API_KEY"),
            ("groq", "GROQ_API_KEY"),
            ("modelscope", "MODELSCOPE_API_KEY"),
        ]:
            if os.getenv(env):
                continue
            with pytest.raises(LLMError):
                build_client(provider, "some-model")

    def test_case_insensitive(self):
        c = build_client("MOCK", "mock")
        assert isinstance(c, MockClient)


class TestMockClient:
    def test_attacker(self):
        c = MockClient()
        r = c.generate(system="you are red-team attacker", user="make sqli")
        assert r.provider == "mock"
        assert "SQL" in r.text or "sql" in r.text.lower() or "SELECT" in r.text

    def test_developer(self):
        c = MockClient()
        r = c.generate(system="you are developer", user="fix it")
        assert r.provider == "mock"
        assert r.total_tokens > 0

    def test_distiller(self):
        c = MockClient()
        r = c.generate(system="distill failure trace", user="trace")
        assert r.provider == "mock"
