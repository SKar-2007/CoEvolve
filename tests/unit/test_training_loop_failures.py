"""Failure-mode tests: the loop must capture errors, never raise."""

from __future__ import annotations

import types

from packages.agents.llm import LLMClient, LLMResponse, MockClient
from packages.agents.training_loop import EpisodeConfig, TrainingLoop


class ExplodingClient(LLMClient):
    def __init__(self):
        super().__init__("exploding")

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        raise ConnectionError("LLM provider down")


class TestLoopFailures:
    def test_llm_failure_captured(self):
        loop = TrainingLoop(llm=ExplodingClient())
        trace = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert "LLM provider down" in trace.error
        assert trace.duration_s >= 0

    def test_judge_failure_captured(self):
        def boom(**kwargs):
            raise RuntimeError("judge crashed")

        judge = types.SimpleNamespace(evaluate=boom)
        loop = TrainingLoop(llm=MockClient(), judge=judge)
        trace = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert "judge crashed" in trace.error

    def test_distiller_failure_captured(self):
        loop = TrainingLoop(llm=MockClient())

        def boom(**kwargs):
            raise RuntimeError("distiller crashed")

        loop.distiller = types.SimpleNamespace(distill=boom)
        # Force the distill path with an exploitable verdict
        loop.judge = types.SimpleNamespace(
            evaluate=lambda **kw: types.SimpleNamespace(
                j=1,
                sast=types.SimpleNamespace(matched=False, findings=[]),
                as_dict=lambda: {},
                trace_id="t",
            )
        )
        trace = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert "distiller crashed" in trace.error

    def test_empty_response_is_error_not_crash(self):
        class EmptyClient(LLMClient):
            def __init__(self):
                super().__init__("empty")

            def generate(self, system, user, temperature=0.7, max_tokens=4096):
                return LLMResponse(text="not json at all", provider="x", model="x")

        loop = TrainingLoop(llm=EmptyClient())
        trace = loop.run_episode(EpisodeConfig(vulnerability_class="SQLi"))
        assert trace.error != ""
