"""Tests for CostTrackingClient and CachingClient."""

from __future__ import annotations

from packages.agents.cost_tracking import (
    CachingClient,
    CostTrackingClient,
    estimate_cost,
)
from packages.agents.llm import MockClient


class TestEstimateCost:
    def test_zero(self):
        assert estimate_cost("openai", "gpt-4o", 0, 0) == 0.0

    def test_positive(self):
        c = estimate_cost("openai", "gpt-4o", 1_000_000, 1_000_000)
        assert c == 2.5 + 10.0

    def test_unknown_defaults(self):
        c = estimate_cost("nosuch", "nosuch", 1_000_000, 0)
        assert c == 1.0


class TestCostTracking:
    def test_tracks(self):
        tracked = CostTrackingClient(MockClient())
        tracked.generate(system="dev", user="hi")
        assert tracked.usage.total_calls == 1
        assert tracked.usage.total_tokens > 0
        assert "mock" in tracked.usage.by_provider


class TestCaching:
    def test_hit(self):
        c = CachingClient(MockClient(), max_size=10, ttl_seconds=60)
        r1 = c.generate(system="s", user="u", temperature=0.0)
        r2 = c.generate(system="s", user="u", temperature=0.0)
        assert r1.text == r2.text
        stats = c.cache_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1

    def test_no_cache_when_sampling(self):
        c = CachingClient(MockClient())
        c.generate(system="s", user="u", temperature=0.7)
        assert c.cache_stats()["size"] == 0
