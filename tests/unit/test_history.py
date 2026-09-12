"""Unit tests for the Elo rating history tracker."""

from __future__ import annotations

from packages.elo.calculator import Ratings
from packages.elo.history import RatingHistory


class TestRatingHistory:
    def test_record_and_series(self) -> None:
        history = RatingHistory()
        history.record(Ratings(attacker=1516.0, developer=1484.0), episode_k=1)
        history.record(Ratings(attacker=1500.0, developer=1500.0), episode_k=2)
        series = history.series()
        assert len(series) == 2
        assert series[0]["attacker"] == 1516.0

    def test_empty_history(self) -> None:
        history = RatingHistory()
        assert history.latest() is None
        assert history.series() == []

    def test_latest(self) -> None:
        history = RatingHistory()
        history.record(Ratings(attacker=1516.0, developer=1484.0), episode_k=1)
        snap = history.latest()
        assert snap is not None
        assert snap.attacker == 1516.0

    def test_trend(self) -> None:
        history = RatingHistory()
        history.record(Ratings(attacker=1500.0, developer=1500.0), episode_k=1)
        history.record(Ratings(attacker=1516.0, developer=1484.0), episode_k=2)
        trend = history.trend()
        assert trend["attacker_delta"] == 16.0
        assert trend["developer_delta"] == -16.0
        assert trend["samples"] == 2

    def test_trend_window(self) -> None:
        history = RatingHistory()
        for i in range(10):
            history.record(Ratings(attacker=1500.0 + i, developer=1500.0 - i), episode_k=i)
        trend = history.trend(window=3)
        assert trend["samples"] == 3
        assert trend["attacker_delta"] == 2.0  # 1509 - 1507
