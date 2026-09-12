"""Tests for TrainingSession stats, class selection, and convergence."""

from __future__ import annotations

import types

from packages.agents.batch_trainer import (
    ClassStats,
    TrainingSession,
)
from packages.agents.llm import MockClient
from packages.agents.training_loop import EpisodeTrace


def _trace(outcome: int = 0, error: str = "", attacker: float = 1500.0, developer: float = 1500.0):
    return EpisodeTrace(
        episode_id="ep",
        judge_outcome=outcome,
        elo_after={"attacker": attacker, "developer": developer},
        duration_s=0.5,
        error=error,
    )


class TestClassStats:
    def test_zero_division(self):
        s = ClassStats(vuln_class="SQLi")
        assert s.win_rate == 0.0
        assert s.avg_duration_s == 0.0

    def test_win_rate(self):
        s = ClassStats(vuln_class="SQLi", total=4, secure=3)
        assert s.win_rate == 0.75


class TestSelection:
    def test_round_robin_cycles(self):
        sess = TrainingSession(llm=MockClient(), episodes=5, vulnerability_classes=["A", "B"])
        assert [sess._select_class(i) for i in range(5)] == ["A", "B", "A", "B", "A"]

    def test_random_mode_stays_in_set(self):
        sess = TrainingSession(
            llm=MockClient(), episodes=5, vulnerability_classes=["A", "B"], round_robin=False
        )
        for i in range(20):
            assert sess._select_class(i) in {"A", "B"}


class TestUpdateStats:
    def test_counts(self):
        sess = TrainingSession(llm=MockClient(), episodes=1)
        sess._update_stats("SQLi", _trace(outcome=0))
        sess._update_stats("SQLi", _trace(outcome=1))
        sess._update_stats("SQLi", _trace(outcome=1, error="boom"))
        s = sess.class_stats["SQLi"]
        assert (s.total, s.secure, s.exploitable, s.errors) == (3, 1, 1, 1)


class TestConvergence:
    def test_not_enough_data(self):
        sess = TrainingSession(llm=MockClient(), episodes=1, convergence_window=20)
        conv = sess._check_convergence(5)
        assert conv.converged is False
        assert conv.message == "Not enough data yet"

    def test_stable_converges(self):
        sess = TrainingSession(llm=MockClient(), episodes=1, convergence_window=3)
        sess.elo_history = [
            {"attacker": 1500.0, "developer": 1500.0},
            {"attacker": 1501.0, "developer": 1499.0},
            {"attacker": 1500.5, "developer": 1500.5},
        ]
        sess.win_rate_history = [0.5, 0.5, 0.5]
        conv = sess._check_convergence(3)
        assert conv.converged is True
        assert conv.elo_stable and conv.win_rate_stable

    def test_elo_swing_not_converged(self):
        sess = TrainingSession(llm=MockClient(), episodes=1, convergence_window=3)
        sess.elo_history = [
            {"attacker": 1400.0, "developer": 1600.0},
            {"attacker": 1600.0, "developer": 1400.0},
            {"attacker": 1500.0, "developer": 1500.0},
        ]
        sess.win_rate_history = [0.5, 0.5, 0.5]
        conv = sess._check_convergence(3)
        assert conv.converged is False
        assert conv.elo_stable is False


class TestRun:
    def _session(self, **kwargs):
        sess = TrainingSession(llm=MockClient(), episodes=10, **kwargs)
        sess.loop = types.SimpleNamespace(
            run_episode=lambda config, current_ratings: _trace(outcome=0)
        )
        return sess

    def test_report_totals(self):
        report = self._session(vulnerability_classes=["SQLi"]).run(verbose=False)
        assert report.total_episodes == 10
        assert report.secure == 10
        assert report.secure_rate == 1.0
        assert report.class_stats["SQLi"].total == 10
        assert report.convergence is not None

    def test_early_stop_on_convergence(self):
        # Window=2 with identical outcomes converges at i=2 -> stops early
        report = self._session(vulnerability_classes=["SQLi"], convergence_window=2).run(
            verbose=False
        )
        assert report.total_episodes < 10
        assert report.convergence is not None
        assert report.convergence.converged is True

    def test_errors_counted(self):
        sess = TrainingSession(llm=MockClient(), episodes=4, vulnerability_classes=["SQLi"])
        calls = {"n": 0}

        def run_episode(config, current_ratings):
            calls["n"] += 1
            if calls["n"] == 2:
                return _trace(outcome=1, error="llm down")
            return _trace(outcome=0)

        sess.loop = types.SimpleNamespace(run_episode=run_episode)
        report = sess.run(verbose=False)
        assert report.errors == 1
        assert report.secure + report.exploitable == 4
