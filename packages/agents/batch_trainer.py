"""Batch training mode — run N episodes with convergence detection.

Provides TrainingSession for running multi-episode training with:
- Per-class win rate tracking
- Convergence detection (Elo stability, win rate plateau)
- Curriculum learning (cycle through vulnerability classes)
- Summary reporting
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field

from .llm import LLMClient
from .training_loop import EpisodeConfig, EpisodeTrace, TrainingLoop

logger = logging.getLogger(__name__)

VULNERABILITY_CLASSES = [
    "SQLi",
    "XSS",
    "PathTraversal",
    "CommandInjection",
    "SSRF",
    "Deserialization",
    "SSTI",
    "XXE",
    "OpenRedirect",
    "PrototypePollution",
]


@dataclass
class ClassStats:
    """Per-vulnerability-class statistics."""

    vuln_class: str
    total: int = 0
    secure: int = 0
    exploitable: int = 0
    errors: int = 0
    total_duration_s: float = 0.0

    @property
    def win_rate(self) -> float:
        return self.secure / self.total if self.total > 0 else 0.0

    @property
    def avg_duration_s(self) -> float:
        return self.total_duration_s / self.total if self.total > 0 else 0.0


@dataclass
class ConvergenceCheck:
    """Result of convergence analysis."""

    converged: bool
    elo_stable: bool
    win_rate_stable: bool
    episodes_since_improvement: int
    message: str


@dataclass
class BatchReport:
    """Full report from a batch training session."""

    total_episodes: int
    total_time_s: float
    episodes_per_second: float

    # Overall outcomes
    secure: int = 0
    exploitable: int = 0
    errors: int = 0
    secure_rate: float = 0.0

    # Elo
    initial_attacker_elo: float = 1500.0
    initial_developer_elo: float = 1500.0
    final_attacker_elo: float = 1500.0
    final_developer_elo: float = 1500.0

    # Per-class breakdown
    class_stats: dict[str, ClassStats] = field(default_factory=dict)

    # Convergence
    convergence: ConvergenceCheck | None = None

    # Rules
    rules_distilled: int = 0
    rules_accepted: int = 0

    # Tokens
    total_tokens: int = 0
    total_llm_calls: int = 0
    total_cost_usd: float = 0.0


class TrainingSession:
    """Runs a batch training session with convergence detection.

    Usage::

        session = TrainingSession(llm=client, episodes=100)
        report = session.run()
        print(f"Secure rate: {report.secure_rate:.1%}")
    """

    def __init__(
        self,
        llm: LLMClient,
        *,
        episodes: int = 100,
        vulnerability_classes: list[str] | None = None,
        use_react: bool = False,
        round_robin: bool = True,
        convergence_window: int = 20,
        convergence_threshold: float = 0.05,
        elo_stability_threshold: float = 10.0,
    ):
        self.episodes = episodes
        self.vuln_classes = vulnerability_classes or VULNERABILITY_CLASSES
        self.use_react = use_react
        self.round_robin = round_robin
        self.convergence_window = convergence_window
        self.convergence_threshold = convergence_threshold
        self.elo_stability_threshold = elo_stability_threshold

        self.loop = TrainingLoop(llm=llm, use_react=use_react)
        self.class_stats: dict[str, ClassStats] = {}
        self.elo_history: list[dict[str, float]] = []
        self.win_rate_history: list[float] = []

    def run(self, verbose: bool = True) -> BatchReport:
        """Run the full batch training session."""
        t0 = time.time()
        attacker_elo = 1500.0
        developer_elo = 1500.0
        secure_count = 0
        exploitable_count = 0
        error_count = 0
        rules_distilled = 0
        rules_accepted = 0
        traces: list[EpisodeTrace] = []

        for i in range(self.episodes):
            # Select vulnerability class
            vuln_class = self._select_class(i)

            # Run episode
            config = EpisodeConfig(vulnerability_class=vuln_class)
            trace = self.loop.run_episode(config, current_ratings=(attacker_elo, developer_elo))
            traces.append(trace)

            # Update stats
            self._update_stats(vuln_class, trace)

            if trace.judge_outcome == 0:
                secure_count += 1
            else:
                exploitable_count += 1

            if trace.error:
                error_count += 1

            if trace.distilled_rule and trace.regression_passed:
                rules_distilled += 1
                rules_accepted += 1
            elif trace.distilled_rule:
                rules_distilled += 1

            # Update Elo
            attacker_elo = trace.elo_after.get("attacker", attacker_elo)
            developer_elo = trace.elo_after.get("developer", developer_elo)
            self.elo_history.append(
                {
                    "attacker": attacker_elo,
                    "developer": developer_elo,
                }
            )

            # Track win rate
            total_done = i + 1
            current_win_rate = secure_count / total_done
            self.win_rate_history.append(current_win_rate)

            # Progress
            if verbose and (i + 1) % max(1, self.episodes // 10) == 0:
                print(
                    f"  [{i + 1}/{self.episodes}] "
                    f"attacker={attacker_elo:.0f} developer={developer_elo:.0f} "
                    f"secure={current_win_rate:.1%}"
                )

            # Check convergence
            if i >= self.convergence_window:
                conv = self._check_convergence(i)
                if conv.converged and verbose:
                    print(f"  Converged at episode {i + 1}: {conv.message}")
                    break

        total_time = time.time() - t0
        total_episodes = len(traces)

        # Build class stats
        class_stats = {}
        for vc, stats in self.class_stats.items():
            class_stats[vc] = stats

        # Build token stats from traces (cost tracking not available here)
        total_tokens = 0
        total_llm_calls = 0

        return BatchReport(
            total_episodes=total_episodes,
            total_time_s=round(total_time, 2),
            episodes_per_second=round(total_episodes / total_time, 2) if total_time > 0 else 0,
            secure=secure_count,
            exploitable=exploitable_count,
            errors=error_count,
            secure_rate=round(secure_count / total_episodes, 4) if total_episodes else 0,
            initial_attacker_elo=1500.0,
            initial_developer_elo=1500.0,
            final_attacker_elo=attacker_elo,
            final_developer_elo=developer_elo,
            class_stats=class_stats,
            convergence=self._check_convergence(total_episodes - 1),
            rules_distilled=rules_distilled,
            rules_accepted=rules_accepted,
            total_tokens=total_tokens,
            total_llm_calls=total_llm_calls,
        )

    def _select_class(self, episode_index: int) -> str:
        """Select vulnerability class for this episode."""
        if self.round_robin:
            return self.vuln_classes[episode_index % len(self.vuln_classes)]
        return random.choice(self.vuln_classes)

    def _update_stats(self, vuln_class: str, trace: EpisodeTrace) -> None:
        """Update per-class statistics."""
        if vuln_class not in self.class_stats:
            self.class_stats[vuln_class] = ClassStats(vuln_class=vuln_class)

        stats = self.class_stats[vuln_class]
        stats.total += 1
        stats.total_duration_s += trace.duration_s

        if trace.error:
            stats.errors += 1
        elif trace.judge_outcome == 0:
            stats.secure += 1
        else:
            stats.exploitable += 1

    def _check_convergence(self, current_index: int) -> ConvergenceCheck:
        """Check if training has converged."""
        if current_index < self.convergence_window:
            return ConvergenceCheck(
                converged=False,
                elo_stable=False,
                win_rate_stable=False,
                episodes_since_improvement=0,
                message="Not enough data yet",
            )

        # Check Elo stability
        recent_elo = self.elo_history[-self.convergence_window :]
        attacker_elo_range = max(h["attacker"] for h in recent_elo) - min(
            h["attacker"] for h in recent_elo
        )
        developer_elo_range = max(h["developer"] for h in recent_elo) - min(
            h["developer"] for h in recent_elo
        )
        elo_stable = (
            attacker_elo_range < self.elo_stability_threshold
            and developer_elo_range < self.elo_stability_threshold
        )

        # Check win rate stability
        recent_wr = self.win_rate_history[-self.convergence_window :]
        wr_range = max(recent_wr) - min(recent_wr)
        win_rate_stable = wr_range < self.convergence_threshold

        # Check episodes since last improvement
        best_wr = max(self.win_rate_history) if self.win_rate_history else 0
        episodes_since_improvement = 0
        for wr in reversed(self.win_rate_history):
            if wr >= best_wr:
                episodes_since_improvement += 1
            else:
                break

        converged = elo_stable and win_rate_stable
        message = (
            f"Elo range: attacker={attacker_elo_range:.0f} developer={developer_elo_range:.0f}, "
            f"Win rate range: {wr_range:.3f}"
        )

        return ConvergenceCheck(
            converged=converged,
            elo_stable=elo_stable,
            win_rate_stable=win_rate_stable,
            episodes_since_improvement=episodes_since_improvement,
            message=message,
        )


def print_batch_report(report: BatchReport) -> None:
    """Pretty-print a batch training report."""
    print("\n" + "=" * 60)
    print("  CoEvolve Batch Training Report")
    print("=" * 60)

    print(f"\n  Episodes:          {report.total_episodes}")
    print(f"  Total time:        {report.total_time_s}s")
    print(f"  Eps/sec:           {report.episodes_per_second}")

    print(f"\n  Secure:            {report.secure} ({report.secure_rate:.1%})")
    print(f"  Exploitable:       {report.exploitable} ({1 - report.secure_rate:.1%})")
    print(f"  Errors:            {report.errors}")

    print(
        f"\n  Attacker Elo:      {report.initial_attacker_elo:.0f} → "
        f"{report.final_attacker_elo:.0f} "
        f"({report.final_attacker_elo - report.initial_attacker_elo:+.0f})"
    )
    print(
        f"  Developer Elo:     {report.initial_developer_elo:.0f} → "
        f"{report.final_developer_elo:.0f} "
        f"({report.final_developer_elo - report.initial_developer_elo:+.0f})"
    )

    if report.class_stats:
        print("\n  Per-Class Win Rates:")
        for vc, stats in sorted(report.class_stats.items()):
            print(f"    {vc:25s} {stats.win_rate:.0%} ({stats.total} episodes)")

    if report.convergence:
        conv = report.convergence
        status = "YES" if conv.converged else "NO"
        print(f"\n  Converged:         {status}")
        print(f"  Elo stable:        {'YES' if conv.elo_stable else 'NO'}")
        print(f"  Win rate stable:   {'YES' if conv.win_rate_stable else 'NO'}")
        print(f"  {conv.message}")

    print(f"\n  Rules distilled:   {report.rules_distilled}")
    print(f"  Rules accepted:    {report.rules_accepted}")

    print("\n" + "=" * 60)
