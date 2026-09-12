#!/usr/bin/env python3
"""Benchmarking script: runs N training episodes and produces statistics.

Usage:
    python scripts/benchmark.py                    # 50 mock episodes
    python scripts/benchmark.py --episodes 200     # 200 episodes
    python scripts/benchmark.py --real             # Real LLM calls
    python scripts/benchmark.py --output report.json  # Save JSON report
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class MockLLM:
    """Simulated LLM for benchmarking."""

    model = "mock-v1"

    _SECURE_PATCHES = [
        "query = 'SELECT * FROM users WHERE name=%s'\ncursor.execute(query, (user_input,))",
        "sanitized = html.escape(user_input)",
        "validated = urljoin(base_url, urlparse(user_input).path)",
    ]

    def generate(self, system: str, user: str, temperature: float = 0.7, max_tokens: int = 4096) -> Any:
        class Response:
            def __init__(self, text: str) -> None:
                self.text = text
                self.provider = "mock"
                self.model = "mock-v1"
                self.prompt_tokens = 120
                self.completion_tokens = 180

        # Attacker: system prompt mentions red-team, coding tasks, vulnerability
        if "red-team" in system.lower() or "coding task" in system.lower() or "generate a task" in user.lower():
            return Response(json.dumps({
                "task_description": "Fix the user search query to be safe",
                "vulnerability_class": "SQLi",
                "difficulty_tier": 5,
                "context_files": [{"path": "app/search.py", "snippet": "query = f'SELECT * FROM users WHERE name={user_input}'"}],
                "acceptance_criteria": "Input is properly parameterized",
                "expected_exploit": "' OR 1=1 --",
                "hidden_trap": "f-string interpolation",
                "suggested_files": ["app/search.py"],
            }))

        # Developer: system prompt mentions expert software engineer
        if "software engineer" in system.lower() or "task:" in user.lower():
            return Response(self._SECURE_PATCHES[hash(user) % len(self._SECURE_PATCHES)])

        # Distiller: system prompt mentions distilled, rules, failure trace
        if "distill" in system.lower() or "failure trace" in system.lower():
            return Response("always use parameterized queries for database operations")

        return Response("Action: search_code\nAction Input: {\"pattern\": \"SELECT\"}")


def run_benchmark(episodes: int, real: bool = False) -> dict[str, Any]:
    """Run N episodes and collect statistics."""
    from packages.agents.cost_tracking import CostTrackingClient
    from packages.agents.training_loop import EpisodeConfig, EpisodeTrace, TrainingLoop
    from packages.elo.calculator import EloCalculator, Ratings

    if real:
        from packages.agents.llm import build_client

        llm = build_client("anthropic")
    else:
        llm = MockLLM()

    tracked = CostTrackingClient(llm)
    calculator = EloCalculator()

    config = EpisodeConfig(vulnerability_class="SQLi")
    traces: list[EpisodeTrace] = []

    attacker_elo = 1500.0
    developer_elo = 1500.0
    elo_history: list[dict[str, float]] = []

    t_start = time.time()

    for i in range(episodes):
        loop = TrainingLoop(llm=tracked, elo_calculator=calculator)
        trace = loop.run_episode(config, current_ratings=(attacker_elo, developer_elo))
        traces.append(trace)

        # Update Elos for next episode
        attacker_elo = trace.elo_after.get("attacker", attacker_elo)
        developer_elo = trace.elo_after.get("developer", developer_elo)
        elo_history.append({"attacker": attacker_elo, "developer": developer_elo})

        # Progress
        if (i + 1) % max(1, episodes // 10) == 0:
            print(f"  [{i + 1}/{episodes}] attacker={attacker_elo:.0f} developer={developer_elo:.0f}")

    total_time = time.time() - t_start

    # Compute statistics
    outcomes = [t.judge_outcome for t in traces]
    durations = [t.duration_s for t in traces]
    difficulties = [t.difficulty_tier for t in traces]
    rules_distilled = sum(1 for t in traces if t.distilled_rule is not None and t.regression_passed)
    errors = sum(1 for t in traces if t.error)

    vuln_classes = Counter()
    for t in traces:
        if t.task:
            vuln_classes[t.task.vulnerability_class] += 1

    report = {
        "summary": {
            "episodes": episodes,
            "total_time_s": round(total_time, 2),
            "avg_episode_time_s": round(total_time / episodes, 3) if episodes else 0,
            "episodes_per_second": round(episodes / total_time, 2) if total_time > 0 else 0,
        },
        "outcomes": {
            "secure": outcomes.count(0),
            "exploitable": outcomes.count(1),
            "errors": errors,
            "secure_rate": round(outcomes.count(0) / len(outcomes), 4) if outcomes else 0,
        },
        "elo": {
            "initial_attacker": 1500.0,
            "initial_developer": 1500.0,
            "final_attacker": round(attacker_elo, 1),
            "final_developer": round(developer_elo, 1),
            "attacker_delta": round(attacker_elo - 1500.0, 1),
            "developer_delta": round(developer_elo - 1500.0, 1),
            "history": elo_history[-10:],  # last 10 snapshots
        },
        "difficulty": {
            "avg_tier": round(sum(difficulties) / len(difficulties), 1) if difficulties else 0,
            "tier_distribution": dict(sorted(Counter(difficulties).items())),
        },
        "rules": {
            "total_distilled": rules_distilled,
            "acceptance_rate": round(rules_distilled / outcomes.count(1), 4) if outcomes.count(1) > 0 else 0,
        },
        "tokens": tracked.usage.as_dict(),
    }

    return report


def print_report(report: dict[str, Any]) -> None:
    """Pretty-print the benchmark report."""
    print()
    print("=" * 60)
    print("  CoEvolve Benchmark Report")
    print("=" * 60)

    s = report["summary"]
    print(f"\n  Episodes:          {s['episodes']}")
    print(f"  Total time:        {s['total_time_s']:.1f}s")
    print(f"  Avg episode time:  {s['avg_episode_time_s']:.3f}s")
    print(f"  Episodes/sec:      {s['episodes_per_second']:.1f}")

    o = report["outcomes"]
    print(f"\n  Secure:            {o['secure']} ({o['secure_rate']:.1%})")
    print(f"  Exploitable:       {o['exploitable']} ({1 - o['secure_rate']:.1%})")
    print(f"  Errors:            {o['errors']}")

    e = report["elo"]
    print(f"\n  Attacker Elo:      {e['initial_attacker']:.0f} → {e['final_attacker']:.0f} ({e['attacker_delta']:+.0f})")
    print(f"  Developer Elo:     {e['initial_developer']:.0f} → {e['final_developer']:.0f} ({e['developer_delta']:+.0f})")

    d = report["difficulty"]
    print(f"\n  Avg difficulty:    {d['avg_tier']:.1f}/10")

    r = report["rules"]
    print(f"  Rules distilled:   {r['total_distilled']}")
    print(f"  Rule acceptance:   {r['acceptance_rate']:.1%}")

    t = report["tokens"]
    print(f"\n  Total tokens:      {t['total_tokens']:,}")
    print(f"  LLM calls:         {t['total_calls']}")
    print(f"  Estimated cost:    ${t['total_cost_usd']:.4f}")

    print("\n" + "=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="CoEvolve benchmark")
    parser.add_argument("--episodes", type=int, default=50, help="Number of episodes")
    parser.add_argument("--real", action="store_true", help="Use real LLM calls")
    parser.add_argument("--output", type=str, default="", help="Save JSON report to file")
    args = parser.parse_args()

    print(f"Running {args.episodes} episodes ({'real' if args.real else 'mock'} mode)...")
    report = run_benchmark(episodes=args.episodes, real=args.real)
    print_report(report)

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
        print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
