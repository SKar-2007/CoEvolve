#!/usr/bin/env python3
"""End-to-end demo: runs a mock training loop to show the full pipeline.

Usage:
    python scripts/demo.py                    # Mock mode (no API keys needed)
    python scripts/demo.py --real             # Real LLM calls (requires API key)
    python scripts/demo.py --episodes 5       # Run 5 episodes
    python scripts/demo.py --vuln XSS         # Target XSS vulnerabilities
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class MockLLM:
    """Simulated LLM client for demo purposes — no API key needed."""

    model = "mock-v1"

    _RESPONSES = {
        "attacker": {
            "task_description": "Find SQL injection in user search endpoint",
            "vulnerability_class": "SQLi",
            "context_files": [
                {"path": "app/search.py", "snippet": "query = f'SELECT * FROM users WHERE name={user_input}'"}
            ],
            "acceptance_criteria": "Input is properly parameterized",
            "suggested_files": ["app/search.py"],
        },
        "developer_patch": "--- a/app/search.py\n+++ b/app/search.py\n@@ -1 +1 @@\n-query = f'SELECT * FROM users WHERE name={user_input}'\n+query = 'SELECT * FROM users WHERE name=%s'\ncursor.execute(query, (user_input,))",
        "distilled_rule": "always use parameterized queries for database operations",
    }

    def generate(self, system: str, user: str, temperature: float = 0.7, max_tokens: int = 4096) -> Any:
        time.sleep(0.05)  # Simulate latency

        class Response:
            def __init__(self, text: str) -> None:
                self.text = text
                self.provider = "mock"
                self.model = "mock-v1"
                self.prompt_tokens = 150
                self.completion_tokens = 200

        # Route based on content
        if "attacker" in system.lower() or "generate a task" in user.lower():
            return Response(json.dumps(self._RESPONSES["attacker"]))
        if "developer" in system.lower() or "task:" in user.lower():
            return Response(self._RESPONSES["developer_patch"])
        if "distill" in system.lower():
            return Response(self._RESPONSES["distilled_rule"])
        return Response("Action: search_code\nAction Input: {\"pattern\": \"SELECT\"}")


def run_demo_mock(episodes: int = 3, vuln_class: str = "SQLi") -> None:
    """Run demo with mock LLM — no API keys required."""
    from packages.agents.cost_tracking import CostTrackingClient, TokenUsage
    from packages.agents.training_loop import EpisodeConfig, EpisodeTrace, TrainingLoop
    from packages.elo.calculator import EloCalculator, Ratings

    print("=" * 70)
    print("CoEvolve Sandbox — End-to-End Demo (Mock Mode)")
    print("=" * 70)

    llm = MockLLM()
    tracked = CostTrackingClient(llm)
    calculator = EloCalculator()

    # Simulate a series of episodes
    attacker_elo = 1500.0
    developer_elo = 1500.0

    print(f"\nTarget vulnerability class: {vuln_class}")
    print(f"Episodes to run: {episodes}")
    print()

    for i in range(episodes):
        print(f"--- Episode {i + 1}/{episodes} ---")
        print(f"  Elo — Attacker: {attacker_elo:.0f}, Developer: {developer_elo:.0f}")

        # Determine difficulty tier
        from packages.elo.difficulty import mapping_for

        mapping = mapping_for(attacker_elo, developer_elo)
        print(f"  Difficulty tier: {mapping.tier} ({mapping.description})")

        # Simulate attacker task
        print("  [Attacker] Generating adversarial task...")
        task = {
            "task_id": f"demo_{i}",
            "task_description": f"Find SQL injection variant #{i + 1}",
            "vulnerability_class": vuln_class,
            "context_files": [{"path": "app/search.py", "snippet": "vulnerable query"}],
        }

        # Simulate developer patch
        print("  [Developer] Generating patch...")
        patch = "--- a/app/search.py\n+++ b/app/search.py\n+query = 'SELECT * FROM users WHERE name=%s'\ncursor.execute(query, (user_input,))"

        # Simulate judge outcome (alternate for variety)
        outcome = 1 if i % 3 == 0 else 0
        verdict_text = "EXPLOITABLE" if outcome == 1 else "SECURE"
        print(f"  [Judge] Verdict: {verdict_text}")

        # Update Elo
        new_ratings = calculator.update_pair(attacker_elo, developer_elo, outcome)
        attacker_elo = new_ratings.attacker
        developer_elo = new_ratings.developer

        if outcome == 1:
            print("  [Distiller] Extracting rule from failure trace...")
            print('  [Rule] "always use parameterized queries for database operations"')
            print("  [RegressionGuard] Checking for regressions... PASSED")

        print(f"  Elo after — Attacker: {attacker_elo:.0f}, Developer: {developer_elo:.0f}")
        print()

    # Summary
    print("=" * 70)
    print("Training Complete — Summary")
    print("=" * 70)
    print(f"  Episodes run:        {episodes}")
    print(f"  Final attacker Elo:  {attacker_elo:.0f}")
    print(f"  Final developer Elo: {developer_elo:.0f}")
    print(f"  Tokens used:         {tracked.usage.total_tokens}")
    print(f"  Estimated cost:      ${tracked.usage.total_cost_usd:.4f}")
    print(f"  LLM calls:           {tracked.usage.total_calls}")
    print()
    print("Run with --real flag and ANTHROPIC_API_KEY set for real LLM calls.")


def run_demo_real(episodes: int = 3, vuln_class: str = "SQLi") -> None:
    """Run demo with real LLM calls — requires API key."""
    from packages.agents.cost_tracking import CostTrackingClient
    from packages.agents.llm import build_client
    from packages.agents.training_loop import EpisodeConfig, TrainingLoop

    print("=" * 70)
    print("CoEvolve Sandbox — End-to-End Demo (Real LLM)")
    print("=" * 70)

    provider = "anthropic"
    llm = build_client(provider)
    tracked = CostTrackingClient(llm)
    loop = TrainingLoop(llm=tracked)

    config = EpisodeConfig(vulnerability_class=vuln_class)

    for i in range(episodes):
        print(f"\n--- Episode {i + 1}/{episodes} ---")
        trace = loop.run_episode(config)
        print(f"  Outcome: {'EXPLOITABLE' if trace.judge_outcome else 'SECURE'}")
        print(f"  Duration: {trace.duration_s:.1f}s")
        if trace.distilled_rule:
            print(f"  Rule: {trace.distilled_rule.rule_text[:60]}")
        if trace.error:
            print(f"  Error: {trace.error}")

    print(f"\nTotal tokens: {tracked.usage.total_tokens}")
    print(f"Estimated cost: ${tracked.usage.total_cost_usd:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CoEvolve Sandbox demo")
    parser.add_argument("--real", action="store_true", help="Use real LLM calls")
    parser.add_argument("--episodes", type=int, default=3, help="Number of episodes")
    parser.add_argument("--vuln", type=str, default="SQLi", help="Vulnerability class")
    args = parser.parse_args()

    if args.real:
        run_demo_real(episodes=args.episodes, vuln_class=args.vuln)
    else:
        run_demo_mock(episodes=args.episodes, vuln_class=args.vuln)


if __name__ == "__main__":
    main()
