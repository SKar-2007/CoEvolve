#!/usr/bin/env python3
"""Batch training script — run N episodes with convergence detection.

Usage:
    python scripts/train.py                    # 50 mock episodes
    python scripts/train.py --episodes 200     # 200 episodes
    python scripts/train.py --real             # Real LLM calls
    python scripts/train.py --react            # Use ReAct developer agent
    python scripts/train.py --no-round-robin   # Random class selection
    python scripts/train.py --output report.json  # Save JSON report
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main() -> None:
    parser = argparse.ArgumentParser(description="CoEvolve batch training")
    parser.add_argument("--episodes", type=int, default=50, help="Number of episodes")
    parser.add_argument("--real", action="store_true", help="Use real LLM calls")
    parser.add_argument("--react", action="store_true", help="Use ReAct tool-use developer")
    parser.add_argument("--round-robin", action="store_true", default=True, help="Cycle through vuln classes (default)")
    parser.add_argument("--no-round-robin", action="store_true", help="Random class selection")
    parser.add_argument("--classes", type=str, nargs="*", help="Vulnerability classes to use")
    parser.add_argument("--output", type=str, default="", help="Save JSON report")
    args = parser.parse_args()

    from dotenv import load_dotenv

    load_dotenv()

    from packages.agents.batch_trainer import TrainingSession, print_batch_report

    if args.real:
        import os
        from packages.agents.llm import build_client

        provider = os.getenv("LLM_PROVIDER", "openrouter")
        model = os.getenv("LLM_MODEL", "deepseek/deepseek-chat-v3-0324")
        llm = build_client(provider, model)
    else:
        from scripts.benchmark import MockLLM

        llm = MockLLM()

    mode = "real" if args.real else "mock"
    agent = "ReAct" if args.react else "simple"
    print(f"Running {args.episodes} episodes ({mode} mode, {agent} developer)...")

    session = TrainingSession(
        llm=llm,
        episodes=args.episodes,
        vulnerability_classes=args.classes,
        use_react=args.react,
        round_robin=not args.no_round_robin,
    )

    report = session.run(verbose=True)
    print_batch_report(report)

    if args.output:
        # Convert to serializable dict
        data = {
            "total_episodes": report.total_episodes,
            "total_time_s": report.total_time_s,
            "episodes_per_second": report.episodes_per_second,
            "secure": report.secure,
            "exploitable": report.exploitable,
            "errors": report.errors,
            "secure_rate": report.secure_rate,
            "elo": {
                "attacker": {"before": report.initial_attacker_elo, "after": report.final_attacker_elo},
                "developer": {"before": report.initial_developer_elo, "after": report.final_developer_elo},
            },
            "class_stats": {
                vc: {"total": s.total, "secure": s.secure, "exploitable": s.exploitable, "win_rate": s.win_rate}
                for vc, s in report.class_stats.items()
            },
            "rules": {"distilled": report.rules_distilled, "accepted": report.rules_accepted},
        }
        Path(args.output).write_text(json.dumps(data, indent=2))
        print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
