"""Background worker for async training jobs.

Polls the task queue and executes training episodes.

Usage:
    python -m packages.api.worker                    # Run worker
    python -m packages.api.worker --concurrency 4    # 4 worker threads
    python -m packages.api.worker --once             # Process one job and exit
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from typing import Any

logger = logging.getLogger("coevolve.worker")

_shutdown = False


def _handle_signal(signum: int, frame: Any) -> None:
    global _shutdown
    logger.info("Received signal %d, shutting down gracefully...", signum)
    _shutdown = True


class TrainingWorker:
    """Polls the queue and runs training episodes."""

    def __init__(self, poll_interval: float = 2.0) -> None:
        self.poll_interval = poll_interval
        self._queue: Any = None
        self._llm: Any = None

    def _ensure_initialized(self) -> None:
        """Lazy-init queue and LLM client."""
        if self._queue is not None:
            return

        from dotenv import load_dotenv

        load_dotenv()

        from packages.agents.llm import build_client
        from packages.api.config import get_settings
        from packages.api.task_queue import TaskQueue

        settings = get_settings()
        self._queue = TaskQueue(redis_url=settings.redis_url)

        provider = os.getenv("LLM_PROVIDER", "openrouter")
        model = os.getenv("LLM_MODEL", "deepseek/deepseek-chat-v3-0324")
        self._llm = build_client(provider, model)

        logger.info(
            "Worker initialized: provider=%s model=%s redis=%s",
            provider,
            model,
            "yes" if self._queue.is_distributed else "no (in-memory)",
        )

    def run_forever(self) -> None:
        """Poll queue and process jobs until shutdown."""
        self._ensure_initialized()
        logger.info("Worker started, polling every %.1fs", self.poll_interval)

        while not _shutdown:
            self._process_one()
            time.sleep(self.poll_interval)

        logger.info("Worker stopped")

    def run_once(self) -> bool:
        """Process one job. Returns True if a job was processed."""
        self._ensure_initialized()
        return self._process_one()

    def _process_one(self) -> bool:
        """Dequeue and execute one job. Returns True if a job was processed."""
        job = self._queue.dequeue(timeout=1)
        if job is None:
            return False

        logger.info(
            "Processing job %s (vuln=%s)",
            job.job_id,
            job.vulnerability_class,
        )

        try:
            from packages.agents.cost_tracking import CostTrackingClient
            from packages.agents.training_loop import EpisodeConfig, TrainingLoop

            # Get current Elo from DB
            from packages.api.database import get_session_factory
            from packages.api.models import EloRecord

            db = get_session_factory()()
            try:
                elo_record = db.get(EloRecord, "global")
                current_ratings = (
                    (elo_record.attacker_rating, elo_record.developer_rating)
                    if elo_record
                    else (1500.0, 1500.0)
                )

                # Get prompt version
                from packages.api.models import PromptRecord

                latest_prompt = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
                prompt_version = latest_prompt.version if latest_prompt else 0
            finally:
                db.close()

            # Run training episode
            tracked = CostTrackingClient(self._llm)
            loop = TrainingLoop(llm=tracked, prompt_version=prompt_version)
            config = EpisodeConfig(
                vulnerability_class=job.vulnerability_class,
                language=job.language,
                context_hint=job.context_hint,
                max_retries=job.max_retries,
            )
            trace = loop.run_episode(config, current_ratings=current_ratings)

            # Persist results to DB
            db = get_session_factory()()
            try:
                from packages.api.models import EpisodeRecord, RuleRecord

                ep = EpisodeRecord(
                    id=trace.episode_id,
                    status="completed" if not trace.error else "failed",
                    vulnerability_class=job.vulnerability_class,
                    difficulty_tier=trace.difficulty_tier,
                    outcome=trace.judge_outcome,
                    task_description=trace.task.task_description if trace.task else "",
                    patch_text=trace.patch_text,
                    judge_verdict=trace.judge_verdict,
                    attacker_rating=trace.elo_after.get("attacker", current_ratings[0]),
                    developer_rating=trace.elo_after.get("developer", current_ratings[1]),
                    prompt_version=trace.prompt_version,
                    error=trace.error or None,
                )
                db.add(ep)

                # Update global Elo
                elo_record = db.get(EloRecord, "global")
                if elo_record:
                    elo_record.attacker_rating = trace.elo_after.get(
                        "attacker", elo_record.attacker_rating
                    )
                    elo_record.developer_rating = trace.elo_after.get(
                        "developer", elo_record.developer_rating
                    )
                    elo_record.episodes_played += 1

                # Record distilled rule
                if trace.distilled_rule and trace.regression_passed:
                    rule = trace.distilled_rule
                    db.add(
                        RuleRecord(
                            rule_text=rule.rule_text,
                            vulnerability_class=rule.vulnerability_class,
                            source_pattern=rule.source_pattern,
                            recommended_fix=rule.recommended_fix,
                            source_trace_id=rule.source_trace_id,
                            prompt_version=trace.prompt_version,
                            approved=True,
                        )
                    )

                db.commit()
            finally:
                db.close()

            # Store result in job
            job.result = {
                "episode_id": trace.episode_id,
                "outcome": trace.judge_outcome,
                "difficulty_tier": trace.difficulty_tier,
                "elo_after": trace.elo_after,
                "rule_distilled": trace.distilled_rule is not None and trace.regression_passed,
                "duration_s": trace.duration_s,
            }
            self._queue.complete(job)

            logger.info(
                "Job %s completed: outcome=%d duration=%.1fs",
                job.job_id,
                trace.judge_outcome,
                trace.duration_s,
            )

        except Exception as exc:
            logger.exception("Job %s failed: %s", job.job_id, exc)
            self._queue.fail(job, str(exc))

        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="CoEvolve training worker")
    parser.add_argument("--concurrency", type=int, default=1, help="Number of worker threads")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between polls")
    parser.add_argument("--once", action="store_true", help="Process one job and exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    worker = TrainingWorker(poll_interval=args.poll_interval)

    if args.once:
        processed = worker.run_once()
        sys.exit(0 if processed else 1)

    worker.run_forever()


if __name__ == "__main__":
    main()
