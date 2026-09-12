"""Background worker for async training jobs.

Polls the task queue and executes training episodes (single-threaded;
scale by running multiple worker processes, ideally with Redis).

Usage:
    python -m packages.api.worker                    # Run worker
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
        """Lazy-init queue and LLM client (uses shared resolve_llm_provider)."""
        if self._queue is not None:
            return

        from dotenv import load_dotenv

        load_dotenv()

        from packages.agents.llm import build_client
        from packages.api.config import get_settings
        from packages.api.task_queue import TaskQueue
        from packages.api.training_service import resolve_llm_provider

        settings = get_settings()
        # Prefer explicit REDIS_URL, fall back to UPSTASH_REDIS_URL.
        redis_url = settings.resolved_redis_url or os.getenv("REDIS_URL", "")
        self._queue = TaskQueue(redis_url=redis_url or None)

        provider, key, model = resolve_llm_provider(settings)
        # Allow explicit LLM_PROVIDER/LLM_MODEL env override for ops flexibility.
        provider = os.getenv("LLM_PROVIDER", provider)
        model = os.getenv("LLM_MODEL", model)
        api_key = key
        if provider == "groq":
            api_key = os.getenv("GROQ_API_KEY", key or "")
        self._llm = build_client(provider, model, api_key=api_key)

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
            from packages.api.database import get_session_factory
            from packages.api.training_service import (
                get_current_ratings,
                get_prompt_version,
                persist_episode,
            )

            # Get current Elo + prompt version via shared helpers
            db = get_session_factory()()
            try:
                current_ratings = get_current_ratings(db)
                prompt_version = get_prompt_version(db)
            finally:
                db.close()

            # Run training episode (honours the job's use_react flag)
            tracked = CostTrackingClient(self._llm)
            loop = TrainingLoop(
                llm=tracked,
                prompt_version=prompt_version,
                use_react=job.use_react,
            )
            config = EpisodeConfig(
                vulnerability_class=job.vulnerability_class,
                language=job.language,
                context_hint=job.context_hint,
                max_retries=job.max_retries,
            )
            trace = loop.run_episode(config, current_ratings=current_ratings)

            # Persist results to DB via shared helper (single source of truth)
            db = get_session_factory()()
            try:
                persist_episode(
                    db,
                    trace=trace,
                    vulnerability_class=job.vulnerability_class,
                    current_ratings=current_ratings,
                )
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
            _notify_failure(job, exc)

        return True


def _build_alerter() -> Any:
    """Build an AlertManager from env (log-only unless channels configured)."""
    from packages.telemetry.alerting import AlertManager, LogChannel, SlackChannel

    manager = AlertManager()
    webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    if webhook:
        manager.add_channel(SlackChannel(webhook))
    else:
        manager.add_channel(LogChannel())
    return manager


def _notify_failure(job: Any, exc: Exception) -> None:
    """Alert on job failure. Never raises (alerting must not break the loop)."""
    try:
        _build_alerter().notify_error(
            f"Training job {job.job_id} failed: {exc}",
            context=f"vuln={job.vulnerability_class} lang={job.language}",
        )
    except Exception:
        logger.warning("Failure notification failed", exc_info=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="CoEvolve training worker")
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
