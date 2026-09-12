"""Redis-backed task queue for async training episodes.

Provides enqueue/dequeue of training jobs so the API can return immediately
while episodes run in the background.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TrainingJob:
    """A training episode job queued for execution."""

    job_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: JobStatus = JobStatus.PENDING
    vulnerability_class: str = "SQLi"
    language: str = "python"
    context_hint: str = ""
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, data: str) -> TrainingJob:
        d = json.loads(data)
        d["status"] = JobStatus(d["status"])
        return cls(**d)


class TaskQueue:
    """Redis-backed task queue for training jobs.

    Falls back to an in-memory queue if Redis is unavailable.
    """

    QUEUE_KEY = "coevolve:training:queue"
    RESULTS_PREFIX = "coevolve:training:result:"
    STATUS_PREFIX = "coevolve:training:status:"

    def __init__(self, redis_url: str | None = None) -> None:
        self._redis: Any = None
        self._memory_queue: list[TrainingJob] = []
        self._memory_results: dict[str, TrainingJob] = {}

        if redis_url:
            try:
                import redis

                self._redis = redis.from_url(redis_url, decode_responses=True)
                self._redis.ping()
                logger.info("Connected to Redis at %s", redis_url)
            except Exception:
                logger.warning("Redis unavailable at %s, using in-memory queue", redis_url)
                self._redis = None

    @property
    def is_distributed(self) -> bool:
        return self._redis is not None

    def enqueue(self, job: TrainingJob) -> TrainingJob:
        """Add a job to the queue."""
        if self._redis:
            self._redis.lpush(self.QUEUE_KEY, job.to_json())
            self._redis.set(f"{self.STATUS_PREFIX}{job.job_id}", job.status.value)
            logger.info("Enqueued job %s to Redis", job.job_id)
        else:
            self._memory_queue.append(job)
            self._memory_results[job.job_id] = job
            logger.info("Enqueued job %s to memory queue", job.job_id)
        return job

    def dequeue(self, timeout: int = 5) -> TrainingJob | None:
        """Blocking dequeue from the queue. Returns None on timeout."""
        if self._redis:
            result = self._redis.brpop(self.QUEUE_KEY, timeout=timeout)
            if result:
                _, data = result
                job = TrainingJob.from_json(data)
                job.status = JobStatus.RUNNING
                job.started_at = time.time()
                self._redis.set(f"{self.STATUS_PREFIX}{job.job_id}", job.status.value)
                return job
            return None
        if self._memory_queue:
            return self._memory_queue.pop(0)
        return None

    def complete(self, job: TrainingJob) -> None:
        """Mark a job as completed and store its result."""
        job.status = JobStatus.COMPLETED
        job.completed_at = time.time()
        if self._redis:
            self._redis.set(f"{self.STATUS_PREFIX}{job.job_id}", job.status.value)
            self._redis.set(f"{self.RESULTS_PREFIX}{job.job_id}", job.to_json())
        else:
            self._memory_results[job.job_id] = job

    def fail(self, job: TrainingJob, error: str) -> None:
        """Mark a job as failed."""
        job.status = JobStatus.FAILED
        job.error = error
        job.completed_at = time.time()
        if self._redis:
            self._redis.set(f"{self.STATUS_PREFIX}{job.job_id}", job.status.value)
            self._redis.set(f"{self.RESULTS_PREFIX}{job.job_id}", job.to_json())
        else:
            self._memory_results[job.job_id] = job

    def get_job(self, job_id: str) -> TrainingJob | None:
        """Get a job by ID."""
        if self._redis:
            data = self._redis.get(f"{self.RESULTS_PREFIX}{job_id}")
            if data:
                return TrainingJob.from_json(data)
            status = self._redis.get(f"{self.STATUS_PREFIX}{job_id}")
            if status:
                return TrainingJob(job_id=job_id, status=JobStatus(status))
            return None
        return self._memory_results.get(job_id)

    def queue_length(self) -> int:
        """Return the number of pending jobs."""
        if self._redis:
            return self._redis.llen(self.QUEUE_KEY)
        return len(self._memory_queue)

    def list_jobs(self, limit: int = 50) -> list[TrainingJob]:
        """List recent jobs."""
        if self._redis:
            keys = self._redis.keys(f"{self.STATUS_PREFIX}*")
            jobs: list[TrainingJob] = []
            for key in keys[-limit:]:
                job_id = key.replace(self.STATUS_PREFIX, "")
                job = self.get_job(job_id)
                if job:
                    jobs.append(job)
            return sorted(jobs, key=lambda j: j.created_at, reverse=True)[:limit]
        return sorted(
            self._memory_results.values(),
            key=lambda j: j.created_at,
            reverse=True,
        )[:limit]
