"""Tests for TaskQueue in-memory backend (Redis fallback path)."""

from __future__ import annotations

from packages.api.task_queue import JobStatus, TaskQueue, TrainingJob


class TestTrainingJob:
    def test_roundtrip(self):
        j = TrainingJob(vulnerability_class="XSS", language="python")
        j2 = TrainingJob.from_json(j.to_json())
        assert j2.job_id == j.job_id
        assert j2.vulnerability_class == "XSS"
        assert j2.status == JobStatus.PENDING


class TestTaskQueueMemory:
    def test_enqueue_dequeue(self):
        q = TaskQueue(redis_url=None)
        assert q.is_distributed is False
        j = q.enqueue(TrainingJob(vulnerability_class="SQLi"))
        assert q.queue_length() == 1
        got = q.dequeue()
        assert got is not None
        assert got.job_id == j.job_id
        assert q.queue_length() == 0

    def test_dequeue_empty(self):
        q = TaskQueue(redis_url=None)
        assert q.dequeue() is None

    def test_complete_and_get(self):
        q = TaskQueue(redis_url=None)
        j = q.enqueue(TrainingJob())
        q.dequeue()
        j.result = {"ok": True}
        q.complete(j)
        fetched = q.get_job(j.job_id)
        assert fetched is not None
        assert fetched.status == JobStatus.COMPLETED

    def test_fail(self):
        q = TaskQueue(redis_url=None)
        j = q.enqueue(TrainingJob())
        q.fail(j, "boom")
        fetched = q.get_job(j.job_id)
        assert fetched is not None
        assert fetched.status == JobStatus.FAILED
        assert fetched.error == "boom"

    def test_list_jobs(self):
        q = TaskQueue(redis_url=None)
        for _ in range(3):
            q.enqueue(TrainingJob())
        jobs = q.list_jobs(limit=2)
        assert len(jobs) == 2

    def test_redis_unavailable_falls_back(self):
        # Invalid URL must not raise — falls back to memory
        q = TaskQueue(redis_url="redis://127.0.0.1:6399/0")
        assert q.is_distributed is False


class TestRedisTTL:
    def test_terminal_keys_expire(self):
        calls = []

        class Stub:
            def set(self, key, value, ex=None):
                calls.append((key, ex))

        q = TaskQueue(redis_url=None)
        q._redis = Stub()
        job = TrainingJob()
        q.complete(job)
        assert calls, "complete must write to redis"
        assert all(ex == TaskQueue.RESULT_TTL_SECONDS for _, ex in calls)
        calls.clear()
        q.fail(TrainingJob(), "boom")
        assert calls, "fail must write to redis"
        assert all(ex == TaskQueue.RESULT_TTL_SECONDS for _, ex in calls)
