"""Tests for RedisRateLimiter using an in-test sorted-set stub (no server needed)."""

from __future__ import annotations

from packages.api.auth import (
    TIER_LIMITS,
    RedisRateLimiter,
    _build_rate_limiter,
    get_rate_limiter,
    reset_rate_limiter,
)


class FakeRedis:
    """Minimal sorted-set stub with real sliding-window semantics."""

    def __init__(self) -> None:
        self.data: dict[str, dict[str, float]] = {}

    # -- direct commands -------------------------------------------------
    def zadd(self, key, mapping):
        self.data.setdefault(key, {}).update(mapping)
        return len(mapping)

    def zremrangebyscore(self, key, lo, hi):
        d = self.data.get(key, {})
        gone = [m for m, s in d.items() if lo <= s <= hi]
        for m in gone:
            del d[m]
        return len(gone)

    def zcount(self, key, lo, hi):
        return sum(1 for s in self.data.get(key, {}).values() if lo <= s <= hi)

    def zcard(self, key):
        return len(self.data.get(key, {}))

    def zrangebyscore(self, key, lo, hi, start=0, num=None, withscores=False):
        items = sorted(
            ((m, s) for m, s in self.data.get(key, {}).items() if lo <= s <= hi),
            key=lambda kv: kv[1],
        )
        items = items[start : start + num if num is not None else None]
        return items if withscores else [m for m, _ in items]

    def zrem(self, key, *members):
        d = self.data.get(key, {})
        n = 0
        for m in members:
            if m in d:
                del d[m]
                n += 1
        return n

    def expire(self, key, ttl):
        return True

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.data:
                del self.data[k]
                n += 1
        return n

    def scan_iter(self, match):
        prefix = match.rstrip("*")
        return [k for k in self.data if k.startswith(prefix)]

    def pipeline(self):
        inner = self

        class Pipe:
            def __init__(self):
                self.ops = []

            def zremrangebyscore(self, key, lo, hi):
                self.ops.append(("zremrangebyscore", key, lo, hi))
                return self

            def zadd(self, key, mapping):
                self.ops.append(("zadd", key, mapping))
                return self

            def expire(self, key, ttl):
                self.ops.append(("expire", key, ttl))
                return self

            def execute(self):
                out = []
                for op in self.ops:
                    out.append(getattr(inner, op[0])(*op[1:]))
                return out

        return Pipe()


class TestRedisRateLimiter:
    def test_allows_within_limit(self):
        r = RedisRateLimiter(FakeRedis())
        allowed, info = r.is_allowed("k1", "standard")
        assert allowed is True
        assert info["remaining"] == TIER_LIMITS["standard"].requests_per_minute - 1

    def test_blocks_over_minute_limit(self):
        r = RedisRateLimiter(FakeRedis())
        for _ in range(60):
            allowed, _ = r.is_allowed("k1", "standard")
            assert allowed is True
        allowed, info = r.is_allowed("k1", "standard")
        assert allowed is False
        assert info["remaining"] == 0
        assert info["retry_after"] >= 1

    def test_keys_independent(self):
        r = RedisRateLimiter(FakeRedis())
        for _ in range(60):
            r.is_allowed("busy", "standard")
        allowed, _ = r.is_allowed("idle", "standard")
        assert allowed is True

    def test_public_tier_lower(self):
        r = RedisRateLimiter(FakeRedis())
        for _ in range(10):
            assert r.is_allowed("p", "public")[0] is True
        assert r.is_allowed("p", "public")[0] is False

    def test_denied_request_not_counted(self):
        stub = FakeRedis()
        r = RedisRateLimiter(stub)
        for _ in range(60):
            r.is_allowed("k", "standard")
        assert r.is_allowed("k", "standard")[0] is False
        # Denied member removed: exactly 60 entries retained
        assert stub.zcard("coevolve:rl:k") == 60

    def test_reset(self):
        stub = FakeRedis()
        r = RedisRateLimiter(stub)
        r.is_allowed("k", "standard")
        r.reset("k")
        assert stub.zcard("coevolve:rl:k") == 0
        r.is_allowed("a", "standard")
        r.is_allowed("b", "standard")
        r.reset()
        assert stub.data == {}

    def test_redis_failure_fails_open(self):
        class Broken:
            def pipeline(self):
                raise ConnectionError("down")

        r = RedisRateLimiter(Broken())
        allowed, _ = r.is_allowed("k", "standard")
        assert allowed is True


class TestLimiterSelection:
    def test_memory_without_redis_url(self, monkeypatch):
        monkeypatch.setenv("REDIS_URL", "")
        monkeypatch.setenv("UPSTASH_REDIS_URL", "")
        from packages.api.config import get_settings

        get_settings.cache_clear()
        reset_rate_limiter()
        try:
            from packages.api.auth import RateLimiter

            assert isinstance(get_rate_limiter(), RateLimiter)
        finally:
            reset_rate_limiter()
            get_settings.cache_clear()

    def test_unreachable_redis_falls_back(self, monkeypatch):
        monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
        monkeypatch.delenv("UPSTASH_REDIS_URL", raising=False)
        from packages.api.config import get_settings

        get_settings.cache_clear()
        reset_rate_limiter()
        try:
            from packages.api.auth import RateLimiter

            assert isinstance(get_rate_limiter(), RateLimiter)
        finally:
            reset_rate_limiter()
            get_settings.cache_clear()

    def test_build_rate_limiter_direct(self):
        from packages.api.auth import RateLimiter

        assert isinstance(_build_rate_limiter(), RateLimiter)
