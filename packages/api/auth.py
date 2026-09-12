"""API authentication and rate limiting middleware.

Provides:
- API key authentication via X-API-Key header or ?api_key= query param
- Per-key rate limiting with sliding window
- Configurable limits per endpoint tier (public, standard, admin)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, APIKeyQuery

# ---------------------------------------------------------------------------
# API Key storage
# ---------------------------------------------------------------------------

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
API_KEY_QUERY = APIKeyQuery(name="api_key", auto_error=False)


@dataclass
class APIKey:
    """An API key with metadata."""

    key: str
    name: str = ""
    tier: str = "standard"  # public, standard, admin
    created_at: float = field(default_factory=time.time)
    last_used: float = 0.0
    disabled: bool = False

    @property
    def key_hash(self) -> str:
        return hashlib.sha256(self.key.encode()).hexdigest()[:16]


class APIKeyStore:
    """Thread-safe in-memory API key store.

    NOTE: keys are lost on restart and are not shared across uvicorn
    workers. Replace with a DB-backed store in production when running
    with --workers > 1 or REQUIRE_AUTH=true.
    """

    def __init__(self) -> None:
        self._keys: dict[str, APIKey] = {}
        self._lock = threading.Lock()

    def create_key(self, name: str, tier: str = "standard") -> APIKey:
        key = f"cov_{secrets.token_urlsafe(32)}"
        api_key = APIKey(key=key, name=name, tier=tier)
        with self._lock:
            self._keys[api_key.key_hash] = api_key
        return api_key

    def validate(self, key: str) -> APIKey | None:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        with self._lock:
            api_key = self._keys.get(key_hash)
            if api_key and not api_key.disabled:
                api_key.last_used = time.time()
                return api_key
        return None

    def disable(self, key: str) -> bool:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        with self._lock:
            if key_hash in self._keys:
                self._keys[key_hash].disabled = True
                return True
        return False

    def list_keys(self) -> list[APIKey]:
        with self._lock:
            return list(self._keys.values())

    def get_key(self, key: str) -> APIKey | None:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        with self._lock:
            return self._keys.get(key_hash)


class DBAPIKeyStore:
    """Database-backed API key store (survives restarts, shared across workers).

    Only key hashes are persisted (``api_keys`` table, created by
    ``Base.metadata.create_all`` on startup). The raw key is returned exactly
    once by :meth:`create_key` and must be stored securely by the operator.
    ``validate`` returns an ``APIKey`` carrying the *presented* credential
    transiently so ``key_hash``-based rate-limit bucketing keeps working;
    it is never written anywhere.
    """

    def __init__(self, session_factory: Any = None) -> None:
        self._session_factory = session_factory

    def _factory(self) -> Any:
        if self._session_factory is not None:
            return self._session_factory
        from .database import get_session_factory

        return get_session_factory()

    def create_key(self, name: str, tier: str = "standard") -> APIKey:
        from .models import ApiKeyRecord

        key = f"cov_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        db = self._factory()()
        try:
            db.add(
                ApiKeyRecord(
                    key_hash=key_hash,
                    name=name,
                    tier=tier,
                    disabled=False,
                    created_at=time.time(),
                    last_used=0.0,
                )
            )
            db.commit()
        finally:
            db.close()
        logger.info("Created API key %r (tier=%s)", name, tier)
        return APIKey(key=key, name=name, tier=tier)

    def validate(self, key: str) -> APIKey | None:
        from .models import ApiKeyRecord

        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        db = self._factory()()
        try:
            record = db.get(ApiKeyRecord, key_hash)
            if record is None or record.disabled:
                return None
            record.last_used = time.time()
            db.commit()
            return APIKey(
                key=key,
                name=record.name,
                tier=record.tier,
                created_at=record.created_at,
                last_used=record.last_used,
                disabled=False,
            )
        finally:
            db.close()

    def disable(self, key: str) -> bool:
        from .models import ApiKeyRecord

        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        db = self._factory()()
        try:
            record = db.get(ApiKeyRecord, key_hash)
            if record is None:
                return False
            record.disabled = True
            db.commit()
            return True
        finally:
            db.close()

    def list_keys(self) -> list[APIKey]:
        """List keys with raw values redacted (hashes are unrecoverable by design)."""
        from .models import ApiKeyRecord

        db = self._factory()()
        try:
            records = db.query(ApiKeyRecord).all()
            return [
                APIKey(
                    key="",
                    name=r.name,
                    tier=r.tier,
                    created_at=r.created_at,
                    last_used=r.last_used,
                    disabled=r.disabled,
                )
                for r in records
            ]
        finally:
            db.close()

    def ensure_bootstrap_key(self, raw_key: str, name: str = "admin-env") -> None:
        """Register the ``ADMIN_API_KEY`` env value if not already present."""
        from .models import ApiKeyRecord

        if not raw_key:
            return
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:16]
        db = self._factory()()
        try:
            if db.get(ApiKeyRecord, key_hash) is None:
                db.add(
                    ApiKeyRecord(
                        key_hash=key_hash,
                        name=name,
                        tier="admin",
                        disabled=False,
                        created_at=time.time(),
                        last_used=0.0,
                    )
                )
                db.commit()
                logger.info("Registered bootstrap admin API key from environment")
        finally:
            db.close()


def _store_backend() -> str:
    try:
        from .config import get_settings

        return (get_settings().api_key_store or "memory").lower()
    except Exception:
        return os.getenv("API_KEY_STORE", "memory").lower()


def _bootstrap_admin_key(store: APIKeyStore | DBAPIKeyStore) -> None:
    """Register ADMIN_API_KEY when set (works with both backends)."""
    try:
        from .config import get_settings

        raw = get_settings().admin_api_key
    except Exception:
        raw = os.getenv("ADMIN_API_KEY", "")
    if not raw:
        return
    if isinstance(store, DBAPIKeyStore):
        store.ensure_bootstrap_key(raw)
    elif store.validate(raw) is None:
        key_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
        with store._lock:
            store._keys[key_hash] = APIKey(key=raw, name="admin-env", tier="admin")


# Global key store
_key_store: APIKeyStore | DBAPIKeyStore | None = None
_key_store_lock = threading.Lock()


def get_key_store() -> APIKeyStore | DBAPIKeyStore:
    global _key_store
    if _key_store is None:
        with _key_store_lock:
            if _key_store is None:
                if _store_backend() == "db":
                    _key_store = DBAPIKeyStore()
                else:
                    _key_store = APIKeyStore()
                    # Create a default admin key for development
                    _key_store.create_key("dev-admin", tier="admin")
                _bootstrap_admin_key(_key_store)
    return _key_store


def reset_key_store() -> None:
    """Reset global key store (for testing)."""
    global _key_store
    with _key_store_lock:
        _key_store = None


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a tier."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst: int = 10  # max burst size


TIER_LIMITS = {
    "public": RateLimitConfig(requests_per_minute=10, requests_per_hour=100, burst=5),
    "standard": RateLimitConfig(requests_per_minute=60, requests_per_hour=1000, burst=10),
    "admin": RateLimitConfig(requests_per_minute=300, requests_per_hour=10000, burst=50),
}


class RateLimiter:
    """Thread-safe in-memory sliding window rate limiter.

    NOTE: state is per-process. With multiple uvicorn workers the effective
    limit is multiplied by the worker count — set REDIS_URL in production
    so get_rate_limiter() returns the shared RedisRateLimiter instead.
    """

    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, tier: str = "standard") -> tuple[bool, dict[str, Any]]:
        config = TIER_LIMITS.get(tier, TIER_LIMITS["standard"])
        now = time.time()
        with self._lock:
            window = self._windows[key]

            # Remove entries older than 1 hour
            window[:] = [t for t in window if now - t < 3600]

            # Count requests in last minute
            recent = sum(1 for t in window if now - t < 60)

            # Check limits
            if recent >= config.requests_per_minute:
                idx = max(0, len(window) - config.requests_per_minute)
                retry_after = max(1.0, 60 - (now - window[idx]))
                return False, {
                    "limit": config.requests_per_minute,
                    "remaining": 0,
                    "reset": int(now + retry_after),
                    "retry_after": int(retry_after),
                }

            # Check hourly limit
            if len(window) >= config.requests_per_hour:
                return False, {
                    "limit": config.requests_per_hour,
                    "remaining": 0,
                    "reset": int(now + 3600),
                    "retry_after": 3600,
                }

            window.append(now)
            return True, {
                "limit": config.requests_per_minute,
                "remaining": config.requests_per_minute - recent - 1,
                "reset": int(now + 60),
            }

    def reset(self) -> None:
        """Clear all windows (for testing)."""
        with self._lock:
            self._windows.clear()


class RedisRateLimiter:
    """Redis sliding-window rate limiter shared across workers/processes.

    Uses one sorted set per identifier (``coevolve:rl:<id>``) with request
    timestamps as scores. Atomicity comes from Redis single-command
    semantics plus add-then-count (a denied request removes its own entry).
    On Redis errors it fails open with a warning so a cache outage does not
    take the API down; wire telemetry/alerting to that log in production.
    """

    KEY_PREFIX = "coevolve:rl:"

    def __init__(self, client: Any) -> None:
        self._redis = client

    def _key(self, identifier: str) -> str:
        return f"{self.KEY_PREFIX}{identifier}"

    def is_allowed(self, key: str, tier: str = "standard") -> tuple[bool, dict[str, Any]]:
        config = TIER_LIMITS.get(tier, TIER_LIMITS["standard"])
        now = time.time()
        rkey = self._key(key)
        member = f"{now:.6f}:{secrets.token_hex(8)}"
        fallback = {
            "limit": config.requests_per_minute,
            "remaining": config.requests_per_minute,
            "reset": int(now + 60),
        }
        try:
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(rkey, 0, now - 3600)
            pipe.zadd(rkey, {member: now})
            pipe.expire(rkey, 3600)
            pipe.execute()

            recent = self._redis.zcount(rkey, now - 60, now)
            total = self._redis.zcard(rkey)

            if recent > config.requests_per_minute:
                oldest = self._redis.zrangebyscore(
                    rkey, now - 60, now, start=0, num=1, withscores=True
                )
                retry_after = max(1.0, 60 - (now - oldest[0][1])) if oldest else 60.0
                self._redis.zrem(rkey, member)
                return False, {
                    "limit": config.requests_per_minute,
                    "remaining": 0,
                    "reset": int(now + retry_after),
                    "retry_after": int(retry_after),
                }

            if total > config.requests_per_hour:
                self._redis.zrem(rkey, member)
                return False, {
                    "limit": config.requests_per_hour,
                    "remaining": 0,
                    "reset": int(now + 3600),
                    "retry_after": 3600,
                }

            return True, {
                "limit": config.requests_per_minute,
                "remaining": max(0, config.requests_per_minute - recent),
                "reset": int(now + 60),
            }
        except Exception:
            logger.warning("Redis rate limiter unavailable, allowing request", exc_info=True)
            return True, fallback

    def reset(self, identifier: str | None = None) -> None:
        """Clear windows (all, or one identifier). Used by tests/ops."""
        try:
            if identifier is not None:
                self._redis.delete(self._key(identifier))
                return
            keys: list[str] = []
            if hasattr(self._redis, "scan_iter"):
                keys = list(self._redis.scan_iter(f"{self.KEY_PREFIX}*"))
            else:  # pragma: no cover - stub clients in tests may lack scan
                keys = list(self._redis.keys(f"{self.KEY_PREFIX}*"))
            if keys:
                self._redis.delete(*keys)
        except Exception:
            logger.warning("Redis rate limiter reset failed", exc_info=True)


_rate_limiter: RateLimiter | RedisRateLimiter | None = None
_rate_limiter_lock = threading.Lock()


def _build_rate_limiter() -> RateLimiter | RedisRateLimiter:
    try:
        from .config import get_settings

        redis_url = get_settings().resolved_redis_url
    except Exception:
        redis_url = ""
    if redis_url:
        try:
            import redis

            client = redis.from_url(redis_url, decode_responses=True)
            client.ping()
            logger.info("Using Redis-backed rate limiter")
            return RedisRateLimiter(client)
        except Exception:
            logger.warning(
                "Redis unavailable for rate limiting, using in-memory limiter",
                exc_info=True,
            )
    return RateLimiter()


def get_rate_limiter() -> RateLimiter | RedisRateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        with _rate_limiter_lock:
            if _rate_limiter is None:
                _rate_limiter = _build_rate_limiter()
    return _rate_limiter


def reset_rate_limiter() -> None:
    """Reset the global limiter (for testing)."""
    global _rate_limiter
    with _rate_limiter_lock:
        _rate_limiter = None


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


async def get_api_key(
    request: Request,
    api_key_header: str | None = Security(API_KEY_HEADER),
    api_key_query: str | None = Security(API_KEY_QUERY),
) -> APIKey | None:
    """Extract and validate API key from header or query param.

    Returns None for unauthenticated requests (allows public endpoints).
    """
    key = api_key_header or api_key_query
    if not key:
        return None

    store = get_key_store()
    api_key = store.validate(key)
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key


async def require_api_key(
    request: Request,
    api_key: APIKey | None = Security(get_api_key),
) -> APIKey:
    """Require a valid API key. Raises 401 if missing or invalid."""
    if api_key is None:
        raise HTTPException(status_code=401, detail="API key required")
    return api_key


async def require_api_key_if_enabled(
    request: Request,
    api_key: APIKey | None = Security(get_api_key),
) -> APIKey | None:
    """Enforce API-key auth only when REQUIRE_AUTH=true.

    This keeps backwards compatibility for existing deployments/tests
    (default REQUIRE_AUTH=false) while allowing production to enforce auth
    on mutating endpoints by setting REQUIRE_AUTH=true.
    """
    try:
        from .config import get_settings

        required = get_settings().require_auth
    except Exception:
        required = False
    if required and api_key is None:
        raise HTTPException(status_code=401, detail="API key required")
    return api_key


async def check_rate_limit(
    request: Request,
    api_key: APIKey | None = Security(get_api_key),
) -> None:
    """Check rate limits. Uses key hash or client IP as identifier."""
    limiter = get_rate_limiter()

    if api_key:
        identifier = f"key:{api_key.key_hash}"
        tier = api_key.tier
    else:
        # Use client IP for unauthenticated requests
        client_ip = request.client.host if request.client else "unknown"
        identifier = f"ip:{client_ip}"
        tier = "public"

    allowed, info = limiter.is_allowed(identifier, tier)

    # Add rate limit headers
    request.state.rate_limit_info = info

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={
                "X-RateLimit-Limit": str(info["limit"]),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(info["reset"]),
                "Retry-After": str(info["retry_after"]),
            },
        )


# ---------------------------------------------------------------------------
# Endpoint tier decorators
# ---------------------------------------------------------------------------

ENDPOINT_TIERS = {
    "/health": "public",
    "/dashboard": "public",
    "/metrics": "public",
    "/docs": "public",
    "/openapi.json": "public",
    "/episodes": "standard",
    "/elo": "standard",
    "/prompts": "standard",
    "/rules": "standard",
    "/training": "standard",
}


def get_endpoint_tier(path: str) -> str:
    """Determine the rate limit tier for an endpoint path."""
    for prefix, tier in sorted(ENDPOINT_TIERS.items(), key=lambda x: -len(x[0])):
        if path.startswith(prefix):
            return tier
    return "standard"


# ---------------------------------------------------------------------------
# Password hashing (for admin UI auth)
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a password with a random salt."""
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a password against a stored hash."""
    salt, h = stored.split(":", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(check.hex(), h)
