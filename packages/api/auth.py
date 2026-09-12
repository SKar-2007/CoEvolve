"""API authentication and rate limiting middleware.

Provides:
- API key authentication via X-API-Key header or ?api_key= query param
- Per-key rate limiting with sliding window
- Configurable limits per endpoint tier (public, standard, admin)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

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
    """In-memory API key store. Replace with DB-backed store in production."""

    def __init__(self) -> None:
        self._keys: dict[str, APIKey] = {}

    def create_key(self, name: str, tier: str = "standard") -> APIKey:
        key = f"cov_{secrets.token_urlsafe(32)}"
        api_key = APIKey(key=key, name=name, tier=tier)
        self._keys[api_key.key_hash] = api_key
        return api_key

    def validate(self, key: str) -> APIKey | None:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        api_key = self._keys.get(key_hash)
        if api_key and not api_key.disabled:
            api_key.last_used = time.time()
            return api_key
        return None

    def disable(self, key: str) -> bool:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        if key_hash in self._keys:
            self._keys[key_hash].disabled = True
            return True
        return False

    def list_keys(self) -> list[APIKey]:
        return list(self._keys.values())

    def get_key(self, key: str) -> APIKey | None:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self._keys.get(key_hash)


# Global key store
_key_store: APIKeyStore | None = None


def get_key_store() -> APIKeyStore:
    global _key_store
    if _key_store is None:
        _key_store = APIKeyStore()
        # Create a default admin key for development
        _key_store.create_key("dev-admin", tier="admin")
    return _key_store


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
    """Sliding window rate limiter."""

    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, tier: str = "standard") -> tuple[bool, dict[str, Any]]:
        config = TIER_LIMITS.get(tier, TIER_LIMITS["standard"])
        now = time.time()
        window = self._windows[key]

        # Remove entries older than 1 hour
        window[:] = [t for t in window if now - t < 3600]

        # Count requests in last minute
        recent = sum(1 for t in window if now - t < 60)

        # Check limits
        if recent >= config.requests_per_minute:
            retry_after = 60 - (now - window[-(config.requests_per_minute)])
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


_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


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
