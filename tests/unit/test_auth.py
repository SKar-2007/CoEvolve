"""Tests for API authentication and rate limiting."""

from __future__ import annotations

from packages.api.auth import (
    TIER_LIMITS,
    APIKeyStore,
    RateLimiter,
    hash_password,
    verify_password,
)


class TestAPIKeyStore:
    def test_create_key(self):
        store = APIKeyStore()
        key = store.create_key("test-key", tier="standard")
        assert key.name == "test-key"
        assert key.tier == "standard"
        assert key.key.startswith("cov_")

    def test_validate_key(self):
        store = APIKeyStore()
        key = store.create_key("test-key")
        validated = store.validate(key.key)
        assert validated is not None
        assert validated.name == "test-key"

    def test_validate_invalid_key(self):
        store = APIKeyStore()
        assert store.validate("invalid-key") is None

    def test_disable_key(self):
        store = APIKeyStore()
        key = store.create_key("test-key")
        assert store.disable(key.key) is True
        assert store.validate(key.key) is None

    def test_list_keys(self):
        store = APIKeyStore()
        store.create_key("key1")
        store.create_key("key2")
        assert len(store.list_keys()) == 2

    def test_key_hash_unique(self):
        store = APIKeyStore()
        key1 = store.create_key("key1")
        key2 = store.create_key("key2")
        assert key1.key_hash != key2.key_hash


class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = RateLimiter()
        allowed, info = limiter.is_allowed("test-key", "standard")
        assert allowed is True
        assert info["remaining"] > 0

    def test_blocks_over_limit(self):
        limiter = RateLimiter()
        # Exhaust the limit
        for _ in range(60):
            limiter.is_allowed("test-key", "standard")
        # Next request should be blocked
        allowed, info = limiter.is_allowed("test-key", "standard")
        assert allowed is False
        assert info["remaining"] == 0
        assert "retry_after" in info

    def test_different_keys_independent(self):
        limiter = RateLimiter()
        for _ in range(60):
            limiter.is_allowed("key1", "standard")
        # key2 should still be allowed
        allowed, _ = limiter.is_allowed("key2", "standard")
        assert allowed is True

    def test_tier_limits(self):
        assert (
            TIER_LIMITS["public"].requests_per_minute < TIER_LIMITS["standard"].requests_per_minute
        )
        assert (
            TIER_LIMITS["standard"].requests_per_minute < TIER_LIMITS["admin"].requests_per_minute
        )


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "secure-password-123"
        stored = hash_password(password)
        assert verify_password(password, stored) is True

    def test_wrong_password(self):
        password = "secure-password-123"
        stored = hash_password(password)
        assert verify_password("wrong-password", stored) is False

    def test_different_hashes(self):
        stored1 = hash_password("password")
        stored2 = hash_password("password")
        assert stored1 != stored2  # Different salts
