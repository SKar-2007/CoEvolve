"""Cost tracking and caching wrappers for LLM clients.

Tracks tokens and estimated costs per call. Provides an LRU cache
to avoid re-running identical prompts.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from .llm import LLMClient, LLMResponse

logger = logging.getLogger(__name__)

# Approximate cost per 1M tokens (USD) — update as pricing changes
_PRICING: dict[str, dict[str, dict[str, float]]] = {
    "anthropic": {
        "claude-sonnet-4-5": {"input": 3.00, "output": 15.00},
        "claude-haiku-4-5": {"input": 0.25, "output": 1.25},
    },
    "openai": {
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    },
    "openrouter": {
        "default": {"input": 1.00, "output": 3.00},
    },
}


@dataclass
class TokenUsage:
    """Accumulated token usage across calls."""

    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_calls: int = 0
    total_cost_usd: float = 0.0
    by_provider: dict[str, dict[str, int | float]] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens

    def as_dict(self) -> dict:
        return {
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "total_calls": self.total_calls,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "by_provider": self.by_provider,
        }


def estimate_cost(provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate cost in USD for a single LLM call."""
    provider_rates = _PRICING.get(provider, {})
    rates = provider_rates.get(model, provider_rates.get("default", {"input": 1.0, "output": 3.0}))
    input_cost = (prompt_tokens / 1_000_000) * rates["input"]
    output_cost = (completion_tokens / 1_000_000) * rates["output"]
    return input_cost + output_cost


class CostTrackingClient(LLMClient):
    """Wrapper that tracks token usage and estimated costs."""

    def __init__(self, client: LLMClient) -> None:
        super().__init__(client.model)
        self._client = client
        self.usage = TokenUsage()

    def generate(
        self,
        system: str,
        user: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = self._client.generate(system, user, temperature, max_tokens)

        # Track usage
        self.usage.total_prompt_tokens += response.prompt_tokens
        self.usage.total_completion_tokens += response.completion_tokens
        self.usage.total_calls += 1

        cost = estimate_cost(
            response.provider, response.model,
            response.prompt_tokens, response.completion_tokens,
        )
        self.usage.total_cost_usd += cost

        # Per-provider breakdown
        if response.provider not in self.usage.by_provider:
            self.usage.by_provider[response.provider] = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0}
        pp = self.usage.by_provider[response.provider]
        pp["prompt_tokens"] = pp.get("prompt_tokens", 0) + response.prompt_tokens  # type: ignore[assignment]
        pp["completion_tokens"] = pp.get("completion_tokens", 0) + response.completion_tokens  # type: ignore[assignment]
        pp["cost_usd"] = pp.get("cost_usd", 0.0) + cost  # type: ignore[assignment]

        return response


class CachingClient(LLMClient):
    """LRU cache wrapper for LLM calls. Avoids re-running identical prompts."""

    def __init__(self, client: LLMClient, max_size: int = 256, ttl_seconds: int = 3600) -> None:
        super().__init__(client.model)
        self._client = client
        self._cache: OrderedDict[str, tuple[LLMResponse, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._hits = 0
        self._misses = 0

    def generate(
        self,
        system: str,
        user: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Only cache deterministic calls (temperature=0)
        cacheable = temperature == 0.0
        if cacheable:
            key = self._make_key(system, user, temperature, max_tokens)
            result = self._get(key)
            if result is not None:
                self._hits += 1
                return result
            self._misses += 1

        response = self._client.generate(system, user, temperature, max_tokens)

        if cacheable:
            self._put(self._make_key(system, user, temperature, max_tokens), response)

        return response

    def cache_stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total > 0 else 0.0,
            "size": len(self._cache),
            "max_size": self._max_size,
        }

    def clear_cache(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def _make_key(self, system: str, user: str, temperature: float, max_tokens: int) -> str:
        raw = json.dumps({"s": system, "u": user, "t": temperature, "m": max_tokens}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _get(self, key: str) -> LLMResponse | None:
        if key in self._cache:
            response, ts = self._cache[key]
            if time.time() - ts < self._ttl:
                self._cache.move_to_end(key)
                return response
            del self._cache[key]
        return None

    def _put(self, key: str, response: LLMResponse) -> None:
        self._cache[key] = (response, time.time())
        self._cache.move_to_end(key)
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)
