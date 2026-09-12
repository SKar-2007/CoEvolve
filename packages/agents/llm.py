"""Unified LLM client abstraction (Anthropic, OpenAI, OpenRouter)."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from pydantic import BaseModel, Field


class LLMError(RuntimeError):
    """Raised when an LLM call fails."""


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    raw: dict = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMClient(ABC):
    """Base class for provider-specific clients."""

    def __init__(self, model: str):
        self.model = model

    @abstractmethod
    def generate(
        self,
        system: str,
        user: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Run a single generation call."""


class AnthropicClient(LLMClient):
    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model)
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise LLMError("ANTHROPIC_API_KEY not set")

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise LLMError("anthropic SDK not installed") from exc
        client = anthropic.Anthropic(api_key=self._api_key)
        msg = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in msg.content if b.type == "text")
        return LLMResponse(
            text=text,
            provider="anthropic",
            model=self.model,
            prompt_tokens=msg.usage.input_tokens,
            completion_tokens=msg.usage.output_tokens,
            raw=msg.model_dump(),
        )


class OpenAIClient(LLMClient):
    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model)
        self._api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self._api_key:
            raise LLMError("OPENAI_API_KEY not set")

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise LLMError("openai SDK not installed") from exc
        client = OpenAI(api_key=self._api_key)
        resp = client.chat.completions.create(
            model=self.model,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        choice = resp.choices[0].message
        return LLMResponse(
            text=choice.content or "",
            provider="openai",
            model=self.model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
            raw=resp.model_dump(),
        )


class OpenRouterClient(OpenAIClient):
    """OpenRouter speaks the OpenAI protocol; just point base_url elsewhere."""

    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model=model, api_key=api_key or os.getenv("OPENROUTER_API_KEY"))
        if not self._api_key:
            raise LLMError("OPENROUTER_API_KEY not set")
        self._base_url = "https://openrouter.ai/api/v1"

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise LLMError("openai SDK not installed") from exc
        client = OpenAI(api_key=self._api_key, base_url=self._base_url)
        resp = client.chat.completions.create(
            model=self.model,
            temperature=temperature,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        choice = resp.choices[0].message
        return LLMResponse(
            text=choice.content or "",
            provider="openrouter",
            model=self.model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
            raw=resp.model_dump(),
        )


class ModelConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5"
    small_model: str = "claude-haiku-4-5"
    temperature: float = 0.7
    max_tokens: int = 4096


def build_client(provider: str, model: str, api_key: str | None = None) -> LLMClient:
    """Factory returning the client for a provider name."""
    provider = (provider or "anthropic").lower()
    if provider == "anthropic":
        return AnthropicClient(model, api_key)
    if provider == "openai":
        return OpenAIClient(model, api_key)
    if provider in {"openrouter", "deepseek", "groq"}:
        return OpenRouterClient(model, api_key)
    raise LLMError(f"Unknown provider: {provider}")