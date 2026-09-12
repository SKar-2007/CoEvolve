"""Unified LLM client abstraction (Anthropic, OpenAI, OpenRouter)."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from pydantic import BaseModel


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


class GroqClient(LLMClient):
    """Groq LPU inference client."""

    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model)
        self._api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self._api_key:
            raise LLMError("GROQ_API_KEY not set")
        self._base_url = "https://api.groq.com/openai/v1"

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:
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
            provider="groq",
            model=self.model,
            prompt_tokens=resp.usage.prompt_tokens if resp.usage else 0,
            completion_tokens=resp.usage.completion_tokens if resp.usage else 0,
            raw=resp.model_dump(),
        )


class GeminiClient(LLMClient):
    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model)
        self._api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self._api_key:
            raise LLMError("GEMINI_API_KEY not set")

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        try:
            from google import genai  # type: ignore[import-not-found]
            from google.genai import types  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise LLMError(
                "google-genai SDK not installed. Run `pip install google-genai`"
            ) from exc
        client = genai.Client(api_key=self._api_key)

        import time

        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model=self.model,
                    contents=user,
                    config=types.GenerateContentConfig(
                        system_instruction=system,
                        temperature=temperature,
                        max_output_tokens=max_tokens,
                    ),
                )
                text = response.text or ""
                usage = response.usage_metadata
                return LLMResponse(
                    text=text,
                    provider="gemini",
                    model=self.model,
                    prompt_tokens=usage.prompt_token_count if usage else 0,
                    completion_tokens=usage.candidates_token_count if usage else 0,
                    raw={"text": text},
                )
            except Exception as exc:
                if "503" in str(exc) and attempt < 2:
                    time.sleep(2**attempt)
                    continue
                raise LLMError(f"Gemini API error: {exc}") from exc
        raise LLMError("Gemini API failed after 3 retries")


class HuggingFaceClient(LLMClient):
    """HuggingFace Inference API client."""

    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model)
        self._api_key = api_key or os.getenv("HUGGINGFACE_API_KEY")
        if not self._api_key:
            raise LLMError("HUGGINGFACE_API_KEY not set")
        self._base_url = "https://router.huggingface.co/v1"

    def generate(self, system, user, temperature=0.7, max_tokens=4096):
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:
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
            provider="huggingface",
            model=self.model,
            prompt_tokens=resp.usage.prompt_tokens if resp.usage else 0,
            completion_tokens=resp.usage.completion_tokens if resp.usage else 0,
            raw=resp.model_dump(),
        )


class ModelConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5"
    small_model: str = "claude-haiku-4-5"
    temperature: float = 0.7
    max_tokens: int = 4096


class MockClient(LLMClient):
    """Mock LLM client for demo/testing without API keys."""

    def __init__(self, model: str = "mock"):
        super().__init__(model)

    def generate(
        self,
        system: str,
        user: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Detect role from system prompt
        if "red-team" in system.lower() or "attacker" in system.lower():
            text = self._mock_attacker_response(user)
        elif "failure trace" in system.lower() or "distill" in system.lower():
            text = self._mock_distiller_response(user)
        else:
            text = self._mock_developer_response(user)

        return LLMResponse(
            text=text,
            provider="mock",
            model=self.model,
            prompt_tokens=len(system.split()) + len(user.split()),
            completion_tokens=len(text.split()),
        )

    def _mock_attacker_response(self, user: str) -> str:
        import json
        task = {
            "task_description": "Create a SQL injection vulnerability in a login endpoint",
            "vulnerability_class": "SQLi",
            "difficulty_tier": 2,
            "target_file": "app.py",
            "vulnerable_code": 'query = f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'"',
            "expected_impact": "Bypass authentication or extract data",
        }
        return json.dumps(task)

    def _mock_developer_response(self, user: str) -> str:
        import json
        patch = {
            "file_path": "app.py",
            "diff": '- query = f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'"\n+ query = "SELECT * FROM users WHERE username = ? AND password = ?"\n+ params = (username, password)',
            "explanation": "Use parameterized queries to prevent SQL injection",
        }
        return json.dumps(patch)

    def _mock_distiller_response(self, user: str) -> str:
        import json
        rule = {
            "rule_text": "Always use parameterized queries for SQL operations. Never interpolate user input into SQL strings.",
            "vulnerability_class": "SQLi",
            "source_pattern": "SELECT * FROM users WHERE username='{input}'",
            "recommended_fix": "Use db.execute('SELECT * FROM users WHERE username = ?', (input,))",
        }
        return json.dumps(rule)


class ReportingLLMClient(LLMClient):
    """Wrapper that notifies a callback on each LLM call."""

    def __init__(self, client: LLMClient, callback: Any = None) -> None:
        super().__init__(client.model)
        self._client = client
        self._callback = callback

    def generate(
        self,
        system: str,
        user: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        response = self._client.generate(system, user, temperature, max_tokens)
        if self._callback is not None:
            self._callback(system, user, response)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def build_client(provider: str, model: str, api_key: str | None = None) -> LLMClient:
    """Factory returning the client for a provider name."""
    provider = (provider or "anthropic").lower()
    if provider == "mock":
        return MockClient(model)
    if provider == "anthropic":
        return AnthropicClient(model, api_key)
    if provider == "openai":
        return OpenAIClient(model, api_key)
    if provider in {"openrouter", "deepseek"}:
        return OpenRouterClient(model, api_key)
    if provider == "groq":
        return GroqClient(model, api_key)
    if provider == "gemini":
        return GeminiClient(model, api_key)
    if provider in {"huggingface", "hf"}:
        return HuggingFaceClient(model, api_key)
    raise LLMError(f"Unknown provider: {provider}")
