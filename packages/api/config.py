"""Application configuration via pydantic-settings."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Supabase PostgreSQL (from Settings > Database > Connection string)
    # NOTE: default is a local-dev placeholder only. Production must set
    # DATABASE_URL via environment; see docker-compose.prod.yml which uses
    # ${POSTGRES_PASSWORD:?} validation to fail fast when missing.
    database_url: str = "postgresql://postgres:password@localhost:5432/coevolve"

    # Upstash Redis (from console.upstash.com)
    upstash_redis_url: str = ""
    # Canonical Redis URL used by TaskQueue / worker. Falls back to
    # UPSTASH_REDIS_URL for backwards compatibility (see redis_url property).
    redis_url: str = ""

    # LLM — Groq free tier (console.groq.com)
    llm_provider: str = "groq"
    llm_model: str = "openai/gpt-oss-120b"
    groq_api_key: str = ""

    # Optional fallback providers
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    openrouter_api_key: str = ""
    gemini_api_key: str = ""
    huggingface_api_key: str = ""

    log_level: str = "INFO"

    # CORS — comma-separated origins, e.g. "https://app.example.com,https://admin.example.com"
    # Use "*" for local development only. When "*" is used, credentials are
    # automatically disabled (browsers reject Access-Control-Allow-Credentials with "*").
    cors_origins: str = "*"

    # Auth — when true, mutating endpoints require X-API-Key. Default false for
    # backwards compatibility with existing deployments/tests; set
    # REQUIRE_AUTH=true in production.
    require_auth: bool = False

    @property
    def resolved_redis_url(self) -> str:
        """Return the effective Redis URL (REDIS_URL preferred, UPSTASH fallback)."""
        return self.redis_url or self.upstash_redis_url

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse CORS_ORIGINS env (comma-separated) into a list."""
        raw = (self.cors_origins or "").strip()
        if not raw:
            return []
        return [o.strip() for o in raw.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
