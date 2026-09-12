"""Application configuration via pydantic-settings."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Supabase PostgreSQL (from Settings > Database > Connection string)
    database_url: str = "postgresql://postgres:password@localhost:5432/coevolve"

    # Upstash Redis (from console.upstash.com)
    upstash_redis_url: str = ""

    # LLM — Groq free tier (console.groq.com)
    llm_provider: str = "groq"
    llm_model: str = "openai/gpt-oss-20b"
    groq_api_key: str = ""

    # Optional fallback providers
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    openrouter_api_key: str = ""
    gemini_api_key: str = ""
    huggingface_api_key: str = ""

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
