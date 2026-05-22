from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VietSafe AI Firewall"
    api_prefix: str = "/api/v1"
    environment: str = "development"

    database_url: str = "sqlite:///./vietsafe_firewall.db"
    bootstrap_tenant_id: str = "demo-insurance"
    bootstrap_tenant_name: str = "Demo Insurance Tenant"
    bootstrap_api_key: str = Field(default="dev_demo_key", repr=False)
    api_key_salt: str = Field(default="change-me-in-production", repr=False)

    rate_limit_per_minute: int = 60
    request_timeout_seconds: float = 20.0

    openai_api_key: str | None = Field(default=None, repr=False)
    openai_base_url: str = "https://api.openai.com"
    openai_model: str | None = None
    openai_moderation_model: str = "omni-moderation-latest"

    anthropic_api_key: str | None = Field(default=None, repr=False)
    anthropic_model: str | None = None

    gemini_api_key: str | None = Field(default=None, repr=False)
    gemini_model: str | None = None

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"
    llama_guard_model: str = "llama-guard3"

    litellm_base_url: str | None = None
    litellm_api_key: str | None = Field(default=None, repr=False)
    litellm_model: str = "gpt-4o-mini"

    perspective_api_key: str | None = Field(default=None, repr=False)

    langfuse_public_key: str | None = Field(default=None, repr=False)
    langfuse_secret_key: str | None = Field(default=None, repr=False)
    langfuse_host: str = "https://cloud.langfuse.com"

    vietnamese_nlp_backend: str = "auto"

    webhook_timeout_seconds: float = 5.0

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
