from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./phishguard.db"
    port: int = 8080
    log_level: str = "INFO"

    phishguard_hmac_key: str = "development-hmac-key-change-me"
    phishguard_encryption_key: str | None = None
    kms_key_name: str | None = None
    google_cloud_project: str | None = None

    web_risk_api_key: str | None = None
    web_risk_base_url: str = "https://webrisk.googleapis.com/v1"
    fetcher_url: str = "https://fetcher:8443"
    fetcher_ca_file: Path | None = None
    fetcher_cert_file: Path | None = None
    fetcher_key_file: Path | None = None

    static_dir: Path = Path("../frontend/dist")
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    cookie_secure: bool = True
    identity_project_id: str | None = None
    dev_auth_enabled: bool = False
    model_path: Path | None = None
    model_sha256: str | None = None
    model_version: str | None = None

    notice_version: str = "2026-07-22"
    enrichment_enabled: bool = True
    scan_retention_days: int = 30
    job_concurrency: int = Field(default=10, ge=1, le=100)
    job_poll_seconds: float = Field(default=1.0, ge=0.1, le=30)
    job_lease_seconds: int = Field(default=30, ge=10, le=300)
    scan_rate_limit_per_minute: int = Field(default=120, ge=1, le=10_000)

    @field_validator("phishguard_hmac_key")
    @classmethod
    def secure_hmac_key(cls, value: str) -> str:
        if len(value.encode()) < 16:
            raise ValueError("PHISHGUARD_HMAC_KEY must contain at least 16 bytes")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value
