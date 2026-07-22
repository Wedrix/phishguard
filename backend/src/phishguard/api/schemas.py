from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class SessionRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=8192)


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    analysis_mode: Literal["local_only", "enriched"] = "local_only"
    enrichment_consent: bool = False


class FeedbackRequest(BaseModel):
    category: Literal["FALSE_POSITIVE", "FALSE_NEGATIVE", "UNCLEAR", "OTHER"]
    comment: str | None = Field(default=None, max_length=1000)


class ShareRequest(BaseModel):
    expires_in_hours: int = Field(default=24, ge=1, le=168)


class RetentionUpdateRequest(BaseModel):
    days: int = Field(ge=1, le=365)


class ReviewActionRequest(BaseModel):
    action: Literal["claim", "release", "annotate", "adjudicate"]
    note: str | None = Field(default=None, max_length=2000)
    outcome: Literal["MALICIOUS", "BENIGN", "INCONCLUSIVE"] | None = None

    @field_validator("outcome")
    @classmethod
    def outcome_is_bounded(cls, value: str | None) -> str | None:
        return value


class ProviderUpdateRequest(BaseModel):
    enabled: bool
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def no_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(str(value)) > 8_192:
            raise ValueError("provider config is too large")
        if any(any(word in str(key).lower() for word in ("secret", "token", "password", "api_key")) for key in value):
            raise ValueError("provider secrets must be managed through Secret Manager")
        return value


class PolicyCreateRequest(BaseModel):
    version: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    config: dict[str, Any] = Field(default_factory=dict)


class ModelCreateRequest(BaseModel):
    version: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    artifact_uri: str = Field(min_length=5, max_length=1000)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metrics: dict[str, Any] = Field(default_factory=dict)


class DatasetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest: dict[str, Any]


class ExperimentCreateRequest(BaseModel):
    dataset_id: str
    config: dict[str, Any] = Field(default_factory=dict)


class ExportCreateRequest(BaseModel):
    filters: dict[str, Any] = Field(default_factory=dict)


class UserUpdateRequest(BaseModel):
    role: Literal["REGISTERED_USER", "ANALYST", "RESEARCHER"]
    disabled: bool = False
