from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceState(StrEnum):
    OBSERVED = "OBSERVED"
    NO_MATCH = "NO_MATCH"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED_POLICY = "SKIPPED_POLICY"
    UNAVAILABLE = "UNAVAILABLE"
    TIMED_OUT = "TIMED_OUT"
    REJECTED_SAFETY = "REJECTED_SAFETY"
    STALE = "STALE"


class EvidenceFamily(StrEnum):
    DNS = "DNS"
    RDAP = "RDAP"
    TLS = "TLS"
    REDIRECT = "REDIRECT"
    STATIC_HTML = "STATIC_HTML"


class EvidenceObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: EvidenceFamily
    state: EvidenceState
    source: str = Field(max_length=120)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    producer_version: str = Field(default="fetcher-0.1.0", max_length=40)
    value: dict[str, Any] | None = None
    reason_code: str | None = Field(default=None, max_length=80)


class EnrichmentBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_redirects: int = Field(default=3, ge=0, le=3)
    total_timeout_seconds: float = Field(default=10.0, gt=0, le=10)
    connect_timeout_seconds: float = Field(default=2.0, gt=0, le=2)
    read_timeout_seconds: float = Field(default=5.0, gt=0, le=5)
    max_header_bytes: int = Field(default=65_536, ge=1024, le=65_536)
    max_wire_bytes: int = Field(default=2_097_152, ge=1024, le=2_097_152)
    max_decoded_bytes: int = Field(default=2_097_152, ge=1024, le=2_097_152)
    max_decompression_ratio: float = Field(default=20.0, ge=1, le=20)


class EnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    analysis_run_id: str = Field(min_length=16, max_length=80)
    correlation_id: str = Field(min_length=16, max_length=80)
    target_url: str = Field(min_length=1, max_length=4096)
    allowed_ports: tuple[int, ...] = (80, 443)
    budget: EnrichmentBudget = Field(default_factory=EnrichmentBudget)

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or any(port not in {80, 443} for port in value):
            raise ValueError("allowed_ports may contain only ports 80 and 443 in schema version 1")
        return tuple(sorted(set(value)))


class EnrichmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    analysis_run_id: str
    correlation_id: str
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    observations: list[EvidenceObservation] = Field(max_length=16)
