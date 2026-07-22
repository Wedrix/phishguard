from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from phishguard.domain.types import Evidence, EvidenceState

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

_MAX_FETCHER_RESPONSE_BYTES = 131_072
_FETCHER_FAMILIES = Literal["DNS", "RDAP", "TLS", "REDIRECT", "STATIC_HTML"]
_ShortText = Annotated[StrictStr, Field(max_length=80)]
_Host = Annotated[StrictStr, Field(min_length=1, max_length=253)]
_Count = Annotated[StrictInt, Field(ge=0, le=1_000_000)]


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _DnsValue(_ClosedModel):
    addresses: list[Annotated[StrictStr, Field(min_length=1, max_length=64)]] = Field(
        min_length=1,
        max_length=32,
    )

    @field_validator("addresses")
    @classmethod
    def validate_addresses(cls, addresses: list[str]) -> list[str]:
        if len(set(addresses)) != len(addresses):
            raise ValueError("DNS addresses must be unique")
        for address in addresses:
            ipaddress.ip_address(address)
        return addresses


class _RdapValue(_ClosedModel):
    handle_present: StrictBool
    status: list[_ShortText] = Field(max_length=12)
    events: dict[_ShortText, _ShortText] = Field(max_length=12)
    nameservers: list[Annotated[StrictStr, Field(max_length=253)]] = Field(max_length=12)
    queried_at: Annotated[StrictStr, Field(min_length=1, max_length=64)]

    @field_validator("queried_at")
    @classmethod
    def validate_queried_at(cls, value: str) -> str:
        if _parse_time(value) is None:
            raise ValueError("RDAP queried_at must be an ISO-8601 timestamp")
        return value


class _TlsValue(_ClosedModel):
    version: Annotated[StrictStr, Field(max_length=32)] | None
    cipher: Annotated[StrictStr, Field(max_length=128)] | None
    not_before: Annotated[StrictStr, Field(max_length=80)] | None
    not_after: Annotated[StrictStr, Field(max_length=80)] | None
    subject_alt_name_count: Annotated[StrictInt, Field(ge=0, le=10_000)]
    hostname_verified: StrictBool


class _RedirectHop(_ClosedModel):
    status: Literal[301, 302, 303, 307, 308]
    from_host: _Host
    to_host: _Host


class _RedirectValue(_ClosedModel):
    count: Annotated[StrictInt, Field(ge=0, le=3)]
    chain: list[_RedirectHop] = Field(max_length=3)

    @model_validator(mode="after")
    def count_matches_chain(self) -> _RedirectValue:
        if self.count != len(self.chain):
            raise ValueError("redirect count must match the chain")
        return self


class _StaticHtmlValue(_ClosedModel):
    forms: _Count
    password_inputs: _Count
    hidden_inputs: _Count
    external_form_actions: _Count
    external_links: _Count
    script_tags_present: StrictBool
    meta_refresh_present: StrictBool


_FETCHER_VALUE_MODELS: dict[str, type[_ClosedModel]] = {
    "DNS": _DnsValue,
    "RDAP": _RdapValue,
    "TLS": _TlsValue,
    "REDIRECT": _RedirectValue,
    "STATIC_HTML": _StaticHtmlValue,
}


class _FetcherObservation(_ClosedModel):
    family: _FETCHER_FAMILIES
    state: EvidenceState
    source: Annotated[StrictStr, Field(min_length=1, max_length=120)]
    observed_at: datetime
    producer_version: Annotated[StrictStr, Field(min_length=1, max_length=40)]
    value: dict[str, Any] | None = None
    reason_code: Annotated[StrictStr, Field(min_length=1, max_length=80)] | None = None

    @model_validator(mode="after")
    def validate_value(self) -> _FetcherObservation:
        if self.state == EvidenceState.OBSERVED:
            if self.value is None:
                raise ValueError("observed fetcher evidence requires a value")
            self.value = _FETCHER_VALUE_MODELS[self.family].model_validate(self.value).model_dump()
        elif self.value not in (None, {}):
            raise ValueError("non-observed fetcher evidence cannot carry a value")
        else:
            self.value = {}
        return self


class _FetcherResponse(_ClosedModel):
    schema_version: Literal[1]
    analysis_run_id: Annotated[StrictStr, Field(min_length=16, max_length=80)]
    correlation_id: Annotated[StrictStr, Field(min_length=16, max_length=80)]
    completed_at: datetime
    observations: list[_FetcherObservation] = Field(max_length=5)

    @model_validator(mode="after")
    def reject_duplicate_families(self) -> _FetcherResponse:
        families = [item.family for item in self.observations]
        if len(families) != len(set(families)):
            raise ValueError("fetcher evidence families must be unique")
        return self


class WebRiskClient:
    def __init__(self, api_key: str | None, base_url: str = "https://webrisk.googleapis.com/v1"):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    async def lookup(self, url: str) -> Evidence:
        if not self._api_key:
            return Evidence("reputation", EvidenceState.UNAVAILABLE, "google_web_risk", reason_code="provider_not_configured")
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
                response = await self._request_with_retry(client, url)
            response.raise_for_status()
            payload = response.json()
            threat = payload.get("threat")
            if not threat:
                return Evidence(
                    "reputation",
                    EvidenceState.NO_MATCH,
                    "google_web_risk",
                    expires_at=datetime.now(UTC) + timedelta(minutes=15),
                    version="v1",
                )
            types = [str(item)[:64] for item in threat.get("threatTypes", [])][:8]
            return Evidence(
                "reputation",
                EvidenceState.OBSERVED,
                "google_web_risk",
                value={"matched": True, "threat_types": types, "risk_delta": 1.0},
                expires_at=_parse_time(threat.get("expireTime")),
                version="v1",
            )
        except httpx.TimeoutException:
            return Evidence("reputation", EvidenceState.TIMED_OUT, "google_web_risk", reason_code="provider_timeout")
        except (httpx.HTTPError, ValueError, TypeError):
            return Evidence("reputation", EvidenceState.UNAVAILABLE, "google_web_risk", reason_code="provider_error")

    async def _request_with_retry(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        response: httpx.Response | None = None
        for attempt in range(3):
            response = await client.get(
                f"{self._base_url}/uris:search",
                params={"uri": url, "threatTypes": "SOCIAL_ENGINEERING", "key": self._api_key},
            )
            if response.status_code not in {429, 500, 502, 503, 504}:
                return response
            if attempt < 2:
                retry_after = response.headers.get("Retry-After", "0")
                try:
                    delay = min(2.0, max(0.0, float(retry_after)))
                except ValueError:
                    delay = 0.0
                await asyncio.sleep(delay or 0.2 * (2**attempt))
        assert response is not None
        return response


class FetcherClient:
    def __init__(self, base_url: str, ca_file: Path | None, cert_file: Path | None, key_file: Path | None):
        self._base_url = base_url.rstrip("/")
        self._verify: bool | ssl.SSLContext = True
        self._cert: tuple[str, str] | None = None
        if ca_file:
            self._verify = ssl.create_default_context(cafile=str(ca_file))
        if cert_file and key_file:
            self._cert = (str(cert_file), str(key_file))

    async def enrich(self, url: str, analysis_run_id: str, correlation_id: str) -> tuple[Evidence, ...]:
        try:
            async with httpx.AsyncClient(verify=self._verify, cert=self._cert, timeout=12.0) as client:
                async with client.stream(
                    "POST",
                    f"{self._base_url}/internal/v1/enrich",
                    json={
                        "schema_version": 1,
                        "analysis_run_id": analysis_run_id,
                        "correlation_id": correlation_id,
                        "target_url": url,
                    },
                    headers={"X-Correlation-ID": correlation_id},
                ) as response:
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > _MAX_FETCHER_RESPONSE_BYTES:
                            raise ValueError("fetcher response exceeded its size limit")
            return _evidence_from_fetcher_response(json.loads(body), analysis_run_id, correlation_id)
        except httpx.TimeoutException:
            return (Evidence("network", EvidenceState.TIMED_OUT, "isolated_fetcher", reason_code="fetcher_timeout"),)
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            return (Evidence("network", EvidenceState.UNAVAILABLE, "isolated_fetcher", reason_code="fetcher_error"),)


def _evidence_from_fetcher_response(
    payload: Any,
    analysis_run_id: str,
    correlation_id: str,
) -> tuple[Evidence, ...]:
    parsed = _FetcherResponse.model_validate(payload)
    if parsed.analysis_run_id != analysis_run_id or parsed.correlation_id != correlation_id:
        raise ValueError("fetcher response identity mismatch")
    return tuple(_evidence_from_fetcher(item) for item in parsed.observations)


def _evidence_from_fetcher(item: Any) -> Evidence:
    parsed = _FetcherObservation.model_validate(item)
    return Evidence(
        family=parsed.family.lower(),
        state=parsed.state,
        source=f"isolated_fetcher:{parsed.source}"[:64],
        value=parsed.value or {},
        observed_at=parsed.observed_at,
        version=parsed.producer_version,
        sensitivity="INTERNAL",
        reason_code=parsed.reason_code[:64] if parsed.reason_code else None,
    )


def _parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None
