from __future__ import annotations

import asyncio
import ipaddress
import ssl
import time
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import aiohttp

from .html_features import StaticHtmlFeatureParser
from .models import (
    EnrichmentRequest,
    EnrichmentResponse,
    EvidenceFamily,
    EvidenceObservation,
    EvidenceState,
)
from .policy import (
    AddressResolver,
    DnsAddressResolver,
    DnsResolutionError,
    SafetyRejected,
    resolve_and_validate,
    socket_family,
)
from .rdap import RdapBootstrap


class StaticResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, hostname: str, addresses: tuple[str, ...]) -> None:
        self.hostname = hostname
        self.addresses = addresses

    async def resolve(self, host: str, port: int = 0, family: int = 0) -> list[dict[str, Any]]:
        if host.lower().rstrip(".") != self.hostname.lower().rstrip("."):
            raise OSError("resolver received an unexpected hostname")
        return [
            {
                "hostname": self.hostname,
                "host": address,
                "port": port,
                "family": socket_family(address),
                "proto": 0,
                "flags": 0,
            }
            for address in self.addresses
        ]

    async def close(self) -> None:
        return None


@dataclass(frozen=True, slots=True)
class FetchedPage:
    final_url: str
    dns_addresses: tuple[str, ...]
    redirects: tuple[dict[str, object], ...]
    tls: dict[str, object] | None
    html_features: dict[str, int | bool] | None


class SafeFetcher:
    def __init__(
        self,
        resolver: AddressResolver | None = None,
        rdap: RdapBootstrap | None = None,
    ) -> None:
        self.resolver = resolver or DnsAddressResolver()
        self.rdap = rdap or RdapBootstrap()

    async def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        observations: list[EvidenceObservation] = []
        started = time.monotonic()
        try:
            page = await asyncio.wait_for(
                self._fetch_page(request, started),
                timeout=request.budget.total_timeout_seconds,
            )
        except asyncio.TimeoutError:
            observations.extend(self._failure_observations(EvidenceState.TIMED_OUT, "total_timeout"))
            return self._response(request, observations)
        except DnsResolutionError as exc:
            observations.extend(self._dns_failure_observations(exc.state, exc.reason_code))
            return self._response(request, observations)
        except SafetyRejected as exc:
            if exc.reason_code == "non_public_address":
                observations.extend(
                    self._dns_failure_observations(EvidenceState.REJECTED_SAFETY, exc.reason_code)
                )
            else:
                observations.extend(self._failure_observations(EvidenceState.REJECTED_SAFETY, exc.reason_code))
            return self._response(request, observations)
        except (aiohttp.ClientError, OSError, ssl.SSLError, ValueError):
            observations.extend(self._failure_observations(EvidenceState.UNAVAILABLE, "fetch_failed"))
            return self._response(request, observations)

        observations.append(
            EvidenceObservation(
                family=EvidenceFamily.DNS,
                state=EvidenceState.OBSERVED,
                source="recursive-dns",
                value={"addresses": list(page.dns_addresses)},
            )
        )
        observations.append(
            EvidenceObservation(
                family=EvidenceFamily.REDIRECT,
                state=EvidenceState.OBSERVED,
                source="target-http",
                value={"count": len(page.redirects), "chain": list(page.redirects)},
            )
        )
        observations.append(
            EvidenceObservation(
                family=EvidenceFamily.TLS,
                state=EvidenceState.OBSERVED if page.tls else EvidenceState.NOT_APPLICABLE,
                source="target-tls",
                value=page.tls,
            )
        )
        observations.append(
            EvidenceObservation(
                family=EvidenceFamily.STATIC_HTML,
                state=EvidenceState.OBSERVED if page.html_features else EvidenceState.NOT_APPLICABLE,
                source="bounded-html-parser",
                value=page.html_features,
            )
        )
        try:
            remaining = request.budget.total_timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise asyncio.TimeoutError
            rdap_observation = await asyncio.wait_for(
                self._rdap_observation(page.final_url, request, started),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            rdap_observation = EvidenceObservation(
                family=EvidenceFamily.RDAP,
                state=EvidenceState.TIMED_OUT,
                source="iana-rdap-bootstrap",
                reason_code="total_timeout",
            )
        observations.append(rdap_observation)
        return self._response(request, observations)

    async def _fetch_page(self, request: EnrichmentRequest, started: float) -> FetchedPage:
        current_url = str(request.target_url)
        redirects: list[dict[str, object]] = []
        last_addresses: tuple[str, ...] = ()
        tls_evidence: dict[str, object] | None = None
        html_features: dict[str, int | bool] | None = None

        for hop in range(request.budget.max_redirects + 1):
            remaining = request.budget.total_timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise asyncio.TimeoutError
            target = await resolve_and_validate(current_url, request.allowed_ports, self.resolver)
            last_addresses = target.addresses
            ssl_context = ssl.create_default_context() if current_url.startswith("https://") else None
            connector = aiohttp.TCPConnector(
                resolver=StaticResolver(target.hostname, target.addresses),
                use_dns_cache=False,
                ssl=ssl_context,
                limit=1,
                force_close=True,
            )
            timeout = aiohttp.ClientTimeout(
                total=min(remaining, request.budget.total_timeout_seconds),
                connect=request.budget.connect_timeout_seconds,
                sock_read=request.budget.read_timeout_seconds,
            )
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                auto_decompress=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                skip_auto_headers={"Referer"},
                headers={"User-Agent": "PhishGuard-Fetcher/0.1", "Accept": "text/html,application/xhtml+xml"},
            ) as session:
                async with session.get(target.url, allow_redirects=False, max_line_size=8190) as response:
                    self._check_headers(response, request)
                    response_tls = self._tls_info(response)
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if not location:
                            raise SafetyRejected("redirect_without_location", "Redirect response omitted Location")
                        if hop >= request.budget.max_redirects:
                            raise SafetyRejected("redirect_limit", "Redirect limit exceeded")
                        next_url = urljoin(target.url, location)
                        redirects.append(
                            {
                                "status": response.status,
                                "from_host": target.hostname,
                                "to_host": (urlsplit(next_url).hostname or "")[:253],
                            }
                        )
                        current_url = next_url
                        continue

                    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    if content_type not in {"text/html", "application/xhtml+xml"}:
                        return FetchedPage(target.url, last_addresses, tuple(redirects), response_tls, None)
                    body = await self._bounded_body(response, request)
                    parser = StaticHtmlFeatureParser(target.url)
                    parser.feed(body.decode(response.charset or "utf-8", errors="replace"))
                    html_features = parser.features()
                    tls_evidence = response_tls
                    return FetchedPage(target.url, last_addresses, tuple(redirects), tls_evidence, html_features)

        raise SafetyRejected("redirect_limit", "Redirect limit exceeded")

    @staticmethod
    def _check_headers(response: aiohttp.ClientResponse, request: EnrichmentRequest) -> None:
        header_bytes = sum(len(key) + len(value) + 4 for key, value in response.headers.items())
        if header_bytes > request.budget.max_header_bytes:
            raise SafetyRejected("headers_too_large", "Response headers exceeded the limit")

    @staticmethod
    async def _bounded_body(response: aiohttp.ClientResponse, request: EnrichmentRequest) -> bytes:
        content_length = response.content_length
        if content_length is not None and content_length > request.budget.max_wire_bytes:
            raise SafetyRejected("wire_body_too_large", "Response body exceeded the wire limit")
        wire = bytearray()
        async for chunk in response.content.iter_chunked(32_768):
            wire.extend(chunk)
            if len(wire) > request.budget.max_wire_bytes:
                raise SafetyRejected("wire_body_too_large", "Response body exceeded the wire limit")

        encoding = response.headers.get("Content-Encoding", "").lower().strip()
        if not encoding or encoding == "identity":
            decoded = bytes(wire)
        elif encoding == "gzip":
            decoded = SafeFetcher._bounded_decompress(bytes(wire), 16 + zlib.MAX_WBITS, request)
        elif encoding == "deflate":
            decoded = SafeFetcher._bounded_decompress(bytes(wire), zlib.MAX_WBITS, request)
        else:
            raise SafetyRejected("unsupported_content_encoding", "Content encoding is not supported")

        if len(decoded) > request.budget.max_decoded_bytes:
            raise SafetyRejected("decoded_body_too_large", "Decoded response exceeded the limit")
        if wire and len(decoded) / len(wire) > request.budget.max_decompression_ratio:
            raise SafetyRejected("decompression_ratio", "Response decompression ratio exceeded the limit")
        return decoded

    @staticmethod
    def _bounded_decompress(data: bytes, window_bits: int, request: EnrichmentRequest) -> bytes:
        try:
            decompressor = zlib.decompressobj(window_bits)
            decoded = decompressor.decompress(data, request.budget.max_decoded_bytes + 1)
        except zlib.error as exc:
            raise SafetyRejected("malformed_compression", "Compressed response was malformed") from exc
        if decompressor.unconsumed_tail or len(decoded) > request.budget.max_decoded_bytes:
            raise SafetyRejected("decoded_body_too_large", "Decoded response exceeded the limit")
        try:
            decoded += decompressor.flush(request.budget.max_decoded_bytes + 1 - len(decoded))
        except zlib.error as exc:
            raise SafetyRejected("malformed_compression", "Compressed response was malformed") from exc
        if not decompressor.eof:
            raise SafetyRejected("malformed_compression", "Compressed response was incomplete")
        return decoded

    @staticmethod
    def _tls_info(response: aiohttp.ClientResponse) -> dict[str, object] | None:
        connection = response.connection
        transport = connection.transport if connection else None
        ssl_object = transport.get_extra_info("ssl_object") if transport else None
        if ssl_object is None:
            return None
        certificate = ssl_object.getpeercert() or {}
        return {
            "version": ssl_object.version(),
            "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter"),
            "subject_alt_name_count": len(certificate.get("subjectAltName", ())),
            "hostname_verified": True,
        }

    async def _rdap_observation(
        self,
        final_url: str,
        request: EnrichmentRequest,
        started: float,
    ) -> EvidenceObservation:
        hostname = urlsplit(final_url).hostname or ""
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            query_domain = self.rdap.registrable_domain_for(hostname)
        else:
            return EvidenceObservation(
                family=EvidenceFamily.RDAP,
                state=EvidenceState.NOT_APPLICABLE,
                source="iana-rdap-bootstrap",
                reason_code="ip_literal",
            )
        endpoint = self.rdap.endpoint_for(query_domain)
        if endpoint is None:
            return EvidenceObservation(
                family=EvidenceFamily.RDAP,
                state=EvidenceState.UNAVAILABLE,
                source="iana-rdap-bootstrap",
                reason_code="tld_not_in_snapshot",
            )
        remaining = request.budget.total_timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            return EvidenceObservation(
                family=EvidenceFamily.RDAP,
                state=EvidenceState.TIMED_OUT,
                source=endpoint,
                reason_code="total_timeout",
            )
        try:
            rdap_target = await resolve_and_validate(endpoint, (443,), self.resolver)
        except DnsResolutionError as exc:
            return EvidenceObservation(
                family=EvidenceFamily.RDAP,
                state=exc.state,
                source="iana-rdap-bootstrap",
                reason_code=exc.reason_code,
            )
        except SafetyRejected as exc:
            return EvidenceObservation(
                family=EvidenceFamily.RDAP,
                state=EvidenceState.REJECTED_SAFETY,
                source="iana-rdap-bootstrap",
                reason_code=exc.reason_code,
            )
        timeout = aiohttp.ClientTimeout(total=min(remaining, 2.0), connect=1.0, sock_read=1.5)
        connector = aiohttp.TCPConnector(
            resolver=StaticResolver(rdap_target.hostname, rdap_target.addresses),
            use_dns_cache=False,
            ssl=ssl.create_default_context(),
            limit=1,
            force_close=True,
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                auto_decompress=False,
            ) as session:
                result = await self.rdap.query(query_domain, session)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            result = None
        return EvidenceObservation(
            family=EvidenceFamily.RDAP,
            state=EvidenceState.OBSERVED if result else EvidenceState.UNAVAILABLE,
            source=result.source if result else endpoint,
            value=result.value if result else None,
            reason_code=None if result else "rdap_unavailable",
        )

    @staticmethod
    def _failure_observations(state: EvidenceState, reason: str) -> list[EvidenceObservation]:
        return [
            EvidenceObservation(family=family, state=state, source="isolated-fetcher", reason_code=reason)
            for family in (
                EvidenceFamily.DNS,
                EvidenceFamily.RDAP,
                EvidenceFamily.TLS,
                EvidenceFamily.REDIRECT,
                EvidenceFamily.STATIC_HTML,
            )
        ]

    @staticmethod
    def _dns_failure_observations(state: EvidenceState, reason: str) -> list[EvidenceObservation]:
        return [
            EvidenceObservation(
                family=EvidenceFamily.DNS,
                state=state,
                source="recursive-dns",
                reason_code=reason,
            ),
            *[
                EvidenceObservation(
                    family=family,
                    state=EvidenceState.SKIPPED_POLICY,
                    source="isolated-fetcher",
                    reason_code="dns_prerequisite_failed",
                )
                for family in (
                    EvidenceFamily.RDAP,
                    EvidenceFamily.TLS,
                    EvidenceFamily.REDIRECT,
                    EvidenceFamily.STATIC_HTML,
                )
            ],
        ]

    @staticmethod
    def _response(
        request: EnrichmentRequest,
        observations: list[EvidenceObservation],
    ) -> EnrichmentResponse:
        return EnrichmentResponse(
            analysis_run_id=request.analysis_run_id,
            correlation_id=request.correlation_id,
            completed_at=datetime.now(UTC),
            observations=observations,
        )
