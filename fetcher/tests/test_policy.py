import ipaddress

import dns.exception
import dns.resolver
import pytest

from phishguard_fetcher.fetch import SafeFetcher
from phishguard_fetcher.models import EnrichmentRequest, EvidenceFamily, EvidenceState
from phishguard_fetcher.policy import (
    DnsAddressResolver,
    DnsResolutionError,
    SafetyRejected,
    is_public_address,
    parse_target,
    resolve_and_validate,
)


class FakeResolver:
    def __init__(self, *answers: str) -> None:
        self.answers = answers

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return self.answers


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.169.254",
        "192.0.2.10",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
    ],
)
def test_non_public_addresses_are_rejected(address: str) -> None:
    assert not is_public_address(address)


def test_public_addresses_are_allowed() -> None:
    assert is_public_address("93.184.216.34")
    assert is_public_address("2606:2800:220:1:248:1893:25c8:1946")


@pytest.mark.parametrize(
    "url,reason",
    [
        ("file:///etc/passwd", "unsupported_scheme"),
        ("https://user:pass@example.com/", "credentials_or_host_missing"),
        ("https://example.com:22/", "port_not_allowed"),
        ("https://[fe80::1%25en0]/", "ipv6_zone_identifier"),
        ("http://2130706433/", "ambiguous_ip_encoding"),
        ("http://0177.0.0.1/", "ambiguous_ip_encoding"),
        ("http://0x7f000001/", "ambiguous_ip_encoding"),
    ],
)
def test_target_policy_rejects_unsafe_syntax(url: str, reason: str) -> None:
    with pytest.raises(SafetyRejected) as error:
        parse_target(url, (80, 443))
    assert error.value.reason_code == reason


@pytest.mark.asyncio
async def test_mixed_public_private_dns_is_rejected() -> None:
    resolver = FakeResolver("93.184.216.34", "10.0.0.1")
    with pytest.raises(SafetyRejected) as error:
        await resolve_and_validate("https://example.com/", (80, 443), resolver)
    assert error.value.reason_code == "non_public_address"


@pytest.mark.asyncio
async def test_non_public_dns_answer_is_closed_safety_evidence() -> None:
    request = EnrichmentRequest(
        analysis_run_id="11111111-1111-4111-8111-111111111111",
        correlation_id="22222222-2222-4222-8222-222222222222",
        target_url="https://example.com/",
    )
    response = await SafeFetcher(resolver=FakeResolver("10.0.0.1")).enrich(request)
    dns = next(item for item in response.observations if item.family == EvidenceFamily.DNS)
    assert (dns.state, dns.reason_code) == (EvidenceState.REJECTED_SAFETY, "non_public_address")
    assert all(
        item.state == EvidenceState.SKIPPED_POLICY
        for item in response.observations
        if item.family != EvidenceFamily.DNS
    )


@pytest.mark.asyncio
async def test_resolution_returns_pinned_public_addresses() -> None:
    resolver = FakeResolver("93.184.216.34")
    result = await resolve_and_validate("https://Example.com/path?q=1#fragment", (80, 443), resolver)
    assert result.hostname == "example.com"
    assert result.addresses == ("93.184.216.34",)
    assert result.url == "https://example.com/path?q=1"


def test_explicit_non_default_port_is_preserved() -> None:
    parts = parse_target("http://example.com:443/path", (80, 443))
    assert parts.netloc == "example.com:443"


def test_public_ipv6_literal_is_canonicalised_before_idna() -> None:
    parts = parse_target("https://[2606:2800:0220:0001:0248:1893:25c8:1946]/", (80, 443))
    assert parts.hostname == "2606:2800:220:1:248:1893:25c8:1946"
    assert parts.netloc == "[2606:2800:220:1:248:1893:25c8:1946]"


class FailingDnsBackend:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def resolve(self, hostname: str, record_type: str, search: bool = False):
        raise self.error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,state,reason",
    [
        (dns.exception.Timeout(), EvidenceState.TIMED_OUT, "dns_timeout"),
        (dns.resolver.NoNameservers(), EvidenceState.UNAVAILABLE, "dns_unavailable"),
        (dns.resolver.NXDOMAIN(), EvidenceState.NO_MATCH, "dns_nxdomain"),
        (dns.resolver.NoAnswer(), EvidenceState.NO_MATCH, "dns_no_answer"),
    ],
)
async def test_dns_failures_have_closed_evidence_states(error, state, reason) -> None:
    resolver = DnsAddressResolver()
    resolver._resolver = FailingDnsBackend(error)
    with pytest.raises(DnsResolutionError) as caught:
        await resolver.resolve("example.invalid")
    assert (caught.value.state, caught.value.reason_code) == (state, reason)
