import asyncio
import gzip

import pytest

from phishguard_fetcher.fetch import FetchedPage, SafeFetcher
from phishguard_fetcher.models import (
    EnrichmentBudget,
    EnrichmentRequest,
    EvidenceFamily,
    EvidenceObservation,
    EvidenceState,
)
from phishguard_fetcher.policy import SafetyRejected


def request_with_budget(**changes) -> EnrichmentRequest:
    return EnrichmentRequest(
        analysis_run_id="11111111-1111-4111-8111-111111111111",
        correlation_id="22222222-2222-4222-8222-222222222222",
        target_url="https://example.com/",
        budget=EnrichmentBudget(**changes),
    )


def test_decompression_bomb_is_rejected() -> None:
    request = request_with_budget(max_decoded_bytes=1024, max_decompression_ratio=20)
    compressed = gzip.compress(b"a" * 2048)
    with pytest.raises(SafetyRejected) as error:
        SafeFetcher._bounded_decompress(compressed, 16 + 15, request)
    assert error.value.reason_code == "decoded_body_too_large"


def test_truncated_compressed_body_is_rejected() -> None:
    request = request_with_budget(max_decoded_bytes=4096)
    compressed = gzip.compress(b"bounded body")[:-3]
    with pytest.raises(SafetyRejected) as error:
        SafeFetcher._bounded_decompress(compressed, 16 + 15, request)
    assert error.value.reason_code == "malformed_compression"


class SlowRdapFetcher(SafeFetcher):
    async def _fetch_page(self, request, started):
        return FetchedPage("https://example.com/", ("93.184.216.34",), (), None, None)

    async def _rdap_observation(self, final_url, request, started):
        await asyncio.sleep(0.05)
        return EvidenceObservation(
            family=EvidenceFamily.RDAP,
            state=EvidenceState.OBSERVED,
            source="test",
            value={"unexpected": "late result"},
        )


@pytest.mark.asyncio
async def test_total_deadline_includes_rdap_and_returns_timeout_evidence() -> None:
    request = request_with_budget(total_timeout_seconds=0.01)
    result = await SlowRdapFetcher().enrich(request)
    rdap = next(item for item in result.observations if item.family == EvidenceFamily.RDAP)

    assert rdap.state == EvidenceState.TIMED_OUT
    assert rdap.reason_code == "total_timeout"
    assert next(item for item in result.observations if item.family == EvidenceFamily.DNS).state == EvidenceState.OBSERVED
