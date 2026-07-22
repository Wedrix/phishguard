import json
import time

import pytest

from phishguard_fetcher.fetch import SafeFetcher
from phishguard_fetcher.models import EnrichmentRequest, EvidenceState
from phishguard_fetcher.rdap import RdapBootstrap


def test_rdap_uses_registered_domain_not_subdomain() -> None:
    bootstrap = RdapBootstrap()
    assert bootstrap.registrable_domain_for("login.accounts.example.com") == "example.com"
    assert bootstrap.registrable_domain_for("login.example.co.uk") == "example.co.uk"
    assert bootstrap.endpoint_for("example.com") == "https://rdap.verisign.com/com/v1/"


class FakeContent:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def iter_chunked(self, size: int):
        yield self.body


class FakeResponse:
    def __init__(self, body: bytes, content_length: int | None = None) -> None:
        self.status = 200
        self.headers = {}
        self.content_length = len(body) if content_length is None else content_length
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeSession:
    def __init__(self, response: FakeResponse | None = None) -> None:
        self.response = response
        self.requested = False

    def get(self, url: str, allow_redirects: bool):
        self.requested = True
        assert self.response is not None
        return self.response


def bootstrap_with_endpoint(tmp_path, endpoint: str) -> RdapBootstrap:
    snapshot = tmp_path / "rdap.json"
    snapshot.write_text(json.dumps({"services": [[['test'], [endpoint]]]}), encoding="utf-8")
    return RdapBootstrap(snapshot_path=snapshot)


class PrivateResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("127.0.0.1",)


@pytest.mark.asyncio
async def test_safe_fetcher_rejects_non_public_rdap_endpoint_resolution(tmp_path) -> None:
    fetcher = SafeFetcher(
        resolver=PrivateResolver(),
        rdap=bootstrap_with_endpoint(tmp_path, "https://rdap.example/"),
    )
    request = EnrichmentRequest(
        analysis_run_id="11111111-1111-4111-8111-111111111111",
        correlation_id="22222222-2222-4222-8222-222222222222",
        target_url="https://example.test/",
    )
    result = await fetcher._rdap_observation(request.target_url, request, time.monotonic())
    assert result.state == EvidenceState.REJECTED_SAFETY
    assert result.reason_code == "non_public_address"


@pytest.mark.asyncio
async def test_rdap_rejects_oversized_response(tmp_path) -> None:
    bootstrap = bootstrap_with_endpoint(tmp_path, "https://rdap.example/")
    session = FakeSession(FakeResponse(b"{}", bootstrap.MAX_RESPONSE_BYTES + 1))
    assert await bootstrap.query("example.test", session) is None


@pytest.mark.asyncio
async def test_rdap_never_requests_plain_http_endpoint(tmp_path) -> None:
    bootstrap = bootstrap_with_endpoint(tmp_path, "http://rdap.example/")
    session = FakeSession()
    assert bootstrap.endpoint_for("example.test") is None
    assert await bootstrap.query("example.test", session) is None
    assert not session.requested


@pytest.mark.asyncio
async def test_rdap_rejects_wrong_response_schema(tmp_path) -> None:
    bootstrap = bootstrap_with_endpoint(tmp_path, "https://rdap.example/")
    session = FakeSession(FakeResponse(b'{"status": {}}'))
    assert await bootstrap.query("example.test", session) is None
