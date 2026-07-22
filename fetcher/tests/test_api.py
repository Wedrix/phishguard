from fastapi.testclient import TestClient

from phishguard_fetcher.api import create_app
from phishguard_fetcher.models import EnrichmentResponse, EvidenceFamily, EvidenceObservation, EvidenceState


class StubFetcher:
    async def enrich(self, request):
        return EnrichmentResponse(
            analysis_run_id=request.analysis_run_id,
            correlation_id=request.correlation_id,
            observations=[
                EvidenceObservation(
                    family=EvidenceFamily.DNS,
                    state=EvidenceState.OBSERVED,
                    source="test",
                    value={"addresses": ["93.184.216.34"]},
                )
            ],
        )


def test_enrichment_contract_is_closed_and_typed() -> None:
    client = TestClient(create_app(StubFetcher()))
    response = client.post(
        "/internal/v1/enrich",
        json={
            "analysis_run_id": "11111111-1111-4111-8111-111111111111",
            "correlation_id": "22222222-2222-4222-8222-222222222222",
            "target_url": "https://example.com/",
        },
    )
    assert response.status_code == 200
    assert response.json()["observations"][0]["state"] == "OBSERVED"
    assert "final_url" not in response.json()


def test_schema_version_is_literal_one() -> None:
    client = TestClient(create_app(StubFetcher()))
    payload = {
        "schema_version": 2,
        "analysis_run_id": "11111111-1111-4111-8111-111111111111",
        "correlation_id": "22222222-2222-4222-8222-222222222222",
        "target_url": "https://example.com/",
    }
    assert client.post("/internal/v1/enrich", json=payload).status_code == 422


def test_target_url_accepts_the_full_backend_contract() -> None:
    client = TestClient(create_app(StubFetcher()))
    prefix = "https://example.com/"
    target_url = prefix + "a" * (4096 - len(prefix))
    response = client.post(
        "/internal/v1/enrich",
        json={
            "analysis_run_id": "11111111-1111-4111-8111-111111111111",
            "correlation_id": "22222222-2222-4222-8222-222222222222",
            "target_url": target_url,
        },
    )
    assert response.status_code == 200


def test_budget_cannot_exceed_security_ceiling() -> None:
    client = TestClient(create_app(StubFetcher()))
    response = client.post(
        "/internal/v1/enrich",
        json={
            "analysis_run_id": "11111111-1111-4111-8111-111111111111",
            "correlation_id": "22222222-2222-4222-8222-222222222222",
            "target_url": "https://example.com/",
            "budget": {"max_redirects": 4},
        },
    )
    assert response.status_code == 422


def test_request_cannot_expand_the_v1_port_allowlist() -> None:
    client = TestClient(create_app(StubFetcher()))
    response = client.post(
        "/internal/v1/enrich",
        json={
            "analysis_run_id": "11111111-1111-4111-8111-111111111111",
            "correlation_id": "22222222-2222-4222-8222-222222222222",
            "target_url": "https://example.com:8443/",
            "allowed_ports": [80, 443, 8443],
        },
    )
    assert response.status_code == 422
