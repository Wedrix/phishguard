from __future__ import annotations

from copy import deepcopy

import pytest

from phishguard.infrastructure.providers import _evidence_from_fetcher_response

RUN_ID = "11111111-1111-4111-8111-111111111111"
CORRELATION_ID = "22222222-2222-4222-8222-222222222222"


def _response(observations: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "analysis_run_id": RUN_ID,
        "correlation_id": CORRELATION_ID,
        "completed_at": "2026-07-22T12:00:01Z",
        "observations": observations,
    }


def _dns() -> dict[str, object]:
    return {
        "family": "DNS",
        "state": "OBSERVED",
        "source": "recursive-dns",
        "observed_at": "2026-07-22T12:00:00Z",
        "producer_version": "fetcher-0.1.0",
        "value": {"addresses": ["93.184.216.34"]},
        "reason_code": None,
    }


def test_fetcher_response_contract_accepts_only_typed_bounded_observations() -> None:
    evidence = _evidence_from_fetcher_response(_response([_dns()]), RUN_ID, CORRELATION_ID)
    assert len(evidence) == 1
    assert evidence[0].family == "dns"
    assert evidence[0].value == {"addresses": ["93.184.216.34"]}


def test_fetcher_response_contract_accepts_each_declared_family() -> None:
    common = {
        "state": "OBSERVED",
        "observed_at": "2026-07-22T12:00:00Z",
        "producer_version": "fetcher-0.1.0",
        "reason_code": None,
    }
    observations = [
        _dns(),
        {
            **common,
            "family": "RDAP",
            "source": "https://rdap.example/",
            "value": {
                "handle_present": True,
                "status": ["active"],
                "events": {"registration": "2026-07-01T00:00:00Z"},
                "nameservers": ["ns1.example"],
                "queried_at": "2026-07-22T12:00:00Z",
            },
        },
        {
            **common,
            "family": "TLS",
            "source": "target-tls",
            "value": {
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "not_before": "Jul 01 00:00:00 2026 GMT",
                "not_after": "Oct 01 00:00:00 2026 GMT",
                "subject_alt_name_count": 2,
                "hostname_verified": True,
            },
        },
        {
            **common,
            "family": "REDIRECT",
            "source": "target-http",
            "value": {
                "count": 1,
                "chain": [{"status": 302, "from_host": "example.com", "to_host": "www.example.com"}],
            },
        },
        {
            **common,
            "family": "STATIC_HTML",
            "source": "bounded-html-parser",
            "value": {
                "forms": 1,
                "password_inputs": 1,
                "hidden_inputs": 0,
                "external_form_actions": 0,
                "external_links": 3,
                "script_tags_present": True,
                "meta_refresh_present": False,
            },
        },
    ]

    evidence = _evidence_from_fetcher_response(_response(observations), RUN_ID, CORRELATION_ID)
    assert {item.family for item in evidence} == {"dns", "rdap", "tls", "redirect", "static_html"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.update(family="REPUTATION"),
        lambda item: item.update(unexpected="data"),
        lambda item: item["value"].update(unexpected=True),
        lambda item: item["value"].update(addresses=["not-an-ip"]),
        lambda item: item.update(state="TIMED_OUT", value={"addresses": ["93.184.216.34"]}),
    ],
)
def test_fetcher_response_contract_rejects_unknown_or_malformed_evidence(mutate) -> None:
    item = deepcopy(_dns())
    mutate(item)
    with pytest.raises(ValueError):
        _evidence_from_fetcher_response(_response([item]), RUN_ID, CORRELATION_ID)


def test_fetcher_response_contract_rejects_duplicate_families() -> None:
    with pytest.raises(ValueError):
        _evidence_from_fetcher_response(_response([_dns(), _dns()]), RUN_ID, CORRELATION_ID)


def test_fetcher_response_contract_rejects_unknown_response_fields_and_identity_mismatch() -> None:
    payload = _response([_dns()])
    payload["target_url"] = "https://must-not-cross-this-boundary.example/"
    with pytest.raises(ValueError):
        _evidence_from_fetcher_response(payload, RUN_ID, CORRELATION_ID)

    with pytest.raises(ValueError):
        _evidence_from_fetcher_response(_response([_dns()]), "different-analysis-run", CORRELATION_ID)
