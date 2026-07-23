from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from phishguard.api.dependencies import get_db
from phishguard.infrastructure.models import (
    AnalysisRun,
    AuditEvent,
    Decision,
    EvidenceObservation,
    IdempotencyRecord,
    ReviewCase,
    Scan,
    ScanJob,
    UserAccount,
)


def _create(client, url: str = "https://example.com/login?token=secret", mode: str = "local_only", key: str = "request-key-0001"):
    csrf = client.cookies.get("phishguard_csrf")
    headers = {"Idempotency-Key": key}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return client.post(
        "/api/v1/scans",
        headers=headers,
        json={"url": url, "analysis_mode": mode, "enrichment_consent": mode == "enriched"},
    )


def test_guest_local_scan_round_trip_and_idempotency(client, app) -> None:
    response = _create(client)
    assert response.status_code == 201
    scan = response.json()["scan"]
    assert scan["requested_mode"] == "local_only"
    assert scan["decision"]["analysis_scope"] == "LOCAL_ONLY"
    assert scan["decision"]["evidence"] == []
    assert "score" not in scan["decision"]
    assert "secret" not in scan["display_url"]
    assert response.headers["x-content-type-options"] == "nosniff"

    replay = _create(client)
    assert replay.status_code == 201
    assert replay.json()["scan"]["id"] == scan["id"]

    fetched = client.get(f"/api/v1/scans/{scan['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["scan"]["decision"]["risk_band"] in {"LOW", "MEDIUM", "HIGH"}
    assert fetched.json()["scan"]["decision"]["evidence"] == []

    with app.state.session_factory() as db:
        stored = db.get(Scan, scan["id"])
        assert stored is not None
        assert "example.com" not in stored.original_ciphertext
        expiry = stored.expires_at if stored.expires_at.tzinfo else stored.expires_at.replace(tzinfo=UTC)
        created = stored.created_at if stored.created_at.tzinfo else stored.created_at.replace(tzinfo=UTC)
        assert 3500 <= (expiry - created).total_seconds() <= 3700
        assert not db.scalar(select(ScanJob).where(ScanJob.run_id == stored.run_id))


def test_enrichment_requires_consent(client) -> None:
    response = client.post(
        "/api/v1/scans",
        headers={"Idempotency-Key": "request-key-0002"},
        json={"url": "https://example.com/", "analysis_mode": "enriched", "enrichment_consent": False},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_scan_request"


def test_local_scan_keeps_local_decision_when_deduplicated_run_is_enriched(client, app) -> None:
    local = _create(client, "https://example.com/path#private", key="request-key-local").json()["scan"]
    enriched_response = _create(client, "https://example.com/path#private", "enriched", "request-key-rich")
    assert enriched_response.status_code == 202
    assert enriched_response.json()["scan"]["status"] == "PROCESSING"
    with app.state.session_factory.begin() as db:
        scan_row = db.get(Scan, local["id"])
        local_decision = db.scalar(select(Decision).where(Decision.run_id == scan_row.run_id, Decision.stage == "LOCAL"))
        db.add(
            Decision(
                run_id=scan_row.run_id,
                supersedes_id=local_decision.id,
                stage="FINAL",
                risk_band="HIGH",
                analysis_scope="ENRICHED",
                completion="COMPLETE",
                engine_mode="RULE_ONLY",
                probability=0.99,
                rule_hits=[],
                policy_version="test",
                ruleset_version="test",
                fusion_version="test",
                reasons=["external"],
                counter_evidence=[],
                missing_evidence=[],
                limitations=[],
                safe_actions=[],
            )
        )
    fetched = client.get(f"/api/v1/scans/{local['id']}").json()["scan"]
    assert fetched["status"] == "COMPLETE"
    assert fetched["decision"]["analysis_scope"] == "LOCAL_ONLY"
    assert fetched["decision"]["evidence"] == []


def test_error_envelope_and_cross_session_404(client) -> None:
    bad = _create(client, "http://0x7f.0.0.1/", key="request-key-bad1")
    assert bad.status_code == 422
    assert set(bad.json()["error"]) == {"code", "message", "correlation_id", "fields"}
    missing = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert missing.status_code == 404


def test_framework_and_unexpected_errors_keep_the_api_envelope(client, app) -> None:
    method = client.put("/api/v1/scans")
    assert method.status_code == 405
    assert method.json()["error"]["code"] == "method_not_allowed"
    assert method.headers["cache-control"] == "no-store"
    assert method.headers["x-content-type-options"] == "nosniff"

    def unexpected_error():
        raise RuntimeError("injected test failure")

    app.dependency_overrides[get_db] = unexpected_error
    try:
        unexpected = client.get("/api/v1/scans")
        assert unexpected.status_code == 500
        assert unexpected.json()["error"]["code"] == "internal_error"
        assert unexpected.headers["cache-control"] == "no-store"
        assert unexpected.headers["x-correlation-id"]
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_expired_scan_cannot_reveal_original_url(client, app) -> None:
    created = _create(client, key="request-key-expired-reveal").json()["scan"]
    with app.state.session_factory.begin() as db:
        db.get(Scan, created["id"]).expires_at = datetime.now(UTC) - timedelta(seconds=1)
    revealed = client.get(f"/api/v1/scans/{created['id']}/original-url")
    assert revealed.status_code == 404
    assert revealed.headers["cache-control"] == "no-store"


def test_delete_cancels_unneeded_enrichment_and_invalidates_create_replay(client, app) -> None:
    key = "request-key-delete-enriched"
    created = _create(client, "https://delete.example/login", "enriched", key).json()["scan"]
    csrf = client.cookies["phishguard_csrf"]
    deleted = client.delete(
        f"/api/v1/scans/{created['id']}",
        headers={"X-CSRF-Token": csrf},
    )
    assert deleted.status_code == 204
    with app.state.session_factory() as db:
        scan = db.get(Scan, created["id"])
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == scan.run_id))
        assert job is not None and job.state == "CANCELLED"
        assert not db.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.principal == f"guest:{scan.guest_session_id}",
                IdempotencyRecord.operation == "create_scan",
            )
        )

    replacement = _create(client, "https://delete.example/login", "enriched", key)
    assert replacement.status_code == 202
    assert replacement.json()["scan"]["id"] != created["id"]


def test_expired_idempotency_key_can_be_reused(client, app) -> None:
    key = "request-key-expired-reuse"
    first = _create(client, "https://first.example/", key=key).json()["scan"]
    with app.state.session_factory.begin() as db:
        record = db.scalar(select(IdempotencyRecord).where(IdempotencyRecord.key == key))
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    second = _create(client, "https://second.example/", key=key)
    assert second.status_code == 201
    assert second.json()["scan"]["id"] != first["id"]


def test_shared_enriched_report_keeps_pinned_evidence_but_not_original_url(client, app) -> None:
    created = _create(client, "https://example.com/login?private=secret", "enriched", "request-key-share").json()["scan"]
    with app.state.session_factory.begin() as db:
        scan = db.get(Scan, created["id"])
        local = db.scalar(select(Decision).where(Decision.run_id == scan.run_id, Decision.stage == "LOCAL"))
        evidence = EvidenceObservation(
            run_id=scan.run_id,
            family="reputation",
            state="NO_MATCH",
            source="google_web_risk",
            value={},
        )
        db.add(evidence)
        db.flush()
        db.add(
            Decision(
                run_id=scan.run_id,
                supersedes_id=local.id,
                stage="FINAL",
                risk_band="MEDIUM",
                analysis_scope="ENRICHED",
                completion="COMPLETE",
                engine_mode="RULE_ONLY",
                probability=0.5,
                rule_hits=[],
                evidence_ids=[evidence.id],
                policy_version="test",
                ruleset_version="test",
                fusion_version="test",
                reasons=[],
                counter_evidence=[],
                missing_evidence=[],
                limitations=[],
                safe_actions=[],
            )
        )
    csrf = client.cookies.get("phishguard_csrf")
    shared = client.post(
        f"/api/v1/scans/{created['id']}/shares",
        headers={"Idempotency-Key": "request-key-report", "X-CSRF-Token": csrf},
        json={"expires_in_hours": 1},
    )
    assert shared.status_code == 201
    report = client.get(f"/api/v1/reports/{shared.json()['report_id']}").json()["scan"]
    assert report["decision"]["evidence"][0]["family"] == "REPUTATION"
    assert report["decision"]["evidence"][0]["value"] is None
    assert report["decision"]["evidence"][0]["value_redacted"] is True
    assert "secret" not in str(report)


def test_privileged_review_access_is_case_bounded_audited_and_read_only(client, app) -> None:
    created = _create(client, "https://owner.example/private", key="request-key-owner").json()["scan"]

    with TestClient(app, base_url="https://testserver") as analyst:
        signed_in = analyst.post(
            "/api/v1/session",
            json={"id_token": "dev:analyst@example.test:analyst-subject"},
        )
        assert signed_in.status_code == 201
        with app.state.session_factory.begin() as db:
            user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == "analyst-subject"))
            assert user is not None
            user.role = "ANALYST"

        assert analyst.get(f"/api/v1/scans/{created['id']}").status_code == 404

        with app.state.session_factory.begin() as db:
            db.add(ReviewCase(scan_id=created["id"]))

        reviewed = analyst.get(f"/api/v1/scans/{created['id']}")
        assert reviewed.status_code == 200
        headers = {
            "X-CSRF-Token": analyst.cookies["phishguard_csrf"],
            "Idempotency-Key": "analyst-mutation-0001",
        }
        assert analyst.post(
            f"/api/v1/scans/{created['id']}/shares",
            headers=headers,
            json={"expires_in_hours": 1},
        ).status_code == 404
        assert analyst.post(
            f"/api/v1/scans/{created['id']}/feedback",
            headers={**headers, "Idempotency-Key": "analyst-mutation-0002"},
            json={"category": "OTHER", "comment": "not the owner"},
        ).status_code == 404
        assert analyst.delete(
            f"/api/v1/scans/{created['id']}",
            headers={"X-CSRF-Token": analyst.cookies["phishguard_csrf"]},
        ).status_code == 404

    with app.state.session_factory() as db:
        scan = db.get(Scan, created["id"])
        assert scan is not None and scan.deleted_at is None
        events = list(
            db.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "scan.review.read",
                    AuditEvent.object_id == created["id"],
                )
            )
        )
        assert len(events) == 1
