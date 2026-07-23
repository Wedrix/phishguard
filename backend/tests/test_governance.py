from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from phishguard.infrastructure.models import (
    ApplicationSession,
    AuditEvent,
    Feedback,
    IdempotencyRecord,
    ProviderConfig,
    ReviewCase,
    UserAccount,
)


def _administrator(client, app) -> dict[str, str]:
    response = client.post(
        "/api/v1/session",
        json={"id_token": "dev:admin@example.test:admin-subject"},
    )
    assert response.status_code == 201
    with app.state.session_factory.begin() as db:
        user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == "admin-subject"))
        assert user is not None
        user.role = "ADMINISTRATOR"
    return {"X-CSRF-Token": client.cookies["phishguard_csrf"]}


def test_governed_mutation_requires_and_replays_idempotency_key(client, app) -> None:
    headers = _administrator(client, app)
    url = "/api/v1/admin/providers/google_web_risk"

    missing = client.put(url, headers=headers, json={"enabled": True, "config": {}})
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "idempotency_key_required"

    headers["Idempotency-Key"] = "provider-change-0001"
    created = client.put(url, headers=headers, json={"enabled": True, "config": {"requests_per_minute": 30}})
    assert created.status_code == 200
    assert created.json()["enabled"] is True

    replay = client.put(url, headers=headers, json={"enabled": False, "config": {}})
    assert replay.status_code == 200
    assert replay.json() == created.json()

    with app.state.session_factory() as db:
        provider = db.scalar(select(ProviderConfig).where(ProviderConfig.provider == "google_web_risk"))
        assert provider is not None and provider.enabled is True
        assert provider.config == {"requests_per_minute": 30}
        audit_count = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "provider.update"))
        assert audit_count == 1


def test_expired_governance_idempotency_key_can_be_reused(client, app) -> None:
    headers = _administrator(client, app)
    headers["Idempotency-Key"] = "provider-expired-reuse"
    url = "/api/v1/admin/providers/google_web_risk"
    first = client.put(url, headers=headers, json={"enabled": True, "config": {}})
    assert first.status_code == 200
    with app.state.session_factory.begin() as db:
        record = db.scalar(select(IdempotencyRecord).where(IdempotencyRecord.key == headers["Idempotency-Key"]))
        assert record is not None
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)

    second = client.put(url, headers=headers, json={"enabled": False, "config": {}})
    assert second.status_code == 200
    assert second.json()["enabled"] is False


def test_privileged_role_assignment_requires_assurance_and_revokes_sessions(client, app) -> None:
    headers = _administrator(client, app)
    with TestClient(app, base_url="https://testserver") as member:
        signed_in = member.post(
            "/api/v1/session",
            json={"id_token": "dev:member@example.test:member-subject"},
        )
        assert signed_in.status_code == 201
        with app.state.session_factory.begin() as db:
            user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == "member-subject"))
            assert user is not None
            user_id = user.id
            user.email_verified = False

        denied_email = client.put(
            f"/api/v1/admin/users/{user_id}",
            headers={**headers, "Idempotency-Key": "role-change-email"},
            json={"role": "ANALYST", "disabled": False},
        )
        assert denied_email.status_code == 409
        assert denied_email.json()["error"]["code"] == "privileged_assurance_required"

        with app.state.session_factory.begin() as db:
            user = db.get(UserAccount, user_id)
            assert user is not None
            user.email_verified = True
            user.mfa_verified = False

        denied_mfa = client.put(
            f"/api/v1/admin/users/{user_id}",
            headers={**headers, "Idempotency-Key": "role-change-mfa00"},
            json={"role": "RESEARCHER", "disabled": False},
        )
        assert denied_mfa.status_code == 409

        with app.state.session_factory.begin() as db:
            user = db.get(UserAccount, user_id)
            assert user is not None
            user.mfa_verified = True

        promoted = client.put(
            f"/api/v1/admin/users/{user_id}",
            headers={**headers, "Idempotency-Key": "role-change-final"},
            json={"role": "ANALYST", "disabled": False},
        )
        assert promoted.status_code == 200
        assert promoted.json()["role"] == "ANALYST"
        revoked = member.get("/api/v1/me")
        assert revoked.status_code == 200
        assert revoked.json()["session_kind"] == "ANONYMOUS"

        with app.state.session_factory() as db:
            sessions = list(db.scalars(select(ApplicationSession).where(ApplicationSession.user_id == user_id)))
            assert sessions and all(session.revoked_at is not None for session in sessions)


def test_privileged_session_resolution_requires_mfa(client, app) -> None:
    with TestClient(app, base_url="https://testserver") as member:
        signed_in = member.post(
            "/api/v1/session",
            json={"id_token": "dev:member@example.test:unguarded-subject"},
        )
        assert signed_in.status_code == 201
        with app.state.session_factory.begin() as db:
            user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == "unguarded-subject"))
            assert user is not None
            user.role = "ANALYST"
            user.mfa_verified = False
        unresolved = member.get("/api/v1/me")
        assert unresolved.status_code == 200
        assert unresolved.json()["session_kind"] == "ANONYMOUS"


def test_review_case_exposes_quarantined_feedback_and_updates_it_on_adjudication(client, app) -> None:
    headers = _administrator(client, app)
    scan_response = client.post(
        "/api/v1/scans",
        headers={**headers, "Idempotency-Key": "review-feedback-scan"},
        json={
            "url": "https://review-feedback.example/login",
            "analysis_mode": "local_only",
            "enrichment_consent": False,
        },
    )
    assert scan_response.status_code == 201
    scan_id = scan_response.json()["scan"]["id"]
    submitted = client.post(
        f"/api/v1/scans/{scan_id}/feedback",
        headers={**headers, "Idempotency-Key": "review-feedback-submit"},
        json={
            "category": "FALSE_NEGATIVE",
            "comment": "Credential form was missed",
            "research_consent": True,
        },
    )
    assert submitted.status_code == 201
    with app.state.session_factory() as db:
        review_case = db.scalar(select(ReviewCase).where(ReviewCase.scan_id == scan_id))
        assert review_case is not None
        case_id = review_case.id

    detail = client.get(f"/api/v1/review-cases/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["feedback"] == {
        "id": submitted.json()["id"],
        "category": "FALSE_NEGATIVE",
        "comment": "Credential form was missed",
        "status": "QUARANTINED",
        "research_consent": True,
        "created_at": detail.json()["feedback"]["created_at"],
    }

    claimed = client.post(
        f"/api/v1/review-cases/{case_id}/actions",
        headers={**headers, "Idempotency-Key": "review-feedback-claim"},
        json={"action": "claim"},
    )
    assert claimed.status_code == 200
    invalid_citation = client.post(
        f"/api/v1/review-cases/{case_id}/actions",
        headers={**headers, "Idempotency-Key": "review-feedback-invalid-citation"},
        json={
            "action": "adjudicate",
            "outcome": "MALICIOUS",
            "note": "This rationale deliberately cites evidence from another case.",
            "evidence_ids": ["reason:999"],
        },
    )
    assert invalid_citation.status_code == 422
    assert invalid_citation.json()["error"]["code"] == "invalid_evidence_reference"
    adjudicated = client.post(
        f"/api/v1/review-cases/{case_id}/actions",
        headers={**headers, "Idempotency-Key": "review-feedback-adjudicate"},
        json={
            "action": "adjudicate",
            "outcome": "MALICIOUS",
            "note": "The stored decision reason and submitted report support this conclusion.",
            "evidence_ids": ["reason:0"],
        },
    )
    assert adjudicated.status_code == 200
    repeated = client.post(
        f"/api/v1/review-cases/{case_id}/actions",
        headers={**headers, "Idempotency-Key": "review-feedback-repeat"},
        json={"action": "adjudicate", "outcome": "BENIGN"},
    )
    assert repeated.status_code == 409
    assert repeated.json()["error"]["code"] == "case_closed"
    with app.state.session_factory() as db:
        feedback = db.get(Feedback, submitted.json()["id"])
        assert feedback is not None and feedback.status == "REVIEWED_MALICIOUS"


def test_model_deployment_gates_and_audit_chain_verification(client, app) -> None:
    headers = _administrator(client, app)
    rejected = client.post(
        "/api/v1/admin/models",
        headers={**headers, "Idempotency-Key": "model-register-rejected"},
        json={
            "version": "candidate-rejected",
            "artifact_uri": "gs://models/rejected.joblib",
            "sha256": "a" * 64,
            "metrics": {"pr_auc": 0.91},
        },
    )
    assert rejected.status_code == 201
    activation = client.post(
        f"/api/v1/admin/models/{rejected.json()['id']}/activate",
        headers={**headers, "Idempotency-Key": "model-activate-rejected"},
    )
    assert activation.status_code == 409
    assert activation.json()["error"]["code"] == "model_gates_failed"

    approved = client.post(
        "/api/v1/admin/models",
        headers={**headers, "Idempotency-Key": "model-register-approved"},
        json={
            "version": "candidate-approved",
            "artifact_uri": "gs://models/approved.joblib",
            "sha256": "b" * 64,
            "metrics": {
                "pr_auc": 0.93,
                "gates": {
                    "data": True,
                    "feature": True,
                    "evaluation": True,
                    "security": True,
                },
            },
        },
    )
    assert approved.status_code == 201
    activation = client.post(
        f"/api/v1/admin/models/{approved.json()['id']}/activate",
        headers={**headers, "Idempotency-Key": "model-activate-approved"},
    )
    assert activation.status_code == 200
    assert activation.json()["deployment_required"] is True
    assert activation.json()["runtime_active"] is False

    verification = client.get("/api/v1/admin/audit-events/verify")
    assert verification.status_code == 200
    assert verification.json()["valid"] is True
    assert verification.json()["checked_events"] >= 3


def test_explicit_session_revocation_invalidates_the_target_session(client, app) -> None:
    headers = _administrator(client, app)
    with TestClient(app, base_url="https://testserver") as member:
        signed_in = member.post(
            "/api/v1/session",
            json={"id_token": "dev:member@example.test:revocation-target"},
        )
        assert signed_in.status_code == 201
        with app.state.session_factory() as db:
            user = db.scalar(
                select(UserAccount).where(UserAccount.identity_subject == "revocation-target")
            )
            assert user is not None
            user_id = user.id

        revoked = client.post(
            f"/api/v1/admin/users/{user_id}/revoke-sessions",
            headers={**headers, "Idempotency-Key": "explicit-session-revocation"},
        )
        assert revoked.status_code == 200
        assert revoked.json()["revoked_session_count"] == 1
        assert member.get("/api/v1/me").json()["session_kind"] == "ANONYMOUS"
