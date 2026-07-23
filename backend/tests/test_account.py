from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from phishguard.infrastructure.models import (
    ApplicationSession,
    AuditEvent,
    IdempotencyRecord,
    Scan,
    ScanJob,
    SharedReport,
    UserAccount,
)


def _sign_in(client: TestClient, subject: str = "member-subject") -> dict[str, str]:
    response = client.post(
        "/api/v1/session",
        json={"id_token": f"dev:member@example.test:{subject}"},
    )
    assert response.status_code == 201
    return {"X-CSRF-Token": client.cookies["phishguard_csrf"]}


def _create(client: TestClient, headers: dict[str, str], key: str, mode: str = "local_only") -> dict:
    response = client.post(
        "/api/v1/scans",
        headers={**headers, "Idempotency-Key": key},
        json={
            "url": "https://account.example/login?private=export-secret",
            "analysis_mode": mode,
            "enrichment_consent": mode == "enriched",
        },
    )
    assert response.status_code in {201, 202}
    return response.json()["scan"]


def test_account_export_is_fresh_authenticated_redacted_and_not_cached(client, app) -> None:
    headers = _sign_in(client)
    scan = _create(client, headers, "account-export-scan")

    exported = client.post("/api/v1/account/export", headers=headers)

    assert exported.status_code == 200
    assert exported.headers["cache-control"] == "no-store"
    assert exported.headers["content-disposition"] == 'attachment; filename="phishguard-account-export.json"'
    payload = exported.json()
    assert payload["schema_version"] == "phishguard-account-export/1"
    assert payload["identity_platform_identity_included"] is False
    assert payload["scans"][0]["id"] == scan["id"]
    assert payload["scans"][0]["decision"]["id"]
    assert "export-secret" not in exported.text
    assert "original_ciphertext" not in exported.text
    with app.state.session_factory() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "account.data.export"))

    with app.state.session_factory.begin() as db:
        session = db.scalar(select(ApplicationSession).where(ApplicationSession.user_id.is_not(None)))
        assert session is not None
        session.reauthenticated_at = datetime.now(UTC) - timedelta(minutes=6)
    stale = client.post("/api/v1/account/export", headers=headers)
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "fresh_auth_required"


def test_per_user_retention_is_idempotent_and_applies_to_new_scans(client, app) -> None:
    headers = _sign_in(client, "retention-subject")
    retention_headers = {**headers, "Idempotency-Key": "account-retention-0001"}

    updated = client.put("/api/v1/account/retention", headers=retention_headers, json={"days": 7})
    assert updated.status_code == 200
    assert updated.json() == {"scan_retention_days": 7, "applies_to": "new_scans"}
    replay = client.put("/api/v1/account/retention", headers=retention_headers, json={"days": 1})
    assert replay.json() == updated.json()
    assert client.get("/api/v1/me").json()["scan_retention_days"] == 7

    scan = _create(client, headers, "retention-created-scan")
    with app.state.session_factory() as db:
        row = db.get(Scan, scan["id"])
        assert row is not None
        created = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=UTC)
        expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
        assert timedelta(days=6, hours=23) < expires - created < timedelta(days=7, minutes=1)

    too_long = client.put(
        "/api/v1/account/retention",
        headers={**headers, "Idempotency-Key": "account-retention-0002"},
        json={"days": app.state.settings.scan_retention_days + 1},
    )
    assert too_long.status_code == 422
    assert too_long.json()["error"]["code"] == "retention_exceeds_policy"


def test_account_scan_deletion_revokes_access_shares_jobs_idempotency_and_sessions(client, app) -> None:
    headers = _sign_in(client, "delete-subject")
    scan = _create(client, headers, "account-delete-scan", "enriched")
    shared = client.post(
        f"/api/v1/scans/{scan['id']}/shares",
        headers={**headers, "Idempotency-Key": "account-delete-share"},
        json={"expires_in_hours": 1},
    )
    assert shared.status_code == 201
    with TestClient(app, base_url="https://testserver") as second_session:
        _sign_in(second_session, "delete-subject")

        deleted = client.delete(
            "/api/v1/account/scans",
            headers={**headers, "Idempotency-Key": "account-delete-all"},
        )

        assert deleted.status_code == 200
        assert deleted.headers["cache-control"] == "no-store"
        assert deleted.json() == {
            "status": "deleted",
            "deleted_scan_count": 1,
            "application_sessions_revoked": True,
            "identity_platform_identity_deleted": False,
        }
        assert client.cookies.get("__Host-phishguard_session") is None
        assert client.cookies.get("phishguard_csrf") is None
        revoked = second_session.get("/api/v1/me")
        assert revoked.status_code == 200
        assert revoked.json()["session_kind"] == "ANONYMOUS"

    assert client.get("/api/v1/reports/" + shared.json()["report_id"]).status_code == 404
    with app.state.session_factory() as db:
        row = db.get(Scan, scan["id"])
        assert row is not None
        assert row.deleted_at is not None
        assert row.original_ciphertext == "deleted"
        assert row.enrichment_consent is False
        share = db.scalar(select(SharedReport).where(SharedReport.scan_id == scan["id"]))
        assert share is not None and share.revoked_at is not None
        job = db.scalar(select(ScanJob).where(ScanJob.run_id == row.run_id))
        assert job is not None and job.state == "CANCELLED"
        user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == "delete-subject"))
        assert user is not None
        sessions = list(db.scalars(select(ApplicationSession).where(ApplicationSession.user_id == user.id)))
        assert sessions and all(session.revoked_at is not None for session in sessions)
        assert not db.scalar(select(IdempotencyRecord).where(IdempotencyRecord.principal == f"user:{user.id}"))
        audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "account.scans.delete"))
        assert audit is not None and audit.actor_user_id == user.id
