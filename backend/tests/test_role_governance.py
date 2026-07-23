from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from phishguard.infrastructure.models import (
    ApplicationSession,
    AuditEvent,
    RoleRequest,
    Scan,
    UserAccount,
)


def _sign_in(client: TestClient, subject: str, requested_role: str | None = None) -> dict:
    body = {"id_token": f"dev:{subject}@example.test:{subject}"}
    if requested_role:
        body["requested_role"] = requested_role
    response = client.post("/api/v1/session", json=body)
    assert response.status_code == 201
    return response.json()


def _csrf(client: TestClient, key: str) -> dict[str, str]:
    return {
        "X-CSRF-Token": client.cookies["phishguard_csrf"],
        "Idempotency-Key": key,
    }


def _make_admin(client: TestClient, app, subject: str, canonical: bool = False) -> tuple[str, dict[str, str]]:
    signed_in = _sign_in(client, subject)
    with app.state.session_factory.begin() as db:
        user = db.get(UserAccount, signed_in["user_id"])
        assert user is not None
        user.role = "ADMINISTRATOR"
        user.is_canonical_admin = canonical
    return signed_in["user_id"], _csrf(client, f"{subject}-admin-key")


def test_me_distinguishes_anonymous_guest_and_user_sessions_and_adopts_guest_scan(
    client, app
) -> None:
    anonymous = client.get("/api/v1/me")
    assert anonymous.status_code == 200
    assert anonymous.json()["session_kind"] == "ANONYMOUS"
    assert anonymous.json()["role"] is None
    assert anonymous.json()["default_route"] == "/"

    created = client.post(
        "/api/v1/scans",
        headers={"Idempotency-Key": "guest-adoption-scan"},
        json={
            "url": "https://adopt.example.test/login",
            "analysis_mode": "local_only",
            "enrichment_consent": False,
        },
    )
    assert created.status_code == 201
    scan_id = created.json()["scan"]["id"]
    guest = client.get("/api/v1/me")
    assert guest.status_code == 200
    assert guest.json()["session_kind"] == "GUEST"
    assert guest.json()["role"] is None
    assert guest.json()["default_route"] == "/"
    with app.state.session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.guest_session_id
        guest_session_id = scan.guest_session_id

    signed_in = _sign_in(client, "adopting-member", "RESEARCHER")
    assert signed_in["session_kind"] == "USER"
    assert signed_in["default_route"] == "/history"
    assert signed_in["role"] == "REGISTERED_USER"
    assert signed_in["adopted_scan_count"] == 1
    assert signed_in["scan_retention_days"] == app.state.settings.scan_retention_days
    assert signed_in["scan_retention_max_days"] == app.state.settings.scan_retention_days
    assert signed_in["role_request"]["requested_role"] == "RESEARCHER"
    assert signed_in["role_request"]["state"] == "PENDING"
    user_id = signed_in["user_id"]

    current = client.get("/api/v1/me")
    assert current.status_code == 200
    assert current.json()["session_kind"] == "USER"
    assert current.json()["default_route"] == "/history"
    assert current.json()["role_request"]["id"] == signed_in["role_request"]["id"]
    with app.state.session_factory() as db:
        scan = db.get(Scan, scan_id)
        guest_session = db.get(ApplicationSession, guest_session_id)
        request = db.get(RoleRequest, signed_in["role_request"]["id"])
        assert scan is not None
        assert (scan.owner_user_id, scan.guest_session_id) == (user_id, None)
        expiry = scan.expires_at if scan.expires_at.tzinfo else scan.expires_at.replace(tzinfo=UTC)
        assert expiry > datetime.now(UTC) + timedelta(days=29)
        assert guest_session is not None and guest_session.revoked_at is not None
        assert request is not None and request.state == "PENDING"
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "scan.guest_adopt"))
        assert db.scalar(select(AuditEvent).where(AuditEvent.action == "role_request.create"))


@pytest.mark.parametrize(
    ("role", "route"),
    [
        ("REGISTERED_USER", "/history"),
        ("ANALYST", "/analyst/cases"),
        ("ADMINISTRATOR", "/admin"),
        ("RESEARCHER", "/research"),
    ],
)
def test_me_returns_stable_default_route_for_each_user_role(client, app, role: str, route: str) -> None:
    signed_in = _sign_in(client, f"route-{role.lower()}")
    with app.state.session_factory.begin() as db:
        user = db.get(UserAccount, signed_in["user_id"])
        assert user is not None
        user.role = role

    response = client.get("/api/v1/me")
    assert response.status_code == 200
    assert response.json()["session_kind"] == "USER"
    assert response.json()["default_route"] == route


def test_role_request_is_idempotent_conflicts_while_pending_and_is_owner_cancellable(
    client, app
) -> None:
    signed_in = _sign_in(client, "requester")
    headers = _csrf(client, "role-request-create")
    created = client.post(
        "/api/v1/account/role-requests",
        headers=headers,
        json={"requested_role": "ANALYST"},
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["user_id"] == signed_in["user_id"]
    assert payload["requested_role"] == "ANALYST"
    assert payload["state"] == "PENDING"
    assert payload["requested_at"]
    assert payload["decided_at"] is None
    assert payload["decided_by_user_id"] is None
    assert payload["decision_note"] is None

    replay = client.post(
        "/api/v1/account/role-requests",
        headers=headers,
        json={"requested_role": "RESEARCHER"},
    )
    assert replay.status_code == 201
    assert replay.json() == payload
    conflict = client.post(
        "/api/v1/account/role-requests",
        headers=_csrf(client, "role-request-conflict"),
        json={"requested_role": "RESEARCHER"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "role_request_conflict"

    with TestClient(app, base_url="https://testserver") as other:
        _sign_in(other, "other-requester")
        hidden = other.delete(
            f"/api/v1/account/role-requests/{payload['id']}",
            headers=_csrf(other, "other-cancel-request"),
        )
        assert hidden.status_code == 404
        assert hidden.json()["error"]["code"] == "role_request_not_found"

    cancel_headers = _csrf(client, "owner-cancel-request")
    cancelled = client.delete(
        f"/api/v1/account/role-requests/{payload['id']}", headers=cancel_headers
    )
    assert cancelled.status_code == 204
    assert client.delete(
        f"/api/v1/account/role-requests/{payload['id']}", headers=cancel_headers
    ).status_code == 204
    with app.state.session_factory() as db:
        row = db.get(RoleRequest, payload["id"])
        assert row is not None and row.state == "CANCELLED"
        assert row.decided_at is not None


def test_only_registered_users_can_request_roles_and_request_intent_never_breaks_sign_in(
    client, app
) -> None:
    forbidden_intent = client.post(
        "/api/v1/session",
        json={
            "id_token": "dev:forbidden-admin@example.test:forbidden-admin",
            "requested_role": "ADMINISTRATOR",
        },
    )
    assert forbidden_intent.status_code == 422

    signed_in = _sign_in(client, "existing-analyst")
    with app.state.session_factory.begin() as db:
        user = db.get(UserAccount, signed_in["user_id"])
        assert user is not None
        user.role = "ANALYST"

    repeated_sign_in = _sign_in(client, "existing-analyst", "RESEARCHER")
    assert repeated_sign_in["role"] == "ANALYST"
    assert repeated_sign_in["role_request"] is None
    denied = client.post(
        "/api/v1/account/role-requests",
        headers=_csrf(client, "analyst-role-request"),
        json={"requested_role": "RESEARCHER"},
    )
    assert denied.status_code == 409
    assert denied.json()["error"]["code"] == "role_request_not_allowed"
    with app.state.session_factory() as db:
        assert not db.scalar(
            select(RoleRequest).where(RoleRequest.user_id == signed_in["user_id"])
        )


def test_admin_can_approve_or_reject_pending_role_requests(client, app) -> None:
    admin_id, headers = _make_admin(client, app, "request-admin")
    with TestClient(app, base_url="https://testserver") as member:
        member_session = _sign_in(member, "approved-member")
        requested = member.post(
            "/api/v1/account/role-requests",
            headers=_csrf(member, "approved-role-request"),
            json={"requested_role": "ANALYST"},
        ).json()

        pending = client.get("/api/v1/admin/role-requests?state=PENDING")
        assert pending.status_code == 200
        assert requested["id"] in {item["id"] for item in pending.json()["items"]}
        approved = client.post(
            f"/api/v1/admin/role-requests/{requested['id']}/actions",
            headers={**headers, "Idempotency-Key": "approve-role-request"},
            json={"action": "APPROVE", "note": "Assurance reviewed"},
        )
        assert approved.status_code == 200
        assert approved.json()["state"] == "APPROVED"
        assert approved.json()["decided_by_user_id"] == admin_id
        assert approved.json()["decision_note"] == "Assurance reviewed"
        assert approved.json()["decided_at"]
        revoked_me = member.get("/api/v1/me")
        assert revoked_me.status_code == 200
        assert revoked_me.json()["session_kind"] == "ANONYMOUS"

    with TestClient(app, base_url="https://testserver") as member:
        rejected_member = _sign_in(member, "rejected-member")
        requested = member.post(
            "/api/v1/account/role-requests",
            headers=_csrf(member, "rejected-role-request"),
            json={"requested_role": "RESEARCHER"},
        ).json()
        rejected = client.post(
            f"/api/v1/admin/role-requests/{requested['id']}/actions",
            headers={**headers, "Idempotency-Key": "reject-role-request"},
            json={"action": "REJECT", "note": "Scope not justified"},
        )
        assert rejected.status_code == 200
        assert rejected.json()["state"] == "REJECTED"
        assert rejected.json()["decision_note"] == "Scope not justified"
        assert member.get("/api/v1/me").json()["session_kind"] == "USER"

    with app.state.session_factory() as db:
        approved_user = db.get(UserAccount, member_session["user_id"])
        rejected_user = db.get(UserAccount, rejected_member["user_id"])
        assert approved_user is not None and approved_user.role == "ANALYST"
        assert rejected_user is not None and rejected_user.role == "REGISTERED_USER"
        target_sessions = list(
            db.scalars(
                select(ApplicationSession).where(
                    ApplicationSession.user_id == approved_user.id
                )
            )
        )
        assert target_sessions and all(row.revoked_at is not None for row in target_sessions)
        actions = set(
            db.scalars(
                select(AuditEvent.action).where(
                    AuditEvent.action.in_(["role_request.approve", "role_request.reject"])
                )
            )
        )
        assert actions == {"role_request.approve", "role_request.reject"}


def test_role_request_approval_requires_verified_email_and_totp(client, app) -> None:
    _admin_id, headers = _make_admin(client, app, "assurance-admin")
    with TestClient(app, base_url="https://testserver") as member:
        signed_in = _sign_in(member, "unassured-member")
        requested = member.post(
            "/api/v1/account/role-requests",
            headers=_csrf(member, "unassured-role-request"),
            json={"requested_role": "ANALYST"},
        ).json()
    with app.state.session_factory.begin() as db:
        user = db.get(UserAccount, signed_in["user_id"])
        assert user is not None
        user.mfa_verified = False

    denied = client.post(
        f"/api/v1/admin/role-requests/{requested['id']}/actions",
        headers={**headers, "Idempotency-Key": "unassured-role-deny"},
        json={"action": "APPROVE"},
    )
    assert denied.status_code == 409
    assert denied.json()["error"]["code"] == "privileged_assurance_required"
    with app.state.session_factory() as db:
        user = db.get(UserAccount, signed_in["user_id"])
        row = db.get(RoleRequest, requested["id"])
        assert user is not None and user.role == "REGISTERED_USER"
        assert row is not None and row.state == "PENDING"


def test_noncanonical_admin_can_promote_assured_user_but_cannot_change_an_admin(
    client, app
) -> None:
    _admin_id, headers = _make_admin(client, app, "ordinary-admin")
    with app.state.session_factory.begin() as db:
        db.add(
            UserAccount(
                identity_subject="canonical-anchor",
                email_hash="c" * 64,
                role="ADMINISTRATOR",
                email_verified=True,
                mfa_verified=True,
                is_canonical_admin=True,
            )
        )
    with TestClient(app, base_url="https://testserver") as member:
        member_session = _sign_in(member, "admin-candidate")
        promoted = client.put(
            f"/api/v1/admin/users/{member_session['user_id']}",
            headers={**headers, "Idempotency-Key": "promote-admin-candidate"},
            json={"role": "ADMINISTRATOR", "disabled": False},
        )
        assert promoted.status_code == 200
        assert promoted.json()["role"] == "ADMINISTRATOR"
        assert promoted.json()["is_canonical_admin"] is False
        assert member.get("/api/v1/me").json()["session_kind"] == "ANONYMOUS"

    denied = client.put(
        f"/api/v1/admin/users/{member_session['user_id']}",
        headers={**headers, "Idempotency-Key": "demote-other-admin"},
        json={"role": "ADMINISTRATOR", "disabled": True},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "canonical_admin_required"


def test_administrator_promotion_requires_canonical_admin_bootstrap(client, app) -> None:
    _admin_id, headers = _make_admin(client, app, "bootstrap-gap-admin")
    with TestClient(app, base_url="https://testserver") as member:
        candidate = _sign_in(member, "bootstrap-gap-candidate")
    denied = client.put(
        f"/api/v1/admin/users/{candidate['user_id']}",
        headers={**headers, "Idempotency-Key": "promotion-without-canonical"},
        json={"role": "ADMINISTRATOR", "disabled": False},
    )
    assert denied.status_code == 409
    assert denied.json()["error"]["code"] == "canonical_admin_missing"
    with app.state.session_factory() as db:
        user = db.get(UserAccount, candidate["user_id"])
        assert user is not None and user.role == "REGISTERED_USER"


def test_only_canonical_admin_can_disable_and_reenable_admin_and_it_is_app_immutable(
    client, app
) -> None:
    canonical_id, canonical_headers = _make_admin(client, app, "canonical-admin", canonical=True)
    with TestClient(app, base_url="https://testserver") as ordinary:
        ordinary_id, ordinary_headers = _make_admin(ordinary, app, "other-admin")
        protected = ordinary.put(
            f"/api/v1/admin/users/{canonical_id}",
            headers={**ordinary_headers, "Idempotency-Key": "change-canonical-admin"},
            json={"role": "REGISTERED_USER", "disabled": True},
        )
        assert protected.status_code == 409
        assert protected.json()["error"]["code"] == "canonical_admin_protected"

    changed = client.put(
        f"/api/v1/admin/users/{ordinary_id}",
        headers={**canonical_headers, "Idempotency-Key": "canonical-disables-admin"},
        json={"role": "ADMINISTRATOR", "disabled": True},
    )
    assert changed.status_code == 200
    assert changed.json()["role"] == "ADMINISTRATOR"
    assert changed.json()["disabled"] is True
    restored = client.put(
        f"/api/v1/admin/users/{ordinary_id}",
        headers={**canonical_headers, "Idempotency-Key": "canonical-enables-admin"},
        json={"role": "ADMINISTRATOR", "disabled": False},
    )
    assert restored.status_code == 200
    assert restored.json()["role"] == "ADMINISTRATOR"
    assert restored.json()["disabled"] is False
    with app.state.session_factory() as db:
        canonical = db.get(UserAccount, canonical_id)
        ordinary_admin = db.get(UserAccount, ordinary_id)
        assert canonical is not None and canonical.is_canonical_admin
        assert ordinary_admin is not None and ordinary_admin.disabled_at is None


def test_disabled_user_cannot_be_newly_promoted_to_administrator(client, app) -> None:
    _canonical_id, headers = _make_admin(client, app, "promotion-canonical", canonical=True)
    with TestClient(app, base_url="https://testserver") as member:
        disabled_candidate = _sign_in(member, "disabled-admin-candidate")
    with app.state.session_factory.begin() as db:
        candidate = db.get(UserAccount, disabled_candidate["user_id"])
        assert candidate is not None
        candidate.disabled_at = datetime.now(UTC)

    disabled = client.put(
        f"/api/v1/admin/users/{disabled_candidate['user_id']}",
        headers={**headers, "Idempotency-Key": "promote-disabled-user"},
        json={"role": "ADMINISTRATOR", "disabled": False},
    )
    assert disabled.status_code == 409
    assert disabled.json()["error"]["code"] == "administrator_must_be_active"

    with TestClient(app, base_url="https://testserver") as member:
        active_candidate = _sign_in(member, "active-admin-candidate")
    disabled_on_promotion = client.put(
        f"/api/v1/admin/users/{active_candidate['user_id']}",
        headers={**headers, "Idempotency-Key": "promote-and-disable-user"},
        json={"role": "ADMINISTRATOR", "disabled": True},
    )
    assert disabled_on_promotion.status_code == 409
    assert disabled_on_promotion.json()["error"]["code"] == "administrator_must_be_active"


def test_admin_health_reports_canonical_admin_configuration(client, app) -> None:
    admin_id, _headers = _make_admin(client, app, "health-admin")
    missing = client.get("/api/v1/admin/health")
    assert missing.status_code == 200
    assert missing.json()["canonical_admin"] == {"status": "MISSING", "count": 0}

    with app.state.session_factory.begin() as db:
        admin = db.get(UserAccount, admin_id)
        assert admin is not None
        admin.is_canonical_admin = True
    configured = client.get("/api/v1/admin/health")
    assert configured.status_code == 200
    assert configured.json()["canonical_admin"] == {"status": "CONFIGURED", "count": 1}


def test_database_enforces_single_active_canonical_administrator(app) -> None:
    with pytest.raises(IntegrityError), app.state.session_factory.begin() as db:
        db.add(
            UserAccount(
                identity_subject="invalid-canonical",
                email_hash="1" * 64,
                role="REGISTERED_USER",
                email_verified=True,
                mfa_verified=True,
                is_canonical_admin=True,
            )
        )

    with app.state.session_factory.begin() as db:
        db.add(
            UserAccount(
                identity_subject="first-canonical",
                email_hash="2" * 64,
                role="ADMINISTRATOR",
                email_verified=True,
                mfa_verified=True,
                is_canonical_admin=True,
            )
        )
    with pytest.raises(IntegrityError), app.state.session_factory.begin() as db:
        db.add(
            UserAccount(
                identity_subject="second-canonical",
                email_hash="3" * 64,
                role="ADMINISTRATOR",
                email_verified=True,
                mfa_verified=True,
                is_canonical_admin=True,
            )
        )
