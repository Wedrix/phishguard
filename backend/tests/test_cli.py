from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from phishguard import cli
from phishguard.application.audit import append_audit
from phishguard.config import Settings
from phishguard.infrastructure.database import create_schema, make_engine, make_session_factory
from phishguard.infrastructure.models import ApplicationSession, AuditEvent, UserAccount


def _database() -> tuple[Settings, object, object]:
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        phishguard_hmac_key="test-hmac-key-with-enough-entropy",
    )
    engine = make_engine(settings.database_url)
    create_schema(engine)
    return settings, engine, make_session_factory(engine)


def _user(subject: str, role: str = "REGISTERED_USER", canonical: bool = False) -> UserAccount:
    return UserAccount(
        identity_subject=subject,
        email_hash=uuid.uuid4().hex * 2,
        role=role,
        email_verified=True,
        mfa_verified=True,
        is_canonical_admin=canonical,
    )


def _session(user_id: str, token: str) -> ApplicationSession:
    return ApplicationSession(
        user_id=user_id,
        token_hash=token * 64,
        csrf_hash=token.upper() * 64,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        reauthenticated_at=datetime.now(UTC),
    )


def _run(monkeypatch, settings: Settings, engine, argv: list[str]) -> None:
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(cli, "make_engine", lambda _database_url: engine)
    monkeypatch.setattr(sys, "argv", ["phishguard", *argv])
    cli.main()


def test_bootstrap_admin_promotes_existing_assured_account_revokes_sessions_and_audits(
    monkeypatch, capsys
) -> None:
    settings, engine, factory = _database()
    with factory.begin() as db:
        seed = append_audit(
            db,
            settings.phishguard_hmac_key.encode(),
            None,
            "deployment.seed",
            "deployment",
            None,
            "SUCCESS",
            str(uuid.uuid4()),
        )
        account = _user("canonical-subject")
        db.add(account)
        db.flush()
        user_id, seed_hmac = account.id, seed.event_hmac
        db.add(_session(account.id, "a"))

    _run(monkeypatch, settings, engine, ["bootstrap-admin", "--subject", "canonical-subject"])

    with factory() as db:
        user = db.get(UserAccount, user_id)
        event = db.scalar(
            select(AuditEvent).where(AuditEvent.action == "user.bootstrap_canonical_admin")
        )
        sessions = list(
            db.scalars(select(ApplicationSession).where(ApplicationSession.user_id == user_id))
        )
        assert user is not None
        assert (user.role, user.is_canonical_admin, user.disabled_at) == (
            "ADMINISTRATOR",
            True,
            None,
        )
        assert sessions and all(row.revoked_at is not None for row in sessions)
        assert event is not None
        assert event.actor_user_id is None
        assert event.object_id == user_id
        assert event.previous_hmac == seed_hmac
        assert event.detail == {
            "previous_role": "REGISTERED_USER",
            "role": "ADMINISTRATOR",
            "is_canonical_admin": True,
        }
        uuid.UUID(event.correlation_id)
        correlation_id = event.correlation_id

    output = capsys.readouterr().out
    assert correlation_id in output
    assert "canonical-subject" not in output


@pytest.mark.parametrize("condition", ["missing", "disabled", "email", "totp"])
def test_bootstrap_admin_requires_existing_active_email_and_totp_assured_account(
    monkeypatch, condition: str
) -> None:
    settings, engine, factory = _database()
    if condition != "missing":
        with factory.begin() as db:
            account = _user("candidate-subject")
            if condition == "disabled":
                account.disabled_at = datetime.now(UTC)
            elif condition == "email":
                account.email_verified = False
            elif condition == "totp":
                account.mfa_verified = False
            db.add(account)

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            settings,
            engine,
            ["bootstrap-admin", "--subject", "candidate-subject"],
        )


def test_transfer_canonical_admin_rotates_roles_revokes_both_accounts_and_audits(
    monkeypatch, capsys
) -> None:
    settings, engine, factory = _database()
    with factory.begin() as db:
        current = _user("current-subject", "ADMINISTRATOR", canonical=True)
        replacement = _user("replacement-subject")
        db.add_all([current, replacement])
        db.flush()
        current_id, replacement_id = current.id, replacement.id
        db.add_all([_session(current.id, "b"), _session(replacement.id, "c")])

    _run(
        monkeypatch,
        settings,
        engine,
        [
            "transfer-canonical-admin",
            "--current-subject",
            "current-subject",
            "--replacement-subject",
            "replacement-subject",
            "--confirm-transfer",
        ],
    )

    with factory() as db:
        current = db.get(UserAccount, current_id)
        replacement = db.get(UserAccount, replacement_id)
        sessions = list(
            db.scalars(
                select(ApplicationSession).where(
                    ApplicationSession.user_id.in_([current_id, replacement_id])
                )
            )
        )
        event = db.scalar(
            select(AuditEvent).where(AuditEvent.action == "user.transfer_canonical_admin")
        )
        assert current is not None and replacement is not None
        assert (current.role, current.is_canonical_admin, current.disabled_at is not None) == (
            "REGISTERED_USER",
            False,
            True,
        )
        assert (replacement.role, replacement.is_canonical_admin, replacement.disabled_at) == (
            "ADMINISTRATOR",
            True,
            None,
        )
        assert len(sessions) == 2 and all(row.revoked_at is not None for row in sessions)
        assert event is not None
        assert event.object_id == replacement_id
        assert event.detail == {
            "previous_canonical_user_id": current_id,
            "replacement_user_id": replacement_id,
            "replacement_previous_role": "REGISTERED_USER",
            "previous_canonical_disabled": True,
        }
        uuid.UUID(event.correlation_id)
        correlation_id = event.correlation_id

    output = capsys.readouterr().out
    assert correlation_id in output
    assert "current-subject" not in output
    assert "replacement-subject" not in output


def test_transfer_canonical_admin_requires_explicit_confirmation(monkeypatch) -> None:
    settings, engine, _factory = _database()
    with pytest.raises(SystemExit, match="--confirm-transfer is required"):
        _run(
            monkeypatch,
            settings,
            engine,
            [
                "transfer-canonical-admin",
                "--current-subject",
                "current-subject",
                "--replacement-subject",
                "replacement-subject",
            ],
        )
