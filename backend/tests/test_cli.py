from __future__ import annotations

import sys
import uuid

import pytest
from sqlalchemy import select

from phishguard import cli
from phishguard.application.audit import append_audit
from phishguard.config import Settings
from phishguard.infrastructure.database import create_schema, make_engine, make_session_factory
from phishguard.infrastructure.models import AuditEvent, UserAccount


@pytest.mark.parametrize("existing_account", [False, True])
def test_bootstrap_admin_appends_chained_audit_event(
    monkeypatch, capsys, existing_account: bool
) -> None:
    settings = Settings(
        environment="test",
        database_url="sqlite://",
        phishguard_hmac_key="test-hmac-key-with-enough-entropy",
    )
    engine = make_engine(settings.database_url)
    create_schema(engine)
    factory = make_session_factory(engine)
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
        seed_hmac = seed.event_hmac
        if existing_account:
            db.add(
                UserAccount(
                    identity_subject="admin-subject",
                    email_hash="0" * 64,
                    role="REGISTERED_USER",
                    email_verified=True,
                    mfa_verified=True,
                )
            )

    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(cli, "make_engine", lambda _database_url: engine)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "phishguard",
            "bootstrap-admin",
            "--subject",
            "admin-subject",
            "--email",
            "admin@example.test",
        ],
    )

    cli.main()

    with factory() as db:
        user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == "admin-subject"))
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == "user.bootstrap_admin"))
        assert user is not None and user.role == "ADMINISTRATOR"
        assert event is not None
        assert event.actor_user_id is None
        assert event.object_type == "user_account"
        assert event.object_id == user.id
        assert event.previous_hmac == seed_hmac
        assert event.detail == {
            "account_created": not existing_account,
            "previous_role": "REGISTERED_USER" if existing_account else None,
            "role": "ADMINISTRATOR",
        }
        uuid.UUID(event.correlation_id)
        correlation_id = event.correlation_id

    output = capsys.readouterr().out
    assert correlation_id in output
    assert "admin@example.test" not in output
