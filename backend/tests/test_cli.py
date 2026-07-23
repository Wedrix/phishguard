from __future__ import annotations

import hashlib
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from phishguard import cli
from phishguard.application.audit import append_audit
from phishguard.config import Settings
from phishguard.infrastructure.database import create_schema, make_engine, make_session_factory
from phishguard.infrastructure.models import (
    AnalysisRun,
    ApplicationSession,
    AuditEvent,
    DatasetSnapshot,
    Decision,
    Experiment,
    Feedback,
    ResearchExport,
    Scan,
    UserAccount,
)


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


def test_recorded_evaluation_verifies_snapshot_and_persists_measured_result(
    monkeypatch, tmp_path: Path
) -> None:
    settings, engine, factory = _database()
    dataset_path = tmp_path / "frozen.csv"
    dataset_path.write_text("url,label\nhttps://example.test,0\n", encoding="utf-8")
    digest = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    with factory.begin() as db:
        researcher = _user("researcher-subject", "RESEARCHER")
        db.add(researcher)
        db.flush()
        dataset = DatasetSnapshot(
            name="Frozen snapshot",
            manifest={"artifact_path": dataset_path.name},
            sha256=digest,
            created_by=researcher.id,
        )
        db.add(dataset)
        db.flush()
        experiment = Experiment(
            dataset_id=dataset.id,
            config={
                "max_expected_calibration_error": 0.1,
                "max_brier_score": 0.1,
            },
            created_by=researcher.id,
        )
        db.add(experiment)
        db.flush()
        experiment_id = experiment.id

    observed: dict[str, object] = {}

    def evaluate(path, output, **gates):
        observed.update(path=path, output=output, gates=gates)
        return {"schema_version": "evaluation/1", "selected_model": "logistic_regression"}

    monkeypatch.setattr(cli, "evaluate_dataset", evaluate)
    _run(
        monkeypatch,
        settings,
        engine,
        ["evaluate-record", "--next", "--artifact-root", str(tmp_path)],
    )

    assert observed["path"] == dataset_path
    assert observed["gates"] == {
        "max_expected_calibration_error": 0.1,
        "max_brier_score": 0.1,
    }
    with factory() as db:
        completed = db.get(Experiment, experiment_id)
        assert completed is not None
        assert completed.state == "COMPLETE"
        assert completed.result["selected_model"] == "logistic_regression"
        assert completed.result["output_path"] == f"outputs/{experiment_id}"


def test_recorded_export_includes_only_consented_adjudicated_redacted_rows(
    monkeypatch, tmp_path: Path
) -> None:
    settings, engine, factory = _database()
    with factory.begin() as db:
        researcher = _user("export-researcher", "RESEARCHER")
        db.add(researcher)
        db.flush()
        run = AnalysisRun(
            fingerprint="a" * 64,
            policy_context="policy-1",
            normalized_ciphertext="encrypted-normalized-url",
        )
        db.add(run)
        db.flush()
        scan = Scan(
            run_id=run.id,
            owner_user_id=researcher.id,
            original_ciphertext="encrypted-original-url",
            display_url="https://example[.]test/[path hidden]",
            requested_mode="LOCAL_ONLY",
            enrichment_consent=False,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
        db.add(scan)
        db.flush()
        db.add(
            Decision(
                run_id=run.id,
                stage="LOCAL",
                risk_band="MEDIUM",
                analysis_scope="LOCAL_ONLY",
                completion="COMPLETE",
                engine_mode="RULE_ONLY",
                probability=0.6,
                policy_version="policy-1",
                ruleset_version="rules-1",
                fusion_version="fusion-1",
            )
        )
        db.add_all(
            [
                Feedback(
                    scan_id=scan.id,
                    author_user_id=researcher.id,
                    category="FALSE_NEGATIVE",
                    comment="This comment must never be exported.",
                    research_consent=True,
                    status="REVIEWED_MALICIOUS",
                ),
                Feedback(
                    scan_id=scan.id,
                    author_user_id=researcher.id,
                    category="OTHER",
                    comment="No research consent.",
                    research_consent=False,
                    status="REVIEWED_BENIGN",
                ),
            ]
        )
        export = ResearchExport(
            filters={"purpose": "acceptance"},
            created_by=researcher.id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        db.add(export)
        db.flush()
        export_id = export.id

    _run(
        monkeypatch,
        settings,
        engine,
        ["export-record", "--next", "--artifact-root", str(tmp_path)],
    )

    output = tmp_path / "exports" / f"{export_id}.json"
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["row_count"] == 1
    assert payload["rows"][0]["redacted_url"] == "https://example[.]test/[path hidden]"
    serialized = output.read_text(encoding="utf-8")
    assert "This comment must never be exported." not in serialized
    assert "No research consent." not in serialized
    assert "encrypted-original-url" not in serialized
    assert "export-researcher" not in serialized
    with factory() as db:
        completed = db.get(ResearchExport, export_id)
        assert completed is not None
        assert completed.state == "COMPLETE"
        assert completed.artifact_uri == f"research/exports/{export_id}.json"
