from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import os
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select, text

from phishguard.application.audit import append_audit
from phishguard.application.roles import RoleRequestService
from phishguard.config import Settings
from phishguard.domain.model import SklearnUrlModel
from phishguard.domain.types import Role
from phishguard.evaluation.train import evaluate_dataset
from phishguard.infrastructure.database import make_engine, make_session_factory
from phishguard.infrastructure.encryption import configured_cipher
from phishguard.infrastructure.models import (
    AuditEvent,
    DatasetSnapshot,
    Decision,
    Experiment,
    Feedback,
    ResearchExport,
    Scan,
    UserAccount,
)
from phishguard.jobs.worker import cleanup_expired, run_worker
from phishguard.logging_config import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(prog="phishguard")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("web")
    jobs = subcommands.add_parser("jobs")
    jobs.add_argument("--once", action="store_true")
    subcommands.add_parser("migrate")
    subcommands.add_parser("cleanup")
    subcommands.add_parser("anchor-audit")
    bootstrap = subcommands.add_parser("bootstrap-admin")
    bootstrap.add_argument("--subject", required=True)
    transfer = subcommands.add_parser("transfer-canonical-admin")
    transfer.add_argument("--current-subject", required=True)
    transfer.add_argument("--replacement-subject", required=True)
    transfer.add_argument("--confirm-transfer", action="store_true")
    evaluation = subcommands.add_parser("evaluate")
    evaluation.add_argument("dataset", type=Path)
    evaluation.add_argument("output", type=Path)
    evaluation.add_argument(
        "--max-ece",
        type=_unit_interval,
        default=os.environ.get("EVALUATION_MAX_ECE"),
        help="governed maximum expected calibration error in [0, 1]",
    )
    evaluation.add_argument(
        "--max-brier",
        type=_unit_interval,
        default=os.environ.get("EVALUATION_MAX_BRIER"),
        help="governed maximum Brier score in [0, 1]",
    )
    recorded_evaluation = subcommands.add_parser("evaluate-record")
    recorded_evaluation.add_argument("--experiment-id")
    recorded_evaluation.add_argument("--next", action="store_true")
    recorded_evaluation.add_argument("--artifact-root", type=Path, default=Path("/artifacts/research"))
    recorded_export = subcommands.add_parser("export-record")
    recorded_export.add_argument("--export-id")
    recorded_export.add_argument("--next", action="store_true")
    recorded_export.add_argument("--artifact-root", type=Path, default=Path("/artifacts/research"))
    args = parser.parse_args()
    settings = Settings()
    configure_logging(settings.log_level)

    if args.command == "web":
        import uvicorn

        uvicorn.run(
            "phishguard.api.app:app",
            host="0.0.0.0",
            port=settings.port,
            log_level=settings.log_level.lower(),
            access_log=False,
            log_config=None,
        )
        return
    if args.command == "migrate":
        config = Config(str(_alembic_config_path()))
        config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
        command.upgrade(config, "head")
        return
    if args.command == "evaluate":
        print(
            evaluate_dataset(
                args.dataset,
                args.output,
                max_expected_calibration_error=args.max_ece,
                max_brier_score=args.max_brier,
            )
        )
        return

    engine = make_engine(settings.database_url)
    factory = make_session_factory(engine)
    cipher = configured_cipher(settings.kms_key_name, settings.phishguard_encryption_key, settings.environment)
    model = None
    model_configuration = (settings.model_path, settings.model_sha256, settings.model_version)
    if any(model_configuration) and not all(model_configuration):
        raise SystemExit("MODEL_PATH, MODEL_SHA256, and MODEL_VERSION must be configured together")
    if all(model_configuration):
        assert settings.model_path and settings.model_sha256 and settings.model_version
        try:
            model = SklearnUrlModel(settings.model_path, settings.model_sha256, settings.model_version)
        except Exception:
            logger.exception(
                "approved model could not be loaded; using rule-only fallback",
                extra={"model_version": settings.model_version},
            )
    if args.command == "bootstrap-admin":
        with factory.begin() as db:
            _canonical_admin_lock(db)
            if db.scalar(select(UserAccount.id).where(UserAccount.is_canonical_admin.is_(True))):
                raise SystemExit("a canonical Administrator already exists")
            user = db.scalar(
                select(UserAccount)
                .where(UserAccount.identity_subject == args.subject)
                .with_for_update()
            )
            _require_canonical_candidate(user)
            assert user is not None
            previous_role = user.role
            user.role = Role.ADMINISTRATOR.value
            user.is_canonical_admin = True
            RoleRequestService(db).revoke_sessions(user.id)
            db.flush()
            correlation_id = str(uuid.uuid4())
            append_audit(
                db,
                settings.phishguard_hmac_key.encode(),
                None,
                "user.bootstrap_canonical_admin",
                "user_account",
                user.id,
                "SUCCESS",
                correlation_id,
                {
                    "previous_role": previous_role,
                    "role": Role.ADMINISTRATOR.value,
                    "is_canonical_admin": True,
                },
            )
        print(f"bootstrapped canonical Administrator (correlation_id={correlation_id})")
    elif args.command == "transfer-canonical-admin":
        if not args.confirm_transfer:
            raise SystemExit("--confirm-transfer is required")
        if args.current_subject == args.replacement_subject:
            raise SystemExit("current and replacement users must be different")
        with factory.begin() as db:
            _canonical_admin_lock(db)
            current = db.scalar(
                select(UserAccount)
                .where(UserAccount.identity_subject == args.current_subject)
                .with_for_update()
            )
            replacement = db.scalar(
                select(UserAccount)
                .where(UserAccount.identity_subject == args.replacement_subject)
                .with_for_update()
            )
            if not current or not current.is_canonical_admin or current.role != Role.ADMINISTRATOR.value:
                raise SystemExit("the current user is not the canonical Administrator")
            _require_canonical_candidate(replacement)
            assert replacement is not None
            previous_replacement_role = replacement.role
            current.is_canonical_admin = False
            # Release the non-deferrable unique slot before assigning it to
            # the replacement; both writes remain in this transaction.
            db.flush()
            current.role = Role.REGISTERED_USER.value
            current.disabled_at = datetime.now(UTC)
            replacement.role = Role.ADMINISTRATOR.value
            replacement.is_canonical_admin = True
            role_service = RoleRequestService(db)
            role_service.revoke_sessions(current.id)
            role_service.revoke_sessions(replacement.id)
            db.flush()
            correlation_id = str(uuid.uuid4())
            append_audit(
                db,
                settings.phishguard_hmac_key.encode(),
                None,
                "user.transfer_canonical_admin",
                "user_account",
                replacement.id,
                "SUCCESS",
                correlation_id,
                {
                    "previous_canonical_user_id": current.id,
                    "replacement_user_id": replacement.id,
                    "replacement_previous_role": previous_replacement_role,
                    "previous_canonical_disabled": True,
                },
            )
        print(f"transferred canonical Administrator (correlation_id={correlation_id})")
    elif args.command == "cleanup":
        with factory.begin() as db:
            count = cleanup_expired(db)
        print(f"removed {count} expired scans")
    elif args.command == "anchor-audit":
        with factory.begin() as db:
            latest = db.scalar(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(1))
        if latest:
            logger.info(
                "audit chain daily anchor",
                extra={"event_id": latest.id, "event_hmac": latest.event_hmac, "status": "anchored"},
            )
        else:
            logger.info("audit chain daily anchor", extra={"status": "empty"})
    elif args.command == "jobs":
        asyncio.run(run_worker(settings, factory, cipher, model, once=args.once))
    elif args.command == "evaluate-record":
        _evaluate_recorded_experiment(factory, args.experiment_id, args.next, args.artifact_root)
    elif args.command == "export-record":
        _export_recorded_research(factory, args.export_id, args.next, args.artifact_root)


def _alembic_config_path() -> Path:
    configured = os.environ.get("ALEMBIC_CONFIG")
    candidates = [
        Path(configured) if configured else None,
        Path.cwd() / "alembic.ini",
        Path(__file__).resolve().parents[2] / "alembic.ini",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate
    raise SystemExit("alembic.ini was not found; set ALEMBIC_CONFIG to its absolute path")


def _evaluate_recorded_experiment(factory, experiment_id: str | None, next_queued: bool, artifact_root: Path) -> None:
    if bool(experiment_id) == bool(next_queued):
        raise SystemExit("provide exactly one of --experiment-id or --next")
    with factory.begin() as db:
        statement = select(Experiment).where(Experiment.state == "QUEUED").order_by(Experiment.created_at)
        if experiment_id:
            statement = statement.where(Experiment.id == experiment_id)
        experiment = db.scalar(statement.with_for_update(skip_locked=True))
        if not experiment:
            if next_queued:
                print("no queued experiment")
                return
            raise SystemExit("queued experiment was not found")
        dataset = db.get(DatasetSnapshot, experiment.dataset_id)
        if not dataset:
            raise SystemExit("experiment dataset was not found")
        relative_path = dataset.manifest.get("artifact_path")
        if not isinstance(relative_path, str) or not relative_path:
            raise SystemExit("dataset manifest requires artifact_path")
        candidate = (artifact_root / relative_path).resolve()
        root = artifact_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise SystemExit("dataset artifact_path leaves the governed artifact root")
        if not candidate.is_file():
            raise SystemExit("dataset artifact is unavailable")
        if _file_sha256(candidate) != dataset.sha256:
            raise SystemExit("dataset artifact checksum does not match its frozen snapshot")
        experiment.state = "RUNNING"
        run_id = experiment.id
        config = dict(experiment.config)
    output = artifact_root / "outputs" / run_id
    try:
        manifest = evaluate_dataset(
            candidate,
            output,
            max_expected_calibration_error=_optional_gate(config, "max_expected_calibration_error"),
            max_brier_score=_optional_gate(config, "max_brier_score"),
        )
    except Exception as exc:
        with factory.begin() as db:
            failed = db.get(Experiment, run_id)
            if failed:
                failed.state = "FAILED"
                failed.result = {"error_code": type(exc).__name__}
        raise
    with factory.begin() as db:
        completed = db.get(Experiment, run_id)
        if not completed:
            raise SystemExit("experiment disappeared before completion")
        completed.state = "COMPLETE"
        completed.result = {**manifest, "output_path": f"outputs/{run_id}"}
    print(f"completed experiment {run_id}")


def _optional_gate(config: dict[str, object], name: str) -> float | None:
    value = config.get(name)
    if value is None:
        return None
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= float(value) <= 1:
        raise SystemExit(f"{name} must be in [0, 1]")
    return float(value)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _export_recorded_research(factory, export_id: str | None, next_queued: bool, artifact_root: Path) -> None:
    if bool(export_id) == bool(next_queued):
        raise SystemExit("provide exactly one of --export-id or --next")
    with factory.begin() as db:
        statement = select(ResearchExport).where(ResearchExport.state == "QUEUED").order_by(ResearchExport.created_at)
        if export_id:
            statement = statement.where(ResearchExport.id == export_id)
        export = db.scalar(statement.with_for_update(skip_locked=True))
        if not export:
            if next_queued:
                print("no queued research export")
                return
            raise SystemExit("queued research export was not found")
        export.state = "RUNNING"
        record_id = export.id
        requested_filters = dict(export.filters)
    try:
        with factory() as db:
            feedback_rows = list(
                db.scalars(
                    select(Feedback).where(
                        Feedback.research_consent.is_(True),
                        Feedback.status.like("REVIEWED_%"),
                    )
                )
            )
            rows: list[dict[str, object]] = []
            for feedback in feedback_rows:
                scan = db.get(Scan, feedback.scan_id)
                if not scan or scan.deleted_at:
                    continue
                decision = db.scalar(
                    select(Decision)
                    .where(Decision.run_id == scan.run_id)
                    .order_by(Decision.created_at.desc())
                )
                if not decision:
                    continue
                rows.append(
                    {
                        "record_id": hashlib.sha256(f"{record_id}:{scan.id}".encode()).hexdigest(),
                        "redacted_url": scan.display_url,
                        "adjudicated_label": feedback.status.removeprefix("REVIEWED_"),
                        "original_risk_band": decision.risk_band,
                        "analysis_scope": decision.analysis_scope,
                        "completion": decision.completion,
                        "engine_mode": decision.engine_mode,
                        "policy_version": decision.policy_version,
                        "ruleset_version": decision.ruleset_version,
                        "model_version": decision.model_version,
                        "research_consent": True,
                    }
                )
        output_dir = artifact_root / "exports"
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{record_id}.json"
        payload = {
            "schema_version": "phishguard-governed-export/1",
            "generated_at": datetime.now(UTC).isoformat(),
            "privacy_controls": {
                "redacted_only": True,
                "consent_required": True,
                "independent_adjudication_required": True,
                "comments_excluded": True,
                "identity_fields_excluded": True,
            },
            "requested_filters": requested_filters,
            "row_count": len(rows),
            "rows": rows,
        }
        temporary = output.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(output)
    except Exception:
        with factory.begin() as db:
            failed = db.get(ResearchExport, record_id)
            if failed:
                failed.state = "FAILED"
                failed.artifact_uri = None
        raise
    with factory.begin() as db:
        completed = db.get(ResearchExport, record_id)
        if not completed:
            raise SystemExit("research export disappeared before completion")
        completed.state = "COMPLETE"
        completed.artifact_uri = f"research/exports/{record_id}.json"
    print(f"completed research export {record_id}")


def _canonical_admin_lock(db) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:key)"),
            {"key": 0x50484341444D},
        )


def _require_canonical_candidate(user: UserAccount | None) -> None:
    if not user:
        raise SystemExit("the selected application user does not exist")
    if user.disabled_at:
        raise SystemExit("the selected application user is disabled")
    if not user.email_verified or not user.mfa_verified:
        raise SystemExit("verified email and TOTP are required for the canonical Administrator")


def _unit_interval(value: str) -> float:
    parsed = float(value)
    if not 0 <= parsed <= 1:
        raise argparse.ArgumentTypeError("must be within [0, 1]")
    return parsed


if __name__ == "__main__":
    main()
