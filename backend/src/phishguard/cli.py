from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import logging
import os
import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from phishguard.application.audit import append_audit
from phishguard.config import Settings
from phishguard.domain.model import SklearnUrlModel
from phishguard.domain.types import Role
from phishguard.evaluation.train import evaluate_dataset
from phishguard.infrastructure.database import make_engine, make_session_factory
from phishguard.infrastructure.encryption import configured_cipher
from phishguard.infrastructure.models import AuditEvent, UserAccount
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
    bootstrap.add_argument("--email", required=True)
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
            if db.scalar(select(UserAccount).where(UserAccount.role == Role.ADMINISTRATOR.value)):
                raise SystemExit("an Administrator already exists")
            user = db.scalar(select(UserAccount).where(UserAccount.identity_subject == args.subject))
            account_created = user is None
            previous_role = user.role if user else None
            email_hash = hmac.new(
                settings.phishguard_hmac_key.encode(), args.email.lower().encode(), hashlib.sha256
            ).hexdigest()
            if not user:
                user = UserAccount(
                    identity_subject=args.subject,
                    email_hash=email_hash,
                    email_verified=True,
                    mfa_verified=True,
                )
                db.add(user)
            user.role = Role.ADMINISTRATOR.value
            db.flush()
            correlation_id = str(uuid.uuid4())
            append_audit(
                db,
                settings.phishguard_hmac_key.encode(),
                None,
                "user.bootstrap_admin",
                "user_account",
                user.id,
                "SUCCESS",
                correlation_id,
                {
                    "account_created": account_created,
                    "previous_role": previous_role,
                    "role": Role.ADMINISTRATOR.value,
                },
            )
        print(f"bootstrapped initial Administrator (correlation_id={correlation_id})")
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


def _unit_interval(value: str) -> float:
    parsed = float(value)
    if not 0 <= parsed <= 1:
        raise argparse.ArgumentTypeError("must be within [0, 1]")
    return parsed


if __name__ == "__main__":
    main()
