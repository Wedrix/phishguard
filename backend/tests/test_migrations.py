from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select

from phishguard.infrastructure.database import make_engine, make_session_factory
from phishguard.infrastructure.models import ProviderConfig


def test_fresh_migration_seeds_effective_web_risk_policy(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite"
    database_url = f"sqlite:///{database}"
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    factory = make_session_factory(make_engine(database_url))
    with factory() as db:
        provider = db.scalar(
            select(ProviderConfig).where(ProviderConfig.provider == "google_web_risk")
        )
        assert provider is not None
        assert provider.enabled is True
        assert provider.config == {"requests_per_minute": 60}
        inspector = inspect(db.get_bind())
        user_columns = {column["name"] for column in inspector.get_columns("user_account")}
        assert {"scan_retention_days", "is_canonical_admin"} <= user_columns
        assert "role_request" in inspector.get_table_names()
        assert "uq_user_account_canonical_admin" in {
            index["name"] for index in inspector.get_indexes("user_account")
        }
        assert {"ix_role_request_user_id", "uq_role_request_pending_user"} <= {
            index["name"] for index in inspector.get_indexes("role_request")
        }
