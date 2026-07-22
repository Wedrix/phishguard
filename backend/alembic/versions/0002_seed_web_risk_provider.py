"""Seed the effective Google Web Risk provider policy.

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-22
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    provider = sa.table(
        "provider_config",
        sa.column("id", sa.String(36)),
        sa.column("provider", sa.String(64)),
        sa.column("enabled", sa.Boolean),
        sa.column("config", sa.JSON),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    connection = op.get_bind()
    exists = connection.scalar(
        sa.select(provider.c.id).where(provider.c.provider == "google_web_risk").limit(1)
    )
    if not exists:
        connection.execute(
            provider.insert().values(
                id="00000000-0000-4000-8000-000000000002",
                provider="google_web_risk",
                enabled=True,
                config={"requests_per_minute": 60},
                updated_at=datetime.now(UTC),
            )
        )


def downgrade() -> None:
    # Forward-only by policy; provider history is not deleted on rollback.
    pass
