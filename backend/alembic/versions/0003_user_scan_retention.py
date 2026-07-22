"""Add an optional per-user scan retention period.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-22
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 0001 creates current metadata on a fresh database, so only older
    # installations need the additive column.
    connection = op.get_bind()
    columns = {column["name"] for column in sa.inspect(connection).get_columns("user_account")}
    if "scan_retention_days" not in columns:
        op.add_column("user_account", sa.Column("scan_retention_days", sa.Integer(), nullable=True))


def downgrade() -> None:
    # Forward-only by policy; retain the preference during an application rollback.
    pass
