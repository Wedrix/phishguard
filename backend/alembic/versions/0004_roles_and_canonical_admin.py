"""Add governed role requests and the canonical administrator marker.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-23
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    user_columns = {column["name"] for column in inspector.get_columns("user_account")}
    if "is_canonical_admin" not in user_columns:
        op.add_column(
            "user_account",
            sa.Column(
                "is_canonical_admin",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )

    inspector = sa.inspect(connection)
    user_indexes = {index["name"] for index in inspector.get_indexes("user_account")}
    if "uq_user_account_canonical_admin" not in user_indexes:
        op.create_index(
            "uq_user_account_canonical_admin",
            "user_account",
            ["is_canonical_admin"],
            unique=True,
            postgresql_where=sa.text("is_canonical_admin"),
            sqlite_where=sa.text("is_canonical_admin = 1"),
        )

    if connection.dialect.name == "postgresql":
        checks = {
            constraint["name"]
            for constraint in sa.inspect(connection).get_check_constraints("user_account")
        }
        if "ck_user_account_role" not in checks:
            op.create_check_constraint(
                "ck_user_account_role",
                "user_account",
                "role IN ('REGISTERED_USER', 'ANALYST', 'ADMINISTRATOR', 'RESEARCHER')",
            )
        if "ck_user_account_canonical_active_admin" not in checks:
            op.create_check_constraint(
                "ck_user_account_canonical_active_admin",
                "user_account",
                "is_canonical_admin = false OR (role = 'ADMINISTRATOR' AND disabled_at IS NULL)",
            )

    if "role_request" not in inspector.get_table_names():
        op.create_table(
            "role_request",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(36),
                sa.ForeignKey("user_account.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("requested_role", sa.String(32), nullable=False),
            sa.Column("state", sa.String(24), nullable=False),
            sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("decided_at", sa.DateTime(timezone=True)),
            sa.Column(
                "decided_by_user_id",
                sa.String(36),
                sa.ForeignKey("user_account.id", ondelete="SET NULL"),
            ),
            sa.Column("decision_note", sa.String(1000)),
            sa.CheckConstraint(
                "requested_role IN ('ANALYST', 'RESEARCHER')",
                name="ck_role_request_requested_role",
            ),
            sa.CheckConstraint(
                "state IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')",
                name="ck_role_request_state",
            ),
        )
        op.create_index("ix_role_request_user_id", "role_request", ["user_id"])
        op.create_index(
            "uq_role_request_pending_user",
            "role_request",
            ["user_id"],
            unique=True,
            postgresql_where=sa.text("state = 'PENDING'"),
            sqlite_where=sa.text("state = 'PENDING'"),
        )


def downgrade() -> None:
    # Forward-only by policy; retain governance records during application rollback.
    pass
