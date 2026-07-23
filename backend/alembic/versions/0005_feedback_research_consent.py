"""Record explicit research consideration consent for feedback.

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-23
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("feedback")}
    if "research_consent" not in columns:
        op.add_column(
            "feedback",
            sa.Column(
                "research_consent",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )


def downgrade() -> None:
    # Forward-only by policy; preserve the consent record during application rollback.
    pass
