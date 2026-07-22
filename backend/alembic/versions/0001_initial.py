"""Initial trusted application schema.

Revision ID: 0001
Revises:
Create Date: 2026-07-22
"""

from alembic import op

from phishguard.infrastructure.models import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    # Forward-only by policy; restore from backup rather than destructively dropping data.
    pass
