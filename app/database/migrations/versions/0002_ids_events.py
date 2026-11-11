"""ids_events table

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ids_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False), sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False), sa.Column("jail", sa.String(32)),
        sa.Column("message", sa.String(300), nullable=False), sa.Column("details", sa.JSON, nullable=False),
        sa.Column("action", sa.String(24), nullable=False),
    )
    for c in ("ts", "kind", "severity", "source_ip"):
        op.create_index(f"ix_ids_events_{c}", "ids_events", [c])


def downgrade() -> None:
    op.drop_table("ids_events")
