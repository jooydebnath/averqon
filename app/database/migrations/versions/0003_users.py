"""users and revoked_tokens

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users", sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(256), nullable=False), sa.Column("role", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False), sa.Column("failed_logins", sa.Integer, nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True)), sa.Column("last_login", sa.DateTime(timezone=True)),
        sa.Column("token_version", sa.Integer, nullable=False),
    )
    op.create_table(
        "revoked_tokens", sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("revoked_tokens")
    op.drop_table("users")
