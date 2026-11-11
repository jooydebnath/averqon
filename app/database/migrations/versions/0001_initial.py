"""initial schema: audit log, firewall rules, whitelist, bans

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_ts = lambda: sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)


def upgrade() -> None:
    op.create_table(
        "audit_log", _ts(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("actor", sa.String(128), nullable=False), sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(256), nullable=False), sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False), sa.Column("details", sa.JSON, nullable=False),
    )
    op.create_index("ix_audit_log_actor", "audit_log", ["actor"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_table(
        "firewall_rules", _ts(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False), sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("priority", sa.Integer, nullable=False), sa.Column("direction", sa.String(3), nullable=False),
        sa.Column("action", sa.String(6), nullable=False), sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("source", sa.String(49)), sa.Column("destination", sa.String(49)),
        sa.Column("sport", sa.JSON, nullable=False), sa.Column("dport", sa.JSON, nullable=False),
        sa.Column("interface", sa.String(15)), sa.Column("states", sa.JSON, nullable=False),
        sa.Column("rate_limit", sa.String(16)), sa.Column("log", sa.Boolean, nullable=False),
        sa.Column("rule_group", sa.String(64)), sa.Column("comment", sa.String(100), nullable=False),
    )
    op.create_index("ix_firewall_rules_priority", "firewall_rules", ["priority"])
    op.create_table(
        "whitelist", _ts(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("network", sa.String(49), nullable=False, unique=True),
        sa.Column("comment", sa.String(100), nullable=False),
    )
    op.create_table(
        "bans", _ts(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("network", sa.String(49), nullable=False), sa.Column("reason", sa.String(200), nullable=False),
        sa.Column("source", sa.String(32), nullable=False), sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)), sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)), sa.Column("ended_by", sa.String(128), nullable=False),
    )
    op.create_index("ix_bans_network", "bans", ["network"])
    op.create_index("ix_bans_active", "bans", ["active"])


def downgrade() -> None:
    for t in ("bans", "whitelist", "firewall_rules", "audit_log"):
        op.drop_table(t)
