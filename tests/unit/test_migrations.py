from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app.database import models  # noqa: F401
from app.database.base import Base

ROOT = Path(__file__).resolve().parents[2]


def cfg(url):
    c = Config()
    c.set_main_option("script_location", str(ROOT / "app" / "database" / "migrations"))
    c.cmd_opts = type("o", (), {"x": [f"url={url}"]})()
    return c


def test_upgrade_matches_models_and_downgrades(tmp_path):
    url = f"sqlite:///{tmp_path/'m.db'}"
    command.upgrade(cfg(url), "head")
    eng = create_engine(url)
    assert {"audit_log", "firewall_rules", "whitelist", "bans"} <= set(inspect(eng).get_table_names())
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"migration drifts from models: {diff}"
    command.downgrade(cfg(url), "base")
    assert "bans" not in inspect(create_engine(url)).get_table_names()
