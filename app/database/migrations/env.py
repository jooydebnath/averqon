"""Alembic environment. DB URL is taken from Averqon settings (or -x url=...)."""

from alembic import context
from sqlalchemy import create_engine

from app.core.config import load_settings
from app.database import models  # noqa: F401  (register tables)
from app.database.base import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return context.get_x_argument(as_dictionary=True).get("url") or load_settings(enforce_permissions=False).database.url


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    run_migrations_online()
