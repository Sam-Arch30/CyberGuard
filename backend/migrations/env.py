import os
import sys
from pathlib import Path
from logging.config import fileConfig

from sqlalchemy import pool, create_engine
from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Add project root to sys.path
sys_path = Path(__file__).resolve().parent.parent.parent
if str(sys_path) not in sys.path:
    sys.path.insert(0, str(sys_path))

from backend.db.session import Base
import backend.db.models  # Ensure all models are registered with Base.metadata

target_metadata = Base.metadata

# Support DATABASE_URL from environment variable (e.g. Render / Railway managed PostgreSQL)
env_db_url = os.getenv("DATABASE_URL")
if env_db_url:
    if env_db_url.startswith("postgres://"):
        env_db_url = env_db_url.replace("postgres://", "postgresql://", 1)
    config.set_main_option("sqlalchemy.url", env_db_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    db_url = config.get_main_option("sqlalchemy.url")
    connect_args = {"check_same_thread": False} if "sqlite" in db_url else {}
    connectable = create_engine(
        db_url,
        poolclass=pool.NullPool,
        connect_args=connect_args
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
