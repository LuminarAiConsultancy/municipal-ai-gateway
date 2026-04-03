"""Alembic environment configuration.

Reads DATABASE_URL from the environment and converts the async driver
to a sync driver for migration execution.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

from dotenv import load_dotenv

load_dotenv()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all models so Alembic can detect them for autogenerate.
from models import Base
from auth import ApiKey  # noqa: F401
from policies import DepartmentPolicy  # noqa: F401
from admin_auth import AdminUser  # noqa: F401
# ldap_auth uses ApiKey model from auth.py (no new models to register)

# RequestLog is defined in main.py. Import it to register with Base.
from main import RequestLog  # noqa: F401

target_metadata = Base.metadata

# Build a sync database URL from the environment.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://gateway:changeme@db:5432/ai_gateway",
)
SYNC_URL = DATABASE_URL.replace("+asyncpg", "")


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    context.configure(
        url=SYNC_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = SYNC_URL
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
