"""Add key_hash and key_prefix columns to api_keys.

Revision ID: 002
Revises: 001
Create Date: 2026-04-03
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = [col["name"] for col in sa.inspect(bind).get_columns("api_keys")]

    if "key_hash" not in columns:
        op.add_column("api_keys", sa.Column("key_hash", sa.String(64), unique=True, index=True))

    if "key_prefix" not in columns:
        op.add_column("api_keys", sa.Column("key_prefix", sa.String(8)))

    # Make key column nullable (existing plaintext keys remain until migrated).
    # SQLite doesn't support ALTER COLUMN, so this is a no-op there.
    try:
        op.alter_column("api_keys", "key", nullable=True)
    except Exception:
        pass  # SQLite — column is already effectively nullable


def downgrade() -> None:
    op.drop_column("api_keys", "key_prefix")
    op.drop_column("api_keys", "key_hash")
