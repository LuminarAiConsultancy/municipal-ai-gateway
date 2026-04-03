"""Create admin_users table for per-admin accounts with TOTP MFA.

Revision ID: 003
Revises: 002
Create Date: 2026-04-03
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    existing_tables = sa.inspect(bind).get_table_names()

    if "admin_users" not in existing_tables:
        op.create_table(
            "admin_users",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("email", sa.String(256), unique=True, nullable=False, index=True),
            sa.Column("password_hash", sa.String(256), nullable=False),
            sa.Column("totp_secret", sa.String(64)),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(timezone=True)),
            sa.Column("last_login_at", sa.DateTime(timezone=True)),
        )


def downgrade() -> None:
    op.drop_table("admin_users")
