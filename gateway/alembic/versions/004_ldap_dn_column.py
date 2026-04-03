"""Add ldap_dn column to api_keys for LDAP/AD integration.

Revision ID: 004
Revises: 003
Create Date: 2026-04-03
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = [col["name"] for col in sa.inspect(bind).get_columns("api_keys")]

    if "ldap_dn" not in columns:
        op.add_column("api_keys", sa.Column("ldap_dn", sa.String(512), index=True))


def downgrade() -> None:
    op.drop_column("api_keys", "ldap_dn")
