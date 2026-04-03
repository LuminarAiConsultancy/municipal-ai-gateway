"""Create failed_logins table for brute force monitoring.

Revision ID: 005
Revises: 004
Create Date: 2026-04-03
"""

from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "failed_logins",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("source_ip", sa.String(45), nullable=False, index=True),
        sa.Column("email_attempted", sa.String(256), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("failed_logins")
