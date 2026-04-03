"""Initial schema: api_keys, request_logs, department_policies.

Revision ID: 001
Revises: None
Create Date: 2026-04-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("key", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("department", sa.String(128), nullable=False),
        sa.Column("description", sa.String(256)),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "request_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime(timezone=True)),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("request_hash", sa.String(64)),
        sa.Column("response_status", sa.Integer()),
        sa.Column("response_hash", sa.String(64)),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("pii_detections_request", sa.Integer(), server_default=sa.text("0")),
        sa.Column("pii_detections_response", sa.Integer(), server_default=sa.text("0")),
        sa.Column("pii_types_found", sa.Text()),
        sa.Column("previous_hash", sa.String(64)),
        sa.Column("chain_hash", sa.String(64)),
        sa.Column("staff_key_id", sa.Integer()),
        sa.Column("department", sa.String(128)),
        sa.Column("model", sa.String(64)),
        sa.Column("input_tokens", sa.Integer(), server_default=sa.text("0")),
        sa.Column("output_tokens", sa.Integer(), server_default=sa.text("0")),
        sa.Column("estimated_cost_cents", sa.Integer(), server_default=sa.text("0")),
    )

    op.create_table(
        "department_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("department", sa.String(128), unique=True, nullable=False, index=True),
        sa.Column("requests_per_minute_per_key", sa.Integer(), server_default=sa.text("60")),
        sa.Column("requests_per_minute_department", sa.Integer(), server_default=sa.text("200")),
        sa.Column("allowed_models", sa.Text()),
        sa.Column("monthly_cost_limit_cents", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("department_policies")
    op.drop_table("request_logs")
    op.drop_table("api_keys")
