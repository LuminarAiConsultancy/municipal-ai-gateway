"""Pydantic request models for input validation."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CreateKeyRequest(BaseModel):
    department: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=256)


class UpsertPolicyRequest(BaseModel):
    department: str = Field(..., min_length=1, max_length=128)
    requests_per_minute_per_key: int | None = Field(None, ge=1)
    requests_per_minute_department: int | None = Field(None, ge=1)
    allowed_models: list[str] | None = None
    monthly_cost_limit_cents: int | None = Field(None, ge=0)
