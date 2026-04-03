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


# ── Admin auth schemas ───────────────────────────────────────────────────────


class AdminLoginRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=1)


class AdminTotpVerifyRequest(BaseModel):
    temp_token: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=6)


class AdminTotpSetupRequest(BaseModel):
    temp_token: str = Field(..., min_length=1)


class AdminCreateRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=8)
    is_active: bool = True


# ── LDAP auth schemas ────────────────────────────────────────────────────────


class LdapLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=1)
