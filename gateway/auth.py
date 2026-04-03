"""Staff API key authentication for the Municipal AI Gateway.

Each staff member or department gets an API key. Every proxy request
must include a valid key in the X-Gateway-Key header. Keys are stored
in PostgreSQL alongside the audit trail.
"""

from __future__ import annotations

import hashlib
import secrets
import datetime as dt

from sqlalchemy import Column, Integer, String, DateTime, Boolean, select, or_
from sqlalchemy.orm import Session
from fastapi import Request, HTTPException

from models import Base


def hash_key(raw_key: str) -> str:
    """Return SHA-256 hex digest of a raw API key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(64), unique=True, nullable=True, index=True)
    key_hash = Column(String(64), unique=True, nullable=True, index=True)
    key_prefix = Column(String(8), nullable=True)
    department = Column(String(128), nullable=False)
    description = Column(String(256))
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc))
    last_used_at = Column(DateTime(timezone=True))


def generate_key() -> str:
    """Generate a cryptographically secure 32-byte hex API key."""
    return secrets.token_hex(32)


async def authenticate(request: Request, session_factory) -> ApiKey:
    """Validate the X-Gateway-Key header and return the matching ApiKey row.

    Looks up by key_hash first, falls back to plaintext key for un-migrated keys.
    Raises HTTPException 401 if missing, invalid, or inactive.
    Updates last_used_at on success.
    """
    key_value = request.headers.get("x-gateway-key")
    if not key_value:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Gateway-Key header.",
        )

    hashed = hash_key(key_value)

    async with session_factory() as session:
        # Try hash lookup first, fall back to plaintext for un-migrated keys
        result = await session.execute(
            select(ApiKey).filter(
                or_(ApiKey.key_hash == hashed, ApiKey.key == key_value)
            )
        )
        api_key = result.scalars().first()

        if api_key is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")

        if not api_key.active:
            raise HTTPException(status_code=401, detail="API key is deactivated.")

        api_key.last_used_at = dt.datetime.now(dt.timezone.utc)
        await session.commit()

        # Detach useful fields before session closes.
        return _detach(api_key)


def authenticate_sync(request: Request, engine) -> ApiKey:
    """Synchronous version of authenticate for use with sync engines (tests)."""
    key_value = request.headers.get("x-gateway-key")
    if not key_value:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Gateway-Key header.",
        )

    hashed = hash_key(key_value)

    with Session(engine) as session:
        api_key = (
            session.query(ApiKey)
            .filter(or_(ApiKey.key_hash == hashed, ApiKey.key == key_value))
            .first()
        )

        if api_key is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")

        if not api_key.active:
            raise HTTPException(status_code=401, detail="API key is deactivated.")

        api_key.last_used_at = dt.datetime.now(dt.timezone.utc)
        session.commit()

        return _detach(api_key)


def _detach(api_key: ApiKey) -> ApiKey:
    """Copy fields so the object is usable outside the session."""
    detached = ApiKey(
        id=api_key.id,
        key=api_key.key,
        key_hash=api_key.key_hash,
        key_prefix=api_key.key_prefix,
        department=api_key.department,
        description=api_key.description,
        active=api_key.active,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
    )
    return detached
