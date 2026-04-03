"""Per-admin accounts with TOTP MFA for the Canadian Municipal AI Gateway.

Replaces the single shared GATEWAY_SECRET with individual admin accounts.
Each admin has: email, bcrypt password, optional TOTP secret.

Login flow:
  1. POST /admin/login  →  email + password  →  temp_token (short-lived)
  2. POST /admin/totp/verify  →  temp_token + TOTP code  →  session JWT (8h)
  3. All /admin/* routes require valid session JWT

TOTP enrollment:
  - POST /admin/totp/setup  →  temp_token  →  QR code URI + secret
  - Admin scans QR in Google Authenticator / Authy
  - POST /admin/totp/verify  →  confirms enrollment + returns session

Sessions are stored in Redis when available for server-side revocation.
Falls back to stateless JWT validation when Redis is unavailable.

Bootstrap: On first startup, if ADMIN_EMAIL and ADMIN_PASSWORD are set,
creates the initial admin account.
"""

from __future__ import annotations

import os
import datetime as dt
import secrets

import bcrypt
import jwt
import pyotp
from sqlalchemy import Column, Integer, String, DateTime, Boolean, select

from models import Base
from logging_config import get_logger

logger = get_logger("admin_auth")

# ── Configuration ────────────────────────────────────────────────────────────

JWT_SECRET = os.getenv("GATEWAY_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_SESSION_HOURS = 8
JWT_TEMP_MINUTES = 10  # Temp token for login flow

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")


def validate_jwt_secret() -> None:
    """Validate JWT secret meets minimum security requirements.

    Called during application startup. Refuses to start if GATEWAY_SECRET
    is missing or too short for HS256 signing.
    """
    if not JWT_SECRET:
        raise SystemExit(
            "FATAL: GATEWAY_SECRET is not set. "
            "Generate one with: openssl rand -hex 32"
        )
    if len(JWT_SECRET) < 32:
        raise SystemExit(
            f"FATAL: GATEWAY_SECRET is only {len(JWT_SECRET)} characters. "
            "Minimum 32 characters required for secure JWT signing. "
            "Generate one with: openssl rand -hex 32"
        )

# Redis key prefix for admin sessions
SESSION_PREFIX = "admin_session:"


# ── Database model ───────────────────────────────────────────────────────────


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(256), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    totp_secret = Column(String(64))  # Base32-encoded TOTP secret
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    last_login_at = Column(DateTime(timezone=True))


# ── Password utilities ───────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


# ── TOTP utilities ───────────────────────────────────────────────────────────


def generate_totp_secret() -> str:
    """Generate a new TOTP secret (Base32-encoded)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """Generate a provisioning URI for QR code scanning."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="Canadian Municipal AI Gateway")


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret. Allows ±1 time step for clock drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ── JWT utilities ────────────────────────────────────────────────────────────


def create_temp_token(admin_id: int, email: str) -> str:
    """Create a short-lived temp token for the login flow (pre-TOTP)."""
    payload = {
        "sub": str(admin_id),
        "email": email,
        "type": "temp",
        "exp": dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=JWT_TEMP_MINUTES),
        "iat": dt.datetime.now(dt.timezone.utc),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_session_token(admin_id: int, email: str) -> tuple[str, str]:
    """Create a session JWT (8h). Returns (token, session_id)."""
    session_id = secrets.token_hex(16)
    payload = {
        "sub": str(admin_id),
        "email": email,
        "type": "session",
        "exp": dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=JWT_SESSION_HOURS),
        "iat": dt.datetime.now(dt.timezone.utc),
        "jti": session_id,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, session_id


def decode_token(token: str, expected_type: str = "session") -> dict:
    """Decode and validate a JWT. Returns the payload dict.

    Raises jwt.InvalidTokenError on any validation failure.
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("type") != expected_type:
        raise jwt.InvalidTokenError(f"Expected token type '{expected_type}', got '{payload.get('type')}'")
    # Convert sub back to int for convenience
    if "sub" in payload:
        try:
            payload["sub"] = int(payload["sub"])
        except (ValueError, TypeError):
            pass
    return payload


# ── Session management ───────────────────────────────────────────────────────


async def store_session(redis_client, session_id: str, admin_id: int, email: str) -> None:
    """Store a session in Redis for server-side validation/revocation."""
    if redis_client is None:
        return  # Stateless mode — JWT-only validation
    key = f"{SESSION_PREFIX}{session_id}"
    await redis_client.setex(
        key,
        JWT_SESSION_HOURS * 3600,
        f"{admin_id}:{email}",
    )


async def validate_session(redis_client, session_id: str) -> bool:
    """Check if a session exists in Redis. Returns True if valid or if Redis unavailable."""
    if redis_client is None:
        return True  # Stateless fallback — trust the JWT signature + expiry
    try:
        key = f"{SESSION_PREFIX}{session_id}"
        return await redis_client.exists(key) > 0
    except Exception:
        return True  # Redis down — fall back to trusting the JWT


async def revoke_session(redis_client, session_id: str) -> None:
    """Remove a session from Redis."""
    if redis_client is None:
        return
    try:
        key = f"{SESSION_PREFIX}{session_id}"
        await redis_client.delete(key)
    except Exception:
        pass


# ── Bootstrap ────────────────────────────────────────────────────────────────


async def bootstrap_admin(session_factory) -> None:
    """Create the initial admin account from ADMIN_EMAIL and ADMIN_PASSWORD env vars.

    Only creates the account if:
      - Both env vars are set
      - No admin with that email exists yet
    """
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        logger.info("admin_bootstrap_skipped", reason="ADMIN_EMAIL or ADMIN_PASSWORD not set")
        return

    async with session_factory() as session:
        result = await session.execute(
            select(AdminUser).filter(AdminUser.email == ADMIN_EMAIL)
        )
        existing = result.scalars().first()
        if existing:
            logger.info("admin_bootstrap_exists", email=ADMIN_EMAIL)
            return

        admin = AdminUser(
            email=ADMIN_EMAIL,
            password_hash=hash_password(ADMIN_PASSWORD),
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        logger.info("admin_bootstrap_created", email=ADMIN_EMAIL)


# ── Request authentication ───────────────────────────────────────────────────


async def require_admin_session(request, redis_client=None) -> dict:
    """Validate the admin session from the Authorization header.

    Supports two auth modes:
      1. JWT session token (new): Authorization: Bearer <jwt>
      2. Legacy shared secret (backward compat): Authorization: Bearer <GATEWAY_SECRET>

    Returns the decoded JWT payload or a synthetic payload for legacy auth.
    Raises HTTPException 401 on failure.
    """
    from fastapi import HTTPException

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Admin authentication required.")

    token = auth_header[7:]

    # Legacy mode: check if the token matches GATEWAY_SECRET
    if token == JWT_SECRET and JWT_SECRET:
        return {"sub": 0, "email": "legacy", "type": "session", "jti": "legacy"}

    # JWT session mode
    try:
        payload = decode_token(token, expected_type="session")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")

    # Server-side session validation
    session_id = payload.get("jti")
    if session_id and not await validate_session(redis_client, session_id):
        raise HTTPException(status_code=401, detail="Session has been revoked.")

    return payload
