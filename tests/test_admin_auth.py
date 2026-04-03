"""Tests for per-admin accounts with TOTP MFA.

Tests cover:
  - Password hashing and verification
  - TOTP generation and verification
  - JWT temp token and session token lifecycle
  - Login flow (email + password → temp token → TOTP → session)
  - Legacy GATEWAY_SECRET backward compatibility
  - Admin bootstrap from env vars
  - Admin CRUD endpoints
  - Session revocation (logout)
"""

import os
import sys

# Ensure gateway is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import pytest
import pyotp
from fastapi import HTTPException

from admin_auth import (
    hash_password,
    verify_password,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    create_temp_token,
    create_session_token,
    decode_token,
    AdminUser,
)


def _create_admin(db_engine, email, password):
    """Helper: insert an AdminUser row into the test database."""
    from sqlalchemy.orm import Session
    from models import Base
    Base.metadata.create_all(db_engine)
    with Session(db_engine) as session:
        existing = session.query(AdminUser).filter(AdminUser.email == email).first()
        if not existing:
            session.add(AdminUser(
                email=email,
                password_hash=hash_password(password),
                is_active=True,
            ))
            session.commit()


# ── Password hashing ────────────────────────────────────────────────────────


class TestPasswordHashing:
    def test_hash_and_verify(self):
        """Correct password verifies against its hash."""
        pw = "correct-horse-battery-staple"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_wrong_password_fails(self):
        """Wrong password does not verify."""
        hashed = hash_password("correct-password")
        assert not verify_password("wrong-password", hashed)

    def test_hash_is_different_each_time(self):
        """bcrypt generates a unique salt each time."""
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2


# ── TOTP ─────────────────────────────────────────────────────────────────────


class TestTotp:
    def test_generate_secret_format(self):
        """TOTP secret is a valid Base32 string."""
        secret = generate_totp_secret()
        assert len(secret) >= 16
        # Should be valid Base32
        pyotp.TOTP(secret)  # Should not raise

    def test_provisioning_uri_contains_issuer(self):
        """Provisioning URI includes the issuer name."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "admin@example.com")
        assert "Municipal+AI+Gateway" in uri or "Municipal%20AI%20Gateway" in uri
        assert "admin%40example.com" in uri or "admin@example.com" in uri

    def test_valid_code_verifies(self):
        """A current TOTP code verifies correctly."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert verify_totp(secret, code)

    def test_wrong_code_fails(self):
        """An incorrect TOTP code fails verification."""
        secret = generate_totp_secret()
        assert not verify_totp(secret, "000000")


# ── JWT tokens ───────────────────────────────────────────────────────────────


class TestJwtTokens:
    def test_temp_token_roundtrip(self):
        """Temp token can be created and decoded."""
        token = create_temp_token(admin_id=1, email="admin@example.com")
        payload = decode_token(token, expected_type="temp")
        assert payload["sub"] == 1
        assert payload["email"] == "admin@example.com"
        assert payload["type"] == "temp"

    def test_session_token_roundtrip(self):
        """Session token can be created and decoded."""
        token, session_id = create_session_token(admin_id=1, email="admin@example.com")
        payload = decode_token(token, expected_type="session")
        assert payload["sub"] == 1
        assert payload["email"] == "admin@example.com"
        assert payload["type"] == "session"
        assert payload["jti"] == session_id

    def test_wrong_type_rejected(self):
        """Decoding a temp token as session type raises."""
        import jwt as pyjwt
        token = create_temp_token(admin_id=1, email="admin@example.com")
        with pytest.raises(pyjwt.InvalidTokenError):
            decode_token(token, expected_type="session")

    def test_session_id_unique(self):
        """Each session token gets a unique session ID."""
        _, sid1 = create_session_token(admin_id=1, email="admin@example.com")
        _, sid2 = create_session_token(admin_id=1, email="admin@example.com")
        assert sid1 != sid2


# ── Integration tests via TestClient ─────────────────────────────────────────


class TestAdminLoginFlow:
    """Test the full login flow through the FastAPI endpoints."""

    def test_login_with_valid_credentials(self, test_client, db_engine):
        """Valid email + password returns a temp token or session token."""
        _create_admin(db_engine, "admin@test.com", "securepassword123")

        resp = test_client.post("/admin/login", json={
            "email": "admin@test.com",
            "password": "securepassword123",
        })
        assert resp.status_code == 200
        data = resp.json()
        # No TOTP enrolled — should return session directly
        assert data["requires_totp"] is False
        assert "token" in data

    def test_login_with_wrong_password(self, test_client, db_engine):
        """Wrong password returns 401."""
        _create_admin(db_engine, "admin2@test.com", "correctpassword")

        resp = test_client.post("/admin/login", json={
            "email": "admin2@test.com",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401

    def test_login_with_nonexistent_email(self, test_client):
        """Nonexistent email returns 401."""
        resp = test_client.post("/admin/login", json={
            "email": "nobody@test.com",
            "password": "anything",
        })
        assert resp.status_code == 401

    def test_session_token_grants_admin_access(self, test_client, db_engine):
        """A session token from login allows access to admin endpoints."""
        _create_admin(db_engine, "admin3@test.com", "password123456")

        # Login
        resp = test_client.post("/admin/login", json={
            "email": "admin3@test.com",
            "password": "password123456",
        })
        token = resp.json()["token"]

        # Use the token to access an admin endpoint
        resp = test_client.get("/admin/keys", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200

    def test_legacy_gateway_secret_still_works(self, test_client, admin_headers):
        """The legacy GATEWAY_SECRET auth still works for backward compatibility."""
        resp = test_client.get("/admin/keys", headers=admin_headers)
        assert resp.status_code == 200

    def test_invalid_token_returns_401(self, test_client):
        """An invalid JWT returns 401."""
        resp = test_client.get("/admin/keys", headers={
            "Authorization": "Bearer invalid-token-here",
        })
        assert resp.status_code == 401


class TestTotpEnrollment:
    """Test TOTP setup and verification flow."""

    def _get_admin_id(self, db_engine, email):
        """Get the actual admin ID from the database."""
        from sqlalchemy.orm import Session
        with Session(db_engine) as session:
            admin = session.query(AdminUser).filter(AdminUser.email == email).first()
            return admin.id if admin else None

    def test_totp_setup_returns_secret_and_uri(self, test_client, db_engine):
        """TOTP setup returns a secret and provisioning URI."""
        _create_admin(db_engine, "totp@test.com", "password123456")
        admin_id = self._get_admin_id(db_engine, "totp@test.com")

        # Create a temp token with the actual admin ID
        token = create_temp_token(admin_id=admin_id, email="totp@test.com")

        resp = test_client.post("/admin/totp/setup", json={
            "temp_token": token,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert "uri" in data
        assert "otpauth://" in data["uri"]

    def test_totp_verify_with_valid_code(self, test_client, db_engine):
        """Valid TOTP code after setup returns a session token."""
        _create_admin(db_engine, "totp2@test.com", "password123456")
        admin_id = self._get_admin_id(db_engine, "totp2@test.com")

        # Setup TOTP using a temp token with correct admin ID
        temp_token = create_temp_token(admin_id=admin_id, email="totp2@test.com")

        resp = test_client.post("/admin/totp/setup", json={
            "temp_token": temp_token,
        })
        secret = resp.json()["secret"]

        # Generate a valid code
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # Login again — now TOTP is enrolled, so we get a temp token
        resp = test_client.post("/admin/login", json={
            "email": "totp2@test.com",
            "password": "password123456",
        })
        assert resp.json()["requires_totp"] is True
        temp_token2 = resp.json()["temp_token"]

        # Verify TOTP
        resp = test_client.post("/admin/totp/verify", json={
            "temp_token": temp_token2,
            "code": code,
        })
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_totp_verify_with_wrong_code(self, test_client, db_engine):
        """Wrong TOTP code returns 401."""
        _create_admin(db_engine, "totp3@test.com", "password123456")
        admin_id = self._get_admin_id(db_engine, "totp3@test.com")

        # Setup TOTP
        temp_token = create_temp_token(admin_id=admin_id, email="totp3@test.com")
        test_client.post("/admin/totp/setup", json={"temp_token": temp_token})

        # Login to get temp token
        resp = test_client.post("/admin/login", json={
            "email": "totp3@test.com",
            "password": "password123456",
        })
        temp_token2 = resp.json()["temp_token"]

        # Wrong code
        resp = test_client.post("/admin/totp/verify", json={
            "temp_token": temp_token2,
            "code": "000000",
        })
        assert resp.status_code == 401

class TestAdminCrud:
    """Test admin account management endpoints."""

    def test_create_admin(self, test_client, admin_headers):
        """Creating an admin account returns the new admin info."""
        resp = test_client.post("/admin/admins", headers=admin_headers, json={
            "email": "new-admin@test.com",
            "password": "password123456",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "new-admin@test.com"
        assert data["is_active"] is True

    def test_create_duplicate_admin_returns_409(self, test_client, db_engine, admin_headers):
        """Creating an admin with an existing email returns 409."""
        _create_admin(db_engine, "dupe@test.com", "password123456")

        resp = test_client.post("/admin/admins", headers=admin_headers, json={
            "email": "dupe@test.com",
            "password": "password123456",
        })
        assert resp.status_code == 409

    def test_list_admins(self, test_client, db_engine, admin_headers):
        """Listing admins returns created accounts."""
        _create_admin(db_engine, "listed@test.com", "password123456")

        resp = test_client.get("/admin/admins", headers=admin_headers)
        assert resp.status_code == 200
        emails = [a["email"] for a in resp.json()]
        assert "listed@test.com" in emails


class TestAdminLogout:
    """Test session revocation."""

    def test_logout_succeeds(self, test_client, db_engine):
        """Logout returns success message."""
        _create_admin(db_engine, "logout@test.com", "password123456")

        # Login
        resp = test_client.post("/admin/login", json={
            "email": "logout@test.com",
            "password": "password123456",
        })
        token = resp.json()["token"]

        # Logout
        resp = test_client.post("/admin/logout", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200
        assert "Logged out" in resp.json()["message"]
