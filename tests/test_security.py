"""Tests for security features: headers, failed login logging, JWT validation.

Covers:
  - HTTP security headers on all responses
  - Failed login attempts logged to the failed_logins table
  - JWT secret validation on startup
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import pytest
from sqlalchemy.orm import Session

from main import FailedLogin
from admin_auth import validate_jwt_secret


# ── HTTP security headers ───────────────────────────────────────────────────


class TestSecurityHeaders:
    """All responses must include the required security headers."""

    EXPECTED_HEADERS = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=(), microphone=(), camera=()",
    }

    def test_health_endpoint_has_security_headers(self, test_client):
        """GET /health includes all required security headers."""
        resp = test_client.get("/health")
        for header, expected in self.EXPECTED_HEADERS.items():
            actual = resp.headers.get(header)
            assert actual == expected, f"Header {header}: expected {expected!r}, got {actual!r}"

    def test_admin_endpoint_has_security_headers(self, test_client, admin_headers):
        """GET /admin/keys includes all required security headers."""
        resp = test_client.get("/admin/keys", headers=admin_headers)
        for header, expected in self.EXPECTED_HEADERS.items():
            actual = resp.headers.get(header)
            assert actual == expected, f"Header {header}: expected {expected!r}, got {actual!r}"

    def test_404_has_security_headers(self, test_client):
        """Even 404 responses include security headers."""
        resp = test_client.get("/nonexistent-path")
        for header, expected in self.EXPECTED_HEADERS.items():
            actual = resp.headers.get(header)
            assert actual == expected, f"Header {header}: expected {expected!r}, got {actual!r}"


# ── Failed login logging ───────────────────────────────────────────────────


class TestFailedLoginLogging:
    """Failed login attempts are persisted to the failed_logins table."""

    def test_wrong_password_logged(self, test_client, db_engine):
        """A failed login with wrong password creates a failed_logins row."""
        from admin_auth import hash_password, AdminUser
        from models import Base

        Base.metadata.create_all(db_engine)

        # Create admin
        with Session(db_engine) as session:
            session.add(AdminUser(
                email="failtest@test.com",
                password_hash=hash_password("correct-password"),
                is_active=True,
            ))
            session.commit()

        # Attempt with wrong password
        test_client.post("/admin/login", json={
            "email": "failtest@test.com",
            "password": "wrong-password",
        })

        # Check the failed_logins table
        with Session(db_engine) as session:
            failures = session.query(FailedLogin).filter(
                FailedLogin.email_attempted == "failtest@test.com"
            ).all()
            assert len(failures) >= 1
            assert failures[0].reason == "invalid_credentials"
            assert failures[0].source_ip is not None

    def test_nonexistent_email_logged(self, test_client, db_engine):
        """A failed login with nonexistent email creates a failed_logins row."""
        from models import Base
        Base.metadata.create_all(db_engine)

        test_client.post("/admin/login", json={
            "email": "nobody@test.com",
            "password": "anything",
        })

        with Session(db_engine) as session:
            failures = session.query(FailedLogin).filter(
                FailedLogin.email_attempted == "nobody@test.com"
            ).all()
            assert len(failures) >= 1
            assert failures[0].reason == "invalid_credentials"


# ── JWT secret validation ──────────────────────────────────────────────────


class TestJwtSecretValidation:
    """Gateway refuses to start without a valid GATEWAY_SECRET."""

    def test_missing_secret_exits(self, monkeypatch):
        """Empty GATEWAY_SECRET causes SystemExit."""
        import admin_auth
        monkeypatch.setattr(admin_auth, "JWT_SECRET", "")
        with pytest.raises(SystemExit, match="GATEWAY_SECRET is not set"):
            validate_jwt_secret()

    def test_short_secret_exits(self, monkeypatch):
        """Secret under 32 characters causes SystemExit."""
        import admin_auth
        monkeypatch.setattr(admin_auth, "JWT_SECRET", "too-short")
        with pytest.raises(SystemExit, match="only 9 characters"):
            validate_jwt_secret()

    def test_valid_secret_passes(self, monkeypatch):
        """Secret of 32+ characters passes validation."""
        import admin_auth
        monkeypatch.setattr(admin_auth, "JWT_SECRET", "a" * 32)
        validate_jwt_secret()  # Should not raise
