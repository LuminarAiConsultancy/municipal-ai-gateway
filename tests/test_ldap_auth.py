"""Tests for LDAP/AD authentication and auto-provisioning.

Uses mocked LDAP connections to test without a real AD server.
"""

import os
import sys

# Ensure gateway is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from sqlalchemy.orm import Session

from auth import ApiKey, hash_key
from ldap_auth import ldap_authenticate, is_ldap_enabled


# ── Configuration tests ──────────────────────────────────────────────────────


class TestLdapConfiguration:
    def test_ldap_disabled_by_default(self):
        """LDAP is disabled when env vars are not set."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove LDAP vars if they exist
            for key in ["LDAP_ENABLED", "LDAP_SERVER", "LDAP_BASE_DN"]:
                os.environ.pop(key, None)
            # Re-import to pick up new env
            import importlib
            import ldap_auth
            importlib.reload(ldap_auth)
            assert not ldap_auth.is_ldap_enabled()

    def test_ldap_enabled_with_config(self):
        """LDAP is enabled when all required vars are set."""
        env = {
            "LDAP_ENABLED": "true",
            "LDAP_SERVER": "ldap.example.com",
            "LDAP_BASE_DN": "dc=example,dc=com",
        }
        with patch.dict(os.environ, env):
            import importlib
            import ldap_auth
            importlib.reload(ldap_auth)
            assert ldap_auth.is_ldap_enabled()


# ── LDAP authentication tests ───────────────────────────────────────────────


class TestLdapAuthenticate:
    """Test ldap_authenticate with mocked ldap3 connections."""

    def _setup_ldap_env(self):
        """Set LDAP environment variables for testing."""
        return {
            "LDAP_ENABLED": "true",
            "LDAP_SERVER": "ldap.example.com",
            "LDAP_PORT": "389",
            "LDAP_BASE_DN": "dc=example,dc=com",
            "LDAP_BIND_DN": "cn=service,dc=example,dc=com",
            "LDAP_BIND_PASSWORD": "service-password",
            "LDAP_USER_FILTER": "(sAMAccountName={username})",
            "LDAP_STARTTLS": "false",
            "LDAP_USE_SSL": "false",
        }

    def _mock_ldap_entry(self, dn, department="Planning", display_name="Jane Smith"):
        """Create a mock LDAP entry."""
        entry = MagicMock()
        entry.entry_dn = dn
        type(entry).department = PropertyMock(return_value=department)
        type(entry).displayName = PropertyMock(return_value=display_name)
        type(entry).cn = PropertyMock(return_value=display_name)
        return entry

    def _create_mock_ldap3(self):
        """Create a mock ldap3 module."""
        mock_module = MagicMock()
        mock_module.ALL = "ALL"
        mock_module.SUBTREE = "SUBTREE"
        mock_module.utils.conv.escape_filter_chars = lambda s: s
        return mock_module

    def test_successful_authentication(self):
        """Successful LDAP auth returns user info dict."""
        env = self._setup_ldap_env()
        mock_ldap3 = self._create_mock_ldap3()

        with patch.dict(os.environ, env), \
             patch.dict("sys.modules", {"ldap3": mock_ldap3, "ldap3.utils": mock_ldap3.utils, "ldap3.utils.conv": mock_ldap3.utils.conv}):
            import importlib
            import ldap_auth
            importlib.reload(ldap_auth)

            # Mock the service account connection
            mock_service_conn = MagicMock()
            mock_service_conn.bind.return_value = True
            mock_service_conn.entries = [
                self._mock_ldap_entry("cn=jsmith,ou=users,dc=example,dc=com")
            ]

            # Mock the user connection
            mock_user_conn = MagicMock()
            mock_user_conn.bind.return_value = True

            mock_ldap3.Connection.side_effect = [mock_service_conn, mock_user_conn]
            mock_ldap3.Server.return_value = MagicMock()

            result = ldap_auth.ldap_authenticate("jsmith", "password123")

            assert result is not None
            assert result["username"] == "jsmith"
            assert result["dn"] == "cn=jsmith,ou=users,dc=example,dc=com"
            assert result["department"] == "Planning"

    def test_wrong_password_returns_none(self):
        """Wrong password returns None."""
        env = self._setup_ldap_env()
        mock_ldap3 = self._create_mock_ldap3()

        with patch.dict(os.environ, env), \
             patch.dict("sys.modules", {"ldap3": mock_ldap3, "ldap3.utils": mock_ldap3.utils, "ldap3.utils.conv": mock_ldap3.utils.conv}):
            import importlib
            import ldap_auth
            importlib.reload(ldap_auth)

            # Service account binds OK
            mock_service_conn = MagicMock()
            mock_service_conn.bind.return_value = True
            mock_service_conn.entries = [
                self._mock_ldap_entry("cn=jsmith,ou=users,dc=example,dc=com")
            ]

            # User bind fails
            mock_user_conn = MagicMock()
            mock_user_conn.bind.return_value = False

            mock_ldap3.Connection.side_effect = [mock_service_conn, mock_user_conn]
            mock_ldap3.Server.return_value = MagicMock()

            result = ldap_auth.ldap_authenticate("jsmith", "wrong-password")
            assert result is None

    def test_user_not_found_returns_none(self):
        """Non-existent user returns None."""
        env = self._setup_ldap_env()
        mock_ldap3 = self._create_mock_ldap3()

        with patch.dict(os.environ, env), \
             patch.dict("sys.modules", {"ldap3": mock_ldap3, "ldap3.utils": mock_ldap3.utils, "ldap3.utils.conv": mock_ldap3.utils.conv}):
            import importlib
            import ldap_auth
            importlib.reload(ldap_auth)

            # Service account binds OK but no entries found
            mock_service_conn = MagicMock()
            mock_service_conn.bind.return_value = True
            mock_service_conn.entries = []

            mock_ldap3.Connection.side_effect = [mock_service_conn]
            mock_ldap3.Server.return_value = MagicMock()

            result = ldap_auth.ldap_authenticate("nobody", "password")
            assert result is None

    def test_ldap_disabled_returns_none(self):
        """Returns None when LDAP is not enabled."""
        with patch.dict(os.environ, {"LDAP_ENABLED": "false"}):
            import importlib
            import ldap_auth
            importlib.reload(ldap_auth)
            result = ldap_auth.ldap_authenticate("jsmith", "password")
            assert result is None


# ── Auto-provisioning tests ──────────────────────────────────────────────────


class TestLdapAutoProvisioning:
    """Test that LDAP auth auto-provisions API keys."""

    def test_ldap_endpoint_disabled(self, test_client):
        """POST /auth/ldap returns 404 when LDAP is disabled."""
        resp = test_client.post("/auth/ldap", json={
            "username": "jsmith",
            "password": "password",
        })
        assert resp.status_code == 404
        assert "not enabled" in resp.json()["detail"]

    @patch("main.ldap_authenticate_and_provision")
    @patch("main.is_ldap_enabled", return_value=True)
    def test_ldap_endpoint_success(self, mock_enabled, mock_provision, test_client):
        """Successful LDAP login returns an API key."""
        mock_provision.return_value = {
            "key": "abc123",
            "department": "Planning",
            "description": "Jane Smith (LDAP: jsmith)",
            "provisioned": True,
        }

        resp = test_client.post("/auth/ldap", json={
            "username": "jsmith",
            "password": "password",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "abc123"
        assert data["department"] == "Planning"
        assert data["provisioned"] is True

    @patch("main.ldap_authenticate_and_provision")
    @patch("main.is_ldap_enabled", return_value=True)
    def test_ldap_endpoint_auth_failure(self, mock_enabled, mock_provision, test_client):
        """Failed LDAP auth returns 401."""
        mock_provision.return_value = None

        resp = test_client.post("/auth/ldap", json={
            "username": "jsmith",
            "password": "wrong",
        })
        assert resp.status_code == 401

    def test_ldap_dn_column_exists(self, db_engine):
        """The api_keys table has the ldap_dn column."""
        from sqlalchemy import inspect
        from models import Base
        Base.metadata.create_all(db_engine)
        columns = [col["name"] for col in inspect(db_engine).get_columns("api_keys")]
        assert "ldap_dn" in columns

    def test_api_key_with_ldap_dn(self, db_engine):
        """An API key can be created with an ldap_dn value."""
        from models import Base
        Base.metadata.create_all(db_engine)

        with Session(db_engine) as session:
            key = ApiKey(
                key="test-key-123",
                key_hash=hash_key("test-key-123"),
                key_prefix="test-key",
                department="Planning",
                description="Jane Smith (LDAP)",
                ldap_dn="cn=jsmith,ou=users,dc=example,dc=com",
                active=True,
            )
            session.add(key)
            session.commit()

        with Session(db_engine) as session:
            stored = session.query(ApiKey).filter(
                ApiKey.ldap_dn == "cn=jsmith,ou=users,dc=example,dc=com"
            ).first()
            assert stored is not None
            assert stored.department == "Planning"
            assert stored.ldap_dn == "cn=jsmith,ou=users,dc=example,dc=com"
