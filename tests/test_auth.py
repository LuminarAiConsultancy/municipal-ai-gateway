"""Tests for staff API key authentication (gateway/auth.py).

Uses the FastAPI TestClient to exercise authentication through the proxy
endpoint. Upstream provider calls are mocked with respx so no real API
calls are made.
"""

import respx
from httpx import Response
from sqlalchemy.orm import Session

from auth import ApiKey, generate_key


# ── Mock helpers ─────────────────────────────────────────────────────────────

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
MOCK_UPSTREAM = Response(200, json={"choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 3}})

PROXY_PATH = "/v1/openai/v1/chat/completions"
PROXY_BODY = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}]}


# ── Tests ────────────────────────────────────────────────────────────────────


class TestProxyAuthentication:
    @respx.mock
    def test_valid_key_authenticates(self, test_client, valid_api_key):
        """Valid API key in X-Gateway-Key header returns non-401."""
        respx.post(OPENAI_URL).mock(return_value=MOCK_UPSTREAM)
        r = test_client.post(
            PROXY_PATH,
            headers={"X-Gateway-Key": valid_api_key, "Content-Type": "application/json"},
            json=PROXY_BODY,
        )
        assert r.status_code != 401

    def test_missing_header_returns_401(self, test_client):
        """Request without X-Gateway-Key returns 401."""
        r = test_client.post(PROXY_PATH, json=PROXY_BODY)
        assert r.status_code == 401
        assert "Missing" in r.json()["detail"]

    def test_wrong_key_returns_401(self, test_client):
        """Invalid API key returns 401."""
        r = test_client.post(
            PROXY_PATH,
            headers={"X-Gateway-Key": "not-a-real-key-at-all"},
            json=PROXY_BODY,
        )
        assert r.status_code == 401
        assert "Invalid" in r.json()["detail"]

    def test_deactivated_key_returns_401(self, test_client, valid_api_key, db_engine):
        """Deactivated API key returns 401."""
        # Deactivate the key in the database.
        with Session(db_engine) as session:
            key_row = session.query(ApiKey).filter(ApiKey.key == valid_api_key).first()
            key_row.active = False
            session.commit()

        r = test_client.post(
            PROXY_PATH,
            headers={"X-Gateway-Key": valid_api_key},
            json=PROXY_BODY,
        )
        assert r.status_code == 401
        assert "deactivated" in r.json()["detail"]

    @respx.mock
    def test_last_used_at_updates(self, test_client, valid_api_key, db_engine):
        """last_used_at timestamp is set after successful authentication."""
        respx.post(OPENAI_URL).mock(return_value=MOCK_UPSTREAM)

        # Before: last_used_at should be None.
        with Session(db_engine) as session:
            before = session.query(ApiKey).filter(ApiKey.key == valid_api_key).first()
            assert before.last_used_at is None

        # Make a proxied request.
        test_client.post(
            PROXY_PATH,
            headers={"X-Gateway-Key": valid_api_key, "Content-Type": "application/json"},
            json=PROXY_BODY,
        )

        # After: last_used_at should be populated.
        with Session(db_engine) as session:
            after = session.query(ApiKey).filter(ApiKey.key == valid_api_key).first()
            assert after.last_used_at is not None


class TestKeyGeneration:
    def test_generate_key_format(self):
        """generate_key() produces a 64-character lowercase hex string."""
        key = generate_key()
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_generate_key_unique(self):
        """Two calls to generate_key() produce different keys."""
        assert generate_key() != generate_key()
