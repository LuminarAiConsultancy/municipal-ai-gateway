"""Tests for the SHA-256 hash-chained audit trail.

Chain functions (_compute_chain_hash, _log_request_sync) live in gateway/main.py.
"""

from sqlalchemy.orm import Session

from main import _compute_chain_hash, _log_request_sync, RequestLog


# ── Helpers ──────────────────────────────────────────────────────────────────

ENTRY_DEFAULTS = dict(
    provider="openai",
    method="POST",
    path="v1/chat/completions",
    request_hash="abc123",
    response_status=200,
    response_hash="def456",
    source_ip="127.0.0.1",
    duration_ms=100,
    pii_detections_request=0,
    pii_detections_response=0,
    pii_types_found=None,
)

LOG_DEFAULTS = dict(
    provider="openai",
    method="POST",
    request_body=b'{"test": true}',
    response_status=200,
    response_body=b'{"ok": true}',
    source_ip="10.0.0.1",
    duration_ms=50,
)


def _insert_entries(db_engine, count=3):
    """Insert *count* valid chain entries via _log_request_sync."""
    for i in range(count):
        _log_request_sync(
            db_engine,
            path=f"v1/test/{i}",
            request_body=f'{{"n": {i}}}'.encode(),
            **{k: v for k, v in LOG_DEFAULTS.items() if k not in ("path", "request_body")},
        )


# ── Unit tests for _compute_chain_hash ───────────────────────────────────────


class TestChainHashComputation:
    def test_single_entry_uses_genesis(self):
        """First entry uses 'GENESIS' when previous_hash is None."""
        h = _compute_chain_hash(previous_hash=None, **ENTRY_DEFAULTS)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest

    def test_two_entries_chain_links(self, db_engine):
        """Second entry's previous_hash equals first entry's chain_hash."""
        _log_request_sync(db_engine, path="v1/first", **{
            k: v for k, v in LOG_DEFAULTS.items() if k != "path"
        })
        _log_request_sync(db_engine, path="v1/second", **{
            k: v for k, v in LOG_DEFAULTS.items() if k != "path"
        })

        with Session(db_engine) as session:
            logs = session.query(RequestLog).order_by(RequestLog.id.asc()).all()

        assert len(logs) == 2
        assert logs[0].previous_hash is None
        assert logs[1].previous_hash == logs[0].chain_hash

    def test_chain_hash_deterministic(self):
        """Same inputs always produce the same hash."""
        h1 = _compute_chain_hash(previous_hash=None, **ENTRY_DEFAULTS)
        h2 = _compute_chain_hash(previous_hash=None, **ENTRY_DEFAULTS)
        assert h1 == h2

    def test_chain_hash_changes_with_input(self):
        """Changing any field produces a different hash."""
        h1 = _compute_chain_hash(previous_hash=None, **ENTRY_DEFAULTS)
        modified = {**ENTRY_DEFAULTS, "duration_ms": 999}
        h2 = _compute_chain_hash(previous_hash=None, **modified)
        assert h1 != h2


# ── Integration tests via /audit/verify ──────────────────────────────────────


class TestChainVerification:
    def test_valid_chain_ok(self, test_client, db_engine):
        """Valid 3-entry chain verifies as ok."""
        _insert_entries(db_engine, 3)
        r = test_client.get("/audit/verify")
        data = r.json()
        assert data["status"] == "ok"
        assert data["entries_checked"] == 3

    def test_tampered_chain_hash_detected(self, test_client, db_engine):
        """Tampering with an entry's chain_hash is detected."""
        _insert_entries(db_engine, 3)

        with Session(db_engine) as session:
            entry = session.query(RequestLog).order_by(RequestLog.id).offset(1).first()
            entry.chain_hash = "0" * 64
            session.commit()

        r = test_client.get("/audit/verify")
        data = r.json()
        assert data["status"] == "tampered"

    def test_tampered_previous_hash_detected(self, test_client, db_engine):
        """Tampering with an entry's previous_hash is detected."""
        _insert_entries(db_engine, 3)

        with Session(db_engine) as session:
            entry = session.query(RequestLog).order_by(RequestLog.id).offset(1).first()
            entry.previous_hash = "f" * 64
            session.commit()

        r = test_client.get("/audit/verify")
        data = r.json()
        assert data["status"] == "tampered"

    def test_empty_chain_ok(self, test_client):
        """Empty chain (no audit entries) returns ok."""
        r = test_client.get("/audit/verify")
        data = r.json()
        assert data["status"] == "ok"
        assert data["entries_checked"] == 0
