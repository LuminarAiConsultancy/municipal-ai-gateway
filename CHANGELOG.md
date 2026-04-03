# Changelog

All notable changes to the Municipal AI Gateway are documented in this file.

## [0.1.0] - 2026-04-03

### Security
- **API key hashing**: Keys are now stored as SHA-256 hashes. Plaintext keys are returned once on creation and never stored. Migration script provided for existing keys (`scripts/migrate_key_hashes.py`).
- **CORS lockdown**: Replaced wildcard origin with configurable `CORS_ORIGINS` env var (default: `http://localhost:8080,https://localhost`). Added `X-Gateway-Key` to allowed headers.
- **Input validation**: Pydantic schemas validate all admin endpoint payloads, returning 422 on invalid input.
- **Graceful scrubber failure**: Configurable `SCRUBBER_FAILURE_MODE` (default: `fail_closed` returns 503; `fail_open` forwards without scrubbing).

### Fixed
- **Rate limiter race condition**: Replaced single shared limiter with per-department instances. Requests are now checked BEFORE being recorded, so rejected requests don't count toward the limit.
- **Audit verify memory**: Verification now streams rows one at a time (O(1) memory) instead of loading the entire table.
- **Async database layer**: All database operations converted from synchronous to async using SQLAlchemy's asyncpg driver. Eliminates thread-blocking on database calls.

### Added
- **SSE streaming**: Requests with `"stream": true` are handled via `httpx` async streaming. PII is scrubbed from each SSE chunk. Logging occurs via `BackgroundTask` after the stream completes.
- **Structured logging**: JSON-formatted logs via `structlog` with correlation IDs for request tracing. Configurable via `LOG_FORMAT` (json/console) and `LOG_LEVEL`.
- **Enhanced health check**: `/health` now checks database connectivity and scrubber availability, returning 200 with `{"status": "ok"}` or 503 with `{"status": "degraded"}`.
- **Paginated request log**: `/admin/requests` supports `page`, `per_page`, `department`, and `provider` query params. Returns `{items, total, page, per_page, pages}`.
- **Audit log export**: `GET /admin/requests/export?format=csv|json&department=X` streams audit entries as a downloadable file.
- **French PII detection**: Optional bilingual support via `ENABLE_FRENCH_NLP=true`. Loads `fr_core_news_lg` spacy model and merges French NLP detections with English results.
- **Alert framework**: Optional webhook (`ALERT_WEBHOOK_URL`) and email (`ALERT_EMAIL`) alerts for PII spikes, budget warnings, and audit chain failures.
- **Token estimation fallback**: When providers don't return usage data, falls back to word-count estimation (`word_count * 1.3`).
- **Docker log rotation**: All services configured with `json-file` driver, 50 MB max size, 5 files retained.
- **Package structure**: Added `gateway/__init__.py` and `tests/__init__.py` for proper Python package structure.
- **Database module**: New `gateway/database.py` with async engine factory and session management.
- **Alembic migration 002**: Adds `key_hash` and `key_prefix` columns to `api_keys` table.

### Changed
- `DATABASE_URL` now uses `+asyncpg` driver by default.
- `.env.production.example` updated with all new env vars and pre-deployment checklist.
- `.env.example` updated with CORS, logging, scrubber, French NLP, and alert configuration.
