# Changelog

All notable changes to the Municipal AI Gateway are documented in this file.

## [1.1.0] - 2026-04-03

### Security
- **Per-admin accounts with TOTP MFA**: Replaced single shared `GATEWAY_SECRET` with individual admin accounts (email, bcrypt password, optional TOTP). Login flow: email + password → TOTP code → 8-hour JWT session. RFC 6238 TOTP compatible with Google Authenticator / Authy. Sessions stored in Redis for server-side revocation. Legacy `GATEWAY_SECRET` auth remains supported for backward compatibility.
- **Admin bootstrap**: Initial admin account auto-created from `ADMIN_EMAIL` and `ADMIN_PASSWORD` env vars on first startup.

### Added
- **Redis-backed rate limiting**: Sliding window rate limiter using Redis sorted sets (`gateway/redis_client.py`, `gateway/policies.py`). Rate limits survive gateway restarts and work across multiple gateway instances. Falls back to in-memory limiting when Redis is unavailable. Configurable via `RATE_LIMIT_REDIS_URL` and `RATE_LIMIT_REQUESTS_PER_MINUTE` env vars. Redis added to `docker-compose.yml` (port 6379, internal only, 128 MB max memory).
- **Admin auth endpoints**: `POST /admin/login`, `POST /admin/totp/setup`, `POST /admin/totp/verify`, `POST /admin/logout`, `POST /admin/admins`, `GET /admin/admins`.
- **LDAP / Active Directory integration**: Optional LDAP authentication (`LDAP_ENABLED=true`). Staff authenticate with AD credentials via `POST /auth/ldap` and receive an auto-provisioned gateway API key. Supports simple bind and STARTTLS. Configurable via `LDAP_SERVER`, `LDAP_PORT`, `LDAP_BASE_DN`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`, `LDAP_USER_FILTER`, `LDAP_DEPT_ATTRIBUTE`.
- **Redis health check**: `/health` endpoint now reports Redis status (`ok`, `degraded`, or `not_configured`). Redis is optional — degraded Redis does not affect overall gateway health.
- **Alembic migration 003**: Creates `admin_users` table for per-admin accounts.
- **Alembic migration 004**: Adds `ldap_dn` column to `api_keys` table for LDAP user mapping.

### Changed
- All admin endpoints (`/admin/*`) now accept JWT session tokens in addition to legacy `GATEWAY_SECRET`.
- `docker-compose.yml` adds Redis 7 Alpine service with health check.
- `.env.example` updated with Redis, admin account, and LDAP configuration.

### Dependencies Added
- `redis[hiredis]` — Redis client for rate limiting and session storage
- `bcrypt` — Password hashing for admin accounts
- `PyJWT` — JWT session tokens
- `pyotp` — TOTP generation and verification
- `qrcode[pil]` — QR code generation for TOTP enrollment
- `ldap3` — LDAP/AD authentication
- `fakeredis[lua]` (test only) — Redis mock for testing

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
