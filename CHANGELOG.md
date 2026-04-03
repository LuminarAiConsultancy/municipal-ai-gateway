# Changelog

All notable changes to municipal-ai-gateway are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com).

## [1.1.0] - 2026-04-03

### Added
- Redis-backed sliding window rate limiting (replaces in-memory limiter)
- Per-administrator accounts replacing single shared secret
- TOTP multi-factor authentication for admin dashboard (RFC 6238, compatible with Google Authenticator and Authy)
- LDAP / Active Directory integration for staff API key auto-provisioning
- Automated TLS via Caddy and Let's Encrypt -- no manual cert rotation
- Daily PostgreSQL backups with 30-day retention and gzip compression
- scripts/backup-now.sh -- on-demand backup
- scripts/restore.sh -- restore from backup file
- scripts/upgrade.sh -- safe upgrade with automatic rollback on health check failure
- Log retention policy -- configurable via LOG_RETENTION_DAYS, default 365 days
- HTTP security headers middleware on all responses
- Admin login brute force protection -- rate limited per IP, failures logged
- Failed login audit table in PostgreSQL
- Database connection pooling with configurable limits
- JWT secret length validation -- gateway refuses to start without a secret of at least 32 characters
- Admin dashboard UI at /admin
- Health check endpoint returning structured status for all services

### Fixed
- JWT signing fallback to empty string removed -- was a critical security issue
- Self-signed certificate replaced with automatic Let's Encrypt
- Unbounded database connections replaced with pooled connections
- Admin login had no rate limiting -- now rate limited per IP
- HTTP security headers were only on nginx responses -- now on all responses via middleware

### Security
- Removed hardcoded changeme password default from docker-compose.yml
- Gateway now refuses to start if GATEWAY_SECRET is missing or under 32 characters

## [1.0.0] - 2026-04-02

### Added
- Initial release
- OpenAI, Anthropic, and Google AI API proxying
- Canadian PII scrubbing: SIN, BC PHN, postal codes, phone numbers, email addresses, person names
- Toggleable scrubbing rules via scrubbing_rules.yaml
- PostgreSQL request logging
- API key authentication for staff
- Hash-chained audit trail
- Docker Compose single-command deployment
