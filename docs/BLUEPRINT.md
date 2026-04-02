---
name: municipal-ai-gateway
description: Build an open-source AI governance proxy gateway for municipalities and public-sector organizations. Use this skill whenever someone asks to build an AI proxy, AI gateway, AI firewall, AI governance tool, shadow AI monitoring, PII scrubbing proxy, organizational AI usage tracker, or any tool that sits between an organization's users and AI providers (OpenAI, Anthropic, Google, etc.) to enforce policy, strip sensitive data, and create audit trails. Also trigger when someone asks about protecting an organization from ungoverned AI usage, monitoring what staff send to ChatGPT/Copilot/Gemini/Claude, or building a free/open-source AI safety tool for government or enterprise. If the request involves intercepting, logging, scrubbing, or governing AI API traffic at the organizational level, use this skill. Even if the person just says "AI firewall" or "shadow AI problem" or "staff using ChatGPT without oversight", this skill applies.
---

# Municipal AI Gateway

An open-source proxy gateway that sits between an organization's network and external AI providers. It intercepts every AI request, strips personally identifiable information before it leaves the building, enforces usage policies, logs everything to a tamper-evident audit trail, and gives administrators a real-time dashboard showing all AI activity across the organization.

The gateway ships as a single `docker compose up` deployment. A municipal IT team can have it running in under an hour.


## Why this exists

Staff across municipalities are already using ChatGPT, Copilot, Gemini, and Claude with zero oversight. In a 2025 KPMG Canada survey, nearly half of Canadian public servants reported using AI tools at work while fewer than a quarter of their organizations had formally adopted AI. Nobody knows what data is going out. Nobody has an audit trail. If a privacy breach happens, the CAO and council are exposed.

This tool makes shadow AI visible and safe without blocking productivity.


## Competitive landscape -- what already exists and how this is different

There are existing AI gateways. None of them are built for municipal government. Understanding the landscape prevents building something redundant and clarifies the unique value proposition.

### Enterprise AI gateways (not competitors, different audience)

These tools exist for developer teams routing API calls at scale. They solve routing, cost, and observability problems for engineering organizations:

- **Portkey** -- Enterprise AI gateway with 200+ LLM integrations, RBAC, guardrails, PII redaction. SOC2/HIPAA/GDPR compliant. Hosted SaaS with enterprise pricing ($499+/month for Pro). Not open-source at the core governance layer. Not designed for non-technical municipal IT staff.
- **LiteLLM** -- Open-source Python proxy that normalizes 100+ providers behind an OpenAI-compatible API. Strong developer adoption. No built-in PII scrubbing, no admin dashboard for non-technical users, no audit trail, no Canadian regulatory awareness. Enterprise tier ($250/month) adds SSO and audit logs.
- **Bifrost** -- Open-source Go-based gateway focused on ultra-low latency (~11 microseconds). Performance-first, not governance-first. No PII scrubbing. No compliance features.
- **Kong AI Gateway** -- Plugin for the Kong API gateway. Enterprise-grade but requires existing Kong infrastructure. AI PII Anonymizer is a private Docker image requiring Kong Support access. Not self-serve for a small municipal IT team.
- **Cloudflare AI Gateway** -- Edge-network gateway for caching, rate limiting, analytics. Requires Cloudflare ecosystem. No PII scrubbing. No Canadian data residency guarantees.
- **IBM API Connect AI Gateway** -- Built for enterprises already in the IBM ecosystem. Strong governance but heavy onboarding, annual enterprise contracts, limited to IBM's model catalog.

### PII scrubbing tools (partial overlap, not complete solutions)

- **Wealthsimple's LLM Gateway** (open-source) -- A Canadian fintech open-sourced a PII scrubbing gateway for LLM calls. Covers email, phone, IP, hostname scrubbing. Does NOT cover Canadian SIN, postal codes, or municipal-specific patterns. No admin dashboard, no policy engine, no audit trail, no department-level tracking. It is a developer library, not a deployable product.
- **Microsoft Presidio** -- Open-source PII detection and anonymization engine. Excellent NLP-based detection. Used as a library inside other systems, not a standalone gateway. No routing, no dashboard, no audit trail. Can be used as a component inside this gateway's scrubbing layer.
- **Various regex-based PII proxies** (DEV.to tutorials, DZone articles) -- Individual developers have built proof-of-concept PII proxies. These are blog post demos, not production tools. They typically cover US patterns (SSN format XXX-XX-XXXX) but not Canadian patterns (SIN format XXX-XXX-XXXX, postal codes).

### What does NOT exist (the gap this fills)

No existing open-source tool combines all of these:

1. **Canadian-specific PII scrubbing** (SIN, postal codes, provincial health numbers)
2. **Tamper-evident audit trail** with hash chaining (not just logs, but provable logs)
3. **Non-technical admin dashboard** that a municipal IT generalist can operate
4. **Provincial privacy law awareness** (BC FIPPA, Alberta FOIPP, Ontario MFIPPA, Quebec Law 25)
5. **Pre-filled PIA templates** that save municipalities weeks of compliance work
6. **Department-level usage tracking** mapped to organizational structure
7. **Warn-not-block policy model** that lets staff keep working while creating accountability
8. **One-command Docker deployment** sized for a 50-500 employee municipality

The existing gateways are built for Silicon Valley engineering teams managing multi-provider API routing at scale. This gateway is built for a municipal IT coordinator in Lethbridge who needs to tell their CAO that staff AI usage is governed and auditable.

### IP considerations

This project does not step on existing IP because:

- The core proxy pattern (reverse proxy intercepting API calls) is a standard architectural pattern, not proprietary to any vendor.
- PII scrubbing via regex and NLP is a well-established technique implemented in dozens of open-source libraries.
- The unique value is in the combination, the Canadian specificity, the municipal UX, and the compliance tooling. No existing project combines these.
- Presidio (Microsoft, MIT license) can be used as a detection engine component without IP concerns.
- The hash-chained audit trail pattern is a general cryptographic technique, not patented.
- Ship under Apache 2.0 or MIT license. Both are permissive and compatible with incorporating Presidio and other MIT/Apache-licensed components.


## Architecture

```
+---------------------------------------------------------+
|               MUNICIPALITY'S NETWORK                     |
|                                                          |
|  +----------+    +---------------+    +--------------+   |
|  |  Staff    |--->|  AI Gateway   |--->|  Admin       |   |
|  |  Browsers |    |  (Proxy)      |    |  Dashboard   |   |
|  +----------+    +------+--------+    +--------------+   |
|                         |                                |
|                  +------+--------+                       |
|                  |  PostgreSQL   |                       |
|                  |  (Audit Logs) |                       |
|                  +---------------+                       |
+-----------------------+---------------------------------+
                        | Only sanitized requests
                        | cross this boundary
                        v
              +------------------+
              |  AI Providers    |
              |  OpenAI/Anthropic|
              |  Google/etc.     |
              +------------------+
```

The gateway runs entirely inside the municipality's infrastructure. The IT team holds the API keys. They control the PII rules. They own the audit logs. Nothing leaves their network without sanitization.


## Project structure

```
municipal-ai-gateway/
  docker-compose.yml          # One-command deployment
  docker-compose.prod.yml     # Production overrides (TLS, secrets)
  .env.example                # Configuration template
  README.md                   # Setup guide written for municipal IT
  SECURITY.md                 # Responsible disclosure policy
  LICENSE                     # Apache 2.0
  
  gateway/                    # Python FastAPI proxy service
    Dockerfile
    requirements.txt
    main.py                   # Proxy endpoints
    scrubber/
      __init__.py
      engine.py               # PII scrubbing orchestrator
      patterns_ca.py          # Canadian PII patterns (SIN, postal, PHN)
      patterns_common.py      # Universal patterns (email, phone, CC)
      custom_rules.py         # User-defined scrubbing rules
    audit/
      __init__.py
      logger.py               # Hash-chained audit trail writer
      models.py               # SQLAlchemy models for audit records
    policy/
      __init__.py
      engine.py               # Policy evaluation (allow/warn/block)
      rules.py                # Default policy rules
    providers/
      __init__.py
      registry.py             # AI provider allowlist
      openai.py               # OpenAI request/response handling
      anthropic.py            # Anthropic request/response handling
      google.py               # Google AI request/response handling
    auth/
      __init__.py
      ldap.py                 # Active Directory / LDAP integration
      local.py                # Local auth fallback
      mfa.py                  # TOTP MFA implementation
      rbac.py                 # Role-based access control
    health.py                 # /health and /ready endpoints
    config.py                 # Configuration loader
  
  dashboard/                  # React admin dashboard
    Dockerfile
    package.json
    src/
      App.jsx
      pages/
        Overview.jsx          # Real-time usage dashboard
        AuditLog.jsx          # Searchable, exportable audit trail
        Policies.jsx          # Policy rule editor
        Departments.jsx       # Department usage breakdown
        PiiRules.jsx          # PII scrubbing rule manager
        Providers.jsx         # AI provider allowlist manager
        Settings.jsx          # System configuration
      components/
        UsageChart.jsx        # Department usage over time
        PiiDetectionFeed.jsx  # Live feed of PII catches
        AuditExport.jsx       # CSV/JSON export controls
  
  migrations/                 # Alembic database migrations
    alembic.ini
    versions/
  
  config/
    provinces/
      bc.yaml                 # BC FIPPA defaults
      ab.yaml                 # Alberta FOIPP defaults
      on.yaml                 # Ontario MFIPPA defaults
      qc.yaml                 # Quebec Law 25 defaults
      default.yaml            # Federal PIPEDA defaults
  
  docs/
    DEPLOYMENT.md             # Step-by-step for municipal IT
    PIA-TEMPLATE.md           # Pre-filled Privacy Impact Assessment
    ARCHITECTURE.md           # Technical architecture for IT review
    FIREWALL-RULES.md         # Exact domains/ports to open
    UPGRADE-GUIDE.md          # Version upgrade procedures
    FAQ-FOR-CAOS.md           # Non-technical FAQ for leadership
    INCIDENT-RESPONSE.md      # Template incident response plan
    SECURITY-TEST-RESULTS.md  # Published with each release
    proxy.pac.example         # PAC file template with comments
  
  scripts/
    generate-cert.sh          # Self-signed cert for initial setup
    setup-ca.sh               # Internal CA for transparent proxy mode
    watchdog.sh               # Health check monitor with alerting
    archive-audit.sh          # Export old partitions to compressed CSV
  
  benchmarking/               # Optional community benchmarking
    docker-compose.yml        # Self-hosted benchmarking server
    server/
      main.py                 # Aggregation API endpoint
      models.py               # Anonymized stats schema
    client/
      reporter.py             # Weekly stats submission (runs in gateway)
      anonymizer.py           # Ensures non-re-identifiability
  
  tests/
    test_scrubber.py
    test_audit.py
    test_policy.py
    test_auth.py
```


## Passing the IT sniff test

Municipal IT departments evaluate tools against real security standards before approving deployment. The gateway must satisfy these concerns out of the box or it dies in review. This section explains what IT looks for, why, and exactly how the gateway addresses each concern.

### Encryption

IT checks whether data is encrypted in transit and at rest. This is non-negotiable in every security framework (SOC 2, ITSG-33, ISO 27001).

Implement:

- **TLS 1.2+ for all inbound traffic.** The proxy terminates TLS. Ship a default self-signed cert for initial setup and document how to replace it with the municipality's own cert or Let's Encrypt. Never allow plaintext HTTP in production mode. The `docker-compose.prod.yml` should enforce HTTPS-only.
- **AES-256 encryption at rest** for the PostgreSQL audit database. Use volume-level encryption (LUKS/dm-crypt on the Docker volume) and document the setup. PostgreSQL's `pgcrypto` extension can provide column-level encryption for especially sensitive fields.
- **TLS for all outbound connections** to AI providers. Verify TLS certificates on every outbound request. Never set `verify=False` or equivalent. Pin minimum TLS version to 1.2.
- **API keys encrypted at rest.** Use Docker secrets (not environment variables in docker-compose.yml). Provide a `secrets/` directory with a setup script. Document this clearly because municipal IT will check.
- **mTLS between internal services** (proxy, dashboard, database) on the Docker bridge network. This prevents a compromised container from sniffing traffic between services.

### Authentication and access control

IT asks: who can access the admin dashboard? Who can change policies? How are users identified?

Implement:

- **RBAC with three roles minimum.** Admin: full config, policy, and user management. Auditor: read-only access to logs and dashboard. User: implicit role for any staff member whose traffic routes through the proxy.
- **MFA for Admin and Auditor dashboard access.** TOTP (Google Authenticator / Microsoft Authenticator compatible) as primary. Email MFA as fallback. MFA is not optional for admin accounts.
- **LDAP / Active Directory integration.** Most municipalities run AD. Support LDAP bind authentication so IT does not maintain a separate user directory. Ship with local auth as default, AD as a documented configuration option. Test against common AD configurations (Azure AD / Entra ID, on-prem AD).
- **Session management.** HTTP-only cookies, Secure flag, SameSite=Strict, configurable session timeout (default 30 minutes for admin). No localStorage for session tokens.

### Audit logging

IT asks: can we prove what happened? Can we produce records for a privacy commissioner investigation?

Every request through the gateway gets logged with:

- Timestamp (UTC, ISO 8601)
- Authenticated user identity or source IP
- Department (mapped from AD group or configurable IP range)
- AI provider and model targeted
- SHA-256 hash of original request content
- SHA-256 hash of scrubbed request content (proves transformation occurred)
- SHA-256 hash of response content
- PII detection count and types found (never the actual PII values)
- Policy action taken (allowed, warned, blocked)
- Scrub actions (which patterns matched, what replacements were made)

Audit log requirements:

- **Append-only.** The proxy's database role has INSERT-only permissions. No admin can delete or modify audit records through the application.
- **Tamper-evident.** Each log entry includes an HMAC hash chaining to the previous entry. If someone modifies a record, the chain breaks and the dashboard flags it. Use rotating HMAC keys with versioning.
- **Retained for configurable period.** Default 7 years (matching most Canadian records retention requirements). Provide automated archival to cold storage.
- **Exportable.** CSV and JSON export, filterable by date range, user, department, and policy action. This is what gets handed to a privacy commissioner or auditor.

### Network segmentation

IT asks: what network access does this thing need?

Document exactly two network paths:

1. **Inbound from the municipal LAN** -- staff browsers connecting to the proxy endpoint
2. **Outbound to specific AI provider domains** -- a strict allowlist

The gateway must:

- Ship a default allowlist of AI provider domains with exact hostnames and ports. Block all other outbound traffic from the proxy container.
- Include a `docs/FIREWALL-RULES.md` listing every domain and port IT needs to open.
- **Never phone home.** No telemetry, no analytics, no update checks. The municipality controls when to pull a new Docker image.
- Run in an isolated Docker network. Only the proxy's inbound port and the dashboard port are exposed to the LAN. The database is never exposed.

### Vulnerability management

IT asks: how do we know this code is safe?

The project must include:

- **pip-audit** and **npm audit** in CI/CD. Show clean results in README badges.
- **Bandit** (Python static analysis) with config file and clean results.
- **Trivy or Grype** container scanning on Docker images in CI/CD.
- **SECURITY.md** with responsible disclosure instructions.
- **Published SHA-256 digests** for every Docker image release so IT can verify integrity.
- **Non-root containers.** All containers run as non-root users. Document the UIDs/GIDs.
- **Minimal base images.** Use `python:3.12-slim` and `node:20-alpine`, not full images.

### Change management

IT asks: how do we update without breaking things?

- Semantic versioning for all releases.
- Changelog with security fixes prominently marked.
- Alembic migration scripts for every database schema change.
- Rollback documentation for every upgrade path.
- `/health` and `/ready` endpoints for monitoring integration (Nagios, Zabbix, or whatever the municipality runs).

### Traffic routing architecture

IT will ask the most basic question first: how does staff traffic actually flow through this thing? The skill must specify a concrete answer, not a vague "configure your proxy."

The gateway operates as an **explicit forward proxy**. Here is exactly how it works:

**Option A: Group Policy deployment (recommended for AD environments).** IT pushes a Proxy Auto-Config (PAC) file via Active Directory Group Policy. The PAC file routes traffic destined for known AI provider domains (api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, etc.) through the gateway. All other traffic bypasses the proxy entirely. This means the gateway only sees AI-related traffic, not general web browsing.

```javascript
// proxy.pac -- deployed via Group Policy
function FindProxyForURL(url, host) {
  // Route AI provider traffic through the gateway
  if (shExpMatch(host, "api.openai.com") ||
      shExpMatch(host, "api.anthropic.com") ||
      shExpMatch(host, "generativelanguage.googleapis.com") ||
      shExpMatch(host, "*.openai.com") ||
      shExpMatch(host, "chat.openai.com") ||
      shExpMatch(host, "claude.ai")) {
    return "PROXY ai-gateway.internal.muni.ca:8443";
  }
  // Everything else goes direct
  return "DIRECT";
}
```

Ship this PAC file as a template in `docs/proxy.pac.example` with comments explaining each line. Include Group Policy deployment instructions with screenshots for Server 2019/2022.

**Option B: DNS-level redirect (for environments without AD).** Configure the municipality's internal DNS to resolve AI provider domains to the gateway's IP. The gateway then proxies the request onward. This requires the gateway to present a TLS certificate that the browser trusts for those domains, which means deploying an internal CA cert to all workstations. More complex but works without AD.

**Option C: Network-level transparent proxy.** For municipalities with managed firewalls (Fortinet, Palo Alto, etc.), configure the firewall to redirect traffic destined for AI provider IPs to the gateway. The gateway operates as a transparent intercepting proxy. This requires no client-side configuration but needs firewall admin cooperation.

Document all three options in `docs/DEPLOYMENT.md` with a decision matrix:

| Environment | Recommended Option | Complexity | Requires AD |
|---|---|---|---|
| AD with Group Policy | Option A (PAC file) | Low | Yes |
| Mixed/BYOD environment | Option B (DNS redirect) | Medium | No |
| Managed firewall | Option C (Transparent proxy) | Medium | No |

### Certificate trust chain

IT will immediately ask: if the gateway terminates TLS, how do staff browsers trust its certificate?

The gateway needs a TLS certificate that browsers accept for the AI provider domains it proxies. There are three approaches, matching the traffic routing options:

**For Option A (PAC file):** The browser connects to the gateway's hostname (e.g., `ai-gateway.internal.muni.ca`), not the AI provider domain. The gateway only needs a certificate for its own hostname. This is the simplest path. Use the municipality's existing internal CA, or generate a cert via Let's Encrypt if the gateway has a public DNS entry. Ship a script (`scripts/generate-cert.sh`) that creates a self-signed cert for initial setup and documents how to replace it.

**For Options B and C (DNS/transparent):** The gateway must present certificates for AI provider domains (api.openai.com, etc.). This requires deploying a custom CA certificate to all workstations so browsers trust the gateway's dynamically generated certs. Document the CA cert deployment process for both AD (Group Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities) and manual installation (macOS Keychain, Linux ca-certificates).

Ship a `scripts/setup-ca.sh` script that generates a root CA key and certificate, stores them in Docker secrets, and outputs instructions for distributing the CA cert.

### Failure mode: fail-closed vs fail-open

IT will ask: what happens when the gateway goes down?

**Default: fail-closed.** If the gateway is unreachable, staff cannot access AI providers. This is the secure default because it means no ungoverned traffic can bypass the proxy during an outage. The PAC file returns the gateway as the only proxy path for AI domains, so if the gateway is down, those requests fail.

**Configurable override: fail-open.** Some municipalities may decide that AI access continuity is more important than guaranteed governance during brief outages. The PAC file can include a fallback: `return "PROXY ai-gateway.internal.muni.ca:8443; DIRECT";` which routes directly to the AI provider if the gateway is unreachable. This must be an explicit opt-in configuration, not the default. When fail-open is enabled, the dashboard should display a prominent banner warning that ungoverned access is possible during outages.

**Availability measures to minimize downtime:**

- Docker restart policy: `restart: unless-stopped` on all containers.
- Health check in docker-compose.yml that restarts unhealthy containers automatically.
- Watchdog script (`scripts/watchdog.sh`) that monitors the `/health` endpoint and sends an alert if it fails three consecutive checks.
- Document a simple high-availability setup using Docker Compose on two servers with a floating IP (keepalived) for municipalities that need uptime guarantees.

### Logging volume and storage planning

IT will ask: how much disk does this eat over 7 years?

Provide concrete estimates in the documentation:

**Assumptions for a 200-person municipality, 50 active AI users:**
- Average 10 AI requests per user per day = 500 requests/day
- Average audit record size: ~2 KB (metadata, hashes, scrub actions, no prompt text)
- Daily: 500 records x 2 KB = ~1 MB/day
- Annual: ~365 MB/year
- 7-year retention: ~2.5 GB total

This is trivially small for PostgreSQL. But document the growth model so IT can plan.

**Storage management strategy:**

- **Partitioning:** Partition the audit table by month using PostgreSQL's native table partitioning. This makes archival and deletion of expired records efficient (drop an entire partition rather than deleting millions of rows).
- **Archival:** Ship a `scripts/archive-audit.sh` script that exports partitions older than a configurable threshold (default: 2 years) to compressed CSV files, stores them in a configurable archive directory, and then drops the partition. Archived files retain the HMAC chain so they remain tamper-verifiable.
- **Monitoring:** The dashboard should display current database size, growth rate, and projected storage needs. Alert when disk usage exceeds 80%.
- **Vacuuming:** Include a scheduled PostgreSQL VACUUM ANALYZE in the Docker health check or as a cron job inside the database container.

### Incident response and alerting

IT will ask: what happens when someone pastes an entire resident database into ChatGPT?

The gateway needs an alerting system, not just logging. Implement:

**Alert triggers (configurable thresholds):**

- Single request with more than N PII detections (default: 10). This catches bulk data paste incidents.
- Single user exceeding N requests in M minutes (default: 50 requests in 5 minutes). This catches automated scraping or bulk operations.
- Any request that triggers a block policy action.
- PII detection of a high-sensitivity category (health numbers, SIN) regardless of count.
- Tamper detection: HMAC chain verification failure in the audit trail.
- Gateway health: container restart, database connection failure, certificate expiration within 30 days.

**Alert delivery channels:**

- Email (SMTP, configured in `.env`). This is the baseline every municipality has.
- Webhook (configurable URL). This enables integration with Microsoft Teams, Slack, or any incident management tool the municipality uses.
- Syslog (RFC 5424). For municipalities that feed logs into a SIEM (Splunk, Elastic, Graylog).
- Dashboard banner for non-critical alerts.

**Incident response workflow:**

When a critical alert fires (bulk PII detection, tamper detection), the gateway should:

1. Log the full incident details in a separate `incidents` table.
2. Optionally auto-suspend the user's proxy access pending admin review (configurable, off by default).
3. Send alerts via all configured channels.
4. Display the incident prominently on the dashboard with a one-click "Review Incident" flow that shows the user, timestamp, what was detected, and what action was taken.

Ship a `docs/INCIDENT-RESPONSE.md` template that municipalities can adapt into their own incident response plan.

### Security testing and penetration test readiness

IT will ask: has this been security tested? Can we see the results?

The project must include documented security testing results, not just scanning tools in CI/CD:

**Automated testing (runs in CI/CD on every release):**

- **OWASP ZAP** baseline scan against the dashboard and proxy endpoints. Ship the ZAP configuration file and the scan results as a release artifact. Target: zero high-severity findings.
- **Bandit** static analysis of all Python code. Ship `.bandit.yaml` config. Target: clean scan.
- **pip-audit** for known vulnerabilities in Python dependencies. Target: zero known vulnerabilities.
- **npm audit** for dashboard dependencies. Target: zero high/critical vulnerabilities.
- **Trivy** container image scan. Target: zero critical CVEs in base images.

**Manual testing (document the process, publish results with each major release):**

- **Authentication bypass testing.** Verify that dashboard endpoints return 401/403 without valid session. Verify MFA cannot be skipped. Verify LDAP injection is not possible.
- **Authorization testing.** Verify Auditor role cannot modify policies. Verify that the proxy service account cannot read audit logs directly (only write).
- **TLS verification.** Verify minimum TLS 1.2 is enforced. Verify certificate validation on outbound requests cannot be bypassed via configuration.
- **HMAC chain integrity.** Verify that modifying a single audit record causes the chain verification to fail and the dashboard to flag it.
- **PII scrubbing completeness.** Test against a standard test dataset of Canadian PII patterns. Document false-positive and false-negative rates for each pattern.

Ship a `docs/SECURITY-TEST-RESULTS.md` with every release containing the scan outputs and manual test attestations. This is the document IT hands to their security review committee.


## Canadian data residency and regulatory compliance

Canadian municipalities operate under a patchwork of provincial privacy legislation. The gateway must help municipalities comply with these laws and document clearly how it does so. This is the section that makes IT and legal comfortable.

### The regulatory landscape by province

**British Columbia** -- Freedom of Information and Protection of Privacy Act (FIPPA/FOIPPA). The 2021 Bill 22 amendments removed the strict in-Canada storage mandate but now require a Privacy Impact Assessment (PIA) when sensitive personal information is stored outside Canada. Section 30 still requires "reasonable security measures" for all personal information. The BC OIPC has stated that disclosure outside Canada demands a very high level of rigour.

**Alberta** -- Freedom of Information and Protection of Privacy Act (FOIPP). No categorical residency rule but cross-border disclosures must be authorized and safeguarded. Alberta's Privacy Commissioner recommended in August 2025 that the province create its own AI law and update privacy legislation for automated decision-making.

**Ontario** -- Municipal Freedom of Information and Protection of Privacy Act (MFIPPA). No explicit in-Canada requirement but compliance depends on safeguards and contractual controls. Ontario's Trustworthy AI Framework Directive (effective December 2024) establishes disclosure, accountability, and risk management requirements for public sector AI. First province to set these guardrails formally.

**Quebec** -- Law 25 (modernized private-sector privacy). Cross-border transfers (even inter-provincial) require a privacy impact assessment (EFVP) and "essentially equivalent" protection in the receiving jurisdiction. Strictest provincial regime.

**Federal** -- Treasury Board Directive on Automated Decision-Making requires algorithmic impact assessments and transparency for federal institutions. PIPEDA applies when personal information crosses provincial or national borders. The Artificial Intelligence and Data Act (AIDA) did not proceed when Parliament prorogued in January 2025, but its risk-based concepts continue influencing policy. A new AI Strategy Task Force is consulting on the next national AI strategy as of May 2025.

### How the gateway addresses data residency

The architecture is inherently data-residency-friendly because it runs inside the municipality's own network. The critical compliance point is what happens when data crosses the boundary to AI providers whose servers may be in the US.

1. **PII scrubbing happens before data leaves Canada.** The proxy strips sensitive personal information before it reaches any AI provider. This materially reduces the PIA burden because sanitized data crossing the border carries much lower privacy risk.

2. **Configurable provider allowlists by jurisdiction.** The dashboard lets IT restrict which AI providers are permitted. If a municipality's PIA only covers Anthropic (which offers specific region routing), they can block OpenAI, Google, etc. until those providers are separately assessed.

3. **Audit trail proves compliance.** Every request includes a before-scrub hash and after-scrub hash. This is the evidence for a PIA or privacy commissioner investigation showing personal information was removed before it left the country.

4. **PIA template included.** Ship a pre-filled Privacy Impact Assessment template with the gateway's architecture, data flows, and security controls already documented. Include province-specific sections for BC, Alberta, Ontario, and Quebec. This saves the municipality weeks of PIA drafting.

5. **Data classification tagging.** Admins tag departments or users by sensitivity level ("handles resident PII", "financial data", "health information"). Higher sensitivity triggers stricter scrubbing or blocks AI access entirely. Maps directly to FIPPA s. 30 "reasonable security measures" proportional to sensitivity.

6. **Canadian deployment guidance.** The README includes deploying to Canadian cloud regions (AWS ca-central-1, Azure Canada Central, GCP northamerica-northeast1) for municipalities wanting cloud hosting in-country. Include Docker Compose and basic Kubernetes manifests for both on-prem and cloud.

7. **No content retention beyond audit hashes.** The proxy does not cache or store the text of AI requests or responses. Actual prompt and response content passes through and is discarded. Only hashes are retained. This minimizes the gateway's own privacy footprint.

### Province-specific configuration presets

Ship YAML presets that pre-configure scrubbing rules and policy defaults for each province:

```yaml
# config/provinces/bc.yaml
province: british_columbia
legislation: FIPPA
data_residency:
  pia_required_for_cross_border: true
  default_provider_restriction: canadian_regions_preferred
scrubbing:
  patterns:
    - sin            # Social Insurance Number
    - bc_phn         # BC Personal Health Number
    - postal_code    # Canadian postal code
    - email
    - phone
    - credit_card
  sensitivity_levels:
    health_data: block     # Block AI requests containing health data
    financial_data: warn   # Warn and log but allow
    general_pii: scrub     # Scrub and allow
audit:
  retention_years: 7
  export_formats: [csv, json]
  tamper_detection: hmac_chain
```

```yaml
# config/provinces/qc.yaml
province: quebec
legislation: Law_25
data_residency:
  pia_required_for_cross_border: true
  efvp_required: true
  equivalent_protection_required: true
  interprovincial_transfers_require_pia: true   # Quebec is stricter
scrubbing:
  patterns:
    - sin
    - qc_health_number    # Quebec RAMQ number
    - postal_code
    - email
    - phone
    - credit_card
  language_support: [en, fr]   # Bilingual scrubbing patterns
audit:
  retention_years: 7
  export_formats: [csv, json]
  tamper_detection: hmac_chain
```


## Data retention, purging, and legal holds

Data retention is where IT, legal, and the clerk's office all converge. The gateway creates records that fall under municipal records management bylaws, provincial privacy legislation, and potentially FOI/access-to-information obligations. Getting this wrong exposes the municipality to either retaining data they are obligated to delete or deleting data they are obligated to keep. The gateway must handle both sides of that tension.

### What the gateway retains vs what passes through

This distinction is the foundation of the gateway's retention posture. IT and legal must understand it clearly.

**Passes through (never stored):**
- The actual text of AI prompts (what the staff member typed)
- The actual text of AI responses (what the model returned)
- The original PII values that were detected and scrubbed

These are never written to disk, never cached, never logged in full. They exist only in memory during request processing and are discarded when the response is returned to the user. This is a deliberate architectural decision: if the gateway stored prompt text, it would become a massive repository of potentially sensitive content that creates its own privacy liability.

**Stored in the audit trail (retained per policy):**
- Request metadata (timestamp, user, department, provider, model)
- SHA-256 hashes of original content, scrubbed content, and response content (proves what happened without storing what was said)
- PII detection metadata (types found, count, pattern that matched, replacement token used)
- Policy actions taken (allowed, warned, blocked, with skip-justifications)
- HMAC chain links for tamper evidence

**Stored in the incidents table (retained per policy):**
- Full incident records when alert thresholds are triggered
- Includes all audit metadata plus the alert type, severity, and resolution status

**Stored in configuration (retained indefinitely):**
- Policy rules, scrubbing patterns, provider allowlists, user accounts, department mappings
- These are operational configuration, not personal information, and do not have retention limits

### Why hashes instead of content

IT and legal will ask: if we only store hashes, how do we investigate an incident? The answer is important to get right.

Hashes serve as proof of what happened, not a record of what was said. If a privacy commissioner asks "did personal information leave your network on March 14?", the audit trail can prove: a request was made at 14:32 UTC by user jsmith in the finance department to ChatGPT. PII was detected (1 SIN, 2 email addresses). The PII was scrubbed before the request was forwarded. The hash of the scrubbed content differs from the hash of the original content, proving transformation occurred.

What the audit trail cannot tell you is the actual question the staff member asked. This is intentional. Storing prompt text would mean the gateway itself holds a searchable database of everything staff said to AI tools, which is a surveillance concern and a privacy liability. The hashes provide accountability without surveillance.

If a municipality's legal counsel determines they need full content logging for a specific investigation, the gateway should support a **temporary content capture mode** that can be enabled per-user or per-department for a defined time window, with explicit admin authorization logged in the audit trail. This is an exceptional measure, not a default.

### Provincial retention requirements

Each province has records retention obligations that apply to municipal records. The gateway's audit logs are municipal records and must be managed accordingly.

**The complication:** Municipalities do not just follow provincial minimums. Every municipality passes its own records retention bylaw that specifies retention periods for different record categories. AI governance logs are new enough that most retention bylaws do not have a specific category for them. The municipality will need to classify them.

Common approaches:

**British Columbia** -- FIPPA requires that personal information used by a public body must be retained for at least one year after use so the individual has a reasonable opportunity to request access. The gateway's audit logs (which contain metadata about PII detection, not the PII itself) likely fall under general administrative records. Most BC municipal retention bylaws set administrative records at 7 years. The gateway should default to 7 years for BC.

**Alberta** -- FOIPP has the same one-year minimum retention for personal information after use. Alberta municipal retention bylaws vary but 7 years is common for administrative and financial records.

**Ontario** -- MFIPPA requires retention of personal information for at least one year after use. Ontario's Municipal Act requires municipalities to retain records in accordance with their retention bylaw. Many Ontario municipalities use the TOMRMS (The Ontario Municipal Records Management System) classification, which would likely place AI audit logs under "Information Technology" or "Administration" with a 5-7 year retention.

**Quebec** -- Law 25 requires organizations to destroy personal information once the purpose for collection has been fulfilled, unless retention is required by law. Quebec's Archives Act may apply to municipal records. Retention periods are typically set by the municipality's calendar of conservation.

**Default configuration:**

```yaml
retention:
  audit_logs:
    default_years: 7
    minimum_years: 1          # Provincial floor (FIPPA/FOIPP/MFIPPA)
    maximum_years: 99         # Effectively permanent if needed
    configurable: true        # Admin can adjust within min/max
  incidents:
    default_years: 10         # Longer for security incidents
    minimum_years: 2
  configuration_history:
    default_years: 10         # Policy change history
  benchmarking_submissions:
    default_years: 3          # Aggregated stats only
  purge_schedule: monthly     # Automated purge check frequency
  purge_requires_approval: true  # Admin must confirm before purge runs
```

### Litigation holds and FOI freezes

This is the retention scenario that catches organizations off guard. If a municipality is involved in litigation, receives an FOI/access-to-information request, or is under investigation by a privacy commissioner, they may be legally obligated to preserve records that would otherwise be scheduled for purging.

The gateway must support:

**Litigation hold flag.** An admin can place the entire audit trail (or a filtered subset by date range, department, or user) under a litigation hold. When a hold is active:

- No automated purging occurs for records covered by the hold.
- No manual deletion is possible for records covered by the hold.
- The hold itself is logged in the audit trail (who placed it, when, what scope, what reason).
- The dashboard displays a prominent indicator that a hold is active.
- Holds can only be released by an Admin role, and the release is also logged.

**FOI/ATIP hold.** Same mechanics as litigation hold but tagged differently for records management purposes. When a municipality receives an access-to-information request that could encompass AI audit records, the clerk can flag those records as under FOI hold.

**Implementation:**

- Add a `holds` table: hold_id, hold_type (litigation/foi/investigation), scope (date range, department, user filter), placed_by, placed_at, reason, released_by, released_at, status.
- The purge job checks for active holds before deleting any partition or record. If a record falls under an active hold, it is preserved regardless of its retention schedule.
- The dashboard "Retention" page shows: current retention policy, active holds, upcoming purge schedule, and a preview of what would be purged in the next cycle.

### Right to deletion vs obligation to retain

This is the tension that legal will flag. Under PIPEDA Principle 5 and provincial equivalents, individuals may have a right to request correction or deletion of their personal information. But the gateway's audit trail is designed to be append-only and tamper-evident.

**The gateway's position:** The audit trail does not contain personal information in the traditional sense. It contains metadata about system events (user X made a request, PII type Y was detected and scrubbed). The user identities in the audit trail are operational records of who used a municipal system, which is standard for any IT system log. The gateway does not store the actual personal information that was detected (SIN values, health numbers, etc.), only the fact that they were detected and scrubbed.

If an individual requests deletion of their personal information from the municipality, the gateway's records are analogous to firewall logs or email server logs: they record that activity occurred, not the content of that activity. Most privacy commissioners have recognized that operational system logs are not subject to deletion requests in the same way as databases of personal information.

However, the gateway should support:

- **User pseudonymization in aged records.** After a configurable period (default: 2 years), the gateway can replace user identities in old audit records with pseudonymous identifiers (e.g., "user-a3f8b2"). The HMAC chain remains valid because the hash was computed on the original record. This reduces privacy exposure in long-retained records while preserving the audit trail's integrity.
- **Deletion request logging.** If someone requests deletion and the municipality determines the audit records are exempt, the request and the determination should be logged. This proves the municipality considered the request and made a defensible decision.

### Retention of PII scrub logs

The scrub logs deserve special attention because they contain sensitive metadata. A scrub log entry that says "SIN detected at position 47 in request from user jsmith, department finance, replaced with [SIN_REDACTED]" does not contain the actual SIN, but it reveals that jsmith was working with SIN data. That metadata is itself sensitive.

**Retention rules for scrub logs:**

- Scrub logs follow the same retention schedule as the parent audit record.
- Scrub logs are included in litigation/FOI holds when the parent audit record is held.
- Scrub log entries never contain the original PII value. They contain: detection type, position in text, pattern that matched, replacement token. Never the matched text itself.
- In the dashboard, scrub log details are visible only to Admin and Auditor roles. Regular usage statistics (aggregate PII detection counts) are visible on the department overview, but individual scrub events are restricted.

### Retention of community benchmarking data

If the municipality opts in to community benchmarking, the anonymized aggregate statistics submitted to the benchmarking service have their own retention considerations:

- Benchmarking submissions contain no personal information (only aggregate counts by size bracket and province).
- The benchmarking service retains submissions for a configurable period (default: 3 years) to enable trend analysis.
- A municipality can request deletion of all their historical submissions when they opt out. Since submissions are tagged only by an anonymous installation ID (not municipality name), deletion removes the ID and all associated records.
- The benchmarking service publishes its own retention policy and data governance documentation.

### Automated purge implementation

The gateway runs a scheduled purge job (default: monthly) that:

1. Identifies audit records and incidents past their retention date.
2. Checks each record against active litigation/FOI holds. Held records are skipped.
3. For records cleared for purging: exports them to a compressed, HMAC-chain-verified archive file (CSV + chain verification metadata).
4. Stores the archive in the configured archive directory with a manifest file listing what was purged and when.
5. Drops the PostgreSQL partition containing the expired records.
6. Logs the purge action in the audit trail (yes, the purge itself is an auditable event).
7. Sends a notification to all Admin users summarizing what was purged.

The purge job requires explicit admin approval before execution if `purge_requires_approval` is true (the default). The dashboard shows a "Pending Purge" notification with a preview of what will be deleted. An admin must click "Approve Purge" or the job remains pending.

For municipalities that want fully automated purging without approval gates (common for larger organizations with mature records management), the approval requirement can be disabled in configuration.


## What the gateway does to protect the organization

Build every one of these protections into the gateway. They are not optional features. They are the reason IT departments approve this tool and CAOs sleep at night.

### 1. PII scrubbing before data leaves the network

Every outbound request passes through a scrubbing layer that catches and redacts sensitive data patterns before they reach any AI provider. Canadian-specific patterns are required at minimum:

- Social Insurance Numbers: `\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b` (with Luhn validation)
- Canadian postal codes: `\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b`
- Provincial health numbers (BC PHN, Ontario OHIP, Alberta PHN, Quebec RAMQ)
- Phone numbers: `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`
- Email addresses: `[\w.+-]+@[\w-]+\.[\w.-]+`
- Credit card numbers (with Luhn validation)
- Street addresses (regex + NLP-assisted via Presidio if available)
- Configurable name blocklist (council members, staff directory)
- Custom patterns per municipality (property roll numbers, bylaw reference codes, file numbers)

The scrubbing engine should support two modes:

- **Regex-only mode** (zero external dependencies, works offline, fast)
- **NLP-enhanced mode** (uses Microsoft Presidio for name/address detection, optional dependency)

Every scrub action is logged: what was found, which pattern matched, what it was replaced with, which request it was in. This log is the evidence a privacy commissioner needs.

### 2. Complete tamper-evident audit trail

See the audit logging section under "Passing the IT sniff test" above. The key architectural decision: use HMAC hash chaining where each audit record's hash includes the previous record's hash. This creates a verifiable chain where any tampering is detectable. Use rotating HMAC keys with version tracking.

### 3. Department-level usage tracking

Map users to departments via AD group membership or configurable IP ranges. The dashboard shows:

- Which departments are using AI and how much
- What types of requests each department sends
- PII detection rates by department (which teams need more training)
- Cost attribution if API key usage is tracked per department

This is the data a CAO needs to make informed policy decisions.

### 4. Policy engine: warn-not-block

The default philosophy is warn, not block. Staff can still use AI, but:

- **Low-risk requests** (no PII detected, general questions) pass through with logging only.
- **Medium-risk requests** (PII detected and scrubbed) pass through with a warning logged and the user notified that data was sanitized.
- **High-risk requests** (health data, financial data, classification threshold exceeded) trigger a configurable action: warn with justification required, or block with explanation.

Every policy action is logged with the user's skip-justification if they override a warning. This creates defensible records without destroying productivity.

### 5. AI provider management

- Allowlist of approved AI providers and models.
- Per-provider API key management (keys stored encrypted, never exposed in dashboard).
- Rate limiting per user, per department, per provider.
- Cost tracking and budget alerts per department.
- Ability to disable a provider instantly if a security concern arises.


## Technology stack

- **Proxy:** Python 3.12+ / FastAPI (chosen for async performance and the team's likely familiarity since many municipal IT tools are Python-based)
- **Dashboard:** React 18+ with Tailwind CSS (simple, modern, no heavy framework)
- **Database:** PostgreSQL 16+ (audit logs, configuration, user management)
- **Optional NLP:** Microsoft Presidio (MIT license, for enhanced PII detection)
- **Containerization:** Docker Compose for deployment, multi-stage Dockerfiles for minimal images
- **CI/CD:** GitHub Actions with pip-audit, Bandit, Trivy, and automated tests


## Key implementation notes

- The proxy must be transparent. A staff member configures their browser/system proxy settings (or IT pushes it via group policy) and their AI tool usage flows through the gateway automatically. The UX for end users should be invisible.
- The dashboard is for IT administrators and auditors only. It is not exposed to general staff.
- The gateway should work with any AI provider that uses HTTPS API calls. It is not limited to specific providers. New providers can be added by defining their API endpoint patterns.
- All configuration is in YAML files and environment variables. No hardcoded values.
- Database migrations use Alembic so upgrades between versions are safe.
- The README is written for a municipal IT generalist, not a DevOps engineer. Include screenshots of the dashboard. Explain Docker concepts briefly. Assume the reader knows networking basics but may not have used Docker before.


## Documentation requirements

Every document in `docs/` must be written in plain language appropriate for its audience:

- **DEPLOYMENT.md** -- Step-by-step for IT staff. Includes prerequisites, Docker installation, initial configuration, certificate setup, AD integration, and verification steps.
- **PIA-TEMPLATE.md** -- Pre-filled Privacy Impact Assessment. Describes the system, data flows, security controls, and residency considerations. Leaves blanks for the municipality to fill in their specific context.
- **ARCHITECTURE.md** -- Technical architecture for IT security review. Network diagrams, data flow diagrams, encryption specifications, authentication flows.
- **FIREWALL-RULES.md** -- Exact hostnames and ports to open. Copy-paste ready for firewall configuration.
- **UPGRADE-GUIDE.md** -- Version-by-version upgrade instructions with rollback procedures.
- **FAQ-FOR-CAOS.md** -- Non-technical FAQ answering: What does this do? What data leaves our network? Who can see our logs? What happens if it goes down? Is this approved by [provincial authority]?
- **INCIDENT-RESPONSE.md** -- Template incident response plan municipalities can adapt. Covers PII exposure incidents, gateway compromise, tamper detection alerts, and breach notification procedures by province.
- **SECURITY-TEST-RESULTS.md** -- Published with each release. Contains OWASP ZAP scan output, Bandit results, pip-audit results, Trivy scan, and manual test attestations.


## Audit data insights and anonymized benchmarking

The audit logs are not just compliance records. Aggregated and analyzed, they become the most valuable dataset in Canadian municipal AI governance. This section describes what the gateway should surface from its own data and how an opt-in community benchmarking layer creates a network effect.

### Local insights (per-municipality, no data sharing required)

The dashboard should automatically surface these analytics from the municipality's own audit trail:

**Usage patterns:**
- Total AI requests per day/week/month, with trend lines
- Breakdown by department (which teams are adopting AI, which are not)
- Breakdown by AI provider and model (are staff using ChatGPT vs Claude vs Copilot?)
- Peak usage times (useful for capacity planning and policy timing)
- Average requests per user per day (identifies power users and outliers)

**Risk and compliance metrics:**
- PII detection rate: percentage of requests that contained personal information before scrubbing. This is the single most important metric for a CAO. "12% of all AI requests from your organization contained PII that would have been sent to a US server without this gateway."
- PII detection breakdown by type (SIN, email, phone, health number, postal code). Shows which types of sensitive data staff are most likely to expose.
- PII detection rate by department. A department with a 30% PII rate needs training. A department with a 2% rate is using AI responsibly.
- Near-miss reports: requests where PII was detected and scrubbed, counted as incidents that were prevented. Frame these positively in the dashboard: "47 potential data exposures prevented this month."
- Policy action distribution: how many requests were allowed, warned, or blocked. If 95% are allowed with no issues, the policy is well-calibrated. If 40% trigger warnings, the rules may be too aggressive or staff need training.

**Cost and budget tracking:**
- Estimated API cost per department per month (calculated from token counts if available, or request counts with average cost estimates per provider).
- Budget utilization alerts: department approaching monthly limit.
- Cost trend analysis: is AI spending increasing, stable, or decreasing?

**Operational health:**
- Gateway uptime percentage
- Average proxy latency added per request
- Database size and growth rate
- Certificate expiration countdown
- Scrubbing engine performance (average processing time per request)

### Community benchmarking (opt-in, anonymized, aggregated)

This is the network effect layer. If municipalities opt in, they contribute anonymized usage statistics to a shared dataset. In return, they see how their AI governance compares to peer municipalities.

**What gets shared (when opted in):**

Only aggregate statistics, never content. Specifically:

- Municipality size bracket (e.g., "100-500 employees", not the exact number or name)
- Province (for regulatory context grouping)
- Weekly aggregate: total request count, PII detection rate, PII type distribution, policy action distribution, provider distribution
- No request content, no prompt text, no response text, no user identities, no department names, no IP addresses

**What the municipality gets back:**

- "Municipalities your size in your province average 280 AI requests per week. You are at 420." (adoption benchmark)
- "Your PII detection rate is 14%. The median for your size bracket is 8%." (risk benchmark)
- "73% of peer municipalities have enabled health number scrubbing. You have not." (compliance gap alert)
- "The most common AI provider among municipalities your size is ChatGPT (62%), followed by Claude (24%)." (market context)

**Implementation:**

- **Opt-in toggle** in the admin dashboard settings. Off by default. Clearly labeled: "Share anonymized usage statistics with the Municipal AI Gateway community."
- **Transparency page** in the dashboard showing exactly what data is being shared, with a preview of the next scheduled submission.
- **Collection endpoint:** A simple HTTPS API hosted at a neutral domain (e.g., `benchmarks.municipal-ai-gateway.org`). The gateway posts a JSON payload of aggregate stats weekly. The endpoint stores only the aggregated data, never raw logs.
- **Privacy commitment:** The benchmarking service must be documented with its own PIA. The data shared must be provably non-re-identifiable (size brackets, not exact counts; province, not municipality name). Publish the server-side code as open source so municipalities can verify what happens with their data.
- **Self-hosted option:** For municipalities that want benchmarking within their own region or association (e.g., all AKBLG member municipalities), ship the benchmarking aggregation server as a separate Docker Compose deployment that a regional body can run themselves.

### Sector-level insights (for conferences, policy advocacy, and thought leadership)

Aggregated across all opt-in municipalities, the benchmarking data produces insights that are valuable to the entire sector:

- National and provincial AI adoption rates in municipal government
- Most common AI use cases by department type (public works, planning, finance, clerks)
- PII exposure risk rates across the sector (ammunition for provincial privacy commissioners considering new regulations)
- Effectiveness of different policy approaches (warn-vs-block outcomes across municipalities)
- Cost benchmarks for municipal AI usage (useful for budget planning across the sector)

This data can be published as an annual "State of Municipal AI in Canada" report. That report, authored by the gateway's maintainers, becomes a powerful thought leadership asset and positions the project (and by extension, LUMINARYX) as the authority on municipal AI governance.

### Data ethics and governance of the benchmarking layer

Because this tool is built for governance, its own data practices must be beyond reproach:

- The benchmarking service must have a published data governance policy.
- Municipalities must be able to withdraw from benchmarking at any time and have their historical aggregate contributions deleted.
- The benchmarking dataset must never be sold or shared with commercial entities (other than publishing the aggregate report).
- An advisory committee of participating municipalities should have input on what metrics are collected and how they are reported.
- All benchmarking code (client and server) must be open source.


## Branding

The open-source project ships with neutral branding. A "Powered by LUMINARYX" footer with a link is appropriate only if the builder is LUMINARYX. Otherwise, the gateway stands alone as a community tool.

The design should feel trustworthy and institutional, not flashy. Navy and white with a simple shield or lock icon. Serif headings for authority, sans-serif body for readability.
