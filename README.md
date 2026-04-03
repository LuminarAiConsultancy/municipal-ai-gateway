# Canadian Municipal AI Gateway

> Open-source AI governance proxy gateway for Canadian municipalities and public sector organizations.

Your staff are already using ChatGPT, Copilot, Gemini, and Claude. This gateway makes that safe and auditable without blocking anyone.

---

## The problem

In a 2025 KPMG Canada survey, nearly half of Canadian public servants reported using AI tools at work while fewer than a quarter of their organizations had formally adopted AI. Nobody knows what data is going out. Nobody has an audit trail. If a privacy breach happens, the CAO and council are exposed.

Blocking AI tools does not work. Staff use personal phones and personal accounts. You lose all visibility and productivity suffers.

The Canadian Municipal AI Gateway is a third option.

---

## What it does

The gateway sits between your organization's network and external AI providers. Every AI request from every staff member flows through it.

- **PII scrubbing** -- Canadian-specific personal information (SIN, provincial health numbers, postal codes, names, addresses) is detected and removed before any request leaves your network
- **Tamper-evident audit trail** -- every request and response is logged with hash chaining, so the record cannot be altered after the fact
- **Policy enforcement** -- warn-not-block model keeps staff productive while creating accountability; all policy exceptions are logged
- **Admin dashboard** -- real-time view of all AI activity across the organization, broken down by department, provider, and risk level
- **Provincial privacy law awareness** -- built for BC FIPPA, Alberta FOIPP, Ontario MFIPPA, and Quebec Law 25

Staff can use any AI tool they want. ChatGPT, Claude, Copilot, Gemini -- whatever they choose. The gateway handles the governance layer invisibly.

---

## Architecture

```
+---------------------------------------------------------+
|               MUNICIPALITY'S NETWORK                     |
|                                                          |
|  +----------+    +---------------+    +--------------+  |
|  |  Staff   |--->|  AI Gateway   |--->|  Admin       |  |
|  |  Browsers|    |  (Proxy)      |    |  Dashboard   |  |
|  +----------+    +------+--------+    +--------------+  |
|                         |                               |
|                  +------+--------+                      |
|                  |  PostgreSQL   |                      |
|                  |  (Audit Logs) |                      |
|                  +---------------+                      |
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

The gateway runs entirely inside your infrastructure. Your IT team holds the API keys. You control the PII rules. You own the audit logs. Nothing leaves your network without sanitization.

---

## Who this is for

- Municipal IT coordinators who need to tell their CAO that staff AI usage is governed
- CAOs and administrators who need a defensible answer for a privacy commissioner or auditor
- Any Canadian public sector organization with 50 to 500 employees using AI tools without oversight

This is not built for Silicon Valley engineering teams. It is built for the IT coordinator in a mid-sized Canadian municipality who needs something running by end of day.

---

## Quick start

### Prerequisites

You need [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed. That is the only requirement. The gateway, the database, TLS termination, and all dependencies run inside Docker containers. You do not need Python, PostgreSQL, nginx, or anything else installed on your machine.

Ports 443 (HTTPS) and 80 (HTTP redirect) must be available on the host machine. If another service is using port 443, stop it before starting the gateway.

### Clone and configure

```bash
git clone --branch v1.1.0 https://github.com/LuminarAiConsultancy/municipal-ai-gateway.git
cd municipal-ai-gateway
cp .env.example .env
```

> **Important:** Always install from a tagged release (e.g. `v1.1.0`), not from `main`. The main branch may contain work in progress. See the [Releases](https://github.com/LuminarAiConsultancy/municipal-ai-gateway/releases) page for the latest stable version.

Open `.env` in any text editor and fill in your values. Here is every variable the gateway uses:

| Variable | Required? | What it is |
|----------|-----------|------------|
| `GATEWAY_SECRET` | **Yes** | A random string that protects the admin dashboard and admin API. Minimum 32 characters. Generate one by running `openssl rand -hex 32` in your terminal. |
| `POSTGRES_PASSWORD` | **Yes** | The database password. Any strong password works. |
| `OPENAI_API_KEY` | If using OpenAI | Your organization's OpenAI API key from [platform.openai.com/api-keys](https://platform.openai.com/api-keys). Only needed if staff use ChatGPT or OpenAI tools. |
| `ANTHROPIC_API_KEY` | If using Anthropic | Your organization's Anthropic API key from [console.anthropic.com](https://console.anthropic.com). Only needed if staff use Claude. |
| `GOOGLE_API_KEY` | If using Google | Your organization's Google AI API key from [aistudio.google.com/apikey](https://aistudio.google.com/apikey). Only needed if staff use Gemini. |
| `GATEWAY_DOMAIN` | No | Your server's public hostname (e.g. `gateway.yourtown.ca`). When set, Caddy obtains a Let's Encrypt certificate automatically. Default is `localhost`. |
| `CADDY_TLS_EMAIL` | No | Email for Let's Encrypt certificate notifications. Recommended for production. |
| `POSTGRES_USER` | No | Database username. Default is `gateway`. Leave it unless your IT policies require a specific name. |
| `POSTGRES_DB` | No | Database name. Default is `ai_gateway`. Leave it unless you have a reason to change it. |
| `DATABASE_URL` | No | Full database connection string. If you changed `POSTGRES_PASSWORD`, update the password in this URL to match. Otherwise leave the default. |
| `GATEWAY_PORT` | No | Port the gateway listens on. Default is `8080`. Change only if that port is already in use. |
| `LOG_LEVEL` | No | How much detail appears in logs. Default is `info`. Set to `debug` only when troubleshooting. |
| `LOG_RETENTION_DAYS` | No | Number of days to keep request logs. Default is `365`. Set to match your municipality's records retention schedule. |
| `BACKUP_RETENTION_DAYS` | No | Number of days to keep daily database backups. Default is `30`. |
| `PROVINCE` | No | Your province code: `BC`, `AB`, `ON`, or `QC`. When set, the gateway maps PII detections to your province's privacy law and the `/frameworks` endpoint returns the active legal framework. |

You need at least one AI provider API key configured. Most organizations start with OpenAI.

### Start the gateway

```bash
docker compose up -d
```

The first time you run this, Docker will download and build the container images. This takes a few minutes depending on your internet connection. After that, starts are fast.

### Verify it is working

Check the health endpoint from your terminal:

```bash
curl -k https://localhost/health
```

The `-k` flag tells curl to accept Caddy's local certificate. Expected response:

```json
{"status": "ok", "checks": {"database": "ok", "scrubber": "ok"}}
```

Or open `https://localhost/health` in your browser. Your browser will warn about the certificate on localhost. Click through the warning (this is expected for local testing). If you see both checks as `"ok"`, the gateway is running with HTTPS.

HTTP requests to `http://localhost` are automatically redirected to HTTPS. Port 8080 is also available for direct HTTP access during testing.

The admin dashboard is at `https://localhost/admin`. Log in with your admin email and password.

### Production TLS with Let's Encrypt

The gateway uses [Caddy](https://caddyserver.com) as its reverse proxy. When you set the `GATEWAY_DOMAIN` variable in your `.env` file to your server's public hostname, Caddy automatically obtains and renews a Let's Encrypt certificate. No manual cert management is required.

```bash
# In your .env file, set:
GATEWAY_DOMAIN=gateway.yourtown.ca
```

Then restart:

```bash
docker compose up -d
```

Caddy will obtain a certificate within seconds. Renewals happen automatically before expiry. Your server must be reachable on ports 80 and 443 from the internet for Let's Encrypt validation.

If your municipality uses its own certificate authority and cannot use Let's Encrypt, see the [Caddy documentation on custom certificates](https://caddyserver.com/docs/caddyfile/directives/tls).

### Point staff at it

Each staff member gets their own API key, which you create from the admin dashboard or the API. When they set up their AI tool, they point it at the gateway address instead of directly at the AI provider. Instead of sending requests to `api.openai.com`, their tool sends requests to `https://your-server/v1/openai`. The gateway handles everything from there: it scrubs personal information out of the request, logs the interaction, enforces your department policies, and forwards the cleaned request to the AI provider using your organization's API key. Staff never see the provider API key, and every interaction is recorded in the audit trail.

---

## What makes this different

No existing open-source tool combines all of these in a single deployable package:

- Canadian-specific PII patterns (SIN format XXX-XXX-XXXX, provincial health numbers, postal codes)
- Hash-chained audit trail that is provably tamper-evident
- Admin dashboard designed for non-technical municipal IT staff
- Provincial privacy law awareness across all four major Canadian frameworks
- Warn-not-block policy model
- One-command Docker deployment sized for a municipality, not a tech company

---

## Why nobody else built this

There are over 3,500 municipalities in Canada. Most have total budgets under $5 million. No venture-backed startup is going after that market. The companies with resources to build governance software want enterprise contracts worth millions of dollars, not $8,000 annual deals with a town of 4,000 people. The market gets ignored. Not because the need is not real, but because it does not fit how software companies get funded and scaled.

Selling to municipalities is also brutally slow. RFP processes, budget cycles that run on a calendar year, committee approvals that take months. A normal SaaS company needs revenue within 90 days or it dies. Municipal sales cycles run 12 to 18 months. Most founders give up or pivot before they ever close a single deal. The ones who stay face procurement processes designed for large vendors with dedicated bid teams, not small specialized tools built by one or two people.

Building this kind of tool also requires speaking two languages at once. You need to understand AI governance technically and understand how a council meeting actually works, what a CAO's real liability exposure looks like, what "defensible decision" means when a councillor says it in a political context. That combination almost never exists in a single person. Developers do not know how local government operates. People who know local government cannot build the software. The gap persists because neither side can cross it alone.

The person who built this gateway sat on municipal council. Not as an observer or a consultant, but as an elected official making the exact decisions this software is designed to govern. She watched AI tools arrive in local government with no framework, no audit trail, and no protection for the people who would be held accountable when something went wrong. She also taught herself to build software. That combination of elected municipal official and self-taught developer who shipped a production system is genuinely rare. The gap exists because the people with technical skills did not have political context, and the people with political context could not build the software. She had both.

---

## Project status

**v1.1.0** | All tests passing | Docker ready | Production hardened

See [CHANGELOG.md](CHANGELOG.md) for release notes.

### What's included

**Core (v1.0.0):**
- OpenAI, Anthropic, and Google AI API proxying
- Canadian PII scrubbing (SIN, provincial health numbers, postal codes, phone numbers, email, names)
- Hash-chained tamper-evident audit trail
- API key authentication per staff member
- PostgreSQL request logging with CSV/JSON export
- SSE streaming proxy with PII scrubbing
- Structured JSON logging with correlation IDs
- Docker Compose single-command deployment

**v1.1.0:**
- Redis-backed sliding window rate limiting
- Per-administrator accounts with TOTP multi-factor authentication
- LDAP / Active Directory integration for staff API key auto-provisioning
- Automated TLS via Caddy and Let's Encrypt
- Daily PostgreSQL backups with 30-day retention
- Admin dashboard at `/admin`
- HTTP security headers on all responses
- Login brute force protection with failed login audit logging
- JWT secret validation on startup
- Database connection pooling with configurable limits
- Log retention policy (configurable via `LOG_RETENTION_DAYS`)

**Not yet built:**
- GitHub Copilot proxy support (uses a different authentication flow)

---

## Verify PII scrubbing is working

Once the gateway is running with at least one AI provider configured, you can send a test request containing personal information and confirm the gateway catches it.

There are two types of authentication headers used in these commands:

- **`Authorization: Bearer YOUR_GATEWAY_SECRET`** is the admin password from your `.env` file. It protects admin endpoints like `/admin/keys` and `/admin/requests`.
- **`X-Gateway-Key: ...`** is a staff API key created via `/admin/keys`. It authenticates proxy requests through `/v1/{provider}/...`. The value is the raw 64-character key string returned when you create the key. No `Bearer` prefix.

**Step 1.** Create a test staff key.

Bash (Linux/Mac/Git Bash):

```bash
curl -sk https://localhost/admin/keys \
  -H "Authorization: Bearer YOUR_GATEWAY_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"department": "Testing", "description": "PII verification test"}'
```

PowerShell (Windows):

```powershell
Invoke-RestMethod https://localhost/admin/keys -Method Post `
  -Headers @{ Authorization = "Bearer YOUR_GATEWAY_SECRET" } `
  -ContentType "application/json" `
  -Body '{"department": "Testing", "description": "PII verification test"}' `
  -SkipCertificateCheck
```

Copy the `key` value from the response.

**Step 2.** Send a request containing obvious PII.

Bash:

```bash
curl -sk https://localhost/v1/openai/v1/chat/completions \
  -H "X-Gateway-Key: PASTE_YOUR_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{
      "role": "user",
      "content": "Look up the file for Jane Smith, 742 Evergreen Terrace, Vancouver BC V5K 0A1. Her SIN is 046-454-286 and email is jane.smith@example.com"
    }]
  }'
```

PowerShell:

```powershell
Invoke-RestMethod https://localhost/v1/openai/v1/chat/completions -Method Post `
  -Headers @{ "X-Gateway-Key" = "PASTE_YOUR_KEY_HERE" } `
  -ContentType "application/json" `
  -Body '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Look up the file for Jane Smith, 742 Evergreen Terrace, Vancouver BC V5K 0A1. Her SIN is 046-454-286 and email is jane.smith@example.com"}]}' `
  -SkipCertificateCheck
```

**Step 3.** Check the audit log to see what the gateway caught.

Bash:

```bash
curl -sk https://localhost/admin/requests \
  -H "Authorization: Bearer YOUR_GATEWAY_SECRET"
```

PowerShell:

```powershell
Invoke-RestMethod https://localhost/admin/requests `
  -Headers @{ Authorization = "Bearer YOUR_GATEWAY_SECRET" } `
  -SkipCertificateCheck
```

In the most recent entry, `pii_detections_request` shows how many PII items were found and `pii_types_found` lists the types detected (such as `CA_SIN,EMAIL_ADDRESS,LOCATION,PERSON`). The AI provider never saw the original personal information. It received `[NAME REMOVED]`, `[SIN REMOVED]`, `[EMAIL REMOVED]`, and `[ADDRESS REMOVED]` instead.

The gateway validates SINs using the Luhn checksum algorithm, the same method used by the CRA and financial institutions. The test SIN above (046-454-286) passes the checksum and will be detected. A random sequence like 123-456-789 is correctly ignored because it fails the checksum. This prevents false positives on ordinary numbers that happen to be nine digits long.

---

## IT Deployment Guide

The gateway audits and controls AI traffic that passes through it. To
enforce its use across your municipality, your IT team must block direct
access to external AI services and route all discretionary AI traffic
through the gateway instead.

### What the gateway governs (and what it does not)

| Traffic type | Governed by gateway? |
|---|---|
| Staff using ChatGPT, Claude.ai, Gemini directly | Yes — block at firewall, route through gateway |
| Departmental AI tools using OpenAI/Anthropic APIs | Yes — reconfigure to point at gateway URL |
| Microsoft 365 Copilot | No — governed through your Microsoft tenant and data processing agreement |
| GitHub Copilot | No — uses a separate authentication flow outside the gateway |

Microsoft 365 Copilot is a licensed, contracted tool that operates
entirely within your M365 tenant. It does not require gateway routing.
The gateway addresses discretionary and ungoverned AI use — the tools
staff are using outside your licensed agreements.

---

### On-network enforcement

#### Step 1 — Block direct AI service access at the firewall

Add outbound deny rules for the following domains on your perimeter
firewall or DNS filtering appliance (Cisco Umbrella, Cloudflare Gateway,
Palo Alto, pfSense, etc.):

**OpenAI / ChatGPT**
```
api.openai.com
chatgpt.com
chat.openai.com
```

**Anthropic / Claude**
```
api.anthropic.com
claude.ai
```

**Google Gemini**
```
generativelanguage.googleapis.com
gemini.google.com
aistudio.google.com
```

**Other common services**
```
api.cohere.com
api.mistral.ai
```

#### Step 2 — Allow gateway outbound traffic only

Permit outbound traffic from the gateway server to AI provider APIs.
All other workstations should have those domains blocked. Staff
workstations only need access to your gateway's internal or hosted
address.

#### Step 3 — Issue API keys to staff

Each staff member or department receives a gateway-issued API key.
Keys are individually scoped, logged, and revocable without affecting
other users.

---

### Off-network enforcement (remote and hybrid staff)

Firewall rules only apply on the municipal network. Staff working from
home or on personal hotspots bypass on-network controls. Choose one or
more of the following approaches:

#### Option A — Split-tunnel VPN (recommended for most municipalities)

Configure your VPN client to route AI service domains back through the
municipal network when staff are off-site. If your staff already VPN in
for remote work, enforcement extends automatically — no additional
tooling required.

Domains to include in your VPN split-tunnel policy are the same as the
firewall block list above.

#### Option B — Device-level DNS filtering

Deploy a DNS filtering agent directly to managed devices via MDM
(Microsoft Intune, Jamf, Mosyle). Tools like Cloudflare Gateway for
Teams or Cisco Umbrella Roaming Client enforce block rules regardless
of network — home wifi, personal hotspot, or coffee shop.

This is the strongest enforcement option and follows the device
everywhere.

#### Option C — Browser policy via Intune or Group Policy

Push URL block policies to managed browsers (Edge, Chrome) via
Microsoft Intune or Group Policy. Device-level enforcement that does
not require DNS filtering infrastructure.

> **Note:** Options B and C require managed devices enrolled in your
> MDM. Personally-owned devices used for work (BYOD) cannot be
> enforced at the device level without explicit MDM enrollment.

---

### What the gateway logs

Every request passing through the gateway is logged with:

- Timestamp
- Staff member (identified by API key)
- AI provider and model requested
- Token count (input and output)
- PII detection events (detection only — no content is stored)
- Response status and latency

Logs are stored in PostgreSQL. Retention period is configurable to
match your municipality's records retention schedule.

---

### Deployment assistance

Contact joy@luminaryx.ca for deployment support, firewall rule
templates, or Intune configuration guidance.

---

## Backups and restore

The gateway runs a daily automated backup of the PostgreSQL database at 2:00 AM. Backups are gzip-compressed SQL files stored in a Docker volume. The last 30 days are kept by default (configurable via `BACKUP_RETENTION_DAYS`).

### On-demand backup

```bash
./scripts/backup-now.sh
```

This creates a timestamped backup file (e.g. `ai_gateway_20260403_143200.sql.gz`) in your current directory.

### Restore from backup

```bash
./scripts/restore.sh ai_gateway_20260403_143200.sql.gz
```

The script stops the gateway, restores the database, and restarts the gateway. It prompts for confirmation before overwriting data.

### List automated backups

```bash
docker compose exec backup ls -lh /backups/
```

---

## Upgrading

To upgrade to a new version:

```bash
./scripts/upgrade.sh
```

The upgrade script:

1. Backs up the database (saved as `pre_upgrade_<timestamp>.sql.gz`)
2. Pulls the latest tagged release from git
3. Rebuilds Docker containers
4. Runs database migrations automatically
5. Verifies the health check passes
6. **Rolls back automatically** if the health check fails

If something goes wrong, the gateway reverts to the previous version and preserves the backup file for manual investigation.

---

## What gets logged

Every request that passes through the gateway is recorded in PostgreSQL with a tamper-evident hash chain. No request content is stored — only metadata.

Here is what a single audit log entry looks like when retrieved from `GET /admin/requests`:

```json
{
  "id": 4217,
  "timestamp": "2026-04-03T14:32:07.881Z",
  "provider": "openai",
  "method": "POST",
  "path": "/v1/openai/v1/chat/completions",
  "response_status": 200,
  "source_ip": "10.0.1.42",
  "duration_ms": 1823,
  "pii_detections_request": 3,
  "pii_detections_response": 0,
  "pii_types_found": "CA_SIN,EMAIL_ADDRESS,PERSON",
  "department": "Planning",
  "staff_key_id": 12,
  "model": "gpt-4o",
  "input_tokens": 847,
  "output_tokens": 312,
  "estimated_cost_cents": 4
}
```

Each entry records:

| Field | What it tells you |
|---|---|
| `pii_detections_request` | Number of PII items found and scrubbed from the outgoing request |
| `pii_detections_response` | Number of PII items found and scrubbed from the AI provider's response |
| `pii_types_found` | Comma-separated list of detected PII categories (e.g. `CA_SIN`, `PERSON`, `EMAIL_ADDRESS`) |
| `department` | Which department sent the request |
| `model` | Which AI model was used |
| `input_tokens` / `output_tokens` | Token counts for cost tracking |
| `estimated_cost_cents` | Estimated cost based on provider pricing |

The hash chain (`previous_hash`, `chain_hash`) links each entry to the one before it. If any record is altered or deleted after the fact, the chain breaks and the tampering is detectable. This gives your CAO and auditors a provably intact record.

---

## PII scrubbing in action

The gateway detects and removes Canadian personal information before any request reaches an AI provider. Here is what happens when a staff member sends a prompt containing PII.

**What the staff member sends:**

```
Look up the file for Jane Smith, 742 Evergreen Terrace, Vancouver BC
V5K 0A1. Her SIN is 046-454-286 and her email is jane.smith@example.com.
Phone: 604-555-0123.
```

**What the AI provider actually receives:**

```
Look up the file for [NAME REMOVED], [ADDRESS REMOVED], [ADDRESS REMOVED]
[POSTAL CODE REMOVED]. Her SIN is [SIN REMOVED] and her email is [EMAIL REMOVED].
Phone: [PHONE REMOVED].
```

The gateway validates SINs using the Luhn checksum algorithm — the same method used by the CRA. A random nine-digit number like `123-456-789` is correctly ignored because it fails the checksum. The test SIN above (`046-454-286`) passes and is caught.

**Detected PII types:**

| Type | Example | Replacement |
|---|---|---|
| `CA_SIN` | 046-454-286 | `[SIN REMOVED]` |
| `CA_BC_PHN` | 9876 543 210 | `[BC PHN REMOVED]` |
| `CA_POSTAL_CODE` | V5K 0A1 | `[POSTAL CODE REMOVED]` |
| `CA_PHONE_NUMBER` | 604-555-0123 | `[PHONE REMOVED]` |
| `EMAIL_ADDRESS` | jane@example.com | `[EMAIL REMOVED]` |
| `PERSON` | Jane Smith | `[NAME REMOVED]` |
| `LOCATION` | 742 Evergreen Terrace | `[ADDRESS REMOVED]` |

Provincial health numbers are supported for BC (PHN), Alberta (PHN), Ontario (OHIP), and Quebec (RAMQ).

### Custom scrubbing rules

Municipalities can add their own PII patterns without touching Python code. Edit `gateway/scrubbing_rules.yaml` and restart the gateway.

For example, to scrub employee IDs in the format `EMP-12345`:

```yaml
custom_rules:
  - name: EMPLOYEE_ID
    pattern: '\bEMP-\d{5}\b'
    replacement: '[REDACTED-EMPLOYEE-ID]'
    enabled: true
```

Each rule needs a unique `name` (used in audit logs and `pii_types_found`), a valid Python regex `pattern`, a `replacement` string, and an `enabled` flag. Set `enabled: false` to disable a rule without deleting it. The gateway validates regex syntax at startup and skips invalid patterns with a warning.

After editing, restart the gateway:

```bash
docker compose restart gateway
```

---

## Releases

### Tagging a release

Releases follow [Semantic Versioning](https://semver.org). To create a new release:

```bash
# Tag the release
git tag -a v1.1.0 -m "v1.1.0 — Redis rate limiting, per-admin MFA, LDAP integration"

# Push the tag
git push origin v1.1.0
```

Then create a GitHub release from the tag:

```bash
gh release create v1.1.0 --title "v1.1.0" --notes-file CHANGELOG.md
```

Or create the release manually at **github.com → Releases → Draft a new release**, selecting the tag and pasting the relevant section from [CHANGELOG.md](CHANGELOG.md).

### Version history

| Version | Date | Highlights |
|---|---|---|
| [1.1.0](CHANGELOG.md) | 2026-04-03 | Redis rate limiting, per-admin MFA, LDAP/AD integration, Caddy TLS, PostgreSQL backups |
| [1.0.0](CHANGELOG.md) | 2026-04-02 | Initial release — PII scrubbing, audit trail, API proxying, Docker deployment |

---

## Security

For security vulnerability reporting, see [SECURITY.md](SECURITY.md).

The gateway enforces the following protections:

- **JWT secret validation** — refuses to start if `GATEWAY_SECRET` is missing or under 32 characters
- **Login brute force protection** — admin login is rate limited to 10 attempts per 15 minutes per IP; all failures are logged to PostgreSQL
- **HTTP security headers** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, HSTS, CSP, Referrer-Policy, and Permissions-Policy on all responses
- **No hardcoded secrets** — the gateway and Docker Compose refuse to start with default or missing credentials
- **Database connection pooling** — bounded connections prevent resource exhaustion under load
- **Hash-chained audit trail** — tamper-evident logging that breaks visibly if records are altered

---

## Ready for full AI governance?

The gateway handles the **technical layer**: what staff are sending and what PII was detected.

[LUMINARYX™](https://luminaryx.ca) handles the **governance layer**: documented decision approvals, regulatory framework mapping, board-ready compliance reports, and a defensible audit trail for your CAO and council.

Together they answer every question a privacy commissioner will ask.

**Learn more: [luminaryx.ca](https://luminaryx.ca)**

---

## Try it for a month

Deploy the gateway, let it run for 30 days, and look at the dashboard. Most municipalities are genuinely surprised by how many AI interactions are happening across their organization without any oversight. When you are ready to talk about what you found, send an email to [joy@luminaryx.ca](mailto:joy@luminaryx.ca).

---

## License

MIT. Free to use, deploy, and modify. See [LICENSE](LICENSE).

---

<p align="center">
Powered by <a href="https://luminaryx.ca">LUMINARYX™</a>. Municipal AI governance for Canadian local government.
</p>
