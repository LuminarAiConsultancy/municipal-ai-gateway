# Municipal AI Gateway

> Open-source AI governance proxy gateway for Canadian municipalities and public sector organizations.

Your staff are already using ChatGPT, Copilot, Gemini, and Claude. This gateway makes that safe and auditable without blocking anyone.

---

## The problem

In a 2025 KPMG Canada survey, nearly half of Canadian public servants reported using AI tools at work while fewer than a quarter of their organizations had formally adopted AI. Nobody knows what data is going out. Nobody has an audit trail. If a privacy breach happens, the CAO and council are exposed.

Blocking AI tools does not work. Staff use personal phones and personal accounts. You lose all visibility and productivity suffers.

The Municipal AI Gateway is a third option.

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
git clone https://github.com/LuminarAiConsultancy/municipal-ai-gateway.git
cd municipal-ai-gateway
cp .env.example .env
```

Open `.env` in any text editor and fill in your values. Here is every variable the gateway uses:

| Variable | Required? | What it is |
|----------|-----------|------------|
| `GATEWAY_SECRET` | **Yes** | A random string that protects the admin dashboard and admin API. Generate one by running `openssl rand -hex 32` in your terminal. |
| `POSTGRES_PASSWORD` | **Yes** | The database password. Change this from the default. Any strong password works. |
| `OPENAI_API_KEY` | If using OpenAI | Your organization's OpenAI API key from [platform.openai.com/api-keys](https://platform.openai.com/api-keys). Only needed if staff use ChatGPT or OpenAI tools. |
| `ANTHROPIC_API_KEY` | If using Anthropic | Your organization's Anthropic API key from [console.anthropic.com](https://console.anthropic.com). Only needed if staff use Claude. |
| `GOOGLE_API_KEY` | If using Google | Your organization's Google AI API key from [aistudio.google.com/apikey](https://aistudio.google.com/apikey). Only needed if staff use Gemini. |
| `POSTGRES_USER` | No | Database username. Default is `gateway`. Leave it unless your IT policies require a specific name. |
| `POSTGRES_DB` | No | Database name. Default is `ai_gateway`. Leave it unless you have a reason to change it. |
| `DATABASE_URL` | No | Full database connection string. If you changed `POSTGRES_PASSWORD`, update the password in this URL to match. Otherwise leave the default. |
| `GATEWAY_PORT` | No | Port the gateway listens on. Default is `8080`. Change only if that port is already in use. |
| `LOG_LEVEL` | No | How much detail appears in logs. Default is `info`. Set to `debug` only when troubleshooting. |
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

The `-k` flag tells curl to accept the self-signed certificate. Expected response:

```json
{"status": "ok"}
```

Or open `https://localhost/health` in your browser. Your browser will warn about the self-signed certificate. Click through the warning (this is expected for local testing). If you see `{"status":"ok"}`, the gateway is running with HTTPS.

HTTP requests to `http://localhost` are automatically redirected to HTTPS. Port 8080 is also available for direct HTTP access during testing.

The admin dashboard is at `https://localhost/dashboard`. Enter your `GATEWAY_SECRET` value as the admin secret when prompted.

### Replace the self-signed certificate for production

The gateway ships with an auto-generated self-signed certificate for local testing. Before deploying to production, replace it with a real certificate from Let's Encrypt or your organization's certificate authority.

**Option A: Let's Encrypt (recommended for internet-facing servers)**

Stop the gateway, then run certbot on the host machine:

```bash
docker compose down
sudo certbot certonly --standalone -d your-domain.ca
```

Copy the certificate files into the gateway's certificate volume:

```bash
docker compose up -d
docker compose cp /etc/letsencrypt/live/your-domain.ca/fullchain.pem nginx:/etc/nginx/ssl/cert.pem
docker compose cp /etc/letsencrypt/live/your-domain.ca/privkey.pem nginx:/etc/nginx/ssl/key.pem
docker compose restart nginx
```

**Option B: Your own certificate authority**

If your municipality issues its own certificates, copy the `.pem` files into the running nginx container:

```bash
docker compose cp your-cert.pem nginx:/etc/nginx/ssl/cert.pem
docker compose cp your-key.pem nginx:/etc/nginx/ssl/key.pem
docker compose restart nginx
```

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

Beta. Suitable for pilot deployments with IT support. Contributions welcome.

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the full product specification, competitive landscape analysis, and architecture decisions.

---

## What is not built yet

This is an honest accounting of what the README describes versus what the code delivers today.

**Before-pilot blockers:**

- ~~**HTTPS/TLS termination**~~: Resolved. The gateway now includes an nginx reverse proxy that terminates TLS on port 443 with automatic self-signed certificate generation. See the setup guide for instructions on replacing with a production certificate.
- ~~**Dashboard policy management**~~: Resolved. The admin dashboard at `/dashboard` now includes a Department Policies panel for viewing, creating, and editing department policies (rate limits, model allowlists, budget caps).
- ~~**Provincial privacy law mapping**~~: Partially resolved. The `/frameworks` endpoint now returns the active provincial framework when `PROVINCE` is set in `.env`. BC FIPPA is fully mapped with PII type coverage, legal sections, and retention periods. Alberta FOIPP, Ontario MFIPPA, and Quebec Law 25 have framework structure and key requirements but incomplete PII coverage mapping.
- ~~**Database migrations**~~: Resolved. Alembic migrations run automatically on `docker compose up`. Schema changes are version-controlled and applied without manual SQL.

**Post-launch improvements:**

- **LDAP / Active Directory integration**: Staff authenticate with gateway-issued API keys only. There is no integration with municipal Active Directory or LDAP, so each staff member needs a manually created key.
- **Multi-instance rate limiting**: The rate limiter runs in memory and resets when the gateway restarts. Fine for single-server deployments. Larger deployments behind a load balancer would need a shared store like Redis.
- **MFA for admin dashboard**: The admin dashboard uses a single shared secret. There are no per-administrator accounts or multi-factor authentication.
- **Email or webhook alerts**: No automated notifications when PII is detected, a budget cap is approached, or the audit chain fails verification. Administrators must check the dashboard.
- **Copilot proxy support**: The gateway proxies OpenAI, Anthropic, and Google APIs. GitHub Copilot uses a different authentication flow that is not yet supported.

---

## Verify PII scrubbing is working

Once the gateway is running with at least one AI provider configured, you can send a test request containing personal information and confirm the gateway catches it.

First, create a test staff key:

```bash
curl -sk https://localhost/admin/keys \
  -H "Authorization: Bearer YOUR_GATEWAY_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"department": "Testing", "description": "PII verification test"}'
```

Copy the `key` value from the response. Then send a request containing obvious PII:

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

Now check the audit log to see what the gateway caught:

```bash
curl -sk https://localhost/admin/requests \
  -H "Authorization: Bearer YOUR_GATEWAY_SECRET"
```

In the most recent entry, `pii_detections_request` shows how many PII items were found and `pii_types_found` lists the types detected (such as `CA_SIN,EMAIL_ADDRESS,LOCATION,PERSON`). The AI provider never saw the original personal information. It received `[NAME REMOVED]`, `[SIN REMOVED]`, `[EMAIL REMOVED]`, and `[ADDRESS REMOVED]` instead.

The gateway validates SINs using the Luhn checksum algorithm, the same method used by the CRA and financial institutions. The test SIN above (046-454-286) passes the checksum and will be detected. A random sequence like 123-456-789 is correctly ignored because it fails the checksum. This prevents false positives on ordinary numbers that happen to be nine digits long.

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
