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

```bash
git clone https://github.com/LuminarAiConsultancy/municipal-ai-gateway.git
cd municipal-ai-gateway
docker compose up
```

Full setup documentation coming soon.

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

## Project status

Active development. Not yet production-ready. Contributions welcome.

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the full product specification, competitive landscape analysis, and architecture decisions.

---

## Ready for full AI governance?

The gateway handles the **technical layer** -- what staff are sending and what PII was detected.

[LUMINARYX](https://luminaryx.ca) handles the **governance layer** -- documented decision approvals, regulatory framework mapping, board-ready compliance reports, and a defensible audit trail for your CAO and council.

Together they answer every question a privacy commissioner will ask.

**Learn more: [luminaryx.ca](https://luminaryx.ca)**

---

## License

MIT -- free to use, deploy, and modify. See [LICENSE](LICENSE).

---

<p align="center">
Built to complement <a href="https://luminaryx.ca">LUMINARYX</a> -- municipal AI governance for Canadian local government.
</p>
