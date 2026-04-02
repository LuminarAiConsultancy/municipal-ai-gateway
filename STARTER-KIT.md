# Municipal AI Governance Starter Kit

Everything you need to go from "we should do something about AI" to a running governance program.

---

## Technical Layer (this repo)

Install the gateway, create staff keys, and start monitoring AI usage across your organization in under an hour.

```bash
git clone https://github.com/LuminarAiConsultancy/municipal-ai-gateway.git
cd municipal-ai-gateway
docker compose up
```

See the [README](README.md) for full setup instructions and the [Deployment Guide](docs/DEPLOYMENT.md) for production hardening.

---

## Governance Documents

These templates are ready to customize for your municipality. Download them from the `docs/` folder or use the links below.

### 1. CAO Briefing Note

**What it is:** A one-page briefing for your Chief Administrative Officer explaining the AI governance gap, the proposed solution, and the ask.

**Use it when:** You need executive approval to deploy the gateway and begin formalizing AI governance.

📄 [docs/Municipal-AI-Gateway-IT-Guide.docx](docs/Municipal-AI-Gateway-IT-Guide.docx)

### 2. Acceptable Use Policy Template

**What it is:** A draft policy defining permitted AI uses, prohibited uses, data handling requirements, and staff responsibilities.

**Use it when:** Council or the CAO asks "what's our AI policy?" This gives them something to review and approve.

📄 [docs/Municipal-AI-Gateway-Enforcement-Guide.docx](docs/Municipal-AI-Gateway-Enforcement-Guide.docx)

### 3. 30-Day Report Template

**What it is:** A structured template for reporting on the first 30 days of gateway operation -- request volumes, PII detection rates, department breakdown, and recommended next steps.

**Use it when:** You've been running the gateway for a month and need to report results to the CAO or council.

📄 *Coming soon -- will be generated from your gateway's actual data*

### 4. Privacy Impact Assessment Template

**What it is:** A PIA template structured for Canadian municipal AI use, covering data flows, risk assessment, and mitigation measures.

**Use it when:** Your privacy officer or FOIPP coordinator needs a formal PIA on file before the gateway goes into production.

📄 *Coming soon*

---

## The Full Picture

| Layer | Covers | Provided by |
|-------|--------|-------------|
| **Technical controls** | PII scrubbing, audit logging, rate limiting, cost tracking | Municipal AI Gateway (this repo) |
| **Policy documents** | Acceptable use, briefing notes, PIA templates | Starter Kit (above) |
| **Governance program** | Decision approvals, regulatory mapping, compliance reporting, commissioner-ready audit trail | [LUMINARYX](https://luminaryx.ca) |

The gateway and starter kit get you running. [LUMINARYX](https://luminaryx.ca) makes it defensible.
