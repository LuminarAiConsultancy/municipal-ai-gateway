# Deployment

This guide covers deploying the Municipal AI Gateway and routing traffic through it so the 30-day picture is accurate. Read the "What the Gateway can and cannot see" section before you start. It explains what an honest test requires and what no proxy can capture.

## Quick start

```bash
git clone https://github.com/LuminarAiConsultancy/municipal-ai-gateway.git
cd municipal-ai-gateway
cp .env.example .env
# edit .env, then:
docker compose up -d
```

The admin dashboard is at `/admin`. TLS is handled automatically by Caddy and Let's Encrypt once you point a domain at the host.

## What the Gateway can and cannot see

The Gateway is a network proxy. It governs the AI traffic that passes through it, and it cannot govern traffic that does not. This is not a limitation to work around. It is the actual shape of the problem, and an honest 30-day test depends on understanding it.

**What it sees:** any AI request routed through the proxy. Once routing is in place on a managed device, every interaction is scrubbed for Canadian personal information, logged, and added to the tamper-evident audit trail.

**What it does not see:**

- AI used on personal or unmanaged devices, for example a staff member using a consumer app on a personal phone over cellular data. That traffic never touches the municipal network.
- AI built into software that runs on-device and makes no outbound API call, for example assistant features embedded in an operating system or desktop application.

No network tool closes these gaps, and no vendor honestly claims to. The defensible posture is not total prevention. It is a governed channel for the work that should be governed, a record you can stand behind, and a written policy for everything else.

## Routing traffic so the test is honest

To make the dashboard reflect reality on the devices you control, you need the Gateway to be the only path from those devices to external AI providers. There are three layers, in order of how much they tighten the picture.

### 1. Point AI tools at the Gateway

Configure each AI tool or integration to use the Gateway's URL as its API base instead of the provider's direct endpoint. The Gateway proxies OpenAI, Anthropic, and Google AI. Staff authenticate with a per-person API key issued from the admin dashboard, or auto-provisioned through LDAP / Active Directory if you have that configured.

This alone captures everything staff route deliberately. It does not stop someone from bypassing it, which is what the next layer addresses.

### 2. Block direct provider endpoints at the firewall

On the managed network, block outbound access to the AI providers' direct API domains so the only reachable path is through the Gateway. At minimum:

- `api.openai.com`
- `api.anthropic.com`
- `generativelanguage.googleapis.com`

With these blocked, a tool pointed at a direct endpoint fails rather than quietly leaving the network ungoverned. Add provider domains as your tool set grows. Keep the list in version control alongside the rest of your network configuration so changes are reviewable.

### 3. Control the device with MDM

Mobile device management on municipal-owned machines lets you push the Gateway configuration, restrict which AI applications can be installed, and apply the firewall and proxy settings above consistently rather than relying on each user to configure their own machine. This is what turns "we asked staff to route through the Gateway" into "the managed devices route through the Gateway by default."

### What the three layers add up to

Layers 1 through 3 give you an accurate picture on every device the municipality controls. They do nothing for personal devices, and they should not try to. That boundary is closed by policy, not configuration: an acceptable-use rule stating that municipal information goes through approved channels, backed by the audit trail that gives the rule evidence.

A defensible position is the combination, not any single piece: a governed channel, a record of what flowed through it, and a policy for what falls outside it.

## Running the 30-day test

1. Deploy the Gateway and confirm the dashboard is reachable at `/admin`.
2. Route AI tools on managed devices through it (layer 1), and tighten with layers 2 and 3 as your environment allows.
3. Let it run for 30 days without changing anything.
4. Review the dashboard. Note both the volume of governed interactions and the categories of personal information that were scrubbed before leaving the network.

The number that usually surprises people is not the personal information caught. It is the sheer volume of AI interaction already happening across the organization with no prior oversight.

When you are ready to talk about what the dashboard showed you, email joy@luminaryx.ca.

## Configuration reference

Key environment variables (see `.env.example` for the full list):

| Variable | Purpose |
|----------|---------|
| `LOG_RETENTION_DAYS` | How long request logs are kept before the retention policy removes them |
| `JWT_SECRET` | Validated on startup; the Gateway refuses to start if unset or weak |

Daily PostgreSQL backups run with 30-day retention by default. Rate limiting, brute-force protection, TOTP multi-factor authentication, and HTTP security headers are described in [CHANGELOG.md](https://github.com/LuminarAiConsultancy/municipal-ai-gateway/blob/main/CHANGELOG.md).
