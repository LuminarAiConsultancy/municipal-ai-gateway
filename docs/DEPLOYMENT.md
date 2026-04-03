# Canadian Municipal AI Gateway — Production Deployment Guide

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A server with at least 2 GB RAM (spaCy NLP model requires ~1 GB)
- A domain name with DNS pointing to your server
- TLS certificate (Let's Encrypt recommended)

## 1. Environment Setup

Copy the production environment template and fill in real values:

```bash
cp .env.production.example .env
```

**Required secrets:**
- `GATEWAY_SECRET` — Admin dashboard password (generate with `openssl rand -hex 32`)
- `POSTGRES_PASSWORD` — Database password (generate with `openssl rand -hex 24`)
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` — Provider API keys (set only the ones you use)

**Never commit `.env` to version control.** The `.gitignore` already excludes it.

## 2. TLS Termination

Place a reverse proxy (Caddy, nginx, or Traefik) in front of the gateway.

### Caddy (recommended — auto TLS)

```
gateway.yourmunicipality.ca {
    reverse_proxy localhost:8080
}
```

### nginx

```nginx
server {
    listen 443 ssl;
    server_name gateway.yourmunicipality.ca;

    ssl_certificate     /etc/letsencrypt/live/gateway.yourmunicipality.ca/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gateway.yourmunicipality.ca/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

## 3. Firewall

Only expose ports 80 and 443 to the network. The gateway (8080) and PostgreSQL (5432) should be accessible only from localhost.

```bash
# UFW example
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 8080/tcp
ufw deny 5432/tcp
ufw enable
```

## 4. Start the Gateway

```bash
docker compose up -d --build
```

Verify:
```bash
curl -s http://localhost:8080/health
# {"status":"ok"}
```

## 5. Create Your First Staff Key

```bash
curl -s -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer YOUR_GATEWAY_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"department": "IT", "description": "Gateway admin"}' | python -m json.tool
```

## 6. Database Backups

Schedule daily PostgreSQL backups:

```bash
# Add to crontab: 0 2 * * *
docker compose exec db pg_dump -U gateway ai_gateway | gzip > /backups/ai_gateway_$(date +%Y%m%d).sql.gz
```

Retain at least 30 days of backups. Test restores quarterly.

## 7. Log Rotation

Gateway logs go to Docker's logging driver. Configure rotation in `docker-compose.yml`:

```yaml
services:
  gateway:
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
```

## 8. Monitoring

- **Health check:** `GET /health` — returns `{"status": "ok"}`
- **Audit chain:** `GET /audit/verify` — confirms tamper-evident log integrity
- **Dashboard:** Open `dashboard/index.html` in a browser, connect with your gateway URL and admin secret

Set up an uptime monitor (e.g., UptimeRobot, Healthchecks.io) to ping `/health` every 60 seconds.

## 9. Updating

```bash
git pull origin main
docker compose up -d --build
```

The gateway auto-migrates database tables on startup via SQLAlchemy `create_all()`.

## 10. Security Checklist

- [ ] `.env` file has strong, unique passwords (32+ hex chars)
- [ ] TLS enabled — no plaintext HTTP in production
- [ ] Firewall blocks direct access to ports 8080 and 5432
- [ ] Provider API keys have spending limits set in their respective dashboards
- [ ] Database backups are scheduled and tested
- [ ] Department policies configured with appropriate rate limits and budget caps
- [ ] Staff keys issued per-person, not shared
- [ ] Audit chain verified periodically via dashboard or `/audit/verify`
