# Deployment Guide

Production deployment of CoEvolve Sandbox using Docker Compose or Render.

## Deploy to Render

`render.yaml` provisions the web service only — create the backing services
first (free-tier database plans change often, so they are deliberately not
in the blueprint):

1. **Postgres** — Supabase, Neon, or Render Postgres. Copy the connection
   string (pooled, port 6543 for Supabase).
2. **Redis** — Upstash or Render Key Value. Copy the `redis://` URL.
3. **Deploy the blueprint** (`render.yaml`) in the Render dashboard.
4. **Set env vars** (all `sync: false` entries must be filled manually):

   | Variable | Value |
   |----------|-------|
   | `DATABASE_URL` | Postgres connection string |
   | `REDIS_URL` | Redis URL (enables async jobs + shared rate limiter) |
   | `GROQ_API_KEY` | At least one LLM provider key |
   | `ADMIN_API_KEY` | `cov_...` bootstrap admin credential (only its hash is stored) |
   | `CORS_ORIGINS` | Your frontend origin, e.g. `https://app.example.com` |
   | `REQUIRE_AUTH` / `API_KEY_STORE` | Pre-set to `true` / `db` — leave as is |

5. **Verify**: `curl https://<your-service>/health` → `{"status":"healthy"}`.

Without `REDIS_URL` the API still runs, but async `/training/jobs` only
works single-process and rate limits are per-instance.

## Deploy with Docker Compose

#### Prerequisites

- Docker 24+ with Compose v2
- 4+ CPU cores, 8GB+ RAM
- Domain name with DNS pointing to your server
- SSL certificates (or use a reverse proxy like Caddy/Nginx)

## Quick Start (5 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/SKar-2007/CoEvolve.git
cd CoEvolve

# 2. Create production environment
cp .env.example .env
# Edit .env with your secrets (see Configuration below)

# 3. Build the sandbox image
make build-sandbox

# 4. Start all services
make docker-prod

# 5. Verify
curl http://localhost:8000/health
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes* | Anthropic API key |
| `OPENAI_API_KEY` | Yes* | OpenAI API key |
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password |
| `GRAFANA_PASSWORD` | No | Grafana admin password |
| `REQUIRE_AUTH` | Yes | Set `true` — requires `X-API-Key` on mutating endpoints |
| `API_KEY_STORE` | Yes | Set `db` — persists keys in Postgres, shared across workers |
| `ADMIN_API_KEY` | Yes | Bootstrap admin credential (only its hash is stored) |
| `CORS_ORIGINS` | Yes | Comma-separated allowed origins, e.g. `https://app.example.com` |

*At least one LLM provider key is required.

### Generating Secrets

```bash
# Generate a secure PostgreSQL password
openssl rand -base64 24

# Generate a bootstrap admin API key (store it in a password manager —
# the raw value is shown only at creation and never logged)
python -c "import secrets; print('cov_' + secrets.token_urlsafe(32))"
```

### API Keys

With `API_KEY_STORE=db`, keys survive restarts and are shared across
uvicorn workers. `ADMIN_API_KEY` from `.env` is registered automatically on
first startup (idempotent). Create further keys from a shell with the
database reachable, e.g.:

```bash
DATABASE_URL=postgresql://... python -c "
from packages.api.auth import DBAPIKeyStore
print(DBAPIKeyStore().create_key('ops-admin', tier='admin').key)
"
```

### Docker Socket (read before deploying)

The `api` service mounts `/var/run/docker.sock` because the sandbox feature
spawns per-episode containers. A compromised API container means Docker
daemon control on that host. Mitigations already applied: required-secrets
validation (fail-fast), `no-new-privileges`, resource limits, non-root app
user. If this risk is unacceptable for your environment, run the sandbox
against a dedicated Docker host over TLS or a rootless daemon instead of the
local socket.

## Architecture

```
                    ┌─────────────┐
                    │   Nginx/    │
                    │   Caddy     │
                    │  (TLS)      │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │   API       │
                    │ (uvicorn)   │
                    └──────┬──────┘
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴───┐ ┌─────┴─────┐
        │ PostgreSQL │ │ Redis │ │ Prometheus│
        └───────────┘ └───────┘ └───────────┘
```

## Production Hardening

### SSL/TLS (Recommended)

Use a reverse proxy for TLS termination:

```nginx
# /etc/nginx/sites-available/coevolve
server {
    listen 443 ssl http2;
    server_name coevolve.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/coevolve.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/coevolve.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall

```bash
# Allow only SSH and HTTPS
ufw allow 22/tcp
ufw allow 443/tcp
ufw enable
```

### Database Backup

```bash
# Backup
docker compose -f docker-compose.prod.yml exec db \
  pg_dump -U coevolve coevolve > backup_$(date +%Y%m%d).sql

# Restore
cat backup_20260912.sql | docker compose -f docker-compose.prod.yml exec -T db \
  psql -U coevolve coevolve
```

### Log Rotation

Docker logs are configured with rotation in the compose file:
- API: 50MB max, 5 files
- Database: 20MB max, 3 files
- Redis: 10MB max, 3 files

## Operations

### Start/Stop

```bash
# Start all services
make docker-prod

# Stop all services
make docker-prod-down

# View logs
make docker-logs

# Check status
make docker-status
```

### Monitoring

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **API Metrics**: http://localhost:8000/metrics

### Updating

```bash
# Pull latest code
git pull origin main

# Rebuild API image
docker compose -f docker-compose.prod.yml build api

# Restart API (zero-downtime with replicas)
docker compose -f docker-compose.prod.yml up -d api
```

## Troubleshooting

### API won't start

```bash
# Check logs
docker compose -f docker-compose.prod.yml logs api

# Common issues:
# - Missing API key: ensure ANTHROPIC_API_KEY or OPENAI_API_KEY is set
# - Database not ready: wait for health check to pass
# - Port in use: change API_PORT in .env
```

### Database connection refused

```bash
# Check if PostgreSQL is running
docker compose -f docker-compose.prod.yml ps db

# Test connection
docker compose -f docker-compose.prod.yml exec db \
  pg_isready -U coevolve
```

### Out of memory

```bash
# Check resource usage
docker stats

# Increase memory limits in docker-compose.prod.yml
# Or add swap space:
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Scaling

### Multiple API Workers

Edit `docker-compose.prod.yml`:

```yaml
api:
  # ... existing config ...
  deploy:
    replicas: 3
    resources:
      limits:
        cpus: "1.0"
        memory: 1G
```

### External Database

For managed PostgreSQL (AWS RDS, GCP Cloud SQL):

1. Update `DATABASE_URL` in `.env`
2. Remove the `db` service from compose
3. Update `depends_on` in the API service

### External Redis

For managed Redis (AWS ElastiCache, Redis Cloud):

1. Update `REDIS_URL` in `.env`
2. Remove the `redis` service from compose
3. Update `depends_on` in the API service

## Security Checklist

- [ ] PostgreSQL not exposed to public (bound to 127.0.0.1)
- [ ] Redis not exposed to public (bound to 127.0.0.1)
- [ ] Strong passwords for all services
- [ ] `.env` file not committed to Git
- [ ] Docker socket access restricted
- [ ] SSL/TLS enabled
- [ ] Firewall configured
- [ ] Regular backups configured
- [ ] Log rotation enabled
- [ ] Resource limits set
