# Deployment Guide

Production deployment of CoEvolve Sandbox using Docker Compose.

## Prerequisites

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
| `JWT_SECRET` | Yes | JWT signing secret (use `openssl rand -hex 32`) |
| `GRAFANA_PASSWORD` | No | Grafana admin password |

*At least one LLM provider key is required.

### Generating Secrets

```bash
# Generate a secure JWT secret
openssl rand -hex 32

# Generate a secure PostgreSQL password
openssl rand -base64 24
```

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
