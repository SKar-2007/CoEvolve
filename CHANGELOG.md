# Changelog

All notable changes to CoEvolve Sandbox are documented here.

## [0.1.0] - 2026-09-12

### Added

#### Core Pipeline
- **Training Loop Controller** — full co-evolutionary orchestrator wiring all agents
- **Attacker Agent** — adversarial task generator with 10+ vulnerability classes and difficulty scaling
- **Developer Agent** — ReAct tool-use agent with 7 tools (read, write, shell, search, tests, git)
- **Hybrid Judge** — two-stage evaluation: Semgrep SAST scanning + dynamic DAST exploit replay
- **Distiller Agent** — converts failure traces into imperative security rules
- **Regression Guard** — validates new rules against all previously-passing tasks
- **Elo Rating** — zero-sum adaptive difficulty matching (10 tiers, 1000-2500 range)

#### Prompt Evolution
- **Git-Backed Store** — each prompt version committed with full audit trail
- **Branch Support** — create, switch, and merge parallel evolution branches
- **Rollback** — restore any previous prompt version
- **Semantic Deduplication** — sentence-transformers cosine similarity with Jaccard fallback

#### Infrastructure
- **FastAPI API** — 16 REST endpoints for episodes, prompts, rules, Elo, training, jobs
- **Redis Task Queue** — async training jobs with in-memory fallback
- **Docker Sandbox** — 7-layer container isolation with seccomp profiles
- **Telemetry** — Prometheus metrics + Grafana dashboards
- **Alerting** — Slack, Email (SMTP), PagerDuty notification channels
- **Cost Tracking** — per-call token counting with provider-specific pricing
- **LLM Caching** — LRU cache for deterministic calls (temperature=0)

#### Testing
- 127 tests (44 unit + 83 integration)
- CI pipeline: lint, typecheck, tests, coverage
- Security scanning: detect-secrets, pip-audit, Trivy

#### Deployment
- Docker Compose for development and production
- Production hardening: resource limits, log rotation, health checks
- Full deployment guide with SSL, backups, scaling

#### Documentation
- Architecture diagrams, API reference, configuration docs
- CONTRIBUTING.md, DEPLOY.md, README with Makefile commands
