# CoEvolve Sandbox

[![CI](https://github.com/SKar-2007/CoEvolve/actions/workflows/ci.yml/badge.svg)](https://github.com/SKar-2007/CoEvolve/actions/workflows/ci.yml)
[![Security](https://github.com/SKar-2007/CoEvolve/actions/workflows/security.yml/badge.svg)](https://github.com/SKar-2007/CoEvolve/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Automated Adversarial-Training-as-a-Service (A-TaaS) framework for autonomous coding agents.

CoEvolve Sandbox pits an **Attacker LLM Agent** against a **Developer LLM Agent** inside
hardened Docker containers. A **Hybrid Judge** (Semgrep SAST + dynamic exploit replay)
verifies whether the Developer's code patch contains a real, exploitable vulnerability.
Confirmed failures are distilled into natural-language security rules and appended to
the Developer's system prompt — a non-parametric alignment loop that keeps base model
weights frozen while defensive coverage evolves monotonically. An **Elo rating system**
automatically matches task difficulty to developer capability.

## Key Ideas

- **Non-parametric alignment** — evolve system prompts, never model weights
- **Verified feedback** — rule updates driven only by confirmed exploits (SAST + DAST)
- **Adaptive difficulty** — zero-sum Elo dynamics balance attacker/developer skill
- **Isolated execution** — ephemeral, hardened Docker containers per episode
- **Regression guarding** — retroactive evaluation prevents prompt-rule regressions

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Training Loop Controller                      │
│  Attacker → Developer → Judge → Distiller → RegressionGuard     │
│                         ↓              ↓                         │
│                    Elo Update    PromptStore (Git-backed)        │
└─────────────────────────────────────────────────────────────────┘
         │                                    │
    ┌────┴────┐    ┌──────────┐    ┌──────────┴──────────┐
    │   LLM   │    │  Redis   │    │  PostgreSQL + API   │
    │ Clients │    │  Queue   │    │  (FastAPI/SQLAlchemy)│
    └─────────┘    └──────────┘    └─────────────────────┘
         │
    ┌────┴────────────────────────────┐
    │  Cost Tracking │ Caching        │
    └─────────────────────────────────┘
```

## Features

### Core Pipeline

| Component | Description |
|-----------|-------------|
| **Training Loop** | Full co-evolutionary orchestrator wiring all agents together |
| **Attacker Agent** | Generates adversarial tasks across 10+ vulnerability classes with difficulty scaling |
| **Developer Agent** | Simple single-turn or **ReAct tool-use** (7 tools: read, write, shell, search, tests, git) |
| **Hybrid Judge** | Two-stage: Semgrep SAST scanning + dynamic DAST exploit replay |
| **Distiller Agent** | Converts failure traces into imperative security rules |
| **Regression Guard** | Validates new rules against all previously-passing tasks |
| **Elo Rating** | Zero-sum adaptive difficulty matching (10 tiers, 1000-2500 range) |
| **Batch Training** | Multi-episode sessions with convergence detection and per-class win rates |

### SAST Rules (29 rules, 3 languages)

| Language | Rules | Vulnerability Classes |
|----------|-------|----------------------|
| **Python** | 10 | SQLi, CmdInj, XSS, SSRF, SSTI, Deserialization, PathTraversal, XXE, OpenRedirect, PrototypePollution |
| **JavaScript** | 10 | SQLi, CmdInj, XSS, SSRF, SSTI, Deserialization, PathTraversal, XXE, OpenRedirect, PrototypePollution |
| **Java** | 9 | SQLi, CmdInj, XSS, SSRF, SSTI, Deserialization, PathTraversal, XXE, OpenRedirect |

### DAST Targets (7 vulnerable apps)

| App | Vulnerability | Exploit Verified |
|-----|--------------|-----------------|
| **SQLi** | SQLite injection via string interpolation | `' OR '1'='1' --` |
| **PathTraversal** | Directory escape to read files | `../../../../etc/passwd` |
| **CommandInjection** | Shell command injection | `; cat /etc/passwd` |
| **XSS** | Reflected cross-site scripting | `<script>alert(1)</script>` |
| **SSTI** | Jinja2 template injection | `{{7*7}}` |
| **SSRF** | Server-side request forgery | `http://127.0.0.1:PORT/internal/metadata` |
| **OpenRedirect** | Unvalidated redirect | `//evil.com/phish` |

### Prompt Evolution

| Component | Description |
|-----------|-------------|
| **Git-Backed Store** | Each prompt version committed to Git with full audit trail |
| **Branch Support** | Create, switch, and merge parallel evolution branches |
| **Rollback** | Restore any previous prompt version |
| **Semantic Deduplication** | sentence-transformers cosine similarity with Jaccard fallback |
| **Rule Portability** | Export/import rules as portable JSON packages |

### Infrastructure

| Component | Description |
|-----------|-------------|
| **FastAPI API** | 19 REST endpoints for episodes, prompts, rules, Elo, training, jobs, export/import |
| **Redis Task Queue** | Async training jobs with in-memory fallback |
| **Job Worker** | Background worker that processes async training jobs |
| **Docker Sandbox** | 7-layer container isolation with seccomp profiles |
| **Telemetry** | Prometheus metrics + Grafana dashboards |
| **Alerting** | Slack, Email (SMTP), PagerDuty notification channels |
| **Cost Tracking** | Per-call token counting with provider-specific pricing |
| **LLM Caching** | LRU cache for deterministic calls (temperature=0) |
| **Dashboard** | Real-time metrics dashboard (Elo trends, win rates, rule growth) |

### LLM Support

| Provider | Models | Auth |
|----------|--------|------|
| **OpenRouter** | DeepSeek, Claude, GPT-4o, any model | `OPENROUTER_API_KEY` |
| **Anthropic** | Claude Sonnet 4.5, Haiku 4.5 | `ANTHROPIC_API_KEY` |
| **OpenAI** | GPT-4o, GPT-4o-mini | `OPENAI_API_KEY` |
| **Google Gemini** | Gemini 2.5 Flash, Gemini 2.5 Pro | `GEMINI_API_KEY` |

## Quick Start

### 1. Install dependencies

```bash
git clone https://github.com/SKar-2007/CoEvolve.git
cd CoEvolve
python -m venv .venv
source .venv/bin/activate
make install
make dev
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 3. Start infrastructure

```bash
docker compose up -d db redis prometheus grafana
```

### 4. Run the API + Worker

```bash
# Terminal 1: API
make run-api

# Terminal 2: Worker (processes async jobs)
make worker
```

### 5. Run the demo

```bash
# Mock mode (no API key needed)
make demo

# Real LLM calls (requires API key in .env)
make demo-real
```

### 6. Run tests

```bash
make test
```

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make install` | Install all packages in dev mode |
| `make dev` | Install dev tools (ruff, mypy, pytest) |
| `make test` | Run full test suite with coverage |
| `make lint` | Run ruff linter |
| `make typecheck` | Run mypy type checker |
| `make docker-up` | Start dev infrastructure (db, redis, prometheus, grafana) |
| `make docker-down` | Stop dev infrastructure |
| `make docker-prod` | Start production stack |
| `make docker-prod-down` | Stop production stack |
| `make docker-logs` | Follow production API logs |
| `make build-sandbox` | Build the sandbox Docker image |
| `make run-api` | Start API in dev mode (auto-reload) |
| `make run-api-prod` | Start API in production mode (4 workers) |
| `make worker` | Start async job worker (polls queue) |
| `make worker-once` | Process one async job and exit |
| `make demo` | Run demo in mock mode |
| `make demo-real` | Run demo with real LLM calls |
| `make benchmark` | Run 100-episode benchmark |
| `make train` | Run 100-episode batch training |
| `make stress` | Run 1000-episode stress test |
| `make dast` | Run DAST exploit verification against 7 vulnerable apps |
| `make dashboard` | Start API + metrics dashboard at localhost:8000/dashboard |
| `make rules-export` | Export trained rules to rules.json |
| `make rules-import` | Import rules from rules.json |
| `make clean` | Remove caches and temp files |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Episode/elo/rules metrics |
| GET | `/dashboard` | Metrics dashboard (HTML) |
| POST | `/episodes` | Create episode |
| GET | `/episodes` | List episodes |
| GET | `/episodes/{id}` | Get episode |
| POST | `/episodes/{id}/stop` | Stop episode |
| GET | `/elo` | Current Elo ratings |
| GET | `/elo/history` | Elo rating history |
| GET | `/prompts/current` | Current prompt version |
| GET | `/prompts/history` | Prompt version history |
| GET | `/prompts/diff/{v1}/{v2}` | Diff between versions |
| GET | `/rules` | List security rules |
| GET | `/rules/{id}` | Get specific rule |
| POST | `/rules/export` | Export rules as JSON package |
| POST | `/rules/import` | Import rules from JSON package |
| POST | `/training/run` | Run training episode (sync) |
| POST | `/training/async` | Enqueue training episode (async) |
| GET | `/training/jobs` | List training jobs |
| GET | `/training/jobs/{id}` | Get job status |

### Usage Examples

```python
import httpx

# Run a training episode (synchronous)
resp = httpx.post("http://localhost:8000/training/run", json={
    "vulnerability_class": "SQLi",
    "language": "python",
    "use_react": True,  # Use ReAct tool-use developer
})
result = resp.json()
print(f"Outcome: {result['judge_outcome']}, Duration: {result['duration_s']:.1f}s")

# Enqueue async training job
resp = httpx.post("http://localhost:8000/training/async", json={
    "vulnerability_class": "XSS",
})
job = resp.json()
print(f"Job {job['job_id']} enqueued")

# Export rules as portable JSON
resp = httpx.post("http://localhost:8000/rules/export", json={
    "name": "my-rules",
    "version": "1.0.0",
})
package = resp.json()
print(f"Exported {package['rules_count']} rules")

# Import rules from another instance
resp = httpx.post("http://localhost:8000/rules/import", json=package)
print(f"Imported {resp.json()['imported']} new rules")
```

### Programmatic Usage

```python
from packages.agents.llm import build_client
from packages.agents.training_loop import TrainingLoop, EpisodeConfig

# Initialize with any provider
llm = build_client("openrouter", "deepseek/deepseek-chat-v3-0324")
# llm = build_client("gemini", "gemini-2.5-flash")
# llm = build_client("anthropic", "claude-sonnet-4-5")

# Run a single episode
loop = TrainingLoop(llm=llm)
config = EpisodeConfig(vulnerability_class="SQLi")
trace = loop.run_episode(config)
print(f"Outcome: {trace.judge_outcome}, Rule: {trace.distilled_rule}")

# Batch training with convergence detection
from packages.agents.batch_trainer import TrainingSession

session = TrainingSession(llm=llm, episodes=100)
report = session.run()
print(f"Secure rate: {report.secure_rate:.1%}")

# Export trained rules
from packages.evolution.portability import export_rules, save_package
from packages.evolution.store import PromptStore

store = PromptStore()
pkg = export_rules(store, name="trained-rules", version="2.0.0")
save_package(pkg, Path("rules.json"))
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `openrouter` | Default LLM provider |
| `LLM_MODEL` | `deepseek/deepseek-chat-v3-0324` | Default model |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `DATABASE_URL` | `postgresql://...` | PostgreSQL connection |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection |
| `JWT_SECRET` | `change-me` | JWT signing secret |
| `GRAFANA_PASSWORD` | `admin` | Grafana admin password |

## Testing

```
137 tests passing (6 Docker tests require daemon)
├── tests/unit/           # 54 unit tests
│   ├── test_elo.py              # Elo calculator + difficulty tiers
│   ├── test_judge.py            # Judge verdict + DAST
│   ├── test_history.py          # Rating history tracker
│   ├── test_dedupe.py           # Semantic deduplication
│   ├── test_regression_guard.py # Regression detection
│   ├── test_telemetry.py        # Prometheus metrics
│   └── test_portability.py      # Rule export/import (10 tests)
├── tests/integration/    # 83 integration tests
│   ├── test_agents_pipeline.py     # Full attacker→developer→judge pipeline
│   ├── test_api_crud.py            # All 19 API endpoints
│   ├── test_evolution.py           # Prompt store versioning
│   ├── test_sandbox.py             # Sandbox config + validation
│   └── test_sandbox_lifecycle.py   # Container lifecycle (29 tests)
└── Makefile targets: test, lint, typecheck
```

## CI/CD Workflows

### CI Pipeline (`.github/workflows/ci.yml`)

Runs on every push and PR to `main`:

1. **Lint** — `ruff check` (0 errors)
2. **Format** — `ruff format --check` (all files formatted)
3. **Typecheck** — `mypy` (strict mode)
4. **Unit Tests** — `pytest tests/unit/` with coverage
5. **Integration Tests** — `pytest tests/integration/` (API, evolution, sandbox)
6. **Coverage Report** — Upload to Codecov

### Security Scanning (`.github/workflows/security.yml`)

Runs weekly and on push:

1. **Secret Detection** — `detect-secrets` baseline scan
2. **Dependency Audit** — `pip-audit` for known vulnerabilities
3. **Container Scanning** — Trivy vulnerability scanner on Docker images

### Dependabot (`.github/dependabot.yml`)

Automated dependency updates:
- **pip** — Weekly Python dependency updates
- **Docker** — Weekly Dockerfile base image updates
- **GitHub Actions** — Weekly action version updates

## Benchmarking

```bash
# Mock mode (no API key)
make benchmark          # 100 episodes
make stress             # 1000 episodes

# Real LLM
python scripts/benchmark.py --episodes 50 --real

# ReAct developer agent
python scripts/benchmark.py --episodes 20 --real --react

# Batch training with convergence detection
make train              # 100 episodes
python scripts/train.py --episodes 200 --real --react --output report.json

# DAST exploit verification
make dast               # Test all 7 vulnerable apps
python -m packages.judge.dast.runner --classes SQLi SSTI  # Test specific
```

### Stress Test Results

| Episodes | Time | Eps/sec | Errors | Tokens |
|----------|------|---------|--------|--------|
| 1,000 | 0.5s | 2,203 | 0 | 600K |
| 2,000 | 0.9s | 2,223 | 0 | 1.2M |
| 5,000 | 2.3s | 2,189 | 0 | 3M |

## Deployment

Production deployment using Docker Compose:

```bash
# 1. Configure environment
cp .env.example .env   # Edit with your secrets

# 2. Build sandbox image
make build-sandbox

# 3. Start all services
make docker-prod

# 4. Verify
curl http://localhost:8000/health

# 5. Open dashboard
open http://localhost:8000/dashboard
```

See [DEPLOY.md](DEPLOY.md) for full deployment guide (SSL, backups, scaling, troubleshooting).

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | FastAPI REST API + Dashboard |
| Worker | — | Background training job processor |
| PostgreSQL | 5432 | Episode/rule database |
| Redis | 6379 | Task queue |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Dashboards |

## Repository Layout

```
packages/
├── api/                # FastAPI REST API (19 endpoints)
│   ├── main.py             # All API routes
│   ├── models.py           # SQLAlchemy ORM models
│   ├── schemas.py          # Pydantic request/response schemas
│   ├── config.py           # pydantic-settings configuration
│   ├── database.py         # Engine, session, base classes
│   ├── task_queue.py       # Redis-backed async job queue
│   ├── worker.py           # Background job worker
│   └── static/dashboard.html  # Metrics dashboard
├── agents/             # LLM agent implementations
│   ├── training_loop.py    # Co-evolutionary orchestrator
│   ├── batch_trainer.py    # Multi-episode training with convergence
│   ├── cost_tracking.py    # Token/cost tracking + LLM caching
│   ├── llm.py              # Unified LLM client (Anthropic, OpenAI, OpenRouter, Gemini)
│   ├── attacker/           # Adversarial task generator
│   │   ├── generator.py        # Task generation with difficulty scaling
│   │   └── prompts.py          # System prompts
│   ├── developer/          # Code patch agent
│   │   ├── executor.py         # Simple single-turn executor
│   │   └── tools.py            # ReAct tool-use agent (7 tools)
│   ├── distiller/          # Trace-to-rule conversion
│   │   └── pipeline.py         # Failure trace → security rule
│   └── regression_guard/   # Rule regression detection
│       └── guard.py            # Retroactive rule validation
├── judge/              # Hybrid Judge Engine
│   ├── engine.py           # Orchestrates SAST + DAST
│   ├── sast/               # Semgrep scanner + 29 rules (Python/JS/Java)
│   │   └── semgrep_rules/      # 29 YAML rule files
│   └── dast/               # Dynamic exploit executor + 7 vulnerable apps
│       ├── executor.py         # Payload library + exploit runner
│       ├── runner.py           # DAST verification runner
│       └── targets/            # 7 vulnerable Flask apps
├── elo/                # Elo rating system
│   ├── calculator.py       # Zero-sum Elo engine
│   ├── difficulty.py       # 10-tier difficulty mapper
│   └── history.py          # Rating history tracker
├── evolution/          # Prompt-Evolution Engine
│   ├── store.py            # Git-backed versioned prompt store
│   ├── dedupe.py           # Semantic deduplication (sentence-transformers)
│   └── portability.py      # Rule export/import (JSON packages)
├── sandbox/            # Docker container orchestration
│   ├── manager.py          # Container lifecycle (create/exec/destroy)
│   ├── lifecycle.py        # Episode orchestrator
│   ├── config.py           # Sandbox configuration + seccomp
│   └── docker/             # Dockerfiles + seccomp profiles
└── telemetry/          # Monitoring and alerting
    ├── exporters/metrics.py    # Prometheus counters/gauges/histograms
    └── alerting.py             # Slack/Email/PagerDuty notifications
data/                   # Vulnerability taxonomy + exploit payloads
tests/                  # 137 tests (unit + integration)
scripts/
├── demo.py                 # End-to-end demo (mock + real)
├── benchmark.py            # Episode benchmarking
├── train.py                # Batch training with convergence
├── rules_export.py         # Export rules as JSON package
├── rules_import.py         # Import rules from JSON package
├── setup.sh                # Dev environment setup
└── test.sh                 # Quick test runner
docker/
└── api/Dockerfile          # Multi-stage API image
.github/
├── workflows/ci.yml        # CI pipeline (lint, typecheck, tests, coverage)
├── workflows/security.yml  # Secret scanning, dependency audit, Trivy
└── dependabot.yml          # Auto dependency updates
docker-compose.yml          # Development compose
docker-compose.prod.yml     # Production compose (resource limits, log rotation)
requirements.txt            # Runtime dependencies
requirements-ci.txt         # CI-specific dependencies
requirements-dev.txt        # Dev tools (ruff, mypy, pytest)
conftest.py                 # Root pytest config (sys.path setup)
pyproject.toml              # Ruff, mypy, pytest, coverage config
Makefile                    # Build, test, deploy targets (25 targets)
DEPLOY.md                   # Full deployment guide
CONTRIBUTING.md             # Contribution guidelines
CHANGELOG.md                # Version history
```

## Documentation

| Document | Purpose |
|----------|---------|
| [problem_statement.md](problem_statement.md) | Problem definition and success criteria |
| [blueprint.md](blueprint.md) | System architecture and formal model |
| [agent.md](agent.md) | Agent system design (attacker, developer, judge, distiller) |
| [build_plan.md](build_plan.md) | Phased 22-week implementation roadmap |
| [technology_stack.md](technology_stack.md) | Technology decisions and justifications |
| [security_governance.md](security_governance.md) | 7-layer container isolation design |
| [threat_model.md](threat_model.md) | STRIDE threat analysis and attack trees |
| [vulnerability_taxonomy.md](vulnerability_taxonomy.md) | 25+ target vulnerability classes |
| [roadmap.md](roadmap.md) | Long-term strategic milestones |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines and code standards |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [DEPLOY.md](DEPLOY.md) | Production deployment guide |

## License

Apache License 2.0. See [LICENSE](LICENSE).
