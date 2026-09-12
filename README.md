# CoEvolve Sandbox

[![CI](https://github.com/SKar-2007/CoEvolve/actions/workflows/ci.yml/badge.svg)](https://github.com/SKar-2007/CoEvolve/actions/workflows/ci.yml)
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

### Prompt Evolution

| Component | Description |
|-----------|-------------|
| **Git-Backed Store** | Each prompt version committed to Git with full audit trail |
| **Branch Support** | Create, switch, and merge parallel evolution branches |
| **Rollback** | Restore any previous prompt version |
| **Semantic Deduplication** | sentence-transformers cosine similarity with Jaccard fallback |

### Infrastructure

| Component | Description |
|-----------|-------------|
| **FastAPI API** | 16 REST endpoints for episodes, prompts, rules, Elo, training, jobs |
| **Redis Task Queue** | Async training jobs with in-memory fallback |
| **Docker Sandbox** | 7-layer container isolation with seccomp profiles |
| **Telemetry** | Prometheus metrics + Grafana dashboards |
| **Alerting** | Slack, Email (SMTP), PagerDuty notification channels |
| **Cost Tracking** | Per-call token counting with provider-specific pricing |
| **LLM Caching** | LRU cache for deterministic calls (temperature=0) |

## Quick Start

### 1. Install dependencies

```bash
# Clone and enter the repo
git clone https://github.com/SKar-2007/CoEvolve.git
cd CoEvolve

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install all packages in dev mode
make install

# Install dev tools
make dev
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your API keys and database URL
```

### 3. Start infrastructure

```bash
docker compose up -d db redis prometheus grafana
```

### 4. Run the API

```bash
uvicorn packages.api.main:app --reload --port 8000
```

### 5. Run the demo

```bash
# Mock mode (no API key needed)
python scripts/demo.py

# Real LLM calls
python scripts/demo.py --real --episodes 5
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
| `make demo` | Run demo in mock mode |
| `make demo-real` | Run demo with real LLM calls |
| `make benchmark` | Run 100-episode benchmark |
| `make stress` | Run 1000-episode stress test |
| `make clean` | Remove caches and temp files |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Episode/elo/rules metrics |
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
| POST | `/training/run` | Run training episode (sync) |
| POST | `/training/async` | Enqueue training episode |
| GET | `/training/jobs` | List training jobs |
| GET | `/training/jobs/{id}` | Get job status |

### Usage Examples

```python
import httpx

# Create an episode
resp = httpx.post("http://localhost:8000/episodes", json={
    "vulnerability_classes": ["SQLi"],
    "max_duration_minutes": 15,
})
episode = resp.json()

# Run a training episode (synchronous)
resp = httpx.post("http://localhost:8000/training/run", json={
    "vulnerability_class": "SQLi",
    "language": "python",
})
result = resp.json()
print(f"Outcome: {result['judge_outcome']}, Duration: {result['duration_s']:.1f}s")

# Check Elo ratings
resp = httpx.get("http://localhost:8000/elo")
print(resp.json())  # {"attacker": 1500.0, "developer": 1500.0}

# List security rules
resp = httpx.get("http://localhost:8000/rules")
for rule in resp.json():
    print(f"Rule: {rule['rule_text'][:60]}...")
```

### Programmatic Usage

```python
from packages.agents.training_loop import TrainingLoop
from packages.agents.llm import LLMClient

# Initialize with your LLM provider
client = LLMClient(provider="anthropic", model="claude-sonnet-4-5")
loop = TrainingLoop(llm_client=client)

# Run a single episode
result = loop.run_episode(vulnerability_class="SQLi")
print(f"Outcome: {result.verdict.outcome}")
print(f"Rule: {result.distilled_rule}")

# Run multiple episodes
for i in range(10):
    result = loop.run_episode(vulnerability_class="XSS")
    print(f"Episode {i+1}: outcome={result.verdict.outcome}")
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `LLM_PROVIDER` | `anthropic` | Default LLM provider |
| `LLM_MODEL` | `claude-sonnet-4-5` | Default model |
| `DATABASE_URL` | `postgresql://...` | PostgreSQL connection |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection |
| `JWT_SECRET` | `change-me` | JWT signing secret |
| `GRAFANA_PASSWORD` | `admin` | Grafana admin password |

## Testing

```
127 tests passing (6 Docker tests require daemon)
├── tests/unit/           # 44 unit tests
│   ├── test_elo.py              # Elo calculator + difficulty tiers
│   ├── test_judge.py            # Judge verdict + DAST
│   ├── test_history.py          # Rating history tracker
│   ├── test_dedupe.py           # Semantic deduplication
│   ├── test_regression_guard.py # Regression detection
│   └── test_telemetry.py        # Prometheus metrics
├── tests/integration/    # 83 integration tests
│   ├── test_agents_pipeline.py     # Full attacker→developer→judge pipeline
│   ├── test_api_crud.py            # All 16 API endpoints
│   ├── test_evolution.py           # Prompt store versioning
│   ├── test_sandbox.py             # Sandbox config + validation
│   └── test_sandbox_lifecycle.py   # Container lifecycle (29 tests)
└── Makefile targets: test, lint, typecheck
```

## Benchmarking

```bash
# Mock mode (no API key)
make benchmark          # 100 episodes
make stress             # 1000 episodes

# Custom
python scripts/benchmark.py --episodes 5000 --output report.json
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
```

See [DEPLOY.md](DEPLOY.md) for full deployment guide (SSL, backups, scaling, troubleshooting).

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | FastAPI REST API |
| PostgreSQL | 5432 | Episode/rule database |
| Redis | 6379 | Task queue |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Dashboards |

## Repository Layout

```
packages/
├── api/                # FastAPI REST API (16 endpoints)
│   ├── main.py             # All API routes
│   ├── models.py           # SQLAlchemy ORM models
│   ├── schemas.py          # Pydantic request/response schemas
│   ├── config.py           # pydantic-settings configuration
│   ├── database.py         # Engine, session, base classes
│   └── task_queue.py       # Redis-backed async job queue
├── agents/             # LLM agent implementations
│   ├── training_loop.py    # Co-evolutionary orchestrator
│   ├── cost_tracking.py    # Token/cost tracking + LLM caching
│   ├── llm.py              # Unified LLM client (Anthropic, OpenAI, OpenRouter)
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
│   ├── sast/               # Semgrep scanner + 7 rule packs
│   └── dast/               # Dynamic exploit executor + payload library
├── elo/                # Elo rating system
│   ├── calculator.py       # Zero-sum Elo engine
│   ├── difficulty.py       # 10-tier difficulty mapper
│   └── history.py          # Rating history tracker
├── evolution/          # Prompt-Evolution Engine
│   ├── store.py            # Git-backed versioned prompt store
│   └── dedupe.py           # Semantic deduplication (sentence-transformers)
├── sandbox/            # Docker container orchestration
│   ├── manager.py          # Container lifecycle (create/exec/destroy)
│   ├── lifecycle.py        # Episode orchestrator
│   ├── config.py           # Sandbox configuration + seccomp
│   └── docker/             # Dockerfiles + seccomp profiles
│       ├── Dockerfile          # Base sandbox image
│       ├── hardened.Dockerfile # Hardened production image
│       ├── entrypoint.sh       # Container entrypoint
│       └── seccomp-profile.json # Syscall filter profile
└── telemetry/          # Monitoring and alerting
    ├── exporters/metrics.py    # Prometheus counters/gauges/histograms
    └── alerting.py             # Slack/Email/PagerDuty notifications
data/                   # Vulnerability taxonomy + exploit payloads
tests/                  # 127 tests (unit + integration)
scripts/                # demo.py, benchmark.py, setup.sh
docker/
└── api/Dockerfile          # Multi-stage API image
.github/workflows/ci.yml   # CI pipeline (lint, typecheck, tests, coverage)
docker-compose.yml         # Development compose
docker-compose.prod.yml    # Production compose (resource limits, log rotation)
requirements.txt           # Runtime dependencies
requirements-ci.txt        # CI-specific dependencies
requirements-dev.txt       # Dev tools (ruff, mypy, pytest)
conftest.py                # Root pytest config (sys.path setup)
pyproject.toml             # Ruff, mypy, pytest, coverage config
Makefile                   # Build, test, deploy targets
DEPLOY.md                  # Full deployment guide
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
