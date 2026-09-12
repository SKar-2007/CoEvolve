# CoEvolve Sandbox

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
┌─────────────────────────────────────────────────────────────┐
│                     Training Loop Controller                │
│  Attacker → Developer → Judge → Distiller → RegressionGuard│
│                         ↓              ↓                    │
│                    Elo Update    PromptStore (Git-backed)   │
└─────────────────────────────────────────────────────────────┘
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

## Repository Layout

```
packages/
├── api/          # FastAPI REST API (episodes, prompts, elo, rules, training)
│   ├── main.py       # All API endpoints
│   ├── models.py     # SQLAlchemy ORM models
│   ├── schemas.py    # Pydantic request/response schemas
│   ├── config.py     # pydantic-settings configuration
│   ├── database.py   # Engine, session, base classes
│   └── task_queue.py # Redis-backed async job queue
├── agents/       # LLM agent implementations
│   ├── training_loop.py    # Co-evolutionary orchestrator
│   ├── cost_tracking.py    # Token/cost tracking + LLM caching
│   ├── llm.py              # Unified LLM client (Anthropic, OpenAI, OpenRouter)
│   ├── attacker/           # Adversarial task generator
│   ├── developer/          # Code patch agent (simple + ReAct tool-use)
│   ├── distiller/          # Trace-to-rule conversion
│   └── regression_guard/   # Rule regression detection
├── judge/        # Hybrid Judge Engine
│   ├── engine.py       # Orchestrates SAST + DAST
│   ├── sast/           # Semgrep scanner + 7 rule packs
│   └── dast/           # Dynamic exploit executor + payload library
├── elo/          # Elo rating system
│   ├── calculator.py   # Zero-sum Elo engine
│   ├── difficulty.py   # 10-tier difficulty mapper
│   └── history.py      # Rating history tracker
├── evolution/    # Prompt-Evolution Engine
│   ├── store.py    # Git-backed versioned prompt store
│   └── dedupe.py   # Semantic deduplication (sentence-transformers)
├── sandbox/      # Docker container orchestration
│   ├── manager.py      # Container lifecycle (create/exec/destroy)
│   ├── lifecycle.py    # Episode orchestrator
│   ├── config.py       # Sandbox configuration + seccomp
│   └── docker/         # Dockerfiles + seccomp profiles
└── telemetry/    # Monitoring and alerting
    ├── exporters/metrics.py  # Prometheus counters/gauges/histograms
    └── alerting.py           # Slack/Email/PagerDuty notifications
data/             # Vulnerability taxonomy + exploit payloads
tests/            # 104 tests (unit + integration)
scripts/          # setup.sh, test.sh, demo.py
```

## Quick Start

### 1. Install dependencies

```bash
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

## Testing

```
104 tests passing
├── tests/unit/           # 28 unit tests
│   ├── test_elo.py           # Elo calculator + difficulty
│   ├── test_judge.py         # Judge verdict + DAST
│   ├── test_history.py       # Rating history tracker
│   ├── test_dedupe.py        # Semantic deduplication
│   ├── test_regression_guard.py  # Regression detection
│   └── test_telemetry.py     # Prometheus metrics
├── tests/integration/    # 76 integration tests
│   ├── test_agents_pipeline.py  # Full attacker→developer→judge pipeline
│   ├── test_api_crud.py         # All API endpoints
│   ├── test_evolution.py        # Prompt store versioning
│   └── test_sandbox.py          # Sandbox config + validation
└── Makefile targets: test, lint, typecheck
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

## License

Apache License 2.0. See [LICENSE](LICENSE).
