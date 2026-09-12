# CoEvolve Sandbox — Complete Project Workflow & Overview

> **Last updated:** September 12, 2026  
> **Status:** 25 commits, 162 tests passing, fully functional  
> **Repository:** https://github.com/SKar-2007/CoEvolve

---

## Table of Contents

1. [Project Summary](#project-summary)
2. [Core Concept](#core-concept)
3. [System Architecture](#system-architecture)
4. [Build Workflow (Chronological)](#build-workflow-chronological)
5. [Component Deep Dive](#component-deep-dive)
6. [Data Flow](#data-flow)
7. [Testing Strategy](#testing-strategy)
8. [CI/CD Pipeline](#cicd-pipeline)
9. [Deployment](#deployment)
10. [API Reference](#api-reference)
11. [Current State](#current-state)
12. [What's Working End-to-End](#whats-working-end-to-end)

---

## Project Summary

CoEvolve Sandbox is an **Adversarial-Training-as-a-Service (A-TaaS)** platform that autonomously improves the security of LLM coding agents. It does this by:

1. Having an **Attacker LLM** generate vulnerable code tasks
2. Having a **Developer LLM** attempt to fix them
3. Having a **Hybrid Judge** (SAST + DAST) verify if the fix actually works
4. When the developer fails, **distilling** the failure into a security rule
5. **Appending** that rule to the developer's system prompt
6. **Repeating** — the developer gets progressively better at security

This is a **non-parametric alignment loop** — the base model weights never change, only the system prompt evolves.

---

## Core Concept

```
┌─────────────────────────────────────────────────────────────────────┐
│                     THE CO-EVOLUTIONARY LOOP                        │
│                                                                     │
│   Attacker LLM ──generates──▶ Vulnerable Code Task                 │
│        │                           │                                │
│        │                           ▼                                │
│        │                    Developer LLM                           │
│        │                    ──produces──▶ Code Patch                │
│        │                                    │                       │
│        │                                    ▼                       │
│        │                           Hybrid Judge                     │
│        │                         (SAST + DAST)                     │
│        │                                    │                       │
│        │                          ┌─────────┴─────────┐            │
│        │                          ▼                   ▼            │
│        │                     j=0 (Secure)        j=1 (Vuln)        │
│        │                     Developer Wins      Attacker Wins     │
│        │                          │                   │            │
│        │                          │                   ▼            │
│        │                          │           Distiller Agent      │
│        │                          │           ──creates──▶ Rule    │
│        │                          │                   │            │
│        │                          │                   ▼            │
│        │                          │          Regression Guard      │
│        │                          │           ──validates──▶ OK?   │
│        │                          │                   │            │
│        │                          │                   ▼            │
│        │                          │          PromptStore (Git)     │
│        │                          │           ──saves──▶ Rule     │
│        │                          │                   │            │
│        │                          │                   ▼            │
│        │                          │          Next Episode...       │
│        │                          │          (Developer now has    │
│        │                          │           the rule in prompt)  │
│        ▼                          ▼                                │
│     Elo Update ◀────────────────────┘                              │
│   (difficulty scales with skill)                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Insight

The developer agent **never learns** in the traditional ML sense. Instead, each failure produces a natural-language rule like:

> "ALWAYS use parameterized queries for database lookups. Never interpolate user input into SQL strings."

These rules are prepended to the developer's system prompt. Over time, the prompt accumulates hundreds of security rules, making the developer progressively harder to exploit — **without any fine-tuning**.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TRAINING LOOP CONTROLLER                         │
│                  (packages/agents/training_loop.py)                  │
│                                                                     │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Attacker │─▶│ Developer │─▶│  Judge   │─▶│ Distiller│          │
│  │  Agent   │  │   Agent   │  │ (SAST +  │  │  Agent   │          │
│  │          │  │           │  │  DAST)   │  │          │          │
│  └──────────┘  └───────────┘  └──────────┘  └──────────┘          │
│       │              │              │              │                 │
│       │              │              ▼              ▼                 │
│       │              │        ┌──────────┐  ┌──────────┐           │
│       │              │        │   Elo    │  │Regression│           │
│       │              │        │Calculator│  │  Guard   │           │
│       │              │        └──────────┘  └──────────┘           │
│       │              │              │              │                 │
│       │              │              ▼              ▼                 │
│       │              │        ┌─────────────────────────┐          │
│       │              │        │     PromptStore (Git)    │          │
│       │              │        │  Versioned rule storage  │          │
│       │              │        └─────────────────────────┘          │
│       ▼              ▼                                             │
│  ┌──────────────────────────────────────────────────────┐         │
│  │                    LLM Clients                        │         │
│  │  OpenRouter │ Anthropic │ OpenAI │ Gemini │ Mock      │         │
│  └──────────────────────────────────────────────────────┘         │
│       │                                                            │
│  ┌────┴─────────────────────────────┐                             │
│  │  Cost Tracking │ Caching │ Queue  │                             │
│  └──────────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
         │                                    │
    ┌────┴────┐    ┌──────────┐    ┌──────────┴──────────┐
    │  Redis  │    │PostgreSQL│    │     FastAPI API      │
    │  Queue  │    │ Database │    │  (22 endpoints)      │
    └─────────┘    └──────────┘    │  + Dashboard         │
                                   │  + Rate Limiting     │
                                   │  + API Key Auth      │
                                   └─────────────────────┘
```

---

## Build Workflow (Chronological)

### Phase 1: Foundation (Commits 1–8)

| Commit | Description |
|--------|-------------|
| `1f3a734` | Initial commit: project structure, package scaffolding |
| `bec750b` | Fix packaging, bugs, lint, test setup |
| `4e49d27` | Implement training loop + developer tool-use framework |
| `d9da09e` | Implement medium-priority features |
| `09b7de7` | Implement cost tracking, caching, tests, demo, alerting |
| `161c076` | Update README with full feature documentation |
| `a9a3dbb` | Add benchmarking script + fix mock mode |
| `3ddcaef` | Fix Path type in training loop + demo MockLLM routing |

**What was built:**
- All 6 Python packages (api, agents, judge, elo, evolution, sandbox, telemetry)
- Training loop controller (the orchestrator)
- Attacker, Developer, Distiller, Regression Guard agents
- Elo rating calculator + difficulty tiers
- Hybrid Judge (SAST + DAST)
- Git-backed prompt store
- Semantic deduplication
- LLM client (Anthropic, OpenAI, OpenRouter, Mock)
- Cost tracking + caching
- Prometheus metrics + alerting
- Benchmarking + demo scripts

### Phase 2: Testing & CI/CD (Commits 9–15)

| Commit | Description |
|--------|-------------|
| `cb9cbd8` | Add sandbox lifecycle integration tests (29 tests) |
| `bc14122` | Add GitHub Actions CI/CD pipeline |
| `10fe557` | Add stress test results (1K/2K/5K episodes) |
| `43d71fb` | Add production deployment guide + Docker Compose |
| `13d9db5` | Rewrite README with full documentation |
| `84d803d` | Fix CI: proper dependency install + ruff format |
| `56fdc60` | Remove test_coevolve.db, add to gitignore |
| `6dbd920` | Update README: Makefile commands table |
| `9699948` | Fix deprecation warnings (Pydantic, FastAPI) |
| `bf824e3` | Add security hardening: Dependabot + Trivy |

**What was built:**
- 29 sandbox lifecycle tests
- CI pipeline (lint, typecheck, tests, coverage)
- Security scanning (secret detection, dependency audit, Trivy)
- Dependabot configuration
- Production Docker Compose with resource limits
- Deployment guide (DEPLOY.md)

### Phase 3: Advanced Features (Commits 16–25)

| Commit | Description |
|--------|-------------|
| `cda47c4` | Add CONTRIBUTING.md, CHANGELOG.md |
| `89be63d` | Wire ReAct Developer Agent into training loop |
| `574839d` | Add batch training mode with convergence detection |
| `25805b8` | Add async job worker for training queue |
| `740a6e1` | Fix demo.py to use .env config |
| `8143c6f` | Add Gemini LLM provider + fix JSON parsing |
| `5b83126` | Add 7 vulnerable Flask apps for DAST exploit replay |
| `11bf9c0` | Add 22 JavaScript + Java semgrep rules (29 total) |
| `97319d5` | Add rule export/import system (JSON packages) |
| `4b951ba` | Add metrics dashboard (Elo trends, win rates, rule growth) |
| `a7e50ab` | Add E2E training test (full mock cycle) |
| `3074194` | Add API hardening (rate limiting, API key auth) |
| `6877ce4` | Update README with all features |

**What was built:**
- ReAct tool-use developer agent (7 tools)
- Batch training with convergence detection
- Async job worker
- Gemini LLM provider
- 7 vulnerable Flask apps (SQLi, PathTraversal, CmdInj, XSS, SSTI, SSRF, OpenRedirect)
- 29 semgrep rules across 3 languages (Python, JS, Java)
- Rule portability (export/import as JSON)
- Real-time metrics dashboard
- 12 E2E training tests
- Rate limiting + API key authentication

---

## Component Deep Dive

### 1. Attacker Agent

**File:** `packages/agents/attacker/generator.py`

Generates adversarial coding tasks designed to trick the developer into introducing vulnerabilities.

```
Input:  vulnerability_class, difficulty_tier, language
Output: GeneratedTask {
    task_description,
    context_files: [{path, snippet}],
    vulnerability_class,
    difficulty_tier,
    expected_exploit,
    acceptance_criteria,
    hidden_trap
}
```

**10 vulnerability classes supported:**
SQLi, PathTraversal, CommandInjection, XSS, SSRF, Deserialization, SSTI, XXE, OpenRedirect, PrototypePollution

**Difficulty scaling:**
- Tier 1-3: Simple, obvious vulnerabilities
- Tier 4-6: Moderate complexity, requires careful review
- Tier 7-10: Advanced, subtle vulnerabilities requiring deep analysis

### 2. Developer Agent

**Two modes:**

#### Simple Mode (`packages/agents/developer/executor.py`)
Single-turn LLM call. Gets the task + rules, produces a patch.

#### ReAct Mode (`packages/agents/developer/tools.py`)
Tool-use agent with 7 tools:

| Tool | Description |
|------|-------------|
| `read_file` | Read file contents |
| `write_file` | Write file contents |
| `run_shell` | Execute shell commands |
| `search_code` | Search for patterns in code |
| `run_tests` | Execute test suites |
| `git_diff` | View git diffs |
| `git_commit` | Create git commits |

The ReAct agent reasons step-by-step:
1. Read the vulnerable code
2. Understand the vulnerability
3. Plan the fix
4. Write the patched code
5. Run tests to verify
6. Commit the changes

### 3. Hybrid Judge

**File:** `packages/judge/engine.py`

Two-stage evaluation:

```
Stage 1: SAST (Static Analysis)
    └── SemgrepScanner scans patch for vulnerability patterns
        ├── 29 rules across Python, JavaScript, Java
        ├── If no match → j=0 (secure) immediately
        └── If match → proceed to Stage 2

Stage 2: DAST (Dynamic Analysis)
    └── ExploitExecutor runs actual exploit payloads
        ├── 7 vulnerable Flask apps
        ├── 10 payload classes
        └── Verifies if vulnerability is actually exploitable
```

**Verdict:**
- `j=0` → Developer wins (secure code)
- `j=1` → Attacker wins (exploitable vulnerability found)

### 4. Distiller Agent

**File:** `packages/agents/distiller/pipeline.py`

Converts failure traces into natural-language security rules:

```
Input:  Failure trace (what went wrong)
Output: DistilledRule {
    rule_text: "ALWAYS use parameterized queries...",
    vulnerability_class: "SQLi",
    source_pattern: "Direct string interpolation in SQL",
    recommended_fix: "Use placeholder syntax"
}
```

**Rule validation:**
- Must start with "ALWAYS" or "NEVER"
- Must be > 10 characters
- Must be actionable and specific

### 5. Regression Guard

**File:** `packages/agents/regression_guard/guard.py`

Validates new rules against all previously-passing tasks:

```
For each task in HistoricalArchive:
    1. Add the new rule to the developer's prompt
    2. Re-run the developer on the task
    3. If the developer now FAILS a previously-passing task → REJECT rule
    4. If all tasks still pass → ACCEPT rule
```

### 6. Elo Rating System

**File:** `packages/elo/calculator.py`

Zero-sum Elo dynamics:

```
If developer wins (j=0):
    Developer Elo ↑ (gains points)
    Attacker Elo ↓ (loses points)

If attacker wins (j=1):
    Attacker Elo ↑ (gains points)
    Developer Elo ↓ (loses points)
```

**Difficulty tiers (10 levels):**

| Tier | Elo Range | Description |
|------|-----------|-------------|
| 1 | < 1200 | Beginner |
| 2 | 1200-1300 | Easy |
| 3 | 1300-1400 | Moderate |
| 4 | 1400-1500 | Intermediate |
| 5 | 1500-1600 | Average |
| 6 | 1600-1700 | Advanced |
| 7 | 1700-1800 | Expert |
| 8 | 1800-1900 | Master |
| 9 | 1900-2000 | Grandmaster |
| 10 | > 2000 | Elite |

### 7. Prompt Store (Git-Backed)

**File:** `packages/evolution/store.py`

Versioned rule storage with Git backing:

```
.prompt_store/
├── v0001.json    # Initial (empty)
├── v0002.json    # +1 rule
├── v0003.json    # +2 rules
└── .git/         # Full Git history
```

**Each version contains:**
- `version`: Sequential number
- `base_prompt`: The base system prompt
- `rules`: List of distilled rules
- `commit_message`: What changed
- `parent_version`: Link to previous version
- `branch`: Git branch name

**Features:**
- Branch/merge for parallel evolution
- Rollback to any previous version
- Diff between versions
- Full audit trail

### 8. LLM Client

**File:** `packages/agents/llm.py`

Unified interface for multiple LLM providers:

| Provider | Class | Models |
|----------|-------|--------|
| OpenRouter | `OpenRouterClient` | DeepSeek, Claude, GPT-4o |
| Anthropic | `AnthropicClient` | Claude Sonnet 4.5, Haiku 4.5 |
| OpenAI | `OpenAIClient` | GPT-4o, GPT-4o-mini |
| Gemini | `GeminiClient` | Gemini 2.5 Flash, Pro |
| Mock | `MockLLMClient` | Deterministic responses |

**Factory function:**
```python
client = build_client("openrouter", "deepseek/deepseek-chat-v3-0324")
client = build_client("gemini", "gemini-2.5-flash")
```

### 9. SAST Rules (29 rules, 3 languages)

**Directory:** `packages/judge/sast/semgrep_rules/`

| Language | Rules | Vulnerability Classes |
|----------|-------|----------------------|
| Python | 10 | SQLi, CmdInj, XSS, SSRF, SSTI, Deserialization, PathTraversal, XXE, OpenRedirect, PrototypePollution |
| JavaScript | 10 | SQLi, CmdInj, XSS, SSRF, SSTI, Deserialization, PathTraversal, XXE, OpenRedirect, PrototypePollution |
| Java | 9 | SQLi, CmdInj, XSS, SSRF, SSTI, Deserialization, PathTraversal, XXE, OpenRedirect |

### 10. DAST Targets (7 vulnerable apps)

**File:** `packages/judge/dast/targets/vulnerable_app.py`

| App | Vulnerability | Exploit Verified |
|-----|--------------|-----------------|
| SQLi | SQLite injection | `' OR '1'='1' --` |
| PathTraversal | Directory escape | `../../../../etc/passwd` |
| CommandInjection | Shell injection | `; cat /etc/passwd` |
| XSS | Reflected XSS | `<script>alert(1)</script>` |
| SSTI | Jinja2 injection | `{{7*7}}` |
| SSRF | Server-side forgery | `http://127.0.0.1:PORT/internal/metadata` |
| OpenRedirect | Unvalidated redirect | `//evil.com/phish` |

### 11. Rule Portability

**File:** `packages/evolution/portability.py`

Export/import rules as portable JSON packages:

```json
{
  "package_id": "uuid",
  "name": "trained-rules",
  "version": "1.0.0",
  "rules": [...],
  "source_version": 5,
  "tags": ["security", "sqli"]
}
```

### 12. API Hardening

**File:** `packages/api/auth.py`

| Feature | Description |
|---------|-------------|
| Rate Limiting | Sliding window per key/IP, tier-based limits |
| API Key Auth | `X-API-Key` header or `?api_key=` query param |
| Key Management | Create, list, disable API keys (admin only) |
| Password Hashing | PBKDF2 with random salt |

**Tier limits:**

| Tier | Requests/min | Requests/hour |
|------|-------------|---------------|
| Public | 10 | 100 |
| Standard | 60 | 1,000 |
| Admin | 300 | 10,000 |

### 13. Metrics Dashboard

**File:** `packages/api/static/dashboard.html`

Real-time visualization:
- Elo history (attacker vs developer over time)
- Win rate by vulnerability class
- Episode volume over time
- Rule growth across versions
- Scrollable rules list

---

## Data Flow

### Single Episode Flow

```
1. TrainingLoop.run_episode(config)
   │
   ├── 2. AttackerAgent.generate(vulnerability_class, difficulty_tier)
   │   └── Returns: GeneratedTask
   │
   ├── 3. DeveloperAgent.execute(task, rules)
   │   └── Returns: patch_text (diff format)
   │
   ├── 4. HybridJudge.evaluate(patch_text, vulnerability_class)
   │   ├── SemgrepScanner.scan_patch(patch_text)
   │   │   └── Returns: SASTResult (findings)
   │   └── ExploitExecutor.execute_http(class_id, base_url)
   │       └── Returns: DASTResult (success, evidence)
   │   └── Returns: JudgeVerdict (j=0 or j=1)
   │
   ├── 5. EloCalculator.update_pair(attacker, developer, j)
   │   └── Returns: new Elo ratings
   │
   ├── 6. IF j==1 (exploitable):
   │   ├── DistillerAgent.distill(trace)
   │   │   └── Returns: DistilledRule
   │   ├── RegressionGuard.approve(rule, all_rules)
   │   │   └── Returns: (approved: bool, report)
   │   └── IF approved:
   │       └── PromptStore.add_rule(rule)
   │           └── Creates new version, commits to Git
   │
   └── 7. Returns: EpisodeTrace (all artifacts)
```

### Batch Training Flow

```
1. TrainingSession(episodes=100)
   │
   ├── For each episode:
   │   ├── Select vulnerability class (round-robin)
   │   ├── Calculate difficulty tier from Elo
   │   ├── Run single episode (see above)
   │   ├── Update Elo ratings
   │   ├── Track per-class statistics
   │   └── Check for convergence
   │
   └── Returns: BatchReport {
       total_episodes,
       secure_rate,
       per_class_stats,
       elo_history,
       convergence_info
   }
```

---

## Testing Strategy

### Test Structure

```
tests/
├── unit/                    # 67 unit tests
│   ├── test_elo.py              # Elo calculator + difficulty tiers
│   ├── test_judge.py            # Judge verdict + DAST
│   ├── test_history.py          # Rating history tracker
│   ├── test_dedupe.py           # Semantic deduplication
│   ├── test_regression_guard.py # Regression detection
│   ├── test_telemetry.py        # Prometheus metrics
│   ├── test_portability.py      # Rule export/import (10 tests)
│   └── test_auth.py             # API auth + rate limiting (13 tests)
│
├── integration/            # 95 integration tests
│   ├── test_agents_pipeline.py     # Full attacker→developer→judge
│   ├── test_api_crud.py            # All 22 API endpoints
│   ├── test_evolution.py           # Prompt store versioning
│   ├── test_sandbox.py             # Sandbox config + validation
│   ├── test_sandbox_lifecycle.py   # Container lifecycle (29 tests)
│   └── test_e2e_training.py        # Full co-evolutionary cycle (12 tests)
│
└── conftest.py             # Root pytest config
```

### E2E Training Test Coverage

The `test_e2e_training.py` file tests the complete co-evolutionary cycle:

| Test | What it verifies |
|------|-----------------|
| `test_secure_episode` | j=0 path, no rule distilled, Elo shifts |
| `test_exploitable_episode` | j=1 path, rule distilled and stored |
| `test_elo_dynamics` | Ratings shift correctly over episodes |
| `test_all_vulnerability_classes` | Each class runs through the pipeline |
| `test_rule_accumulation` | Multiple exploitable episodes accumulate rules |
| `test_mixed_outcomes` | Alternating secure/exploitable produces correct count |
| `test_prompt_version_increments` | Version increments when rules accepted |
| `test_rules_passed_to_developer` | Rules appear in developer's system prompt |
| `test_multiple_classes_accumulate` | Multiple class rules all in prompt |
| `test_valid_rule_accepted` | Regression guard passes valid rules |
| `test_archive_grows` | Archive accumulates tasks |
| `test_batch_session` | Batch training produces a report |

---

## CI/CD Pipeline

### GitHub Actions Workflows

#### 1. CI Pipeline (`.github/workflows/ci.yml`)

Triggers: Push to `main`, PRs

```
┌─────────────────────────────────────────────────────────┐
│  Job: lint                                              │
│  ├── Checkout code                                      │
│  ├── Setup Python 3.14                                  │
│  ├── Install dependencies                               │
│  ├── Run: ruff check (0 errors)                         │
│  └── Run: ruff format --check (all formatted)           │
├─────────────────────────────────────────────────────────┤
│  Job: typecheck                                         │
│  ├── Checkout code                                      │
│  ├── Setup Python 3.14                                  │
│  ├── Install dependencies                               │
│  └── Run: mypy --strict                                 │
├─────────────────────────────────────────────────────────┤
│  Job: test                                              │
│  ├── Checkout code                                      │
│  ├── Setup Python 3.14                                  │
│  ├── Install dependencies                               │
│  ├── Run: pytest tests/unit/ (coverage)                 │
│  ├── Run: pytest tests/integration/                     │
│  └── Upload coverage to Codecov                         │
└─────────────────────────────────────────────────────────┘
```

#### 2. Security Scanning (`.github/workflows/security.yml`)

Triggers: Weekly schedule, push to `main`

```
┌─────────────────────────────────────────────────────────┐
│  Job: secret-detection                                  │
│  ├── Checkout code                                      │
│  ├── Run: detect-secrets scan                           │
│  └── Compare with baseline                              │
├─────────────────────────────────────────────────────────┤
│  Job: dependency-audit                                  │
│  ├── Checkout code                                      │
│  ├── Run: pip-audit                                     │
│  └── Report known vulnerabilities                       │
├─────────────────────────────────────────────────────────┤
│  Job: container-scan                                    │
│  ├── Checkout code                                      │
│  ├── Build Docker image                                 │
│  └── Run: Trivy vulnerability scanner                  │
└─────────────────────────────────────────────────────────┘
```

#### 3. Dependabot (`.github/dependabot.yml`)

Automated dependency updates:
- **pip** — Weekly Python dependency updates
- **Docker** — Weekly Dockerfile base image updates
- **GitHub Actions** — Weekly action version updates

---

## Deployment

### Development

```bash
# 1. Clone and setup
git clone https://github.com/SKar-2007/CoEvolve.git
cd CoEvolve
python -m venv .venv
source .venv/bin/activate
make install
make dev

# 2. Configure
cp .env.example .env
# Edit .env with API keys

# 3. Start infrastructure
docker compose up -d db redis prometheus grafana

# 4. Run API + Worker
make run-api        # Terminal 1
make worker         # Terminal 2

# 5. Run demo
make demo           # Mock mode
make demo-real      # Real LLM
```

### Production

```bash
# 1. Build sandbox image
make build-sandbox

# 2. Start all services
make docker-prod

# 3. Verify
curl http://localhost:8000/health

# 4. Open dashboard
open http://localhost:8000/dashboard
```

### Docker Compose Services

| Service | Port | Description |
|---------|------|-------------|
| API | 8000 | FastAPI REST API + Dashboard |
| Worker | — | Background training job processor |
| PostgreSQL | 5432 | Episode/rule database |
| Redis | 6379 | Task queue |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Dashboards |

---

## API Reference

### Authentication

All endpoints support optional API key authentication:

```bash
# Via header
curl -H "X-API-Key: cov_your_key_here" http://localhost:8000/episodes

# Via query param
curl "http://localhost:8000/episodes?api_key=cov_your_key_here"
```

### Rate Limits

All responses include rate limit headers:
- `X-RateLimit-Limit` — Max requests per window
- `X-RateLimit-Remaining` — Requests remaining
- `X-RateLimit-Reset` — Unix timestamp when window resets
- `Retry-After` — Seconds until retry (only on 429)

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | — | Health check |
| GET | `/metrics` | — | Episode/elo/rules metrics |
| GET | `/dashboard` | — | Metrics dashboard (HTML) |
| POST | `/episodes` | standard | Create episode |
| GET | `/episodes` | standard | List episodes |
| GET | `/episodes/{id}` | standard | Get episode |
| POST | `/episodes/{id}/stop` | standard | Stop episode |
| GET | `/elo` | standard | Current Elo ratings |
| GET | `/elo/history` | standard | Elo rating history |
| GET | `/prompts/current` | standard | Current prompt version |
| GET | `/prompts/history` | standard | Prompt version history |
| GET | `/prompts/diff/{v1}/{v2}` | standard | Diff between versions |
| GET | `/rules` | standard | List security rules |
| GET | `/rules/{id}` | standard | Get specific rule |
| POST | `/rules/export` | standard | Export rules as JSON |
| POST | `/rules/import` | standard | Import rules from JSON |
| POST | `/training/run` | standard | Run training (sync) |
| POST | `/training/async` | standard | Enqueue training (async) |
| GET | `/training/jobs` | standard | List training jobs |
| GET | `/training/jobs/{id}` | standard | Get job status |
| POST | `/auth/keys` | admin | Create API key |
| GET | `/auth/keys` | admin | List API keys |
| DELETE | `/auth/keys/{hash}` | admin | Disable API key |

---

## Current State

### By the Numbers

| Metric | Value |
|--------|-------|
| **Commits** | 25 |
| **Tests** | 162 passing, 6 skipped |
| **SAST Rules** | 29 (Python, JS, Java) |
| **DAST Targets** | 7 vulnerable apps |
| **API Endpoints** | 22 |
| **Makefile Targets** | 25 |
| **LLM Providers** | 5 (OpenRouter, Anthropic, OpenAI, Gemini, Mock) |
| **Vulnerability Classes** | 10 |
| **Packages** | 7 (api, agents, judge, elo, evolution, sandbox, telemetry) |

### What's Working End-to-End

1. **Mock Training Loop** — Full co-evolutionary cycle with mock LLM
2. **Real LLM Training** — Works with OpenRouter, Gemini, Anthropic
3. **SAST Scanning** — 29 semgrep rules across 3 languages
4. **DAST Exploitation** — 7 vulnerable apps with verified exploits
5. **Rule Distillation** — Failure traces → security rules
6. **Regression Guarding** — Validates rules against historical tasks
7. **Elo Rating** — Adaptive difficulty matching
8. **Batch Training** — Multi-episode sessions with convergence detection
9. **Async Jobs** — Background training with Redis queue
10. **Rule Portability** — Export/import as JSON packages
11. **Metrics Dashboard** — Real-time visualization
12. **API Hardening** — Rate limiting + API key auth
13. **CI/CD** — Automated testing + security scanning
14. **Deployment** — Docker Compose for dev and production

### What's Not Yet Implemented

1. **Vulnerable Target Apps (JS/Java)** — Only Python Flask apps exist
2. **Multi-language DAST** — Current apps are Python-only
3. **Persistent Elo History** — Currently in-memory only
4. **Webhook Notifications** — Only Slack/Email/PagerDuty
5. **User Authentication** — Only API key auth, no user accounts
6. **Web UI** — Only dashboard, no full management interface

---

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make install` | Install all packages in dev mode |
| `make dev` | Install dev tools (ruff, mypy, pytest) |
| `make test` | Run full test suite with coverage |
| `make lint` | Run ruff linter |
| `make typecheck` | Run mypy type checker |
| `make docker-up` | Start dev infrastructure |
| `make docker-down` | Stop dev infrastructure |
| `make docker-prod` | Start production stack |
| `make docker-prod-down` | Stop production stack |
| `make docker-logs` | Follow production API logs |
| `make build-sandbox` | Build sandbox Docker image |
| `make run-api` | Start API in dev mode |
| `make run-api-prod` | Start API in production mode |
| `make worker` | Start async job worker |
| `make worker-once` | Process one async job |
| `make demo` | Run demo in mock mode |
| `make demo-real` | Run demo with real LLM |
| `make benchmark` | Run 100-episode benchmark |
| `make train` | Run 100-episode batch training |
| `make stress` | Run 1000-episode stress test |
| `make dast` | Run DAST exploit verification |
| `make dashboard` | Start API + metrics dashboard |
| `make rules-export` | Export rules to rules.json |
| `make rules-import` | Import rules from rules.json |
| `make clean` | Remove caches and temp files |

---

## Repository Layout

```
CoEvolve Sandbox/
├── packages/
│   ├── api/                    # FastAPI REST API
│   │   ├── main.py                 # 22 API routes
│   │   ├── auth.py                 # API key auth + rate limiting
│   │   ├── models.py               # SQLAlchemy ORM models
│   │   ├── schemas.py              # Pydantic schemas
│   │   ├── config.py               # pydantic-settings config
│   │   ├── database.py             # Engine, session, base
│   │   ├── task_queue.py           # Redis-backed job queue
│   │   ├── worker.py               # Background job worker
│   │   └── static/dashboard.html   # Metrics dashboard
│   │
│   ├── agents/                 # LLM agent implementations
│   │   ├── training_loop.py        # Co-evolutionary orchestrator
│   │   ├── batch_trainer.py        # Multi-episode training
│   │   ├── cost_tracking.py        # Token/cost tracking + caching
│   │   ├── llm.py                  # Unified LLM client (5 providers)
│   │   ├── attacker/               # Adversarial task generator
│   │   │   ├── generator.py            # Task generation
│   │   │   └── prompts.py              # System prompts
│   │   ├── developer/              # Code patch agent
│   │   │   ├── executor.py             # Simple executor
│   │   │   └── tools.py                # ReAct tool-use (7 tools)
│   │   ├── distiller/              # Trace-to-rule conversion
│   │   │   └── pipeline.py             # Failure trace → rule
│   │   └── regression_guard/       # Rule regression detection
│   │       └── guard.py                # Retroactive validation
│   │
│   ├── judge/                  # Hybrid Judge Engine
│   │   ├── engine.py               # Orchestrates SAST + DAST
│   │   ├── sast/                   # Semgrep scanner + 29 rules
│   │   │   └── semgrep_rules/          # 29 YAML rule files
│   │   └── dast/                   # Dynamic exploit executor
│   │       ├── executor.py             # Payload library + runner
│   │       ├── runner.py               # DAST verification
│   │       └── targets/                # 7 vulnerable Flask apps
│   │
│   ├── elo/                    # Elo rating system
│   │   ├── calculator.py           # Zero-sum Elo engine
│   │   ├── difficulty.py           # 10-tier difficulty mapper
│   │   └── history.py              # Rating history tracker
│   │
│   ├── evolution/              # Prompt-Evolution Engine
│   │   ├── store.py                # Git-backed versioned store
│   │   ├── dedupe.py               # Semantic deduplication
│   │   └── portability.py          # Rule export/import
│   │
│   ├── sandbox/                # Docker container orchestration
│   │   ├── manager.py              # Container lifecycle
│   │   ├── lifecycle.py            # Episode orchestrator
│   │   ├── config.py               # Sandbox config + seccomp
│   │   └── docker/                 # Dockerfiles + profiles
│   │
│   └── telemetry/              # Monitoring and alerting
│       ├── exporters/metrics.py    # Prometheus metrics
│       └── alerting.py             # Notification channels
│
├── tests/                      # 162 tests
│   ├── unit/                   # 67 unit tests
│   └── integration/            # 95 integration tests
│
├── scripts/                    # CLI tools
│   ├── demo.py                     # End-to-end demo
│   ├── benchmark.py                # Episode benchmarking
│   ├── train.py                    # Batch training
│   ├── rules_export.py             # Export rules
│   └── rules_import.py             # Import rules
│
├── .github/
│   ├── workflows/ci.yml            # CI pipeline
│   ├── workflows/security.yml      # Security scanning
│   └── dependabot.yml              # Dependency updates
│
├── docker-compose.yml          # Development compose
├── docker-compose.prod.yml     # Production compose
├── Makefile                    # 25 build/test/deploy targets
├── requirements.txt            # Runtime dependencies
├── requirements-ci.txt         # CI dependencies
├── pyproject.toml              # Tool configuration
├── README.md                   # Full documentation
├── DEPLOY.md                   # Deployment guide
├── CONTRIBUTING.md             # Contribution guidelines
├── CHANGELOG.md                # Version history
└── vulnerability_taxonomy.md   # 26 vulnerability classes
```

---

## Summary

CoEvolve Sandbox is a **complete, production-ready** adversarial training platform that:

1. **Autonomously improves** LLM coding agent security through co-evolution
2. **Verifies** vulnerabilities with real SAST + DAST analysis
3. **Distills** failures into actionable security rules
4. **Evolves** system prompts without model fine-tuning
5. **Scales** with adaptive Elo-based difficulty matching
6. **Secures** with rate limiting, API key auth, and container isolation
7. **Monitors** with real-time dashboards and Prometheus metrics
8. **Deploys** with Docker Compose for dev and production

The system has been tested with **162 passing tests**, **25 commits**, and **5 LLM providers**. It's ready for real-world use.
