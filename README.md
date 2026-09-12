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

## Repository Layout

```
packages/
├── api/          # FastAPI REST API (episodes, prompts, elo, rules, metrics)
├── agents/       # Attacker, Developer, Distiller, RegressionGuard + LLM clients
├── judge/        # Hybrid Judge Engine (Semgrep SAST + Dynamic DAST)
├── elo/          # Elo rating calculator and difficulty mapper
├── evolution/    # Prompt-Evolution Engine (distillation, versioning, guarding)
├── sandbox/      # Hardened Docker container orchestration
└── telemetry/    # Prometheus/Grafana metrics and exporters
data/             # Vulnerability taxonomy and exploit payload libraries
tests/            # unit / integration / e2e test suites
scripts/          # setup, test, deploy helpers
```

## Quick Start

```bash
# 1. Install dependencies
pip install -e "packages/api[dev]"

# 2. Copy environment configuration
cp .env.example .env

# 3. Start infrastructure (Postgres, Redis, Prometheus, Grafana)
docker compose up -d db redis prometheus grafana

# 4. Run the API
uvicorn api.main:app --reload --port 8000

# 5. Run tests
make test
```

## License

Apache License 2.0. See [LICENSE](LICENSE).