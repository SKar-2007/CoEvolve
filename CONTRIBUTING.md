# Contributing to CoEvolve Sandbox

Thanks for your interest in contributing! This guide covers development setup, code standards, and the contribution process.

## Development Setup

```bash
# Clone and setup
git clone https://github.com/SKar-2007/CoEvolve.git
cd CoEvolve
python -m venv .venv
source .venv/bin/activate
make install
make dev

# Start infrastructure
docker compose up -d db redis

# Run tests
make test
```

## Code Standards

### Style
- **Formatter/Linter:** ruff (line length 100)
- **Type checker:** mypy with `--ignore-missing-imports`
- **Imports:** sorted by ruff (`I` rule)

### Testing
- Write tests for all new functionality
- Unit tests go in `tests/unit/`
- Integration tests go in `tests/integration/`
- Mark Docker-dependent tests with `@pytest.mark.integration`
- Run `make test` before committing

### Commits
- Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
- Keep commits focused — one logical change per commit
- Reference issues when applicable: `fix: resolve #42`

## Project Structure

```
packages/
├── api/          # FastAPI REST API
├── agents/       # LLM agent implementations
├── judge/        # Hybrid Judge Engine
├── elo/          # Elo rating system
├── evolution/    # Prompt-Evolution Engine
├── sandbox/      # Docker container orchestration
└── telemetry/    # Monitoring and alerting
```

## Adding a New Agent

1. Create `packages/agents/{agent_name}/`
2. Add `__init__.py` and implementation module
3. Add tests in `tests/unit/test_{agent_name}.py`
4. Register in `packages/agents/__init__.py`
5. Update README feature table

## Adding a New API Endpoint

1. Add request/response schemas in `packages/api/schemas.py`
2. Add endpoint in `packages/api/main.py`
3. Add tests in `tests/integration/test_api_crud.py`
4. Update API table in README

## Adding a New Vulnerability Class

1. Add to taxonomy in `data/vulnerability_taxonomy.json`
2. Add SAST rules in `packages/judge/sast/rules/`
3. Add DAST payloads in `packages/judge/dast/payloads/`
4. Add tests in `tests/unit/test_judge.py`

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make changes following the standards above
3. Run `make test` and `make lint`
4. Push and open a PR against `main`
5. CI must pass (lint, typecheck, tests)
6. Request review from a maintainer

## Reporting Issues

- Use GitHub Issues
- Include: steps to reproduce, expected vs actual behavior, Python version, OS
- For security vulnerabilities, email security@coevolve.dev instead

## License

By contributing, you agree that your contributions will be licensed under Apache License 2.0.
