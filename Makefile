.PHONY: install dev test lint typecheck docker-up docker-down docker-prod setup run-api \
       demo benchmark stress clean build-sandbox dast rules-export rules-import

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------

install:
	pip install -e "packages/api[dev]" -e "packages/agents" -e "packages/judge" -e "packages/sandbox"

dev:
	pip install -r requirements-dev.txt

test:
	pytest tests -v --cov=packages --cov-report=term-missing

lint:
	ruff check packages tests

typecheck:
	mypy packages --ignore-missing-imports

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

docker-up:
	docker compose up -d db redis prometheus grafana

docker-down:
	docker compose down

docker-prod:
	docker compose -f docker-compose.prod.yml up -d

docker-prod-down:
	docker compose -f docker-compose.prod.yml down

docker-logs:
	docker compose -f docker-compose.prod.yml logs -f api

docker-status:
	docker compose -f docker-compose.prod.yml ps

build-sandbox:
	docker build -t coevolve-sandbox:latest -f packages/sandbox/docker/Dockerfile .

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

run-api:
	uvicorn packages.api.main:app --reload --host 0.0.0.0 --port 8000

run-api-prod:
	uvicorn packages.api.main:app --host 0.0.0.0 --port 8000 --workers 4

worker:
	python -m packages.api.worker

worker-once:
	python -m packages.api.worker --once

# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------

demo:
	python scripts/demo.py

demo-real:
	python scripts/demo.py --real --episodes 5

benchmark:
	python scripts/benchmark.py --episodes 100

train:
	python scripts/train.py --episodes 100

stress:
	python scripts/benchmark.py --episodes 1000

dast:
	python -m packages.judge.dast.runner --all

rules-export:
	python scripts/rules_export.py --name coevolve-rules -o rules.json

rules-import:
	python scripts/rules_import.py --input rules.json

dashboard:
	@echo "Dashboard available at http://localhost:8000/dashboard"
	uvicorn packages.api.main:app --reload --host 0.0.0.0 --port 8000

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml
