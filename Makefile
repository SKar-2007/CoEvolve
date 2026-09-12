.PHONY: install dev test lint typecheck docker-up docker-down setup run-api

install:
	pip install -e "packages/api[dev]" -e "packages/agents" -e "packages/judge" -e "packages/sandbox"

dev:
	pip install -r requirements-dev.txt

test:
	pytest tests -v --cov=packages --cov-report=term-missing

lint:
	ruff check packages tests

typecheck:
	mypy packages

docker-up:
	docker compose up -d db redis prometheus grafana

docker-down:
	docker compose down

setup:
	bash scripts/setup.sh

run-api:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000