#!/usr/bin/env bash
set -euo pipefail

# CoEvolve Sandbox test runner
# Runs unit, integration, and e2e test suites

echo "=== CoEvolve Sandbox Test Runner ==="

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Run unit tests
echo "--- Running unit tests ---"
cd "$ROOT"
python -m pytest tests/unit -v --cov=packages 2>&1 | tail -30

echo "--- Running integration tests ---"
cd "$ROOT"
python -m pytest tests/integration -v --cov=packages 2>&1 | tail -30

echo "Test run complete."