#!/usr/bin/env bash
set -euo pipefail

# CoEvolve Sandbox setup script
# Runs initial project setup: installs deps, builds packages, runs migrations

echo "=== CoEvolve Sandbox Setup ==="

# Install root deps
pip install -r requirements.txt

# Install all packages in development mode
pip install -e "packages/elo" -e "packages/agents" -e "packages/judge" \
    -e "packages/sandbox" -e "packages/api" -e "packages/telemetry" \
    -e "packages/evolution"

# Install dev tools
pip install -r requirements-dev.txt

# Install pre-commit if available
pip install pre-commit 2>/dev/null || true

echo "Setup complete. Run 'make dev' to start development mode."