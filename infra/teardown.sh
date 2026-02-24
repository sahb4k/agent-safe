#!/usr/bin/env bash
# Tear down integration test infrastructure for agent-safe.
# Usage: bash infra/teardown.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Agent-Safe Integration Test Teardown ==="

echo "[1/2] Deleting Kind cluster..."
kind delete cluster --name agent-safe-test 2>/dev/null || true

echo "[2/2] Stopping LocalStack..."
docker compose -f "$SCRIPT_DIR/docker-compose.yaml" down -v 2>/dev/null || true

echo "=== Teardown complete ==="
