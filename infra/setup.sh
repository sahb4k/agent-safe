#!/usr/bin/env bash
# Set up integration test infrastructure for agent-safe.
# Usage: bash infra/setup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Agent-Safe Integration Test Setup ==="
echo ""

# --- Check prerequisites ---
missing=0
for cmd in docker kind kubectl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' is not installed or not in PATH."
        missing=1
    fi
done
if [ "$missing" -eq 1 ]; then
    echo ""
    echo "Install missing tools:"
    echo "  docker:  https://docs.docker.com/get-docker/"
    echo "  kind:    https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

# --- Start LocalStack ---
echo "[1/4] Starting LocalStack..."
docker compose -f "$SCRIPT_DIR/docker-compose.yaml" up -d
echo "       Waiting for LocalStack to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1; then
        echo "       LocalStack is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: LocalStack did not become ready in 30 seconds."
        exit 1
    fi
    sleep 1
done

# --- Create Kind cluster ---
echo "[2/4] Creating Kind cluster 'agent-safe-test'..."
if kind get clusters 2>/dev/null | grep -q "^agent-safe-test$"; then
    echo "       Cluster already exists."
else
    kind create cluster --config "$SCRIPT_DIR/kind-config.yaml" --name agent-safe-test
fi

# --- Bootstrap K8s resources ---
echo "[3/4] Bootstrapping Kubernetes test resources..."
kubectl apply -f "$SCRIPT_DIR/k8s-bootstrap.yaml" --context kind-agent-safe-test

# --- Wait for deployment ---
echo "[4/4] Waiting for test-nginx deployment to be ready..."
kubectl rollout status deployment/test-nginx \
    -n agent-safe-inttest \
    --context kind-agent-safe-test \
    --timeout=120s

echo ""
echo "=== Setup complete ==="
echo "  Kind cluster:  kind-agent-safe-test  (2 worker nodes)"
echo "  Namespace:     agent-safe-inttest"
echo "  LocalStack:    http://localhost:4566"
echo ""
echo "Run tests with:"
echo "  pytest tests/integration/ -m integration -v"
