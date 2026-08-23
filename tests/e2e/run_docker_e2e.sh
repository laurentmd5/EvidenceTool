#!/bin/bash
set -e

echo "=== Starting Real Docker E2E Tests ==="

cleanup() {
  echo "Cleaning up Docker E2E test containers..."
  docker rm -f test-stopped-e2e test-crash-e2e test-unhealthy-e2e test-healthy-e2e 2>/dev/null || true
}
trap cleanup EXIT

cleanup

# Locate script and workspace directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CATALOG_PATH="$ROOT_DIR/catalogs/docker.yaml"
POLICY_PATH="$ROOT_DIR/policies/docker.yaml"

PYTHON_CMD="python3"
if [ -f "/tmp/venv/bin/python" ]; then
    PYTHON_CMD="/tmp/venv/bin/python"
elif [ -f "$ROOT_DIR/.venv/bin/python" ]; then
    PYTHON_CMD="$ROOT_DIR/.venv/bin/python"
elif ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

# Ensure Python has required runtime dependencies (click, yaml)
if ! PYTHONPATH="$ROOT_DIR/src" "$PYTHON_CMD" -c "import click, yaml" >/dev/null 2>&1; then
    echo "Preparing dedicated host virtualenv for E2E..."
    VENV_DIR="/tmp/evidencetool_e2e_host_venv"
    if [ ! -f "$VENV_DIR/bin/python" ]; then
        python3 -m venv "$VENV_DIR" || python -m venv "$VENV_DIR"
        "$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools wheel
        "$VENV_DIR/bin/pip" install --quiet -e "$ROOT_DIR"
    fi
    PYTHON_CMD="$VENV_DIR/bin/python"
fi

echo "Using Python binary: $PYTHON_CMD"
echo "Root directory: $ROOT_DIR"

run_diagnose() {
    PYTHONPATH="$ROOT_DIR/src" "$PYTHON_CMD" -m evidencetool.cli.main diagnose "$@"
}

check_result() {
    local out="$1"
    local expected_status="$2"
    local expected_situation="$3"
    
    local status
    local reason

    if command -v "$PYTHON_CMD" >/dev/null 2>&1; then
        status=$("$PYTHON_CMD" -c "import sys, json; d=json.loads(sys.argv[1]); print(d.get('decision',{}).get('status',''))" "$out" 2>/dev/null || true)
        reason=$("$PYTHON_CMD" -c "import sys, json; d=json.loads(sys.argv[1]); print(d.get('decision',{}).get('reason',''))" "$out" 2>/dev/null || true)
    elif command -v jq >/dev/null 2>&1; then
        status=$(echo "$out" | jq -r '.decision.status // empty')
        reason=$(echo "$out" | jq -r '.decision.reason // empty')
    fi
    
    if [ "$status" != "$expected_status" ]; then
        echo "FAIL: Expected status $expected_status, got $status"
        echo "Output: $out"
        exit 1
    fi
    
    if [ -n "$expected_situation" ] && [[ ! "$reason" == *"$expected_situation"* ]]; then
        echo "FAIL: Expected situation $expected_situation not found in reason: $reason"
        echo "Output: $out"
        exit 1
    fi
    echo "PASS: Status=$status, Situation/Reason matches '$expected_situation'"
}

# --- Scenario 1: Stopped Container ---
echo "--- Scenario 1: Stopped Container (CONTAINER_STOPPED) ---"
docker run -d --name test-stopped-e2e alpine sleep 0.1 >/dev/null
sleep 1
OUT=$(run_diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-stopped-e2e --output json) || true
check_result "$OUT" "ALLOW" "CONTAINER_STOPPED"

# --- Scenario 2: Crash Loop Container ---
echo "--- Scenario 2: Crash Loop Container (CONTAINER_CRASH_LOOP) ---"
docker run -d --restart=always --name test-crash-e2e alpine sh -c "exit 1" >/dev/null
sleep 2
OUT=$(run_diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-crash-e2e --output json) || true
check_result "$OUT" "ALLOW" "CONTAINER_CRASH_LOOP"

# --- Scenario 3: Unhealthy Container ---
echo "--- Scenario 3: Unhealthy Container (CONTAINER_UNHEALTHY) ---"
docker run -d --name test-unhealthy-e2e --health-cmd="exit 1" --health-interval=1s --health-retries=1 --health-timeout=1s alpine sleep 30 >/dev/null
sleep 3
OUT=$(run_diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-unhealthy-e2e --output json) || true
check_result "$OUT" "ALLOW" "CONTAINER_UNHEALTHY"

# --- Scenario 4: Non-Existent Container ---
echo "--- Scenario 4: Non-Existent Container (CONTAINER_NOT_FOUND) ---"
OUT=$(run_diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=nonexistent_container_xyz --output json) || true
check_result "$OUT" "BLOCK" "CONTAINER_NOT_FOUND"

# --- Scenario 5: Running Healthy Container (Action Blocked Because Already Healthy) ---
echo "--- Scenario 5: Running Healthy Container ---"
docker run -d --name test-healthy-e2e alpine sleep 30 >/dev/null
OUT=$(run_diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-healthy-e2e --output json) || true
check_result "$OUT" "BLOCK" ""

echo "=== All Docker E2E Scenarios Passed Successfully ==="
