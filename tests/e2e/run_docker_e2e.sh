#!/bin/bash
set -e

echo "=== Starting Real Docker E2E Tests ==="

cleanup() {
  echo "Cleaning up Docker E2E test containers..."
  docker rm -f test-stopped-e2e test-crash-e2e test-unhealthy-e2e test-healthy-e2e 2>/dev/null || true
}
trap cleanup EXIT

cleanup

# Determine python command
if [ -f "/opt/EvidenceTool/.venv/bin/evidencetool" ]; then
    DIAGNOSE_BIN="/opt/EvidenceTool/.venv/bin/evidencetool"
    CATALOG_PATH="/opt/EvidenceTool/catalogs/docker.yaml"
    POLICY_PATH="/opt/EvidenceTool/policies/docker.yaml"
elif [ -f ".venv/bin/evidencetool" ]; then
    DIAGNOSE_BIN=".venv/bin/evidencetool"
    CATALOG_PATH="catalogs/docker.yaml"
    POLICY_PATH="policies/docker.yaml"
else
    DIAGNOSE_BIN="evidencetool"
    CATALOG_PATH="catalogs/docker.yaml"
    POLICY_PATH="policies/docker.yaml"
fi

check_result() {
    local out="$1"
    local expected_status="$2"
    local expected_situation="$3"
    
    local status=$(echo "$out" | jq -r '.decision.status')
    local reason=$(echo "$out" | jq -r '.decision.reason')
    
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
OUT=$($DIAGNOSE_BIN diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-stopped-e2e --output json) || true
check_result "$OUT" "ALLOW" "CONTAINER_STOPPED"

# --- Scenario 2: Crash Loop Container ---
echo "--- Scenario 2: Crash Loop Container (CONTAINER_CRASH_LOOP) ---"
docker run -d --restart=always --name test-crash-e2e alpine sh -c "exit 1" >/dev/null
sleep 2
OUT=$($DIAGNOSE_BIN diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-crash-e2e --output json) || true
check_result "$OUT" "ALLOW" "CONTAINER_CRASH_LOOP"

# --- Scenario 3: Unhealthy Container ---
echo "--- Scenario 3: Unhealthy Container (CONTAINER_UNHEALTHY) ---"
docker run -d --name test-unhealthy-e2e --health-cmd="exit 1" --health-interval=1s --health-retries=1 --health-timeout=1s alpine sleep 30 >/dev/null
sleep 3
OUT=$($DIAGNOSE_BIN diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-unhealthy-e2e --output json) || true
check_result "$OUT" "ALLOW" "CONTAINER_UNHEALTHY"

# --- Scenario 4: Non-Existent Container ---
echo "--- Scenario 4: Non-Existent Container (CONTAINER_NOT_FOUND) ---"
OUT=$($DIAGNOSE_BIN diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=nonexistent_container_xyz --output json) || true
check_result "$OUT" "BLOCK" "CONTAINER_NOT_FOUND"

# --- Scenario 5: Running Healthy Container (Action Blocked Because Already Healthy) ---
echo "--- Scenario 5: Running Healthy Container ---"
docker run -d --name test-healthy-e2e alpine sleep 30 >/dev/null
OUT=$($DIAGNOSE_BIN diagnose docker --catalog "$CATALOG_PATH" --policy "$POLICY_PATH" -a container=test-healthy-e2e --output json) || true
check_result "$OUT" "BLOCK" ""

echo "=== All Docker E2E Scenarios Passed Successfully ==="
