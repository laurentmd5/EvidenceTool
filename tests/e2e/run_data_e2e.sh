#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== Starting Data and Dependency E2E Tests ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
NETWORK="evidencetool-data-e2e"
REDIS_CONTAINER="evidencetool-e2e-redis"
HTTP_CONTAINER="evidencetool-e2e-http"
HTTP_DIR=""

command -v docker >/dev/null || { echo "docker is required for data E2E" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required for data E2E" >&2; exit 1; }

cleanup() {
  docker rm -f "$REDIS_CONTAINER" "$HTTP_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  if [ -n "$HTTP_DIR" ]; then
    rm -rf "$HTTP_DIR"
  fi
}
trap cleanup EXIT

cleanup
HTTP_DIR="$(mktemp -d)"
docker network create "$NETWORK" >/dev/null
printf 'EvidenceTool E2E health\n' > "$HTTP_DIR/health"

docker run -d --name "$REDIS_CONTAINER" --network "$NETWORK" -p 16379:6379 redis:7-alpine >/dev/null
docker run -d --name "$HTTP_CONTAINER" --network "$NETWORK" -p 18080:8000 \
  -v "$HTTP_DIR:/srv:ro" python:3.12-alpine \
  python -m http.server 8000 --directory /srv >/dev/null

for attempt in $(seq 1 30); do
  if docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -q PONG && \
     curl --silent --fail http://127.0.0.1:18080/health >/dev/null; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "FAIL: data E2E services did not become ready" >&2
    exit 1
  fi
  sleep 1
done

PYTHON_CMD="python3"
if [ -x /tmp/venv/bin/python ]; then
  PYTHON_CMD=/tmp/venv/bin/python
elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON_CMD="$ROOT_DIR/.venv/bin/python"
fi

run_diagnose() {
  set +e
  PYTHONPATH="$ROOT_DIR/src" "$PYTHON_CMD" -m evidencetool.cli.main diagnose "$@" --output json
  local result=$?
  set -e
  return "$result"
}

extract_status() {
  "$PYTHON_CMD" -c 'import json,sys; d=json.load(sys.stdin); wanted=sys.argv[1]; print(next(e["status"] for e in d["evidence"] if e["id"] == wanted))' "$1"
}

COMMON=(--policy "$ROOT_DIR/policies/data.yaml" --catalog "$ROOT_DIR/catalogs/data.yaml")

echo "--- Dependency provider: HTTP 200 ---"
OUT="$(run_diagnose dependency "${COMMON[@]}" -a url=http://127.0.0.1:18080/health || true)"
[ "$(printf '%s' "$OUT" | extract_status dependency.http_status)" = PASS ] || {
  echo "FAIL: dependency.http_status was not PASS"; exit 1;
}

echo "--- Redis provider: healthy instance ---"
OUT="$(run_diagnose redis "${COMMON[@]}" -a redis_host=127.0.0.1 -a redis_port=16379 || true)"
for evidence_id in redis.reachable redis.ping redis.memory_pressure redis.role; do
  [ "$(printf '%s' "$OUT" | extract_status "$evidence_id")" = PASS ] || {
    echo "FAIL: $evidence_id was not PASS"; exit 1;
  }
done

echo "--- PostgreSQL provider: closed port ---"
OUT="$(run_diagnose postgres "${COMMON[@]}" -a db_host=127.0.0.1 -a db_port=15432 || true)"
[ "$(printf '%s' "$OUT" | extract_status postgres.reachable)" = FAIL ] || {
  echo "FAIL: postgres.reachable was not FAIL"; exit 1;
}

echo "--- MySQL provider: closed port ---"
OUT="$(run_diagnose mysql "${COMMON[@]}" -a db_host=127.0.0.1 -a db_port=13306 || true)"
[ "$(printf '%s' "$OUT" | extract_status mysql.reachable)" = FAIL ] || {
  echo "FAIL: mysql.reachable was not FAIL"; exit 1;
}

echo "=== Data and Dependency E2E Tests Passed ==="