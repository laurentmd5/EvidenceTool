#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== Starting Kubernetes Minikube E2E Tests ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROFILE="evidencetool-e2e"
NAMESPACE="evidencetool-e2e"

cleanup() {
  kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  minikube delete -p "$PROFILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v minikube >/dev/null || { echo "minikube is required for Kubernetes E2E" >&2; exit 1; }
command -v kubectl >/dev/null || { echo "kubectl is required for Kubernetes E2E" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required for Minikube Docker driver" >&2; exit 1; }

cleanup
minikube start -p "$PROFILE" --driver=docker --wait=all
kubectl create namespace "$NAMESPACE"

kubectl -n "$NAMESPACE" create deployment healthy --image=nginx:1.27-alpine
kubectl -n "$NAMESPACE" rollout status deployment/healthy --timeout=180s

PYTHON_CMD="python3"
if [ -x /tmp/venv/bin/python ]; then
  PYTHON_CMD=/tmp/venv/bin/python
elif [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PYTHON_CMD="$ROOT_DIR/.venv/bin/python"
fi

run_diagnose() {
  set +e
  PYTHONPATH="$ROOT_DIR/src" "$PYTHON_CMD" -m evidencetool.cli.main diagnose k8s \
    --policy "$ROOT_DIR/policies/kubernetes.yaml" \
    --catalog "$ROOT_DIR/catalogs/kubernetes.yaml" \
    -a pod="$1" -a namespace="$NAMESPACE" --output json
  local result=$?
  set -e
  return "$result"
}

extract_decision() {
  "$PYTHON_CMD" -c 'import json,sys; print(json.load(sys.stdin)["decision"][sys.argv[1]])' "$1"
}

echo "--- Healthy pod ---"
HEALTHY_POD="$(kubectl -n "$NAMESPACE" get pods -l app=healthy -o jsonpath='{.items[0].metadata.name}')"
[ -n "$HEALTHY_POD" ] || { echo "FAIL: healthy pod name was not found"; exit 1; }
OUT="$(run_diagnose "$HEALTHY_POD" || true)"
[ "$(printf '%s' "$OUT" | extract_decision status)" = ALLOW ] || {
  echo "Healthy pod diagnostic output:"
  printf '%s\n' "$OUT"
  echo "FAIL: healthy pod was not ALLOW"; exit 1;
}
printf '%s' "$OUT" | "$PYTHON_CMD" -c 'import json,sys; d=json.load(sys.stdin); assert "K8S_POD_HEALTHY" in d["decision"]["reason"]'

kubectl -n "$NAMESPACE" run crashloop --image=busybox:1.36 \
  --restart=Always -- /bin/sh -c 'exit 1'
for attempt in $(seq 1 60); do
  reason="$(kubectl -n "$NAMESPACE" get pod crashloop -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
  [ "$reason" = CrashLoopBackOff ] && break
  if [ "$attempt" -eq 60 ]; then
    echo "FAIL: CrashLoopBackOff was not observed (last reason: ${reason:-none})"
    kubectl -n "$NAMESPACE" describe pod crashloop || true
    kubectl -n "$NAMESPACE" get events --sort-by=.lastTimestamp || true
    exit 1
  fi
  sleep 2
done

echo "--- CrashLoopBackOff pod ---"
OUT="$(run_diagnose crashloop || true)"
[ "$(printf '%s' "$OUT" | extract_decision status)" = BLOCK ] || {
  echo "CrashLoopBackOff diagnostic output:"
  printf '%s\n' "$OUT"
  echo "FAIL: crashloop pod was not BLOCK"; exit 1;
}
printf '%s' "$OUT" | "$PYTHON_CMD" -c 'import json,sys; d=json.load(sys.stdin); assert "K8S_CRASH_LOOP_BACKOFF" in d["decision"]["reason"]'

echo "=== Kubernetes Minikube E2E Tests Passed ==="