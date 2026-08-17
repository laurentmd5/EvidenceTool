#!/bin/bash
set -e

# Build the image
docker build -t evidencetool-e2e -f tests/e2e/Dockerfile.systemd .

# Start the container.
# --privileged          : required for systemd to manage cgroups inside Docker
# --cgroupns=host       : required for Docker 20.10+ on cgroup v2 hosts (Ubuntu 22.04+)
#                         Without this, systemd fails to initialise as PID 1 silently.
# -v .../cgroup:rw      : cgroup v2 requires read-write access; :ro is a legacy cgroup v1 pattern.
# -v /run/systemd/...   : exposes the host's D-Bus socket so dbus-based providers work correctly.
CONTAINER_ID=$(docker run -d \
  --privileged \
  --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  evidencetool-e2e)

echo "Started container $CONTAINER_ID"

# Ensure cleanup on exit — always dump container logs first so failures are
# never silent (this was the root cause of the opaque "is not running" errors).
cleanup() {
  echo "--- Container logs (last 50 lines) ---"
  docker logs --tail 50 "$CONTAINER_ID" 2>&1 || true
  echo "--- Cleaning up container ---"
  docker rm -f "$CONTAINER_ID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for systemd to fully boot before running tests
echo "Waiting for systemd to boot..."
sleep 8

# Verify the container is still alive before proceeding
if ! docker inspect -f '{{.State.Running}}' "$CONTAINER_ID" | grep -q "true"; then
  echo "ERROR: Container exited before tests could run. See logs above."
  exit 1
fi

# Copy the test script into the container and execute it
docker cp tests/e2e/run_tests_in_container.sh "$CONTAINER_ID":/opt/EvidenceTool/run_tests_in_container.sh
docker exec "$CONTAINER_ID" chmod +x /opt/EvidenceTool/run_tests_in_container.sh

# Run the tests
docker exec "$CONTAINER_ID" /opt/EvidenceTool/run_tests_in_container.sh

echo "SUCCESS"
