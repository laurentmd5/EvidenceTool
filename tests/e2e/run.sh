#!/bin/bash
set -e

for DOCKERFILE in Dockerfile.systemd Dockerfile.debian; do
  echo ">>> Building and testing with $DOCKERFILE <<<"
  # Build the image
  docker build -t evidencetool-e2e -f tests/e2e/$DOCKERFILE .

  # Start the container.
  CONTAINER_ID=$(docker run -d \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    evidencetool-e2e)

  echo "Started container $CONTAINER_ID"

  # Wait for systemd to fully boot before running tests
  echo "Waiting for systemd to boot..."
  sleep 8

  # Verify the container is still alive before proceeding
  if ! docker inspect -f '{{.State.Running}}' "$CONTAINER_ID" | grep -q "true"; then
    echo "ERROR: Container exited before tests could run. See logs:"
    docker logs --tail 50 "$CONTAINER_ID" 2>&1 || true
    exit 1
  fi

  # Copy the test script into the container and execute it
  docker cp tests/e2e/run_tests_in_container.sh "$CONTAINER_ID":/opt/EvidenceTool/run_tests_in_container.sh
  docker exec "$CONTAINER_ID" chmod +x /opt/EvidenceTool/run_tests_in_container.sh

  # Run the tests
  docker exec "$CONTAINER_ID" /opt/EvidenceTool/run_tests_in_container.sh
  
  echo "--- Cleaning up container ---"
  docker rm -f "$CONTAINER_ID" 2>/dev/null || true
  
  echo "SUCCESS on $DOCKERFILE"
done

echo "ALL E2E SUCCESS"
