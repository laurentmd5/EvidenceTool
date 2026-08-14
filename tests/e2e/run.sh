#!/bin/bash
set -e

# Build the image
docker build -t evidencetool-e2e -f tests/e2e/Dockerfile.systemd .

# Start the container
# We use --privileged and mount cgroup to allow systemd to run inside Docker
CONTAINER_ID=$(docker run -d --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro evidencetool-e2e)

echo "Started container $CONTAINER_ID"

# Ensure cleanup on exit
trap "echo 'Cleaning up container...'; docker rm -f $CONTAINER_ID" EXIT

# Wait for systemd
sleep 5

# Copy the test script into the container and execute it
docker cp tests/e2e/run_tests_in_container.sh $CONTAINER_ID:/opt/EvidenceTool/run_tests_in_container.sh
docker exec $CONTAINER_ID chmod +x /opt/EvidenceTool/run_tests_in_container.sh

# Run the script
docker exec $CONTAINER_ID /opt/EvidenceTool/run_tests_in_container.sh

echo "SUCCESS"
