#!/usr/bin/env bash
# Run the real kernel-enforcement tests inside a throwaway privileged container.
# The container gets its own network name, and the tests only touch netns
# namespaces they create and delete themselves: the host firewall is untouched.
#
#   ./scripts/test-kernel.sh                 # all integration tests
#   ./scripts/test-kernel.sh -k iptables -x  # extra args go to pytest
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${AVERQON_TEST_IMAGE:-averqon-kernel-tests}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required (or run: sudo -E pytest -m integration tests/integration)" >&2
  exit 1
fi

docker build --quiet -f "$REPO_ROOT/tests/integration/Dockerfile" -t "$IMAGE" "$REPO_ROOT"
exec docker run --rm --privileged \
  -e AVERQON_REQUIRE_KERNEL_TESTS=1 \
  "$IMAGE" \
  pytest -q -m integration tests/integration -rs "$@"
