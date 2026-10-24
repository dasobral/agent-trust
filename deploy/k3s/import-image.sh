#!/usr/bin/env bash
# Makes the att-node image available to k3s.
#
#   deploy/k3s/import-image.sh [IMAGE]
#
# With the containerd runtime (the k3s default) the image is exported from Docker and
# imported into k3s's containerd. With `--docker` k3s uses Docker's images directly,
# and nothing is needed. For a multi-node cluster, push the image to a registry
# instead and set ATT_K8S_PULL_POLICY=Always (see deploy/k3s/README.md).
set -euo pipefail
IMAGE="${1:-agent-trust-testbed/att-node:local}"
if pgrep -af "k3s server" | grep -q -- "--docker"; then
  echo "k3s uses the Docker runtime: $IMAGE is already visible"; exit 0
fi
docker image inspect "$IMAGE" >/dev/null
docker save "$IMAGE" | sudo k3s ctr images import -
sudo k3s ctr images ls | grep "${IMAGE%%:*}"
