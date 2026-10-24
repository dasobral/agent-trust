#!/usr/bin/env bash
# Installs a single-node k3s cluster for the testbed.
#
#   sudo deploy/k3s/install-k3s.sh                 # online install, containerd runtime
#   sudo deploy/k3s/install-k3s.sh --airgap        # images from the release bundle
#   sudo deploy/k3s/install-k3s.sh --docker        # use the host's Docker as runtime
#   sudo deploy/k3s/install-k3s.sh --sandbox       # --docker, plus kubelet settings for a
#                                                   # container with a small disk allowance
#
# The version is pinned (K3S_VERSION). Traefik and metrics-server are disabled: the
# testbed needs neither. NetworkPolicy enforcement is on by default in k3s.
set -euo pipefail
K3S_VERSION="${K3S_VERSION:-v1.31.5+k3s1}"
AIRGAP=0; DOCKER=0; SANDBOX=0
for arg in "$@"; do
  case "$arg" in
    --airgap) AIRGAP=1 ;;
    --docker) DOCKER=1 ;;
    --sandbox) DOCKER=1; SANDBOX=1 ;;
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
release="https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION/+/%2B}"
flags="--disable traefik --disable metrics-server --write-kubeconfig-mode 600"
[ "$DOCKER" = 1 ] && flags="$flags --docker"
if [ "$SANDBOX" = 1 ]; then
  # A sandbox reports a disk far larger than its allowance: the kubelet would see it
  # as nearly full and garbage-collect images and evict pods. Turn both off.
  flags="$flags --kubelet-arg=image-gc-high-threshold=100 --kubelet-arg=image-gc-low-threshold=99"
  flags="$flags --kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%"
fi

if [ "$AIRGAP" = 1 ]; then
  mkdir -p /var/lib/rancher/k3s/agent/images
  curl -sSfL -o /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst \
    "$release/k3s-airgap-images-amd64.tar.zst"
  curl -sSfL -o /usr/local/bin/k3s "$release/k3s" && chmod +x /usr/local/bin/k3s
  if [ "$DOCKER" = 1 ]; then
    # The Docker runtime does not read the airgap directory: load the bundle into Docker.
    zstd -dc /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst | docker load
  fi
  export INSTALL_K3S_SKIP_DOWNLOAD=true
fi

if command -v systemctl >/dev/null && systemctl is-system-running >/dev/null 2>&1; then
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC="server $flags" sh -
else
  # No systemd (containers, CI sandboxes): run the server directly.
  [ -x /usr/local/bin/k3s ] || { curl -sSfL -o /usr/local/bin/k3s "$release/k3s"; chmod +x /usr/local/bin/k3s; }
  # shellcheck disable=SC2086
  setsid /usr/local/bin/k3s server $flags > /var/log/k3s.log 2>&1 &
fi

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for _ in $(seq 1 120); do
  kubectl get nodes 2>/dev/null | grep -q " Ready" && break
  sleep 2
done
kubectl get nodes
echo "k3s ready. KUBECONFIG=/etc/rancher/k3s/k3s.yaml"
