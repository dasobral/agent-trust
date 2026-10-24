# k3s infrastructure

The `k8s` backend of `attctl` runs the testbed on any Kubernetes cluster. k3s is the
reference cluster: it is one binary, it enforces NetworkPolicy out of the box, and it
ships a `local-path` storage class. Everything here was run on k3s `v1.31.5+k3s1`.

## What the backend creates

For a topology named `three-agents`, in namespace `att-three-agents`:

| Object | Per | Purpose |
|---|---|---|
| `Namespace` | deployment | Isolation and one-command teardown |
| `Secret att-tokens` | deployment | Control, app and bootstrap tokens, read through `secretKeyRef` |
| `Secret att-pki-<service>` | service, mTLS only | The CA plus that service's own certificate and key (mode 0440) |
| `Deployment` (1 replica, `Recreate`) | service | `att-node <role>`; probes on `/healthz` (`att-node probe` under mTLS) |
| `Service` (ClusterIP) | service | Stable DNS name: `apf`, `relay`, `qrng`, `<agent>` |
| `PersistentVolumeClaim` (256 Mi) | APF and each agent | Adapter state; agent identity, MLS state and bookkeeping |
| `NetworkPolicy` | deployment | Default deny ingress; agents → APF and relay; APF and agents → QRNG |

Pods run as uid 10001 with a read-only root filesystem, no privilege escalation, no
capabilities and no service account token. The control plane reaches each service
through `kubectl port-forward` on `127.0.0.1`; nothing is exposed outside the cluster.

`stop` and `start` (experiment steps) scale one Deployment to 0 and back to 1; the
volume keeps the state, so a restarted APF or agent resumes where it stopped.

## Install

What was tested: the default online install with containerd runs in CI (job `k3s`),
where `k8s-isolation`, E1, E1-mtls and E3 pass. The development sandbox ran the same
k3s version with the Docker runtime and the sandbox settings below, started by hand
with the same flags. `--airgap`, `--docker` and `--sandbox` as script options are
documented here but were not run as a script.

```bash
sudo deploy/k3s/install-k3s.sh              # online, containerd runtime (default; tested in CI)
sudo deploy/k3s/install-k3s.sh --airgap     # images from the k3s release bundle
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml # attctl also finds this file by itself
```

## Image

```bash
./attctl build && ./attctl image            # agent-trust-testbed/att-node:local
deploy/k3s/import-image.sh                  # into k3s's containerd
```

For several nodes, push the image to a registry the nodes can pull from, run with
`--image REGISTRY/att-node:TAG`, and set `ATT_K8S_PULL_POLICY=Always`.

## Run

```bash
./attctl run experiments/e1-revocation-fence.toml --backend k8s
./attctl run experiments/k8s-isolation.toml --backend k8s       # NetworkPolicy checks
./attctl run experiments/e1-revocation-fence-mtls.toml --backend k8s
```

`attctl up TOPOLOGY --backend k8s` keeps a deployment running for manual work
(`attctl status`, `attctl call`, `kubectl -n att-<name> ...`); `attctl down` deletes
the namespace and waits until it is gone.

Static manifests, for review or GitOps:

```bash
./attctl render topologies/three-agents-mtls.toml --out three-agents.json
kubectl apply -f three-agents.json
```

The rendered file contains the Secrets (tokens and, with mTLS, keys): treat it as a
secret.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `KUBECONFIG` | k3s's `/etc/rancher/k3s/k3s.yaml` if present, else `~/.kube/config` | Cluster; recorded in `deploy.json` |
| `ATT_K8S_PULL_POLICY` | `IfNotPresent` | Image pull policy |
| `ATT_K8S_STORAGE_CLASS` | cluster default | Storage class of the claims |

## Running k3s inside a container

The testbed's own development sandbox is a container without systemd and without
`CAP_SYS_RESOURCE`. Two adjustments were needed there, and only there:

1. k3s runs with `--docker` (the host's Docker as container runtime), because nested
   containerd failed to start pods (`runc ... can't get final child's PID`).
   `install-k3s.sh --docker` does this, and `--airgap --docker` loads the image bundle
   into Docker. `kubectl port-forward` then needs `socat` on the host.
2. Kubernetes gives pod sandboxes `oomScoreAdj = -998`, which needs
   `CAP_SYS_RESOURCE`. `sandbox/runc-sandbox` is a runc wrapper that clamps a negative
   value to 0. Install it as Docker's default runtime:

   ```json
   { "runtimes": { "sandbox": { "path": "/usr/local/bin/runc-sandbox" } },
     "default-runtime": "sandbox" }
   ```

   in `/etc/docker/daemon.json`, then restart Docker. Do not do this on a normal
   host: it removes the OOM protection of pod sandboxes.

3. The sandbox reports a disk far larger than its writable allowance, so the kubelet
   sees the node as nearly full: it garbage-collects images (the att-node image
   disappears: `ErrImagePull`) and may evict pods. `install-k3s.sh --sandbox` sets
   `image-gc-high-threshold=100` and near-zero eviction thresholds.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `kubectl cannot reach the cluster` | Wrong or missing `KUBECONFIG` |
| A pod restarts once at start | The APF or an agent started before the QRNG service answered; the entropy source is chosen at start and never falls back, so the pod exits and Kubernetes restarts it |
| `start` of a service is slow after an entropy outage | Crash-loop back-off; `start` deletes the failing pod to restart it at once |
| `port-forward ... socat not found` | Docker runtime: install `socat` |
| `ErrImagePull` for `agent-trust-testbed/att-node:local` | The image is not in the node's runtime (import it), or the kubelet garbage-collected it (see "Running k3s inside a container") |
