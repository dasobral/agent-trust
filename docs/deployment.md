# Deployment

A deployment is a **topology** started by a **backend**. The topology says what runs;
the backend says where. Both backends start the same `att-node` binary with the same
environment, so a result on one backend is a result on the same software.

## Topologies

`topologies/*.toml`:

```toml
name = "three-agents"
group = "lab"            # MLS group id and kernel group
root = "alice"           # the founding agent

[mls]
suite = "pq"             # pq (default) | classical: agent-trust C-42, see below

[entropy]
source = "qrng"          # os | mock | qrng
# url = "https://entropy.example.net"   # a real QRNG Open API endpoint instead of the mock
# seed = 0                              # for source = "mock"
# key_exchange = "pq-preferred"         # TLS of the QRNG link: pq-only (default for the qrng service) | pq-preferred (default for a url)

[relay]
seed = 7

[tls]
enabled = false          # true: mutual TLS between every pair of services

[[agent]]
name = "alice"
[[agent]]
name = "bob"
```

Provided topologies: `three-agents` (E1 to E4, E8 `pq`), `three-agents-classical` (E8
`classical`), `three-agents-mtls` (E1 over mTLS), `four-agents` (E7), `scale-8` (E5;
`scripts/make-topology.py N` makes others).

### Cryptographic suite

`[mls] suite` selects the suite of agent-trust C-42 for every identity the deployment
creates. The APF takes the suite from the root's key at genesis.

| Suite | MLS ciphersuite | Key exchange | Signatures (identities, requests, APF) |
|---|---|---|---|
| `pq` (default) | `0x0052` | X-Wing: ML-KEM-768 with X25519 | ML-DSA-44 |
| `classical` | `0x0001` | X25519 | Ed25519 |

`attctl` passes it to the APF and the agents as `AGENT_TRUST_SUITE`. An agent that
restarts with an identity of the other suite refuses to start.

From a topology, `attctl` plans these services:

| Service | Present when | Role |
|---|---|---|
| `qrng` | `source = "qrng"` and no `url` | `att-node qrng-mock` |
| `apf` | always | `att-node apf` |
| `relay` | always | `att-node relay` |
| one per `[[agent]]` | always | `att-node agent` |

### Entropy sources

| Topology | Every node draws from | Claim |
|---|---|---|
| `source = "os"` | The OS RNG of its own host | Default; no QRNG involved |
| `source = "mock"` | openmls-qrand `MockEntropy`, seeded | **Not random.** Reproducible keys for debugging |
| `source = "qrng"` | The testbed's `qrng-mock` service over HTTP | Exercises the real QRNG client path; the bytes are OS RNG bytes |
| `source = "qrng"`, `url = ...` | That endpoint, for example Quside Entropy Core | The live gate of agent-trust (`live_entropy_core`) |

Over `https://`, the QRNG link uses the hybrid key exchange `X25519MLKEM768`
(openmls-qrand). The link to the testbed's own `qrng` service offers only that group
(`key_exchange = "pq-only"`). A link to a real endpoint (`url`), such as an Entropy Core,
defaults to `key_exchange = "pq-preferred"` (agent-trust D-14): it offers the hybrid group
first and also accepts a classical group from a server without it. That is a downgrade,
and every node shows it: `GET /control/entropy` on the APF and on each agent returns
`key_exchange` (the negotiated group, for example `X25519MLKEM768` or `X25519`) and
`post_quantum`. openmls-qrand learns the group from one extra TLS handshake at connect,
directly over TCP; through a proxy that check can fail, and the group is then
`unknown (reason)`. Set `key_exchange = "pq-only"` to refuse a classical server.

Secrets for a real endpoint never go in the topology. Export them before `attctl up`
or `attctl run` (`AGENT_TRUST_QRNG_API_KEY`, `AGENT_TRUST_QRNG_BEARER_TOKEN`,
`AGENT_TRUST_QRNG_CA_PEM`, ...); `attctl` passes every `AGENT_TRUST_QRNG_*` variable
through to the nodes.

## Backends

### `local`

```bash
./attctl build                       # target/release/att-node
./attctl up topologies/three-agents.toml --backend local
```

- One process per service on `127.0.0.1`, each on a free port.
- Logs: `runs/current/logs/<service>.log` (one JSON line per event).
- APF state: `runs/current/state/apf`.
- `./attctl down` stops the process group of each service.

### `compose`

```bash
./attctl build
./attctl image --base ubuntu:24.04   # from the host binary (Dockerfile.prebuilt)
# or: ./attctl image --from-source   # multi-stage build (Dockerfile), needs GitHub access
./attctl up topologies/three-agents.toml --backend compose
```

- One container per service on a private bridge network; services reach each other
  by name (`http://apf:7000`).
- Only `127.0.0.1` host ports are published, for the control plane.
- The APF state is a named volume (`apf-state`); the container runs as an
  unprivileged user.
- `runs/current/docker-compose.yml` is generated and kept (mode 0600: it holds the
  deployment tokens). `./attctl down` removes containers, network and volume.
- If Docker Hub rate limits you, pass a mirror as base, for example
  `--base mirror.gcr.io/library/ubuntu:24.04`.
- The prebuilt image needs a base whose glibc is at least the build host's.

### `k8s` (tested on k3s)

```bash
./attctl build && ./attctl image && deploy/k3s/import-image.sh
./attctl up topologies/three-agents.toml --backend k8s
```

- One namespace per deployment (`att-<topology>`); one Deployment, Service and (for
  the APF and agents) PersistentVolumeClaim per service; tokens and certificates in
  Secrets; default-deny ingress NetworkPolicies; unprivileged, read-only pods.
- The control plane reaches services through `kubectl port-forward` on `127.0.0.1`.
- `./attctl render TOPOLOGY --out FILE` writes the same objects as static manifests.
- Cluster setup, image import, multi-node notes and sandbox caveats:
  [`deploy/k3s/README.md`](../deploy/k3s/README.md).

### Mutual TLS, post quantum

With `[tls] enabled = true`, `attctl up` first creates the deployment PKI
(`att-node pki`, in `<run_dir>/pki`):

- a **post quantum CA** (ML-DSA-44) and, from it, one certificate per service, per
  application (`<agent>-app`) and for `attctl`: `ca.crt`, `<name>.crt`, `<name>.key`;
- a **classical CA** (ECDSA P-256) and, from it, the same names again:
  `classical-ca.crt`, `<name>.classical.crt`, `<name>.classical.key`.

Every link between services is TLS 1.3 with an ML-DSA-44 certificate over the hybrid key
exchange `X25519MLKEM768`, the QRNG link included. Service clients offer only that group
and trust only the post quantum CA. The classical chain exists for one client: the
control plane, when its Python links an OpenSSL older than 3.5 (no `X25519MLKEM768`, no
ML-DSA). A server presents its classical certificate only to a client that offers no
ML-DSA signature scheme, and accepts a classical client certificate only for `attctl` and
`<agent>-app`: a classical certificate that names a service is refused (`403`). With
OpenSSL 3.5 or later, `attctl` uses its post quantum certificate instead; reports name
the chain it used (`check.pq_tls`, `control_link`). In these runs the classical control
link also carries the decrypted messages that `attctl` reads from `/app/inbox` as the
application, and the app token. A real application uses its own post quantum
`<agent>-app` certificate.

Each backend gives each service its own certificates: local processes read
`<run_dir>/pki`; compose mounts it read-only at `/etc/att/pki` (its keys are made
readable by the container user: a lab tradeoff); Kubernetes mounts a per-service Secret
with both CA certificates and that service's own two certificates and keys. The CA keys
stay in the run directory. Every URL becomes `https://`.

### Service lifecycle

Experiments can stop and start one service (`stop`, `start`, `restart` steps):

| Backend | Stop | Start | State kept in |
|---|---|---|---|
| local | `SIGKILL` of the process group | the same command and environment | `<run_dir>/state/<service>` |
| compose | `docker compose kill` | `docker compose start` | named volumes |
| k8s | scale to 0 | delete any failing pod, scale to 1 | PersistentVolumeClaims |

### Adding a backend

A backend is a module in `controller/attctl/deploy/` with three functions:

```python
def up(topology, run_dir, ...) -> dict      # start services, write deploy.json
def down(run_dir) -> None
def logs(run_dir) -> dict[str, str]
def stop(run_dir, name) -> None             # optional: restart experiments
def start(run_dir, name) -> None
```

`up` calls `topology.plan(topology, address)`, where `address(name, role)` returns
the URL under which other services reach `name`, and records the endpoints the
control plane uses in `deploy.json` (`common.deployment_record`). Nothing above the
backend changes.

## `deploy.json`

Every backend writes `<run_dir>/deploy.json` (mode 0600):

```json
{
  "backend": "local", "name": "three-agents", "group": "lab", "root": "alice",
  "agents": ["alice", "bob", "carol"], "entropy": {"source": "qrng"},
  "endpoints": {"qrng": "http://127.0.0.1:41001", "apf": "...", "relay": "...", "alice": "..."},
  "tokens": {"control": "...", "app": "...", "bootstrap": "..."}
}
```

It is the only interface between the backends and the rest of the control plane.
It holds secrets: it is never recorded as evidence and `runs/` is ignored by git.
