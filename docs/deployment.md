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

[entropy]
source = "qrng"          # os | mock | qrng
# url = "https://entropy.example.net"   # a real QRNG Open API endpoint instead of the mock
# seed = 0                              # for source = "mock"

[relay]
seed = 7

[[agent]]
name = "alice"
[[agent]]
name = "bob"
```

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

### Adding a backend

A backend is a module in `controller/attctl/deploy/` with three functions:

```python
def up(topology, run_dir, ...) -> dict      # start services, write deploy.json
def down(run_dir) -> None
def logs(run_dir) -> dict[str, str]
```

`up` calls `topology.plan(topology, address)`, where `address(name, role)` returns
the URL under which other services reach `name`, and records the endpoints the
control plane uses in `deploy.json` (`common.deployment_record`). Nothing above the
backend changes. A Kubernetes backend, for example, renders one Deployment and
Service per planned service, with `address = http://<name>.<namespace>.svc:<port>`.

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
