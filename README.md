# agent-trust-testbed

Networked testbed for the **Agent Trust** stack. It runs the parties of
[agent-trust](https://github.com/dasobral/agent-trust) as separate network services
(an APF authority, one trust sidecar per agent, an untrusted relay and a QRNG
service), deploys them on local processes, Docker Compose or Kubernetes (k3s),
drives them from a control plane, and checks every run with agent-trust's
independent oracle.

This is research software, not a production system.

> **Where this lives.** The session that built the testbed could not create a new
> GitHub repository, so the history is on the branch `testbed/main` of
> `dasobral/agent-trust` (unrelated to that repository's `main`). To move it to its
> own repository, create an empty `dasobral/agent-trust-testbed` and run
> `git push git@github.com:dasobral/agent-trust-testbed.git origin/testbed/main:refs/heads/main`
> from any clone of agent-trust. Nothing in the testbed depends on the branch name.

**Owner:** [Daniel Sobral Blanco](https://github.com/dasobral) · **License:** [MIT](LICENSE)

## Status

| Experiment | Question | local | compose | k3s |
|---|---|---|---|---|
| [E1](docs/experiments/E1-revocation-fence.md) | Revocation fence, repair against a retained key adversary, rekey, under relay faults | PASS | PASS | PASS |
| E1-mtls | E1 with mutual TLS everywhere, plus transport negative controls | PASS | PASS | PASS |
| [E2](docs/experiments/E2-entropy-outage.md) | QRNG outage: fail closed, change nothing, recover | PASS | PASS | PASS |
| [E3](docs/experiments/E3-restarts.md) | APF and agent crashes, outages, offline members | PASS | PASS | PASS |
| [E4](docs/experiments/E4-hostile-commits.md) | Forged, replayed, spliced, hidden and reordered commits | PASS | PASS | PASS |
| [E5](docs/experiments/E5-scale.md) | Eight agents in parallel: latency, cost growth, safety | PASS | | |
| [E7](docs/experiments/E7-confused-deputy.md) | Confused deputy: invocation provenance and attenuation | PASS | PASS | PASS |
| [K8S](deploy/k3s/README.md) | NetworkPolicy isolation of the services | | | PASS |

Evidence (reports, traces, service logs) is in [`results/`](results/); the dates and
exact revisions are in each `report.json`. Every recorded run names a clean testbed
commit (`6c0331a` or `86fd2e7`, which differ only in documentation); a run from a
tree with uncommitted changes would be marked `-dirty`. GitHub CI run
`40115418056` on `d2ab776` passed the local job (every experiment, E5 included), the
compose job and the k3s job (a fresh k3s with containerd). Stability: 60 of 60 runs pass (10 each of
E1, E1-mtls, E2, E3, E4 and E7, local backend,
[`results/stability-2026-10-24.txt`](results/stability-2026-10-24.txt)). E6 (a live Entropy Core) is the one planned
experiment not run: it needs a reachable endpoint. In every run here the QRNG service
is a **mock** (OS RNG bytes): no quantum origin is claimed.

Stack under test: agent-trust `5cf724e` (branch `feat/durable-lab-provider`: `main`
`9af877c` plus the durable provider this testbed needed, finding F-2; the branch head
`43750a8` adds only its contract text, C-41, flagged for approval and not yet merged), OpenMLS fork
`dd33278`, openmls-qrand `a102450`.

Findings on the stack, with proposals: [`docs/findings.md`](docs/findings.md). The
most important: the kernel's cost per request grows with the square of its history
(F-8, measured by E5), and any epoch change makes not yet consumed messages
undeliverable (F-7). F-9: every public key algorithm in the stack is classical; a probe
shows that the hybrid post quantum MLS suite (ML-KEM-768 with X25519) already works
([`results/F9/`](results/F9/README.md)).

## How the stack builds up

```text
 L4  attctl            control plane: topologies, backends (local, compose, k8s), experiments, oracle
 L3  att-node          apf │ agent sidecar (one per agent) │ relay │ qrng-mock   (HTTP or mTLS services)
 L2  agent-trust       APF kernel + adapter │ client endpoint │ trace export │ oracle
 L1  OpenMLS fork      MLS groups, public sequencer, staged KeyPackages, libcrux DRBG
 L0  openmls-qrand     QRNG Open API randomness, fail closed  ──▶  qrng-mock or Entropy Core
```

- **L0 to L2 are libraries**, pinned once in [`Cargo.toml`](Cargo.toml). The testbed adds
  no cryptography and no authorization logic: every decision is agent-trust's.
- **L3 cuts L2 at its party boundaries.** `att-node apf` wraps the agent-trust
  `Adapter`. `att-node agent` wraps one `ClientEndpoint` and is the only holder of its
  agent's keys; it persists its identity and MLS state and survives restarts.
  `att-node relay` carries opaque, signed or encrypted bytes, leases them until they
  are acknowledged, and injects faults on demand. `att-node qrng-mock` serves the QRNG
  Open API.
- **L4 deploys and controls L3** through HTTP APIs only, with per deployment tokens
  (and, with mTLS, its own certificate). It never holds an agent key.

[`docs/architecture.md`](docs/architecture.md) explains each layer, the trust
boundaries, every flow with its agent-trust contract section, and the durability and
delivery guarantees.

## Quick start

You need Rust 1.91 or newer and Python 3.11 or newer. Docker for the compose backend;
a Kubernetes cluster for the k8s backend ([`deploy/k3s/`](deploy/k3s/README.md)).

```bash
./attctl build                                                   # att-node, release
./attctl run experiments/e1-revocation-fence.toml --backend local
scripts/ci.sh                                                    # unit tests and every experiment
```

Containers and Kubernetes:

```bash
./attctl image                                                   # image from the host binary
./attctl run experiments/e1-revocation-fence.toml --backend compose
sudo deploy/k3s/install-k3s.sh && deploy/k3s/import-image.sh     # a k3s cluster
./attctl run experiments/k8s-isolation.toml --backend k8s
```

## Deploy and control

```bash
./attctl up topologies/three-agents.toml --backend local         # or compose, k8s
./attctl status                                                  # APF view, agents, relay
./attctl call relay POST /control/faults '{"drop": 30, "duplicate": 30, "reorder": true}'
./attctl trace                                                   # export and run the oracle
./attctl down
./attctl render topologies/three-agents-mtls.toml --out k8s.json # static Kubernetes manifests
```

| Document | Contents |
|---|---|
| [`docs/deployment.md`](docs/deployment.md) | Topologies, entropy sources, the three backends, mTLS, service lifecycle, adding a backend |
| [`deploy/k3s/README.md`](deploy/k3s/README.md) | The k3s infrastructure: objects, install, image, NetworkPolicy, sandbox notes |
| [`docs/control.md`](docs/control.md) | `attctl` commands, the experiment format, every action and check, evidence |
| [`docs/protocol.md`](docs/protocol.md) | HTTP API and configuration of each service |

## Integrating an agent

An application talks only to its own sidecar, with two calls:

```text
POST /app/send   {"text": "..."}      → {"op", "recipients", "epoch"} or a refusal code
GET  /app/inbox?after=N               → messages delivered after APF consumption
```

The application never handles keys, MLS state, the APF protocol or the relay. Any
agent framework in any language integrates the same way (an `invocation` field lets it
act for another agent under an APF invocation);
[`examples/echo_agent.py`](examples/echo_agent.py) is a complete example.

## Repository layout

| Path | Contents |
|---|---|
| `crates/att-node/` | The four network services, the PKI tool and the probe (Rust) |
| `controller/attctl/` | Control plane: topology, backends, API clients, runner, oracle loader (Python, standard library only) |
| `attctl` | Entry point of the control plane |
| `topologies/` | Deployment descriptions |
| `experiments/` | Experiment specifications |
| `deploy/docker/`, `deploy/k3s/` | Container images; k3s install, image import and sandbox notes |
| `examples/` | Application integrations |
| `results/` | Recorded evidence: reports, traces, logs |
| `scripts/` | `ci.sh` (all gates), `stability.sh` (repeated runs), `make-topology.py` |
| `tests/` | Control plane unit tests |
| `docs/` | Architecture, protocol, deployment, control, experiments, findings, roadmap |

## License

Copyright © 2026 Daniel Sobral Blanco. Released under the [MIT License](LICENSE).
The pinned OpenMLS crates remain under their own licenses.
