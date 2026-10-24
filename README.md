# agent-trust-testbed

Networked testbed for the **Agent Trust** stack. It runs the parties of
[agent-trust](https://github.com/dasobral/agent-trust) as separate network services
(an APF authority, one trust sidecar per agent, an untrusted relay and a QRNG
service), deploys them on any backend, drives them from a control plane, and checks
every run with agent-trust's independent oracle.

This is research software, not a production system.

**Owner:** [Daniel Sobral Blanco](https://github.com/dasobral) · **License:** [MIT](LICENSE)

## Status

| Item | State |
|---|---|
| Experiment E1, local backend | **PASS**, 55/55 steps ([evidence](results/E1/)) |
| Experiment E1, compose backend | **PASS**, 55/55 steps ([evidence](results/E1/)) |
| Stability, E1 local | 20/20 runs pass ([log](results/E1/stability-2026-10-24.txt)) |
| Entropy | Every node draws from the QRNG Open API service over HTTP. In E1 that service is a **mock** (OS RNG bytes): no quantum origin is claimed. |
| Stack under test | agent-trust `9af877c`, OpenMLS fork `dd33278`, openmls-qrand `a102450` |

## How the stack builds up

```text
 L4  attctl            control plane: topologies, backends, experiments, oracle, reports
 L3  att-node          apf │ agent sidecar (one per agent) │ relay │ qrng-mock    (HTTP services)
 L2  agent-trust       APF kernel + adapter │ client endpoint │ trace export │ oracle
 L1  OpenMLS fork      MLS groups, public sequencer, staged KeyPackages, libcrux DRBG
 L0  openmls-qrand     QRNG Open API randomness, fail closed  ──▶  qrng-mock or Entropy Core
```

- **L0 to L2 are libraries**, pinned once in [`Cargo.toml`](Cargo.toml). The testbed adds
  no cryptography and no authorization logic: every decision is agent-trust's.
- **L3 cuts L2 at its party boundaries.** `att-node apf` wraps the agent-trust
  `Adapter`. `att-node agent` wraps one `ClientEndpoint` and is the only holder of its
  agent's keys. `att-node relay` carries opaque, signed or encrypted bytes and injects
  faults. `att-node qrng-mock` serves the QRNG Open API.
- **L4 deploys and controls L3** through HTTP APIs only, with per deployment tokens.
  It never holds an agent key.

[`docs/architecture.md`](docs/architecture.md) explains each layer, the trust
boundaries and every flow (genesis, admission, send and receive, revocation and
repair, rekey) with its agent-trust contract section.

## Quick start

You need Rust 1.91 or newer and Python 3.11 or newer. Docker is needed only for the
compose backend.

```bash
./attctl build                                                   # att-node, release
./attctl run experiments/e1-revocation-fence.toml --backend local
```

With containers:

```bash
./attctl image                                                   # from the host binary
./attctl run experiments/e1-revocation-fence.toml --backend compose
```

The full verification (unit tests of both layers, then E1) is `scripts/ci.sh`.

## Deploy and control

```bash
./attctl up topologies/three-agents.toml --backend local         # or compose
./attctl status                                                  # APF view, agents, relay
./attctl call relay POST /control/faults '{"drop": 30, "duplicate": 30, "reorder": true}'
./attctl trace                                                   # export and run the oracle
./attctl down
```

- [`docs/deployment.md`](docs/deployment.md): topologies, entropy sources (os, mock,
  the QRNG mock service, a real Entropy Core), the `local` and `compose` backends,
  and how to add a backend.
- [`docs/control.md`](docs/control.md): `attctl` commands, the experiment format,
  every action and check, reports and evidence.
- [`docs/protocol.md`](docs/protocol.md): the HTTP API and configuration of each
  service.

## Integrating an agent

An application talks only to its own sidecar, with two calls:

```text
POST /app/send   {"text": "..."}      → {"op", "recipients", "epoch"} or a refusal code
GET  /app/inbox?after=N               → messages delivered after APF consumption
```

The application never handles keys, MLS state, the APF protocol or the relay. Any
agent framework in any language integrates the same way;
[`examples/echo_agent.py`](examples/echo_agent.py) is a complete example.

## Experiments

| ID | Question | Spec | Write-up |
|---|---|---|---|
| E1 | Do revocation, repair and rekey keep authorization and capability coherent across a faulty network, against a retained key adversary? | [spec](experiments/e1-revocation-fence.toml) | [E1](docs/experiments/E1-revocation-fence.md) |

Planned experiments are in [`docs/roadmap.md`](docs/roadmap.md). Points found in
the stack while building the testbed are in [`docs/findings.md`](docs/findings.md).

## Repository layout

| Path | Contents |
|---|---|
| `crates/att-node/` | The four network services (Rust) |
| `controller/attctl/` | Control plane: topology, backends, API clients, runner, oracle loader (Python, standard library only) |
| `attctl` | Entry point of the control plane |
| `topologies/` | Deployment descriptions |
| `experiments/` | Experiment specifications |
| `deploy/docker/` | Container images |
| `examples/` | Application integrations |
| `results/` | Recorded evidence: reports, traces, logs |
| `scripts/` | `ci.sh` (all gates), `stability.sh` (repeated runs) |
| `tests/` | Control plane unit tests |
| `docs/` | Architecture, protocol, deployment, control, experiments, findings, roadmap |

## License

Copyright © 2026 Daniel Sobral Blanco. Released under the [MIT License](LICENSE).
The pinned OpenMLS crates remain under their own licenses.
