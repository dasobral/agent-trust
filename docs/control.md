# Control

`attctl` is the control plane. It uses only the services' HTTP control and
application APIs and the deployment record `deploy.json`; it holds no agent key.

## Commands

| Command | Effect |
|---|---|
| `./attctl build [--debug]` | `cargo build --locked -p att-node` |
| `./attctl image [--base IMG] [--from-source]` | Build `agent-trust-testbed/att-node:local` |
| `./attctl up TOPOLOGY [--backend local\|compose\|k8s]` | Deploy and wait until every service is healthy |
| `./attctl render TOPOLOGY [--out FILE]` | Static Kubernetes manifests |
| `./attctl status` | APF policy view, each agent's membership and epoch, relay counters |
| `./attctl call SERVICE METHOD PATH [JSON]` | One raw call with the right token, for example `./attctl call relay POST /control/faults '{"drop": 30}'` |
| `./attctl trace [--out FILE]` | Export the APF trace and run the oracle; exit 1 on a violation |
| `./attctl logs [SERVICE]` | Service logs |
| `./attctl down` | Stop the deployment |
| `./attctl run EXPERIMENT [--backend B] [--record DIR] [--keep]` | Deploy, run, verify, report and stop |

`--run-dir DIR` (before the command) selects the deployment; the default is
`runs/current`. `attctl run` uses a new `runs/<id>-<time>-<backend>` directory.

## Driving a deployment by hand

```bash
./attctl up topologies/three-agents.toml
./attctl call alice POST /control/genesis
BOB_KEY=$(./attctl call bob GET /control/status | python3 -c 'import json,sys; print(json.load(sys.stdin)["ok"]["public_key"])')
./attctl call alice POST /control/delegate "{\"subject\": \"bob\", \"subject_key\": \"$BOB_KEY\", \"rights\": [\"read\", \"write\", \"admit\"]}"
./attctl call bob POST /control/join
./attctl call alice POST /control/add '{"subject": "bob"}'
./attctl status
./attctl trace
./attctl down
```

## Experiments

An experiment is a TOML file in `experiments/`:

```toml
[experiment]
id = "E1"
title = "..."
topology = "../topologies/three-agents.toml"
hypothesis = "..."

[[step]]
do = "send"                 # an action or a check
name = "B2 alice sends m1"  # shown in the report
agent = "alice"
label = "m1"                # later steps refer to the message by its label
text = "m1: hello"
expect = "ok"               # default; or an error code such as "read_fenced"
```

The runner executes the steps in order and stops at the first failure. Every action
states its expected outcome; an action that succeeds when a refusal was expected
fails the step.

### Actions

| `do` | Fields | Effect |
|---|---|---|
| `genesis` | `agent` | The root founds the group |
| `delegate` | `by, subject, rights`, optional `resources, ttl_secs, depth` | Delegation with the subject's own public key |
| `admit` | `by, subject` | Join, add, wait for the Welcome, sync every member |
| `send` | `agent`, `text` or `payload_hex`, optional `label, op, content_type` | Application send through the sidecar |
| `burst` | `agents, count`, optional `label` | `count` interleaved sends per agent, labelled `<label>-<agent>-<i>` |
| `quiesce` | optional `timeout` | Wait until the relay has nothing pending and every agent finished two poll rounds |
| `faults` | `drop, duplicate, reorder, seed` | Relay fault model |
| `hold` | `mailbox, held` | Keep a mailbox in flight |
| `tap` | `victim, observer`, optional `enabled` | Leak copies to another agent |
| `revoke` | `by, subject, right` | Signed `revoke` |
| `grant` | `by, subject, right, generation`, optional `expect_result` | Signed `grant` |
| `request` | `agent, body` | Any routed APF command |
| `repair` | `by`, optional `expect_removed, expect_evidence` | Repair, then wait until the fence is open |
| `rekey` | `agent, right, generation` | New key and incarnation |
| `adversary` | `agent, retain` | Retained key adversary mode |
| `sync` | | Every member applies the handshake log |
| `join` | `agent` | The candidate certifies and publishes its KeyPackage |
| `add` | `by, subject` | Add a published KeyPackage, wait for the Welcome, sync |
| `admit_all` | `by, rights` | Delegate and admit every other agent, timing each admission |
| `rounds` | `count`, optional `agents, except, per_agent, label, max_round_seconds` | Parallel send rounds, each drained; records round time and APF time per request |
| `invoke` | `by, executor, rights`, optional `parent, resources, label` | An APF invocation (confused deputy); `send` takes `invocation = "<label>"` |
| `stop`, `start`, `restart` | `service`; `start` takes `expect = "fails"` | Service lifecycle through the backend |
| `entropy_outage` | `available` | QRNG service outage on or off |
| `handshake` | `action` and its fields | Relay attack on the commit log (replay, inject, splice, hide, show, reverse) |

### Checks

| `do` | Fields | Passes when |
|---|---|---|
| `check.apf` | any of `roster, epoch, read_fenced, repair_pending` | The APF policy view has these values |
| `check.frontiers` | `agents` | Each agent's epoch and branch equal the APF's |
| `check.delivered` | `agent, ops`, optional `exact` | Each labelled message was delivered exactly once, from its sender, with its payload; with `exact` (default), nothing else was |
| `check.not_delivered` | `agent, ops` | None of them reached the application |
| `check.complete` | optional `exclude = ["agent:label"]`, `exclude_prefix = ["agent:prefix"]` | Every sent message reached every reader of its certificate exactly once (`exclude`: must be missing; `exclude_prefix`: may be missing) |
| `check.rejected` | `agent, op, codes`, optional `duplicate_codes` | The first copy was refused with one of `codes`; later copies only as duplicates |
| `check.rejections_are_duplicates` | `agents` | Every refused copy belongs to a message that agent already delivered |
| `check.adversary` | `agent, ops` | Every leaked copy failed raw MLS decryption and the APF refused its consumption |
| `check.exactly_once` | optional `allow_lost` | No duplicate delivery; delivered pairs equal the APF's consumed pairs (`allow_lost`: consumed but undelivered pairs, B5, are reported, not failed) |
| `check.oracle` | | The independent oracle accepts the exported trace (saved as `trace.json`) |
| `check.broken_controls` | `revoked_reader, writer`, optional `minimum` | Every control trace derived from the real trace is rejected with its named code |
| `check.entropy` | `source` | Every node used `source` with zero failures; the QRNG service refused nothing |
| `check.no_errors` | `agents` | The agents logged no processing error |
| `check.errors_within` | `indices` | Every logged error is a handshake error on one of these (forged) log indices |
| `check.agent` | `agent`, any of `membership, restarts, retain, on_frontier, min_skipped` | One agent's status |
| `check.at_most_once` | `agent, prefix` | Labelled messages arrived at most once; reports losses |
| `check.operation` | `op`, any of `actor, invocation, status` | The APF's record of an operation (executor, invocation) |
| `check.metrics` | optional `max_send_p95, max_delivery_p95` | Send, delivery and admission latency; APF time per request against history length |
| `check.mtls` | | Transport negative controls with the Rust probe (no certificate, wrong peer, foreign CA, a post quantum certificate over classical key exchange, a classical certificate that names a service) and one positive control |
| `check.pq_tls` | optional `expect_peers = ["service<-peer"]` | Every service-to-service connection each service accepted used an ML-DSA-44 certificate over `X25519MLKEM768`; reports the control plane's own chain (`control_link`) |
| `check.suite` | `suite` | The APF and every agent run that suite (agent-trust C-42), with keys of its size |
| `measure.sizes` | | Records the size in bytes of every KeyPackage, commit, ack and Welcome on the relay |
| `check.network_policy` | `allowed, denied` (`"src->dst"`) | Kubernetes only: connectivity probed from inside the pods |

## Reports and evidence

`attctl run` writes into its run directory:

- `report.md`: the step table and the final state;
- `report.json`: every step's detail, the final observations (APF view, relay
  counters, each agent's status, the adapter trace) and the exact stack revisions;
- `trace.json`: the exported trace contract v2 trace;
- `service-logs/`: one log per service.

`--record results/<experiment>/<name>` copies these files (never `deploy.json`) into
the repository. The recorded evidence of this repository lives in `results/`.
