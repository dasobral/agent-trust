# E5: Eight agents in parallel

Spec: [`experiments/e5-scale.toml`](../../experiments/e5-scale.toml) ·
Topology: [`topologies/scale-8.toml`](../../topologies/scale-8.toml) (other sizes:
`scripts/make-topology.py N`) · Evidence: [`results/E5/`](../../results/E5/)

## Scope

E5 runs at 8 agents. A first attempt at 12 agents, 5 messages each in parallel, did
not finish: the APF's cost per request grew too fast (finding F-8 below). Sends
passed the 60 s client timeout, and at a history of about 700 events one request
spent about 16 s in the APF, waiting included. Larger groups wait for F-8.

## Question

How do admission, release and delivery cost grow with the group and the run length,
and do the safety properties hold with all agents sending in parallel?

## Method

Eight agents. Agent01 admits the seven others one by one. Then rounds: in each
round, every agent sends one message in parallel (one thread per agent), and the
testbed drains. Four clean rounds, one round under 10 % drop and 10 % duplication, a
read revocation and repair with seven continuing members, and one more round. The
APF records, for every worker request, the kernel history length and the handling
time inside its lock (`GET /control/metrics`).

## Results

Safety: all 22 steps pass. Every message reached its seven readers exactly once,
under faults too; the repair excluded agent08; the oracle accepted the 480 event
trace and rejected the 8 broken controls.

Cost (local backend, the recorded run in `results/E5/2026-10-24-local/report.json`,
steps A2, B1, C2, D3 and D10; testbed `6c0331a`):

| Measure | Result |
|---|---|
| Admission, group of 2 → 8 | 154 to 231 ms each (median 182 ms) |
| APF time per request, history ≤ 48 events | 7 ms (median) |
| … ≤ 192 events | 183 ms |
| … ≤ 336 events | 538 ms |
| … ≤ 481 events | 1 058 ms |
| Round duration (8 messages, 56 deliveries), clean rounds 1 → 4 | 3.1 → 10.6 → 24.3 → 43.1 s |
| Round under 10 % drop and duplication (history 335 → 414) | 68.7 s |
| Send latency, whole run | median 6.6 s, p95 22.7 s |
| Delivery latency (send to inbox), whole run | median 7.6 s, p95 40.6 s |

The APF's time per request grows roughly with the square of the history length, and
the APF serializes requests, so throughput falls as a run gets longer.

## In the post quantum suite (2026-10-25)

Since F-9, every topology runs the `pq` suite (agent-trust C-42). E5 in that suite does
not complete (`results/E5/2026-10-25-local`, testbed `b7e9fa3`); the same steps in the
classical suite pass (`experiments/e5-scale-classical.toml`,
`results/E5-classical/2026-10-25-local`). Both runs on the same machine:

| Measure | `classical` | `pq` |
|---|---|---|
| Admission, group of 2 → 8 (median) | 167 ms | 199 ms |
| APF time per request, history ≤ 335 events (median) | 716 ms | 1 576 ms |
| Clean rounds 1 → 4 | 3.9 → 14.2 → 30.8 → 51.6 s | 6.4 → 27.1 → 63.0 → 112.9 s |
| Round under faults (history 335 → 414), APF median | 81.5 s, 975 ms | 173.2 s, 2 014 ms |
| Kernel history file at the end | 31 MB | 143 MB (run stopped at D3) |
| Result | PASS, 22 steps | FAIL at D3: parallel sends passed the 60 s client timeout |

The cause is F-8 below, made steeper: the kernel stores each persisted envelope in every
history snapshot, and a `pq` envelope carries two ML-DSA-44 signatures (2420 bytes each:
the APF release certificate and the MLS message), so it is about four times larger. The
F-8 proposal would remove the effect; it needs approval. CI runs E5 in the classical
suite (`SCALE=1`); `SCALE=pq scripts/ci.sh` runs it in the `pq` suite.

## Finding F-8 (agent-trust kernel)

Every kernel request starts with `load()`, which re-validates the whole hash chain
(`validate_history`), and every history event stores a full snapshot of the state,
whose size grows with the run. The adapter also reads the full `checkpoint` (all
events, all snapshots) several times per request. So each request costs time
proportional to the total size of the history: quadratic in the number of events.

This is a design decision of the kernel ("persistence replay validates chain before
use"), not a bug, and changing it changes tamper-detection behavior, so the testbed
does not change it. Proposed correction, for approval:

- events carry a hash of the snapshot (or a delta) instead of the full snapshot;
- the kernel validates the chain fully at `open` and then incrementally (new events,
  plus the stored tip hash), and keeps the current state row as it does now;
- `checkpoint` gains an option to return only the last event, which the adapter uses.

The testbed already avoids the one quadratic read that was its own: the APF's public
view now reads the kernel's current state row instead of `checkpoint`.
