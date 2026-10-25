# E8: the same scenario in both suites

Spec: [`experiments/e8-suite-pq.toml`](../../experiments/e8-suite-pq.toml) and
[`experiments/e8-suite-classical.toml`](../../experiments/e8-suite-classical.toml) ·
Topologies: `three-agents` (`pq`, the default) and
[`three-agents-classical`](../../topologies/three-agents-classical.toml) · Evidence:
[`results/E8-pq/`](../../results/E8-pq/), [`results/E8-classical/`](../../results/E8-classical/)

## Question

agent-trust C-42 adds a post quantum suite (finding F-9, steps PQ-1 and PQ-3). Does the
whole protocol behave the same in both suites, and what does the post quantum suite
cost on the wire?

| Suite | MLS ciphersuite | Key exchange | Signatures (identities, requests, APF) |
|---|---|---|---|
| `pq` | `0x0052` | X-Wing: ML-KEM-768 with X25519 | ML-DSA-44 (1312-byte keys, 2420-byte signatures) |
| `classical` | `0x0001` | X25519 | Ed25519 (32-byte keys, 64-byte signatures) |

## Hypotheses

| | Hypothesis |
|---|---|
| H1 | Every node runs the topology's suite, with keys of its size (`check.suite`) |
| H2 | Admission, delivery, revocation with repair, and rekey behave the same in both suites; the oracle accepts the trace and rejects every broken control |
| H3 | The report records the size of every MLS object on the relay (`measure.sizes`) |

## Method

Twin experiments with the same 25 steps: alice founds the group and admits bob and
carol; alice and bob send; alice revokes carol's read right and repairs; alice sends;
alice revokes bob's write right and grants it again at generation 1; bob rekeys and
sends; then sizes, the oracle and its broken controls. The two runs differ only in
`[mls] suite`.

## Results

Recorded on every backend; see the reports in `results/E8-pq/` and
`results/E8-classical/` and the summary table in the testbed README.
