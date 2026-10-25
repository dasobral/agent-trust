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

Both experiments pass on the local, compose and k3s backends: every node runs its
suite with keys of its size, the protocol behaves the same, and the oracle accepts the
trace and rejects every broken control in both suites.

Sizes on the relay, in bytes (local backend; the other backends give the same sizes):

| Object | classical | pq | Factor |
|---|---|---|---|
| KeyPackage | 536 to 542 | 11255 to 11261 | 20.8 |
| Commit (admission, repair, rekey) | 537 to 1130 | 10054 to 22551 | 20.0 |
| APF ack | 310 | 2666 | 8.6 |
| Welcome | 1027 to 1346 | 15413 to 21763 | 16.2 |

An ML-DSA-44 signature is 2420 bytes and a key 1312 bytes, against 64 and 32 for
Ed25519; an X-Wing ciphertext is 1120 bytes and a key 1216 bytes, against 32 and 32
for X25519. A KeyPackage carries the leaf key, the signature key, the APF admission
certificate and two signatures, so it grows about twenty times. Application messages
carry an APF release certificate and an MLS signature, so they grow too, and the
kernel stores them in every history snapshot (F-8, see E5).

Run time, seconds (one run each, not a benchmark):

| Backend | classical run (s) | pq run (s) |
|---|---|---|
| local | 2.57 | 2.831 |
| compose | 2.683 | 3.04 |
| k8s | 3.61 | 3.474 |

The protocol cost is visible only at scale: see E5.
