# E2: QRNG outage over the network

Spec: [`experiments/e2-entropy-outage.toml`](../../experiments/e2-entropy-outage.toml) ·
Evidence: [`results/E2/`](../../results/E2/)

## Question

agent-trust selects one entropy source per process and never falls back (C-40). Does a
networked deployment behave safely when the QRNG service refuses requests: does every
step that needs fresh randomness stop, does nothing change, and does the group recover
by itself?

## Hypotheses

| | Hypothesis | Basis |
|---|---|---|
| H1 | During the outage, send, add and rekey are refused with `entropy_unavailable` | C-40, §8.1 error code |
| H2 | A refused step changes neither frontier, roster nor keys; a released but unprotected operation is abandoned at the APF | §6 barrier B2 |
| H3 | A node cannot start during the outage | C-40 (no fallback at selection) |
| H4 | When the source returns, every refused step succeeds without repair, and the oracle accepts the trace | |

## Method

Topology `three-agents` (QRNG over HTTP, mock). Bob is admitted; carol publishes a
certified KeyPackage but is not yet added. Then `POST /control/outage {available:false}`
on the QRNG service:

- B2: alice sends: refused. The sidecar had already allocated and released the
  operation; the protect step needs a reuse-guard draw, fails, and the sidecar sends
  `abandon` (B2).
- B3: alice adds carol: refused (path secrets).
- B4 to B6: alice revokes bob's write and offers it at generation 1 (the APF draws
  nothing); bob's rekey is refused (new signature key).
- B7, B8: roster, epoch and every agent's frontier are unchanged.
- B9, B10: bob is stopped and cannot start: its entropy source cannot be connected.

The source returns; bob starts and resumes from its data directory; alice sends,
adds carol with the same KeyPackage, bob completes the pending rekey, everyone sends.

## Results

All 34 steps pass (5 of 5 local runs, compose and k3s: see `results/E2/`). The
exported trace contains the abandoned release (`abandon: 1`) and is accepted.

## Findings

- **F-7 (agent-trust).** An epoch change at the APF makes every not yet consumed
  message undeliverable: `consume` requires the release epoch to equal the APF's
  *current* epoch (§5.3, kernel `consume`). In the first version of this experiment,
  alice added carol right after sending m2; bob had decrypted m2 but the APF had
  already moved to epoch 2, so the consumption was refused (`binding_mismatch`) and
  m2 was lost. The conservative profile intends this; operators must let delivery
  settle before a membership change (step C4b), or accept the loss.
- The sidecar's failure counter restarts with the process, so after bob's restart
  only alice still reports refused draws; B6 asserts bob's refusal directly.
