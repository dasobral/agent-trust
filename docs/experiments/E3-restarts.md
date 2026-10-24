# E3: APF and agent restarts, outages and offline members

Spec: [`experiments/e3-restarts.toml`](../../experiments/e3-restarts.toml) ·
Evidence: [`results/E3/`](../../results/E3/)

## Question

Can every party crash and come back without breaking safety or losing what it should
keep? The APF keeps its adapter state on disk (agent-trust C-31 to C-34). Agents keep
their identity, MLS state and bookkeeping on disk through the durable provider added
for the testbed (agent-trust `LabEntropy::durable_provider`, `ClientIdentity::restore`,
finding F-2).

## Hypotheses

| | Hypothesis |
|---|---|
| H1 | An APF restart keeps policy, frontier and registered keys; members continue unchanged |
| H2 | While the APF is down nothing is released or delivered; a message decrypted during the outage is delivered once the APF returns (delay, not loss) |
| H3 | A restarted agent resumes as the same member (same key, frontier and request sequence) and receives what was sent while it was down |
| H4 | An offline member does not block a revocation and repair; on return it applies its own removal and receives nothing sent after it |
| H5 | The oracle accepts the trace across two APF restarts |

## Method

Every stop is a `SIGKILL` (local), `docker kill` (compose) or a scale to zero (k3s).

- B: the APF is killed and restarted; bob sends through it.
- C: carol's mailbox is held, alice sends m3, the APF goes down, the relay releases
  carol's copy: carol decrypts it, its `consume` fails in transport and is retried;
  the APF returns and carol delivers m3.
- D: bob is killed and restarted, receives and sends; bob is stopped while alice
  sends m6 and receives it on return; then bob is killed in the middle of a 10
  message burst.
- E: carol goes offline; alice revokes her read right and repairs (bob confirms);
  alice sends m7; carol returns and applies its own removal.

## Results

All 54 steps pass (6 of 6 local runs; compose and k3s in `results/E3/`).

- H3, crash in the middle of a burst: in every recorded run bob received all 10
  messages exactly once. The relay leases a fetched message until the agent
  acknowledges it after saving its state, so a crash before the acknowledgement
  makes the relay send the batch again. The remaining windows (crash after the MLS
  decryption is stored and before `consume`; crash after `consume` and before the
  inbox is saved) can lose a message, which the contract accepts (B4, B5);
  `check.at_most_once` would report such a loss and fails only on a duplicate.

## Design changes found by E3

- The relay used to delete a message when it was fetched; an agent killed before it
  processed the batch lost it. The mailbox is now at-least-once (lease and ack).
- A consumption that fails in transport kept the plaintext undeliverable; the
  sidecar now keeps the pending delivery and retries.
