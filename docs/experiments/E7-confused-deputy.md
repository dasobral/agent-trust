# E7: Confused deputy over the network

Spec: [`experiments/e7-confused-deputy.toml`](../../experiments/e7-confused-deputy.toml) ·
Topology: [`topologies/four-agents.toml`](../../topologies/four-agents.toml) ·
Evidence: [`results/E7/`](../../results/E7/)

## Question

agent-trust's invocations (`docs/confused-deputy.md`) bound what a deputy can do for
an origin. Does the property hold when the origin, the deputy and the second-hop
executor are separate agents that talk only through the network?

## Setup

alice (root); bob, the privileged deputy (`read, write, admit`); carol, an origin with
write (`read, write, admit`); dave, a reader only (`read, admit`). The sidecar binds a
send to an invocation at `allocate` (`POST /app/send {..., invocation}`).

## Hypotheses and results

All 34 steps pass (3 of 3 local runs; compose and k3s in `results/E7/`).

| | Hypothesis | Steps | Refused where |
|---|---|---|---|
| H1 | A deputy acts for an origin only through an invocation, within the rights both hold | B1–B5 | |
| H2 | An origin without a right cannot get it through a deputy | C1 dave invokes bob for write: `unauthorized`; C2 dave writes himself: `unauthorized` | `invoke`, `release` |
| H3 | A nested invocation cannot widen its parent; only its executor can use it | C3 widen to admin: `invalid_invocation`; C4 pass to dave: `unauthorized`; C6 bob uses alice's nested invocation, C7 dave uses bob's: `unauthorized` | `invoke`, `allocate` |
| H4 | Revoking the origin's right stops every use of the chain; the deputy keeps its own authority | D2, D3: `unauthorized`; D4 bob's own message: delivered | `release` |
| H5 | The APF records executor and invocation; the oracle accepts the trace | B3, C9, D5, E4 | |

The APF records `actor: bob, invocation: invocation:7` for m1 and
`actor: alice, invocation: invocation:15` (the nested one) for m2.

## Limits

As agent-trust states, this bounds authority; it does not detect a deputy that is
talked into misusing its *own* authority (prompt injection). In the testbed an
application on bob's sidecar could still send bob's own messages on dave's request.
