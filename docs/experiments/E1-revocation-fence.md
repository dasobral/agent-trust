# E1: Revocation fence, repair and rekey across a faulty network

Spec: [`experiments/e1-revocation-fence.toml`](../../experiments/e1-revocation-fence.toml) ·
Topology: [`topologies/three-agents.toml`](../../topologies/three-agents.toml) ·
Evidence: [`results/E1/`](../../results/E1/)

## Question

agent-trust shows authorization–capability coherence (ACC) for one in-process lab
(`agent-trust lab`). Does it hold when the parties are separate network services,
each with its own keys and its own entropy draws, and the network in between is
hostile?

## Hypotheses

| | Hypothesis | Contract basis (agent-trust `docs/adapter-contract.md`) |
|---|---|---|
| H1 | Every authorized message reaches each current reader exactly once, and only after an APF consumption, while the relay drops, duplicates and reorders traffic | §5.3, C-15, C-18, C-39 |
| H2 | A read revocation stops every new release and every in-flight delivery until a repair commit removes the reader | §5.4, kernel `read_fenced` |
| H3 | A removed member that keeps its keys can neither decrypt nor consume later traffic, even when the relay leaks that traffic to it | §5.4 (retained key adversary), §11 |
| H4 | A re-granted write right needs a new signature key: the grant alone is only an offer | §5.5, C-28 |
| H5 | The independent oracle accepts the trace exported by the networked APF and rejects every broken control derived from it | §9, C-37, C-38 |

## Setup

- Services: `qrng` (mock QRNG Open API), `apf`, `relay`, agents `alice` (root),
  `bob`, `carol`. One process or container each.
- Entropy: every node draws its keys and MLS randomness from the `qrng` service over
  HTTP (`AGENT_TRUST_ENTROPY_SOURCE=qrng`). **The service is a mock: OS RNG bytes.**
- Faults: from phase B on, the relay drops 25 % of fetch attempts (retransmitted
  later, byte identical), duplicates 25 % of delivered messages once, and shuffles
  every batch. Seed 11.

## Method

| Phase | Steps | What it does |
|---|---|---|
| A | A1–A7 | Genesis by alice; delegate `read, write, admit` to bob and carol; admit both through certified KeyPackages; check roster, epoch 2 and that every agent sits on the APF frontier |
| B | B1–B11 | Turn faults on; one message from each agent, then a burst of 4 interleaved messages from each agent (15 messages, 30 deliveries); drain; check completeness, payloads, exactly once, and that every refused copy was a duplicate |
| C | C1–C12 | Hold carol's mailbox; alice sends m4; revoke carol's read; the fence is closed; alice and bob are refused (`read_fenced`); release the hold; carol decrypts m4 but the APF refuses its consumption; carol's application never sees it |
| D | D1–D8 | carol turns adversary (keeps its epoch 2 keys, ignores its removal); alice repairs; bob confirms; the fence opens with `pair` evidence; the relay leaks every copy for bob to carol; alice sends m6; bob gets it; carol's raw OpenMLS decryption fails and the APF refuses its consumption |
| E | E1–E8 | Revoke bob's write; bob is refused (`unauthorized`); alice re-grants write at generation 1, which is only an offer, and bob is still refused; bob commits a new key and incarnation; bob sends m8 and alice receives it |
| F | F1–F6 | Frontier agreement; completeness over the whole run (only carol's fenced m4 is missing); exactly once against the APF consumed set; oracle acceptance; 8 broken controls rejected; every node used the QRNG service with zero failures; no processing error at the honest agents |

## Expected results (pass criteria)

Each step in the spec states its expected outcome. The run passes only if all 55
steps pass. In particular:

- **H1:** `check.complete`, `check.exactly_once` and
  `check.rejections_are_duplicates` pass after phase B and again over the whole run.
- **H2:** C6, C7 are refused `read_fenced`; C10: the first copy of m4 at carol is
  refused `read_fenced` (a relay duplicate of it may then be refused `undecryptable`,
  because the ratchet already moved); C11: m4 never reaches carol's application.
- **H3:** D8: every leaked copy fails raw `process_message` and `consume` is not `ok`.
- **H4:** E2 and E4 refused `unauthorized`; E3 returns exactly `{pending: true}`; E6
  succeeds.
- **H5:** the oracle returns no violation (F3), and each control returns exactly
  its expected violation at the expected index (F4):

  | Broken control | Expected code |
  |---|---|
  | Release after the read denial | `read_fenced` |
  | Fence opened by API only (no repair commit) | `invalid_repair` |
  | Fence opened without confirmation | `unconfirmed` |
  | Repair that keeps the revoked reader | `invalid_repair` |
  | Release cover that omits a reader | `unsound_cover` |
  | Second envelope under one operation | `binding_mismatch` |
  | Replayed consumption | `replay` |
  | Rekey that reuses another member's key | `stale_key` |

## Results

Recorded runs are in [`results/E1/`](../../results/E1/) and
[`results/E1-mtls/`](../../results/E1-mtls/), one directory per run with
`report.md`, `report.json`, `trace.json` and the service logs:

| Variant | Backends | Result | Steps |
|---|---|---|---|
| E1 | local processes, Docker Compose, k3s | PASS | 55/55 |
| E1-mtls (mutual TLS everywhere, QRNG included) | local processes, Docker Compose, k3s | PASS | 56/56 (step F7 adds the transport negative controls) |
| Stability, first version (2026-10-24) | local | 20/20 PASS | `results/E1/stability-2026-10-24.txt` |
| Stability, current version | local | 10/10 PASS each for E1 and E1-mtls | `results/stability-2026-10-24.txt` |

In the compose run, four distinct container addresses drew entropy from the QRNG
service, one per node. Over mTLS, F7 shows that a client without a certificate and a
certificate from a foreign CA are refused at the handshake, that bob's certificate
cannot read carol's mailbox or publish carol's KeyPackage (403), that alice cannot
send a request signed in bob's name (403), and that bob can read his own mailbox
(the positive control).

Observed details that the pass criteria do not show:

- MLS refuses a relay duplicate before the APF sees it: the second copy fails
  `process_message` (`undecryptable`) because the secret tree generation was already
  consumed. The kernel `replay` check is therefore a second line that the honest
  path never reaches; the oracle's `replayed consumption` control covers it.
- carol's raw decryption of the leaked m6 fails with `ValidationError(WrongEpoch)`:
  carol holds epoch 2 keys and m6 is an epoch 3 message.
- The APF refuses carol's consumption of m6 with `unauthorized` (carol is no longer
  on the roster).

An early version of check C10 required every copy of m4 at carol to be refused
`read_fenced`. One run in five failed it: the relay had duplicated m4, and the
duplicate was refused `undecryptable`. The system was right and the check was
wrong; C10 now requires `read_fenced` for the first copy and only duplicate codes
for later copies.

## Threats to validity

- The QRNG service is a mock. No run here supports a quantum origin claim. Point
  the topology at a real endpoint (`entropy.url`) to close agent-trust's
  `live_entropy_core` gate.
- Thread timing varies; the relay seed fixes fault decisions per fetch, not the
  global interleaving. The stability series addresses this statistically only.
- In E1 the handshake log on the relay is reliable and in order; E4 attacks it.
- One group, three agents, one APF. E3 covers crashes and E5 a larger group.
- Like the agent-trust claim, a pass covers the executed schedules only. It is not
  a proof; `Bridge_remove^ETK` stays an open proof obligation.
