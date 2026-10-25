# Findings on the stack

Points found while building and running the testbed on agent-trust, the OpenMLS fork
`dd33278` and openmls-qrand `a102450`. Each names its status, what the testbed does,
and the proposal upstream.

| # | Repository | Finding | Status | Testbed today | Proposal |
|---|---|---|---|---|---|
| F-1 | agent-trust | A worker has no routed request to read the policy state (frontier, `policy_revision`, roster, grants) that it needs to build a release cover and digest (§5.3). | Open | The APF service exposes `GET /v1/state`, read from the kernel's current state row. It is advisory: the kernel re-checks every value. | A read-only routed command (`policy_view`) for roster members, authenticated and traced like every request. |
| F-2 | agent-trust | `LabEntropy::provider()` has memory storage only, and an identity cannot be restored, so a networked agent cannot survive a restart. | **Implemented** on branch `feat/durable-lab-provider` (`5cf724e`), test first (`tests/lab_durable.rs`, `evidence/durable-provider-{red,green}.txt`, full verifier green, `full_lap_mls` still true). The testbed pins that commit. | `LabEntropy::durable_provider(path)`, `ClientIdentity::restore(key_pair)`; E3 restarts agents. | Merge the branch into `main`. |
| F-3 | agent-trust | Commit distribution is outside the contract: after `submit_commit` only the committer holds the commit and ack; if it stops before publishing them, the group cannot move (B7 at group scale). | Open | The committer appends `{commit, ack}` to the relay's log; E4 shows a hostile log costs liveness only. | The adapter serves the canonical `(commit, ack)` log it already sequences. |
| F-4 | agent-trust | `ClientEndpoint` has no "still active" accessor; a removed member is detected because `confirmation()` fails. | Open | The sidecar uses that failure. | `ClientEndpoint::is_active()`. |
| F-5 | agent-trust | The C-37 export reads the adapter files from outside the `Adapter`. | Open | The APF service holds its lock during the export. | `Adapter::export_trace(&self)`. |
| F-6 | agent-trust | A relay duplicate is refused by MLS (`undecryptable`) before the kernel's `replay` check, so the honest path never reaches `replay`. | Note | `check.rejected` accepts duplicate codes after the first copy. | None; correct and allowed by C-39. |
| F-7 | agent-trust | Any epoch change at the APF makes every not yet consumed message undeliverable: kernel `consume` requires the release epoch to equal the APF's current epoch (§5.3). A membership change right after a send loses that send for slow readers. | Note (by design) | Agents drain their mailbox before applying a commit; experiments let delivery settle before membership changes (E2 C4b). | Document it as an operating rule, or let `consume` accept the release epoch while the reader is still at it (a profile change). |
| F-8 | agent-trust | Kernel cost per request grows with the square of the history: `load()` re-validates the whole hash chain, every event stores a full state snapshot, and the adapter reads the full `checkpoint` several times per request. Measured in E5: 7 ms at ≤ 48 events, 1.1 s at ≤ 481 events. | Open, needs approval (changes tamper detection) | E5 measures it; the APF view no longer reads `checkpoint`. | Events carry a snapshot hash or a delta; validate fully at `open`, then incrementally; a `checkpoint` option for the last event only. |
| F-9 | agent-trust, OpenMLS fork, openmls-qrand, testbed | Every public key algorithm in the stack is classical, so a large quantum computer breaks it. Key exchange: X25519 in MLS (suite `0x0001`) and X25519 or P-256 ECDHE on every TLS link, the QRNG link included. Signatures: Ed25519 for MLS credentials, APF records and requests; ECDSA P-256 for the testbed certificates. Recorded traffic can be decrypted later. | Open, needs a decision. A probe shows the hybrid suite `0x004F` works today. | Classical everywhere. Probe evidence in `results/F9/`. | Four steps, PQ-1 to PQ-4, below. |

## F-9 in detail: post quantum readiness

A large quantum computer breaks every key exchange and every signature that the stack
uses today. Key exchange is the urgent part: an attacker can record traffic now and
decrypt it when such a computer exists. A signature can be forged only while the attacker
has one, so signatures matter later, and mostly for records that must stay valid for a
long time.

The stack uses Ed25519 for MLS and APF signatures, not ECDSA. ECDSA P-256 appears only in
the testbed certificates (the `rcgen` default) and in provider suites that the lab does
not use. Ed25519 and ECDSA have the same quantum exposure.

### Where classical public key cryptography is used

| Where | Algorithm today | It protects | Quantum risk | Post quantum option available now |
|---|---|---|---|---|
| MLS group key exchange (HPKE in commits, Welcome, KeyPackages) | DHKEM X25519, suite `0x0001` | The content of every message | **High**: record now, decrypt later | Suite `0x004F`, `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (hybrid ML-KEM-768 and X25519), in the fork's libcrux provider behind the feature `draft-ietf-mls-pq-ciphersuites` |
| QRNG link (Entropy Core or mock to the APF and each sidecar; openmls-qrand uses `reqwest` with rustls over `ring`) | TLS ECDHE, X25519 or P-256 | The entropy that every key comes from | **High**, and it defeats the row above: whoever records the entropy can rebuild the ML-KEM keys too | rustls with the `aws-lc-rs` provider offers `X25519MLKEM768` (on by default in rustls 0.23 with that provider). The Entropy Core TLS server must offer it too: check in E6 |
| Testbed service links (rustls over `ring`) and the control tool (Python `ssl`; OpenSSL 3.0.13 on the development host and on the Ubuntu 24.04 CI runners) | TLS ECDHE | Tokens, membership metadata | Medium | The same rustls provider change; Python needs OpenSSL 3.5 or later |
| MLS signatures (credentials, leaf nodes, commits) | Ed25519 | Who sent a commit or a message | Medium, grows with time | Suites with ML-DSA in the same fork, for example `0x0052` `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44` |
| APF signatures (permits, acks, certificates, receipts) and request signatures | Ed25519 (`ed25519-dalek`; keys fixed at 32 bytes by C-1) | Every authorization decision, and the evidence of the history | Medium now; high for records kept as evidence | ML-DSA (FIPS 204), alone or together with Ed25519. Contract change |
| Testbed mTLS certificates | ECDSA P-256 | Service identity, live only | Low | ML-DSA certificates: rustls-webpki 0.103 can verify them with its `aws-lc-rs` backend; `rcgen` 0.13 cannot issue them, and the TLS handshake support in rustls is not yet checked |

AES-128-GCM and SHA-256 stay acceptable: a quantum computer only halves their security
margin, and AES-128 is the reference for NIST category 1. Suites with AES-256 and
SHA-384 exist if a higher category is required.

New randomness needs no extra work: ML-KEM key generation, encapsulation and hedged
ML-DSA signing in the libcrux provider draw from its DRBG, so from the selected source
(C-40, fork change 2). `adapter_entropy` and `lab_entropy` pass under `0x004F`.

### Probe (2026-10-25)

Evidence: [`results/F9/`](../results/F9/README.md). agent-trust `5cf724e` with the
feature on every OpenMLS crate and the lab ciphersuite set to `0x004F` (6 changed
lines):

- 164 of 164 tests of the adapter, authority, entropy and durable suites pass;
- the testbed passes E1, E1-mtls, E2, E3, E4 and E7 on the local backend, with the
  oracle and its broken controls;
- a KeyPackage grows from 542 to 2912 bytes, a commit from at most 1130 to at most 8144,
  a Welcome from at most 1346 to at most 8360; acks and application messages do not
  change;
- single runs show no clear time cost.

Not covered: the `full_lap_mls` gate (`scripts/verify.py` and the Python integration
harness), E5, compose and k3s. The legacy `MlsLab` (`mls-demo`, not on the adapter
path) fails to add a member under `0x004F`. Build trap: enable the feature on every
OpenMLS crate, or `openmls_rust_crypto` does not compile.

### Proposal

| Step | Change | Where | Needs |
|---|---|---|---|
| PQ-1 | MLS key exchange on the hybrid suite `0x004F`. Better: make the suite a lab option, like the entropy source (C-40), so that one topology setting selects it and the testbed runs both | agent-trust | A decision: the suites come from `draft-ietf-mls-pq-ciphersuites`, which is not yet an RFC, so the code points can change. Then the `full_lap_mls` gate is run again |
| PQ-2 | Hybrid key exchange `X25519MLKEM768` on every TLS link: rustls on `aws-lc-rs` in openmls-qrand and in `att-node`; OpenSSL 3.5 or later for the control tool | openmls-qrand, testbed | The Entropy Core must offer the group. Do it together with PQ-1: PQ-1 alone does not protect against an attacker who records the entropy link |
| PQ-3 | ML-DSA signatures: an MLS suite with ML-DSA, and ML-DSA (or Ed25519 and ML-DSA together) for APF and request signatures | agent-trust contract (C-1 key format, wire sizes, C-41 identity restore) | A decision. An ML-DSA-44 public key is 1312 bytes and a signature 2420 bytes, against 32 and 64 for Ed25519 |
| PQ-4 | ML-DSA certificates for mTLS | testbed | Stable ML-DSA support in `rcgen` and rustls-webpki |

A new experiment, E8, would run E1 to E7 under both suites on all three backends and
record sizes and time.
