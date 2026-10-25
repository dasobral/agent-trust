# SDD ledger — plan: docs/implementation-plan.md

Approval: Daniel approved specification revision 0.1 and instructed execution.
Isolation: fresh repository in an otherwise empty sandbox; branch experiment; no existing user checkout modified.

| Task/interface check | Finding |
|---|---|
| 1 -> 2 command contract | Freeze before implementation; test author owns assertions. |
| 1 -> 3 MLS contract | Real dependency compatibility is a gate, not inferred from docs. |
| 2 -> 4 release/consumption | Freeze-before-release; consume is replay barrier; no second authorization cut. |
| 3 -> 4 frontier/envelope | Canonical epoch/branch and exact persisted bytes required. |
| 4 -> 5 demo | Broker must call the same adapter, never a parallel permissive authorization path. |
| Task 1 internal | Setup failures separately recorded from behavioral red. |
| Task 2 internal | No MLS claim based on authority flags. |
| Task 3 internal | Retained-key outsider must exercise raw decryption. |
| Task 4 internal | Lost envelope is abandonment, not re-encryption. |
| Task 5 internal | Tool/runtime absence produces unmet gate. |

Ruling: use disjoint file ownership in the fresh experimental checkout — user approved parallel scoped agents; no pre-existing branch needs preservation — overlapping ownership would require serialization or worktrees.

2026-09-12 continuation: previous workers did not survive the turn; resumed from files and Git without repeating completed test authorship.
Task 1: toolchain available; Rust 1.98.1, OpenMLS 0.9.0 fetched. Interface tests commit 26eb7e1 compiles and records 12 authority + 4 MLS behavioral failures.
Task 1: oracle implemented at 4b23b52; 20 passing tests reported and independent source review dispatched.
Ruling: complete the independently testable authority kernel and real MLS laboratory while leaving exact LAP binding visibly blocked — OpenMLS has no public two-phase KeyPackage API — costs an additional integration/API-extension phase before deployment claims.
Ruling: distinguish external APF proposal constructors from member proposal methods — direct source inspection corrected audit citations — external-sender runtime behavior remains a separate unverified gate.

2026-10-24 (testbed session): C-41 proposed and implemented test first on branch `feat/durable-lab-provider` (durable lab provider, identity restore; testbed finding F-2). Red: interface build failure only. Green: `tests/lab_durable.rs` 6 passed; `scripts/verify.py` all gates pass, `full_lap_mls` true. Waiting for Daniel's approval before merge into `main`.
2026-10-25 (testbed session): D-13 approved by Daniel (testbed finding F-9: "Proceed with all the PQs"). C-42 implemented test first on branch `feat/post-quantum` (on `feat/durable-lab-provider`): the `pq` suite (MLS `0x0052`, X-Wing, ML-DSA-44) for identities, request keys and the APF key, chosen by the root key, stored with the adapter, `AGENT_TRUST_SUITE` in the lab (default `pq`). Baseline: the OpenMLS PQ feature alone changes nothing (`evidence/pq-baseline.txt`). Red: interface build failure only (`evidence/pq-suite-red.txt`). Green: `tests/pq_suite.rs` 11 passed; `scripts/verify.py` all gates pass with the integration gate in both suites, `full_lap_mls` true (`evidence/pq-suite-green.txt`, `evidence/verify-2026-10-25-pq.txt`).
2026-10-25 (testbed session): C-42 extended to the QRNG link: openmls-qrand pinned at `66026082` (post quantum TLS, `X25519MLKEM768` only by default), `[qrng] key_exchange` and `AGENT_TRUST_QRNG_KEY_EXCHANGE`, `GenesisPending::suite`. Red: interface build failure only; green: `tests/pq_suite.rs` 13 passed, verifier all gates in both suites, `full_lap_mls` true (`evidence/pq-qrng-tls.txt`).
2026-10-25 (testbed session): D-14 approved by Daniel: `feat/post-quantum` and openmls-qrand `feat/pq-tls` merged ("Let's do this"), C-41 accepted, and "pq-preferred" for the Entropy Core link. Implemented test first on branch `feat/ec-pq-preferred`: the `qrng` source defaults to `pq-preferred`; openmls-qrand pinned at `868f058` (`QrngClient::key_exchange()`), and the lab `entropy` report of a `qrng` source adds `key_exchange` and `post_quantum`. Red: two assertion failures (`evidence/ec-pq-preferred-red.txt`); green: the targeted tests and the verifier, all gates in both suites, `full_lap_mls` true (`evidence/ec-pq-preferred-green.txt`).
2026-10-25 (testbed session): Daniel asked to merge the branches and to install the latest by default. The OpenMLS crates now follow the fork branch `agent-trust/integration` and `openmls_qrand` follows openmls-qrand `main`, instead of fixed revisions; `Cargo.lock` still records the exact commits (`dd332780`, `868f058`, unchanged by this move), so `--locked` builds stay reproducible and `cargo update` takes the latest.
