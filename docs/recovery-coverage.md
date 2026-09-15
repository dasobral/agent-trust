# Recovery coverage

This repository is a forensic reconstruction of the `agent-trust` work that was split across multiple conversations and interrupted handoffs. It preserves exact surviving artifacts where available and labels reconstructed material explicitly.

| Surface | Recovery source | Fidelity | Result |
|---|---|---|---|
| 2026-09-13 project snapshot | Library folder `/Agents/agent-trust-recovered-2026-09-13` | Exact: 49 files, 301,037 bytes | Restored in commit `542b326` |
| Interim source repair | `agent-trust-interim-2026-09-13.patch` and its Library folder | Exact surviving patch and nine-file checkpoint | Replayed in commit `9c7ad49` |
| Authority-gap RED suite | `tests/authority_gap_contract.rs` from the interim checkpoint | Exact | Three failures and one guard pass reproduced before repair |
| Latest APF, MLS, CLI and Rust tests | Surviving local `agent-trust` checkout | Exact surviving files | Restored, audited, and repaired |
| Public verifier | Prior chat contract and recorded five-test result | Behaviorally reconstructed; original bytes unavailable | Five fail-closed tests restored |
| Confused-deputy extension | Surviving local checkout and handoff | Exact surviving files | Added after the recovered pre-fork checkpoint |
| Historical Git objects | Chat records of `22e6cb3` and `fff718a` | Commit identities recorded; objects unavailable | Not fabricated |

The historical pre-fork checkpoint was recorded as `fff718a`, descended from recovered HEAD `22e6cb3603ec0f06a3326d8915c9aa1cf3c9897f`. Neither object survived in the available Git object databases or remote repository. This reconstruction therefore uses new commit IDs and records the old IDs only as provenance.

Recovered executable coverage includes:

- durable single-node SQLite authority state and hash-chained history;
- attenuated delegation, generations, cascading revocation, fencing, repair, and one-shot release/consume semantics;
- OpenMLS 0.9.0 laboratory behavior and retained-state exclusion experiment;
- JSONL CLI persistence and malformed-input behavior;
- independent Python authorization oracle;
- fail-closed public verification;
- authenticated invocation provenance and confused-deputy prevention.

Known boundary: `full_lap_mls` remains `false`. Canonical staged KeyPackage construction and the embedded APF admission binding are now verified against pinned fork commit `6daabe33ddb616a6ed54b511d333e691db18a99f`; the complete durable APF-to-MLS context/incarnation/repair coupling remains future work.
