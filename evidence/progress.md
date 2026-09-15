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
