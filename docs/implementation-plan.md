# agent-trust Implementation Plan

> For agentic workers: use superpowers:subagent-driven-development. Read only your assigned task and the interface contract.

**Goal:** Implement and verify the approved experimental ACC/LAP-MLS design, then ship a reproducible source package.
**Architecture:** A durable single authority orders release, policy, and consumption. Real MLS adapters enforce cryptographic membership; an independent model checks traces and a broker demonstrates resource mediation.
**Tech Stack:** Rust/OpenMLS/SQLite; Python acceptance harness; container demo.
**Spec:** docs/specification.md (approved by Daniel on 11 September 2026).

## Global constraints
- Commit-immediate means the atomic release of frozen content, never later network delivery.
- Released operations without durable ciphertext are terminally abandoned after crash.
- Every child has separate credentials; rights, resource set, validity and depth only attenuate.
- Parent read revocation fences the entire affected group until cryptographic removal and repair.
- APF storage is trusted not to roll back. Client rollback is tested against it.
- Tests precede corresponding implementation; test author and implementer are different agents.
- Live QRNG, ARM64 runtime, and container results are claimed only if executed.
- Only the coordinator commits; parallel agents have disjoint file ownership.

## Task 1: Environment and executable contracts
Files: docs/contracts.md, Cargo.toml, tests/*, harness/*, evidence/*.
- [ ] Check Rust/OpenMLS availability without bypassing network restrictions.
- [ ] Write the JSON command/response contract and independent trace-oracle contract.
- [ ] Independent authors create acceptance tests and mutation witnesses.
- [ ] Execute tests against a named deliberately broken fixture: assert concrete unsafe behavior is detected. A setup failure is not a red test.

## Task 2: Durable authority and delegation
Files: src/authority.rs, src/protocol.rs; tests/authority_contract.rs.
Interfaces: typed commands from docs/contracts.md, persistent authority state; no direct cryptographic group mutation.
- [ ] Run author-written tests, retain initial failures.
- [ ] Implement serialized policy, generations, reservations, frozen release, exact cover checks, canonical parent CAS, abandonment and consumption.
- [ ] Add attenuated delegation, chain validity, cascading revocation and monotonic checkpoint comparison.
- [ ] Run focused tests and independent review; retain failures and fixes.

## Task 3: Real MLS adapter compatibility and implementation
Files: src/mls.rs; tests/mls_contract.rs.
Interfaces: canonical group frontier, exact roster/incarnation binding, frozen release envelope; OpenMLS provider/storage traits.
- [ ] Write retained-state decryption, authenticated-data binding, qualifying remove, and persistence tests first.
- [ ] Verify supported source APIs against pinned OpenMLS dependencies.
- [ ] Implement MLS creation/admission, context and incarnation binding, exact authenticated envelopes, and repair processing.
- [ ] Demonstrate API-only revocation failure and real successor exclusion; report unsupported adapter obligations explicitly.

## Task 4: Adapter integration and adversarial recovery
Files: src/main.rs, src/adapter.rs; harness/test_integration.py.
Interfaces: line-delimited JSON laboratory command protocol; subprocess tests drive real authority/MLS components.
- [ ] Write process restart, release/fence race, lost envelope, duplicate delivery and stale-client tests.
- [ ] Implement protect/persist/emit ordering and fail-closed resumption.
- [ ] Run deterministic schedules and continue authorized operations after repair.

## Task 5: Resource demo and portable delivery
Files: demo/*, scripts/*, README.md, docs/run.md, evidence/manifest.json.
- [ ] Define and test authenticated resource access and direct-backend denial.
- [ ] Implement isolated demo configurations with distinct worker credentials.
- [ ] Supply one verification command and an archive/checksum command; test them where runtime permits.
- [ ] Final independent review and coordinator verification. Package all source, tests, reports and exact capability limitations.

## Verification commands
The public verification entrypoint is `python3 scripts/verify.py` (created with tests). It runs the independent oracle suite and, when provisioned, `cargo test --locked`. Missing required tooling must yield a nonzero exit and explicit unmet gate, not an apparent pass. `python3 -m unittest discover -s harness -v` runs the standard-library model/contract harness. Native Rust gates cannot be replaced with Python results.

## Acceptance examples
```python
self.assertEqual(oracle.check(trace_with_post_denial_release), ['unauthorized_release'])
self.assertEqual(oracle.check(trace_with_pre_denial_release_late_delivery), [])
self.assertFalse(child_rights > parent_rights)
```
Exact type-specific tests are written by the independent authors from docs/contracts.md before implementation. Their executable files are the detailed task steps; implementers receive them verbatim with the brief.
