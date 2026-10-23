# APF↔MLS Adapter Integration Plan (Task 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Read only your assigned phase, `docs/adapter-contract.md`, and the files that phase lists.

**Status:** Approved by Daniel on 2026-10-23 (`docs/adapter-contract.md` §13, D-1 to D-6 as proposed). Phase 4.0 is complete. Evidence: `evidence/adapter-compat.txt`, `evidence/kernel-corrections-red.txt` and `evidence/kernel-corrections-green.txt`.

Phase 4.1 and the approved R-8 kernel correction are complete. R-8 was tested in `tests/authority_resource_contract.rs`. Evidence: `evidence/adapter-identity-red.txt`, `evidence/resource-attenuation-red.txt` and `evidence/phase-4.1-r8-green.txt`.

Phase 4.2 and the approved R-9 correction are complete. Phase 4.2 tests are in `tests/adapter_admission.rs` and `tests/authority_subject_status.rs`; R-9 tests are in `tests/authority_invocation_resources.rs`, plus the A-2 scenario. Evidence: `evidence/adapter-admission-red.txt`, `evidence/invocation-resources-red.txt`, `evidence/invocation-resources-green.txt` and `evidence/phase-4.2-r9-green.txt`.

Phase 4.3 is complete. Tests: `tests/adapter_release.rs`. Evidence: `evidence/adapter-release-red.txt` and `evidence/phase-4.3-green.txt`.

Phase 4.4 is complete: 4.4a, 4.4b with the approved R-10, and the approved D-10 stacked repair. Phase 4.5 is complete. Tests: `tests/adapter_recovery.rs`. Evidence: `evidence/recovery-red.txt` and `evidence/recovery-green.txt`.

Gaps that remain after phase 4.5:
- There is no API to fetch an artifact that recovery re-signed (ack, certificate or receipt); such artifacts are stored in `adapter_recovered`.
- Client storage writes are not atomic.
- The application must persist the seed of a rekey's new identity.
- Recovery assumes a single adapter process per directory.
- The trace still grows without bound, and kernel history still grows roughly quadratically.

**Goal:** Couple the durable APF kernel to real OpenMLS processing. Every kernel frontier, admission, repair and fresh-key fact then comes from validated MLS evidence, and every protected message is bound to an APF-signed release certificate.

**Architecture:** A new adapter (`src/adapter.rs`) owns the APF key, authenticates client requests, runs a public sequencer (`PublicGroup`), issues admission, release and canonical-ack certificates, and is the only caller of the key-free kernel. Clients are generic OpenMLS endpoints with their own keys and SQLite storage. A seeded in-process delivery simulator carries opaque bytes. Exported traces are checked by the independent Python oracle.

**Tech Stack:** Rust ≥ 1.91 (verified locally on 1.99.1), OpenMLS fork `6daabe33ddb616a6ed54b511d333e691db18a99f`, `openmls_sqlite_storage` 0.3.0 from the same revision, rusqlite 0.37, Python 3 standard library harness, `openmls_qrand` via `[patch]` (phase 4.6 only).

**Spec:** `docs/specification.md` §2–3, `docs/adapter-contract.md`, `docs/authority-contract.md`, `docs/trace-contract.md`.

## Global constraints

- Test authors own the test files. Implementers MUST NOT weaken, delete or rewrite their assertions. A test changes only with a recorded requirement correction (`docs/adapter-contract.md` §10).
- A red run counts only if it is behavioral. Each phase first lands an interface skeleton, so the tests compile and fail on assertions. A build or setup failure is recorded separately and never as red.
- A stub that returns errors must not pass a negative test. Every negative test first runs the matching positive path in the same test and asserts that it succeeds.
- No security claim from booleans. The kernel `update_path`, `confirmed`, `durable` and `fresh_keys` inputs are set only by the adapter, from checked evidence.
- The adapter MUST NOT call `SignatureKeyPair::new` or RustCrypto `signature_key_gen` (contract §8).
- Use only the normal OpenMLS feature surface: no `test-utils`, `virtual-clients-draft` or `extensions-draft`.
- Existing tests stay green and unchanged in every phase: 39 Rust integration tests, 32 harness tests, and `scripts/verify.py`.
- Never write key material, real credentials or live endpoint details into evidence, traces, logs or docs. Use no absolute workspace paths in commands.
- Only the coordinator commits, integrates and packages. File ownership per phase is disjoint (table at the end).
- `full_lap_mls` stays `false` until phase 4.7 passes the contract §11 gate.

## Standard gate commands

Run from the repository root:

```bash
cargo fmt --all -- --check
cargo build --locked
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python3 -m unittest discover -s harness -v
python3 scripts/verify.py
git diff --check
```

Focused red and green runs use `cargo test --locked --test <file> 2>&1 | tee evidence/<phase>-<red|green>.txt`. Record the command, the exit code, the toolchain (`rustc --version`) and the host architecture at the top of each evidence file.

---

### Phase 4.0: Contract, compatibility gate and kernel corrections

**Files:**
- Modify: `docs/authority-contract.md` (R-1, R-2, R-3, R-6, R-7 text)
- Create: `tests/adapter_compat.rs` (test author)
- Create: `tests/authority_corrections.rs` (test author)
- Modify: `src/authority.rs` (implementer)
- Modify: `Cargo.toml`, `Cargo.lock` (coordinator: `openmls_sqlite_storage` at the pinned revision; `ed25519-dalek` to derive public keys from seeds)
- Create: `evidence/adapter-compat.txt`, `evidence/kernel-corrections-red.txt`, `evidence/kernel-corrections-green.txt`

**Interfaces:**
- Consumes: the pinned fork APIs listed in contract §4–§6.
- Produces: kernel commands with an optional adapter frontier (R-1, R-2), `policy_revision` and `policy_digest` (R-3), a release-event history hash (R-4 support), `MAX_ENVELOPE` (R-6), and two-step repair if D-3 is approved.

The compatibility gate tests the dependency, not our code. These tests can pass on their first run, and they are recorded as gate evidence, not as red/green.

- [x] Write the compatibility gate tests:
  - `public_group_from_external_tracks_member_frontier`
  - `staged_commit_group_context_equals_merged_member_context`
  - `plaintext_handshake_is_processable_by_public_group`
  - `application_messages_stay_private_under_pure_plaintext_policy`
  - `leaf_node_extensions_survive_key_package_into_ratchet_tree`
  - `one_commit_carries_removals_gce_and_forced_path`
  - `required_capabilities_reject_key_package_without_acc_extensions`
  - `sqlite_storage_round_trips_mls_group_load`
  - `epoch_authenticator_matches_across_members`
  - `signature_key_pair_from_raw_signs_and_verifies`
- [x] Run the gate. Any unsupported API is recorded as a blocker in `evidence/adapter-compat.txt` and reported. It is never worked around silently.
- [x] Write the kernel correction tests:
  - `init_accepts_genesis_frontier_and_defaults_to_genesis`
  - `admit_with_adapter_frontier_requires_exact_parent_and_next_epoch`
  - `admit_without_adapter_frontier_keeps_fixture_branch` (guard: green before and after)
  - `policy_revision_ignores_allocate_persist_and_consume`
  - `release_with_policy_revision_survives_unrelated_allocate`
  - `release_with_stale_policy_revision_is_stale_frontier`
  - `policy_digest_changes_exactly_when_policy_changes`
  - `release_response_exposes_its_history_event_hash`
  - `persist_accepts_envelopes_up_to_max_envelope_and_rejects_larger`
  - `repair_stage_keeps_fence_closed_until_repair_open` (only if D-3 chooses two commands)
- [x] Run them against the unchanged kernel. Retain the behavioral failures.
- [x] Implement the kernel corrections in `src/authority.rs` only.
- [x] Run the focused tests green, then the full standard gate.

**Claim after 4.0:** the kernel accepts adapter-supplied frontiers and separates policy revision from state revision. No MLS coupling is claimed.

### Phase 4.1: Keys, identity, signed requests and clock

**Files:**
- Create: `src/adapter.rs`, skeleton then implementation (implementer)
- Modify: `src/lib.rs` (coordinator: `pub mod adapter;`)
- Create: `tests/adapter_identity.rs` (test author)
- Create: `tests/common/mod.rs` with `CountingRand` and `FailingRand` provider wrappers and a deterministic `Clock` (test author)

**Interfaces:**
- Produces: `Adapter<P: OpenMlsProvider>`, `Clock`, `SignedRequest` (contract §4.8), APF key generation and storage (§7), and client key generation from a provider-rand seed (§8).

- [x] Land the interface skeleton. Every method returns `Err("not_implemented")`, and the crate compiles.
- [x] Write the tests:
  - `apf_key_is_drawn_from_provider_rand`
  - `apf_private_key_never_appears_in_kernel_database_or_trace`
  - `client_signature_key_derives_from_provider_rand_seed`
  - `valid_signed_request_reaches_kernel`
  - `bad_signature_is_unauthenticated_and_kernel_unchanged`
  - `replayed_or_decreasing_sequence_is_unauthenticated`
  - `request_body_actor_and_now_fields_cannot_override_adapter_values`
  - `unknown_actor_is_unauthenticated`
- [x] Run red and retain the evidence.
- [x] Implement, then run green and the standard gate.

**Claim after 4.1:** in-process requests are authenticated by registered signature keys, with adapter-owned time. This is not network authentication (Task 5).

### Phase 4.2: Canonical frontier, sequencer, genesis and admission

**Files:**
- Modify: `src/adapter.rs` (implementer)
- Modify: `src/mls.rs` (implementer). Extract a provider-generic `ClientEndpoint`, add `acc_context` and `authz_incarnation`, and keep the existing `MlsLab` API and `tests/mls_contract.rs` green unchanged.
- Create: `tests/adapter_admission.rs` (test author)

**Interfaces:**
- Consumes: kernel R-1 and R-2; contract §4.1–§4.4, §4.6, §5.1, §5.2.
- Produces: genesis transaction, admission certificate v2, sequencer validation of Add commits, signed canonical ack, and client merge rule.

- [x] Write the tests:
  - `genesis_kernel_branch_is_hash_of_real_group_context`
  - `genesis_group_carries_acc_context_and_required_capabilities`
  - `admission_certificate_requires_active_read_and_admit_at_current_generations`
  - `admitted_frontier_matches_kernel_branch_at_every_member`
  - `add_commit_without_valid_v2_certificate_is_noncanonical`
  - `add_commit_with_stale_generation_certificate_is_noncanonical`
  - `add_commit_from_non_admin_sender_is_noncanonical`
  - `commit_with_unexpected_extra_proposal_is_noncanonical`
  - `sibling_commits_on_one_parent_have_exactly_one_canonical_winner`
  - `client_refuses_commit_without_matching_canonical_ack`
  - `joiner_rejects_welcome_whose_frontier_differs_from_ack`
  - `incarnation_relabeling_to_fresh_generation_is_rejected`
- [x] Run red and retain the evidence.
- [x] Implement, then run green, the unchanged `tests/mls_contract.rs`, and the standard gate.

**Claim after 4.2:** kernel epoch and branch equal the real MLS frontier for genesis and admission. Admission requires an APF-certified KeyPackage, a sequencer-validated commit and a CAS win.

### Phase 4.3: Release certificates and the receive path

**Files:**
- Modify: `src/adapter.rs` (implementer)
- Create: `tests/adapter_release.rs` (test author)

**Interfaces:**
- Consumes: kernel R-3, R-4 and R-6; contract §4.5, §5.3.
- Produces: frozen operation digest, signed release certificate, protect-once with `AAD = H(cert)`, exact envelope persistence, and the delivery predicate with consume-before-deliver.

- [x] Write the tests:
  - `released_ciphertext_aad_equals_hash_of_signed_certificate`
  - `receiver_delivers_plaintext_only_after_consume`
  - `certificate_from_another_operation_is_binding_mismatch`
  - `ciphertext_protected_outside_the_adapter_is_not_delivered`
  - `sender_leaf_incarnation_not_matching_actor_is_rejected`
  - `write_revocation_blocks_delivery_of_stale_writer_generation`
  - `duplicate_delivery_is_replay`
  - `one_operation_cannot_persist_two_different_ciphertexts`
  - `retransmission_is_byte_identical`
  - `pre_cut_release_delivers_late_within_same_frontier`
  - `pre_cut_release_is_not_delivered_across_a_frontier_change`
  - `invocation_provenance_appears_in_the_release_certificate`
- [x] Run red and retain the evidence.
- [x] Implement, then run green and the standard gate.

**Claim after 4.3:** every delivered application message is bound to one APF-signed release certificate and one consumption.

### Phase 4.4: Revocation, repair and the retained-key adversary

This phase is split in two:
- **4.4a (complete):** read revocation, repair, confirmation, the retained-key adversary and read rejoin. Tests: `tests/adapter_repair.rs`. Evidence: `evidence/adapter-repair-red.txt` and `evidence/phase-4.4a-green.txt`.
- **4.4b (complete, D-9 approved):** non-read re-authorization of a current member through an update commit with a new signer (R-10 kernel `rekey`, C-28 to C-30). Tests: `tests/adapter_rekey.rs`, `tests/authority_rekey_contract.rs` and the A-3 edit. Evidence: `evidence/rekey-red.txt` and `evidence/rekey-green.txt`.
- **D-10 stacked repair (complete):** tests in `tests/adapter_repair_stacked.rs`. Evidence: `evidence/stacked-repair-red.txt` and `evidence/stacked-repair-green.txt`.


**Files:**
- Modify: `src/adapter.rs`, `src/mls.rs` (implementer)
- Create: `tests/adapter_repair.rs` (test author)

**Interfaces:**
- Consumes: kernel R-3, R-7 and D-3; contract §4.7, §5.4, §5.5.
- Produces: designated-member repair commit, sequencer exact-removal and `acc_context` checks, canonical-but-fenced state, confirmation-gated reopening, local per-client fencing, and fresh-key reauthorization evidence.

- [x] Write the tests (4.4a; `reauthorized_writer_requires_update_with_new_signer` moves to 4.4b):
  - `api_only_revocation_lets_a_retained_endpoint_decrypt_new_traffic`. This is a named broken control: kernel revoke only, no MLS removal. The test asserts the unsafe decryption succeeds.
  - `read_revocation_fences_release_until_confirmed_repair`
  - `repair_missing_one_revoked_reader_is_noncanonical`
  - `repair_removing_a_continuing_reader_is_noncanonical`
  - `repair_without_acc_context_update_is_noncanonical`
  - `repair_with_policy_revision_older_than_fence_is_noncanonical`
  - `repair_without_update_path_is_noncanonical`
  - `canonical_repair_stays_fenced_until_confirmation`
  - `inconsistent_confirmation_hash_keeps_fence_closed`
  - `removed_endpoint_storage_copy_cannot_decrypt_successor_traffic`. This uses a byte copy of the SQLite file and raw OpenMLS loading outside the adapter.
  - `continuing_members_send_and_deliver_after_repair`
  - `offline_client_stays_locally_fenced_without_blocking_others`
  - `write_revocation_does_not_remove_an_authorized_reader`
  - `reauthorized_writer_requires_update_with_new_signer`
  - `reallowed_reader_rejoins_only_with_new_generation_key_package`
- [x] Run red and retain the evidence. The broken-control test is expected to pass from the start; that pass is its evidence.
- [x] Implement, then run green and the standard gate (4.4a).
- [x] 4.4b: write `reauthorized_writer_requires_update_with_new_signer` and the R-10 kernel tests, run red, implement, run green.

**Claim after 4.4:** Stage C is shown in executed schedules: real removal excludes retained state from successor traffic, and the fence opens only on confirmed, canonical, policy-bound repair. `Bridge_remove^ETK` stays open.

### Phase 4.5: Durability and crash recovery

**Files:**
- Modify: `src/adapter.rs` (implementer: SQLite adapter store, `SqliteStorageProvider` clients, barrier hooks)
- Create: `tests/adapter_recovery.rs` (test author)

**Interfaces:**
- Consumes: contract §6.
- Produces: restartable adapter, sequencer and clients, plus a `Barrier` hook enum (B1–B8) available to tests without timing sleeps.

- [x] Also cover the gaps found in phase 4.1. The adapter store and the kernel are two SQLite files, so they never commit together:
  - A crash after the kernel commits but before the adapter store commits leaves a kernel change with no registered key and no trace event. This currently fails closed, because the subject cannot authenticate. Fix it with an intent log reconciled against kernel history on `open`.
  - A crash in the middle of `Adapter::create` leaves files that block both `create` and `open`.
  - Phase 4.2: if kernel `admit` commits but the sequencer merge fails, `open` refuses with `binding_mismatch: sequencer frontier`. That fails closed but has no recovery; it needs an intent log of the commit bytes.
  - Phase 4.2: if the sequencer merges but the adapter store transaction is lost, the certificate record and trace event are lost while the sequence stays consumed.
  - A crash in the middle of `GenesisPending::complete` leaves partial files, which are cleaned up only on an error return.
  - Phase 4.3: if the kernel commits and the adapter store does not, three cases follow:
    - an `allocate` leaves no owner row, so C-17 makes the operation permanently unusable;
    - a `release` leaves no stored certificate (B2), so even the owner cannot `abandon` it until adapter recovery exists;
    - a `consume` leaves no receipt (B5), so the delivery is lost.
  - Full envelopes still go to kernel `persist`, so history snapshots keep growing roughly quadratically. The adapter store already keeps the exact bytes, so the kernel could keep a digest instead; that would be a requirement correction.
  - Phase 4.4a: if kernel `repair_stage` commits and the sequencer merge fails, `open` refuses with no recovery path.
  - Phase 4.4a: if the store commit is lost after the kernel and the sequencer, the repair record is missing. Every confirmation is then `invalid_repair` and the fence stays closed for good. Fix: write a repair intent before the kernel call.
  - Phase 4.4a: if the store commit is lost after `repair_open`, the fence is open but the confirmation evidence is missing.
  - Phase 4.4a: `durable: true` is sent to `repair_stage` before the sequencer and store writes are durable.
  - Phase 4.4b: if kernel `rekey` commits and the sequencer merge fails, `open` refuses with no recovery path.
  - Phase 4.4b: if the store commit is lost after the merge, the old key keeps authenticating and the offer row remains. This needs a write-ahead rekey intent plus reconciliation of leaf keys on `open`.
  - Phase 4.4b: the client's new identity exists only in memory between `stage_rekey` and `apply_ack`, so a client restart loses it.
  - Unauthenticated requests make the trace grow without bound. This needs a bound or rate limit before Task 5 exposes the adapter on a network.
- [x] Write the tests:
  - `b1_crash_after_allocate_allows_release_after_restart`
  - `b2_crash_after_release_before_persist_abandons_permanently`
  - `b3_crash_after_persist_reemits_identical_bytes`
  - `b4_crash_after_decrypt_before_consume_never_delivers`
  - `b5_crash_after_consume_rejects_replay`
  - `b6_crash_after_stage_before_ack_never_merges`
  - `b7_crash_after_ack_before_merge_stays_locally_fenced_until_exact_merge`
  - `b8_client_storage_rollback_is_unready_until_exact_frontier`
  - `adapter_restart_reloads_sequencer_certificates_and_request_sequences`
- [x] Run red and retain the evidence.
- [x] Implement, then run green and the standard gate.

**Claim after 4.5:** recovery behaves as specified at the eight enumerated barriers. This is finite coverage, not a proof.

### Phase 4.6: Entropy seam

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock` (coordinator: `[patch.crates-io] openmls_traits` to the fork revision; `openmls_qrand` git dependency behind an `entropy-qrng` feature)
- Modify: `src/adapter.rs` (implementer)
- Create: `tests/adapter_entropy.rs` and `tests/common/mock_qrng.rs` (test author; a loopback mock of the QRNG Open API, labelled as a mock)
- Create: `harness/test_rand_inventory.py` (test author: static check that adapter sources do not call `SignatureKeyPair::new` or `signature_key_gen`)

**Interfaces:**
- Consumes: contract §8.
- Produces: a provider-generic adapter running on `QrngOpenMlsProvider`, and `entropy_unavailable` fail-closed behavior.

- [ ] Write the tests:
  - `every_adapter_key_generation_draws_from_configured_rand`
  - `failing_rand_fails_closed_without_kernel_mutation`
  - `mock_qrng_provider_runs_genesis_admission_and_release`
  - `qrng_outage_mid_session_fails_closed_without_fallback`
  - `live_entropy_core_gate`: `#[ignore]`, reads the endpoint from the environment, never from the repository. It is recorded as unmet until it is executed against a real appliance.
  - `test_adapter_never_calls_hidden_randomness_constructors`
- [ ] Run red and retain the evidence.
- [ ] Implement, then run green and the standard gate, with and without `--features entropy-qrng`.

**Claim after 4.6:** the consumers marked "Yes" in contract §8 draw from the configured provider, and failure is closed. HPKE encapsulation randomness is excluded. No live or quantum-origin claim.

### Phase 4.7: JSONL lab protocol, integration harness and oracle cross-check

**Files:**
- Modify: `src/main.rs` (implementer: `lab` subcommand driving adapter scenarios over JSONL; `mls-demo` unchanged)
- Modify: `docs/trace-contract.md` (oracle author: version 2, R-5)
- Modify: `harness/oracle.py` and create `harness/test_oracle_v2.py` (oracle author; v1 tests unchanged)
- Create: `harness/test_integration.py` (test author)
- Modify: `scripts/verify.py`, `harness/test_verify.py` (test author for the gate tests, implementer for the script)
- Modify: `evidence/manifest.json`, `README.md`, `docs/OPENMLS-INTEGRATION-READY.md` (coordinator, after green)

**Interfaces:**
- Consumes: all previous phases.
- Produces: a subprocess-driven lab with seeded scheduling, exported traces in trace contract v2, and the `full_lap_mls` claim gate.

- [ ] Write the tests:
  - `test_lab_scenario_trace_is_accepted_by_oracle`
  - `test_broken_controls_are_rejected_by_oracle`. Controls: post-denial release, API-only removal, omitted-reader cover, re-encryption of one operation, spent-cell replay, reopening without confirmation.
  - `test_process_restart_preserves_frontier_and_fence`
  - `test_seeded_schedules_reorder_drop_and_duplicate`. Record every seed in the evidence.
  - `test_full_lap_mls_is_true_only_when_every_gate_passes`
  - `test_verify_runs_adapter_gates_and_fails_closed`
- [ ] Run red and retain the evidence.
- [ ] Implement, then run green and the standard gate.
- [ ] Independent review of the adapter, distinct from the implementer, against contract §4–§6, then a coordinator rerun of every gate.
- [ ] Update claims only for gates actually executed. State `Bridge_remove^ETK` as open and list the HPKE limitation.

**Claim after 4.7:** `full_lap_mls` may be reported `true` under contract §11 for the recorded run, toolchain, architecture and seeds only.

---

## File ownership

| Phase | Test author | Implementer | Coordinator |
|---|---|---|---|
| 4.0 | `tests/adapter_compat.rs`, `tests/authority_corrections.rs` | `src/authority.rs` | `Cargo.toml`, `Cargo.lock`, `docs/authority-contract.md` |
| 4.1 | `tests/adapter_identity.rs`, `tests/common/mod.rs` | `src/adapter.rs` | `src/lib.rs` |
| 4.2 | `tests/adapter_admission.rs` | `src/adapter.rs`, `src/mls.rs` | none |
| 4.3 | `tests/adapter_release.rs` | `src/adapter.rs` | none |
| 4.4 | `tests/adapter_repair.rs` | `src/adapter.rs`, `src/mls.rs` | none |
| 4.5 | `tests/adapter_recovery.rs` | `src/adapter.rs` | none |
| 4.6 | `tests/adapter_entropy.rs`, `tests/common/mock_qrng.rs`, `harness/test_rand_inventory.py` | `src/adapter.rs` | `Cargo.toml`, `Cargo.lock` |
| 4.7 | `harness/test_integration.py`, `harness/test_verify.py`; oracle author: `harness/oracle.py`, `harness/test_oracle_v2.py`, `docs/trace-contract.md` | `src/main.rs`, `scripts/verify.py` | `README.md`, `evidence/manifest.json`, `docs/OPENMLS-INTEGRATION-READY.md` |

Phases run in order. `src/adapter.rs` has one implementer at a time. Phase 4.6 can be authored in parallel with 4.3–4.5 because its test files are disjoint, but it is implemented after 4.5.

## Deferred to Task 5

Network transport and mTLS for the signed requests, the broker and protected backend, container definitions and network isolation, and the external or hardware APF signer.
