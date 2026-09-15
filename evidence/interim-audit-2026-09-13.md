# agent-trust interim recovery audit — 2026-09-13

## Scope

This checkpoint advances the recovered working tree without changing the approved design. The original Library recovery remains untouched. Work was performed in an isolated copy materialized from `/Agents/agent-trust-recovered-2026-09-13`.

The local execution container has Python 3.13.5 but no `rustc`/`cargo`, and shell network access is unavailable. Therefore **no Rust change in this checkpoint is claimed green**. Rust changes are limited to source recovery fixes supported by the frozen contracts/upstream OpenMLS 0.9.0 API, plus new regression tests that intentionally remain unexecuted until a Rust-enabled session can record the required red run.

## Fresh verification completed here

- `python3 -m unittest discover -s harness -p 'test_oracle*.py' -v`
  - exit `0`
  - 21 tests passed
  - captured in `evidence/python-oracle-fresh-green.txt`
- `python3 -m py_compile harness/test_cli.py harness/oracle.py harness/test_oracle.py harness/test_oracle_repair.py`
  - exit `0`
  - captured in `evidence/python-syntax-check.txt`

## Recovered MLS source repairs

Two compile-level defects are evident in the recovered `src/mls.rs` and are corrected in this checkpoint:

1. `impl Endpoint` was closed immediately before `process_commit(&mut self, ...)`, leaving a method with `self` outside the impl. The premature brace is removed.
2. `PendingMember.key_package` was declared `KeyPackage`, while `KeyPackage::builder().build(...)` in pinned OpenMLS 0.9.0 returns `KeyPackageBundle`, and the later code calls `.key_package()` on the stored value. The field is changed to `KeyPackageBundle`.

These are recovery fixes only. The entire MLS laboratory still requires `cargo test --locked --test mls_contract` before any green claim.

## CLI contract correction

`harness/test_cli.py` expected the first durable history record to have `sequence == 1`. The authoritative Rust contract suite and `Authority::save` both define zero-based durable sequence numbers: the first record is `0`. The CLI assertion is corrected to `0`.

This is a test-contract alignment, not a weakening of production behavior.

## Authority contract gaps found by source audit

The production authority implementation is deliberately **not changed** for these findings in this checkpoint. New tests are supplied first in `tests/authority_gap_contract.rs`; run them red before implementing fixes.

### A1 — read revocation fences unrelated non-roster grants

Current `revoke` sets `read_fenced = true` after any changed `read` revocation. The contract is narrower: the fence closes only if an affected active or pending MLS roster reader exists. Revoking a standalone non-roster read grant must not fence the group.

Regression tests:
- `revoking_read_from_a_non_roster_subject_does_not_close_the_group_fence`
- `revoking_a_non_roster_ancestor_still_fences_when_an_affected_descendant_is_in_the_roster`

The second test prevents an over-broad fix: an off-roster ancestor revocation must still fence when cascading invalidation reaches an in-roster reader.

### A2 — release accepts rights outside the content-release domain

Current `release` parses `right` using the generic four-right parser, so `admin` and `admit` pass schema validation. The authority contract restricts `release.right` to `read|write`.

Regression test:
- `release_rejects_admin_or_admit_as_content_rights_without_consuming_the_reservation`

The test also checks failure atomicity: the reservation must remain usable for a subsequent valid write release.

### A3 — repair silently exempts a revoked root reader

Current `repair` excludes `s.delegations[0].subject` (the root) when computing the required removal set. The contract explicitly permits root self-revocation and requires repair to remove exactly all inactive/invalid pending roster readers. If root read is revoked while another authorized reader remains, root must be removable from the MLS roster.

Regression test:
- `repair_can_remove_a_revoked_root_reader_when_an_authorized_reader_continues`

## Known external blocker preserved

Do not bypass the previously recorded exact LAP–MLS binding gate. OpenMLS 0.9.0 does not expose the required public two-phase KeyPackage/LeafNode pre-sign API. The real MLS laboratory can still validate ordinary group membership/removal behavior, but an exact LAP certificate-binding claim remains blocked until an upstream API addition or maintained fork supplies that hook.

## Resume sequence in a Rust-enabled session

Run from the recovered project root after applying `agent-trust-interim-2026-09-13.patch`:

```bash
# 1. Required new red evidence before touching authority.rs
cargo test --locked --test authority_gap_contract

# 2. Record the current Rust integration baseline
cargo test --locked --test authority_contract --test authority_adversarial --test mls_contract

# 3. Only after the authority_gap_contract red run, implement minimal fixes for A1-A3.
#    Do not alter the new test assertions to obtain green.

# 4. Re-run all Rust contracts
cargo test --locked --test authority_gap_contract \
  --test authority_contract --test authority_adversarial --test mls_contract

# 5. Build the CLI and execute black-box acceptance
cargo build --locked
python3 -m unittest harness.test_cli -v

# 6. Full Python harness
python3 -m unittest discover -s harness -v
```

If step 1 does not fail for the expected A1-A3 reasons, stop and inspect the recovered source/version before implementing anything. If `src/mls.rs` still fails compilation, fix compile/API mismatches separately from authority behavior and retain the exact compiler output.

## Files in this checkpoint

- `src/mls.rs` — two source-recovery fixes; Rust-unverified here
- `harness/test_cli.py` — history sequence contract correction; Python syntax verified
- `tests/authority_gap_contract.rs` — four new independent regression contracts; must be run red first
- `evidence/python-oracle-fresh-green.txt` — fresh 21-test green run
- `evidence/python-syntax-check.txt` — fresh Python syntax check
- `evidence/interim-sha256.txt` — base/modified hashes
- `agent-trust-interim-2026-09-13.patch` — changes relative to the recovered files

