# Contract test review

## Scope

Reviewed `AGENTS.md`, `docs/authority-contract.md`,
`tests/authority_contract.rs`, and `tests/mls_contract.rs`. No production
module or oracle was changed.

## Corrections applied

- Authority `release.cover` is a list of supports, where each support is a
  list of grants. The helpers now emit singleton supports, so an accepted
  write release has the shape
  `[[root-write], [root-read], [alice-read]]` rather than a flat grant list.
- The sound-cover test now rejects a joint support containing both root grants.
  This keeps the contract's required singleton supports observable instead of
  allowing a grouped proof to satisfy two required singleton entries.
- The rejection helper no longer requires successful values to implement
  `Debug`. This lets `Authority::open(...)` be checked for `corrupt_history`
  without imposing a contract-irrelevant public trait bound.
- The MLS round-trip test now decrypts only as Bob and Carol. In pinned
  OpenMLS 0.9.0, `framing/validation.rs` states that a client's own private
  message cannot be decrypted because its own sender ratchet produces only
  encryption keys. The test does not require a plaintext cache for Alice.

The remaining authority cases match the documented API shape and behavior:
frontier binding, fencing, generation changes, dependent revocation, exact
envelope persistence, repair, malformed requests, and history tamper
detection.

## Verification

Commands were run from the repository root with the supplied Rust toolchain
environment.

| Command | Exit | Result |
| --- | ---: | --- |
| `cargo test --test authority_contract` | 101 | Compiled and ran 12 tests; all failed against the existing `unimplemented` scaffold. |
| `cargo test --test mls_contract` | 101 | Compiled and ran 4 tests; all failed because `MlsLab::new()` returns `unimplemented`. |
| `cargo fmt --check` | 1 | Setup-only failure: `cargo-fmt` is not installed for the supplied stable toolchain. |

These are retained red results, not behavioral regressions from the test
review. No green result is available until the authority and MLS
implementations replace the scaffold.
