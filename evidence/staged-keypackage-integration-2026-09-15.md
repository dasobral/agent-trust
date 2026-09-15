# Staged KeyPackage integration verification — 2026-09-15

## Pinned OpenMLS fork

- Repository: `dasobral/openmls`
- Branch: `agent-trust/keypackage-staging-v0.9`
- Pinned commit: `6daabe33ddb616a6ed54b511d333e691db18a99f`
- Rust toolchain: `rustc 1.91.1`, `cargo 1.91.1`

The fork initially failed a clean external build because staged library,
consumer, and integration-test modules omitted required traits and the public
`prepare` method had malformed rustdoc. After the minimal repair and rustfmt,
the following passed:

- `cargo test --locked -p openmls`: 289 unit tests passed, 3 ignored; all
  package integration tests passed; 9 doctests passed, 1 ignored.
- `cargo run --locked --manifest-path lap-binding-consumer/Cargo.toml`:
  printed `staged KeyPackage binding verified`.
- `git diff --check`: clean.

## agent-trust integration

Joining endpoints now use the fork's `prepare → with_external_binding →
finalize` state machine. The embedded versioned certificate binds the group,
subject, authorization generation, and SHA-256 digest of the canonical stripped
KeyPackage bytes. Admission independently validates the final MLS KeyPackage,
recomputes the stripped bytes, checks the certificate fields and digest, and
verifies the laboratory APF Ed25519 signature.

Fresh project gates:

| Gate | Exit | Result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | Formatting clean |
| `cargo build --locked` | 0 | Locked build succeeded |
| `cargo test --locked --all-targets` | 0 | 39 Rust tests passed |
| `python3 -m unittest discover -s harness -v` | 0 | 32 Python tests passed |
| `python3 scripts/verify.py` | 0 | Python oracle: 21; Rust: 39 |
| `git diff --check` | 0 | No whitespace errors |

The six MLS tests cover embedded canonical binding equality, APF subject
substitution rejection, Add/Welcome and peer message compatibility, ciphertext
tamper rejection, removal epoch advance, retained-key exclusion, and continuing
member progress.

## Claim boundary

`staged_keypackage_binding_verified` is true for this executable laboratory.
`full_lap_mls` remains false because the durable authority kernel is not yet
coupled to MLS `acc_context`, `authz_incarnation`, and the complete qualifying
policy-bound repair transition. Strict Clippy additionally reports one existing
style warning in `src/authority.rs`; it is unrelated to this integration and was
not changed.
