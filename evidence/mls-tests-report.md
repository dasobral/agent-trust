# MLS contract test report

## Scope

`tests/mls_contract.rs` defines the public API contract for
`agent_trust::mls::MlsLab`. It uses only the requested methods and checks
observable success or rejection; it does not inspect library-specific error text.

## Cases

- New labs start with **alice** as the sole member.
- Alice's protected payload and authenticated data round-trip for alice, bob, and
  carol after they are current members.
- A one-bit wire modification is rejected by a current recipient.
- A pre-removal bob snapshot decrypts fresh old-epoch traffic, establishing that a
  snapshot remains a complete endpoint before the removal transition.
- Removing bob advances the epoch, updates the roster, lets carol decrypt
  successor traffic, and rejects that traffic for both bob and the snapshot.
- Removed and unknown senders cannot protect traffic.

## Test run evidence

Command: `cargo test --test mls_contract`

Exit code: 127

Result: build/setup failure, not a behavioral red test. At test-authoring time,
`cargo` is unavailable in the environment and there is no `Cargo.toml` in this
repository. The captured command output is in `evidence/mls-tests-red.txt`.

## Dependency need

The implementation needs a Rust package named `agent_trust` that exports
`agent_trust::mls::MlsLab` with the API under test. A real MLS implementation
will also require its selected MLS crate and the cryptographic provider/runtime
that crate documents. These tests intentionally do not prescribe either
implementation dependency.
