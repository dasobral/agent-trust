# OpenMLS integration readiness

The authority kernel, ordinary OpenMLS laboratory, CLI, recovery behavior, and confused-deputy enforcement can be verified independently of the missing LAP–MLS construction hook.

## Current dependency boundary

The project pins OpenMLS `0.9.0` and the corresponding `0.6.0` provider crates. Stock OpenMLS exposes ordinary group creation, Add/Welcome, application messages, Remove commits with an update path, authenticated data, and public group-frontier fields. Those capabilities are exercised by `src/mls.rs` and `tests/mls_contract.rs`.

Stock OpenMLS 0.9.0 does not expose a public two-phase KeyPackage/LeafNode construction API that retains final key material while exposing the canonical stripped preimage before final MLS signatures. Consequently, an outer sidecar, post-hoc hash, or reconstructed look-alike must not be presented as the required LAP binding.

## Fork insertion point

The separate OpenMLS work starts from tag `openmls-v0.9.0` on branch `agent-trust/keypackage-staging-v0.9`. It must supply:

1. a generic staged-construction API;
2. canonical preimage and recomputation semantics;
3. unchanged Add/Welcome compatibility;
4. negative binding tests;
5. a standalone consumer proof and `CONSUMER-API.md`.

After that work is independently verified, `agent-trust` must pin an exact fork commit SHA rather than a moving branch and add end-to-end tests for the embedded LAP certificate.

## Enablement gate

`full_lap_mls` must remain `false` until all of the following pass against the pinned fork:

- canonical stripped-preimage equality;
- APF certificate binding inside the final MLS object;
- Add/Welcome compatibility;
- qualifying removal with retained-key exclusion;
- complete `agent-trust` Rust and Python verification.

The OpenMLS fork is a separate repository. Its worktree and branch are not merged into this repository.
