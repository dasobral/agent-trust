# OpenMLS staged-KeyPackage integration

The staged-KeyPackage construction hook is integrated into the real OpenMLS laboratory. The wider durable-authority-to-MLS adapter remains a separate phase.

## Current dependency boundary

The project takes every OpenMLS crate (`openmls`, `openmls_traits`, `openmls_rust_crypto`, `openmls_basic_credential`, `openmls_sqlite_storage` and `openmls_libcrux_crypto`) from the custom-fork branch `agent-trust/integration` (since 2026-10-25 it follows the branch; `Cargo.lock` records the commit, `dd33278099426c2ffc8a4ec686e88bde1f937963` at that date, and `cargo update` moves it). That branch is current upstream `main` with the staged KeyPackage API (branch `agent-trust/keypackage-staging`) and the libcrux provider entropy source (branch `feat/libcrux-provider-rng`) merged in, and it keeps the normal non-draft feature surface.

Until 2026-10-24 the pin was `6daabe33ddb616a6ed54b511d333e691db18a99f` on `agent-trust/keypackage-staging-v0.9`, based on OpenMLS `0.9.0`; that branch is kept unchanged, because earlier evidence was recorded against it.

Each joining endpoint now calls `prepare`, signs an APF admission certificate over the SHA-256 digest of the returned canonical stripped bytes, inserts that certificate with `with_external_binding`, and calls `finalize`. Before the KeyPackage is admitted, the laboratory parses and validates the final MLS object, structurally recomputes the stripped bytes through the fork API, checks the certificate fields and digest, and verifies the APF Ed25519 signature. The certificate is a top-level KeyPackage extension, not a sidecar.

## Fork insertion point

The separate OpenMLS work started from tag `openmls-v0.9.0` on branch `agent-trust/keypackage-staging-v0.9` and now supplies:

1. a generic staged-construction API;
2. canonical preimage and recomputation semantics;
3. unchanged Add/Welcome compatibility;
4. negative binding tests;
5. a standalone consumer proof and `CONSUMER-API.md`.

The fork package suite, external staged API test, doctests, and standalone consumer were executed before the exact commit was pinned in `agent-trust`.

## Enablement gate

The staged-KeyPackage milestone is enabled because all of the following pass against the pinned fork:

- canonical stripped-preimage equality;
- APF certificate binding inside the final MLS object;
- Add/Welcome compatibility;
- qualifying removal with retained-key exclusion;
- complete `agent-trust` Rust and Python verification.

`full_lap_mls` (now `full_construction_mls`, C-43) remains `false` because this milestone does not yet implement the complete durable APF adapter, `acc_context`, `authz_incarnation`, or policy-bound repair coupling. (Milestone record. The current claim is in the README: `full_lap_mls` was recorded `true` on 2026-10-24 under the claim gate of `docs/adapter-contract.md` §11.) The OpenMLS fork remains a separate repository and is consumed only through the exact Git revision.
