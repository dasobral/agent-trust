# OpenMLS staged-KeyPackage integration

The staged-KeyPackage construction hook is integrated into the real OpenMLS laboratory. The wider durable-authority-to-MLS adapter remains a separate phase.

## Current dependency boundary

The project pins `openmls`, `openmls_traits`, `openmls_rust_crypto`, and `openmls_basic_credential` to custom-fork commit `6daabe33ddb616a6ed54b511d333e691db18a99f` on branch `agent-trust/keypackage-staging-v0.9`. The fork remains based on OpenMLS `0.9.0` and preserves the normal non-draft feature surface.

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

`full_lap_mls` remains `false` because this milestone does not yet implement the complete durable APF adapter, `acc_context`, `authz_incarnation`, or policy-bound repair coupling. The OpenMLS fork remains a separate repository and is consumed only through the exact Git revision.
