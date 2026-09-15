# MLS API audit report

**Scope:** OpenMLS compatibility with `docs/specification.md` section 2 only. Candidate: `openmls = 0.9.0`, normal/default feature surface; no virtual-client, test, or draft feature is part of this conclusion.

## Result

| Result | Count |
|---|---:|
| Supported API requirements | 8 |
| Integration-dependent items | 2 |
| Public-API blockers | 1 |

The blocker is exact and narrow: OpenMLS 0.9.0 has no public two-phase KeyPackage/LeafNode construction API that gives APF canonical stripped preimage bytes before the final MLS signatures, then accepts the APF certificate and produces the final signed KeyPackage. Its internal `KeyPackageTbs::unsigned_payload()` exists but is private. The public builder creates fresh key material and finalizes the signatures in one operation. Exact LAP-MLS binding therefore needs an upstream API addition or an approved maintained fork.

The audit did **not** replace the required binding with an outer certificate sidecar.

## Evidence

- [Upstream 0.9.0 release](https://github.com/openmls/openmls/releases/tag/openmls-v0.9.0)
- [Feature declaration and virtual-client boundary](https://github.com/openmls/openmls/blob/openmls-v0.9.0/openmls/Cargo.toml#L45-L113)
- [Private KeyPackage TBS preimage and private completed fields](https://github.com/openmls/openmls/blob/openmls-v0.9.0/openmls/src/key_packages/mod.rs#L153-L185)
- [One-shot public KeyPackage builder](https://github.com/openmls/openmls/blob/openmls-v0.9.0/openmls/src/key_packages/mod.rs#L518-L620)
- [Normal-feature standalone Remove and GroupContextExtensions proposal APIs](https://github.com/openmls/openmls/blob/openmls-v0.9.0/openmls/src/group/mls_group/proposal.rs#L434-L449)
- [Forced UpdatePath condition in regular commit building](https://github.com/openmls/openmls/blob/openmls-v0.9.0/openmls/src/group/mls_group/commit_builder.rs#L849-L870)
- [Persistent-storage loading interface](https://github.com/openmls/openmls/blob/openmls-v0.9.0/openmls/src/group/mls_group/mod.rs#L497-L534)

## Executable API gate

A temporary Cargo crate was checked offline with exact dependencies `openmls = "=0.9.0"`, `default-features = false`, and `openmls_traits = "=0.6.0"`. It typechecked calls for AAD, external Remove and GroupContextExtensions proposals, `CommitBuilder::propose_removals`, `force_self_update`, GroupContextExtensions in a commit, public frontier getters, KeyPackage/LeafNode extension slots, and `MlsGroup::load` over `StorageProvider`.

The check completed successfully; the only diagnostics were expected dead-code warnings in the type-only gate. This supports the positive API findings but cannot overcome the missing two-phase pre-sign API.
