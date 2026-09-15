# OpenMLS Staged KeyPackage Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the stock OpenMLS compatibility blocker with the verified staged-KeyPackage fork and prove the embedded admission binding through the existing real-MLS laboratory.

**Architecture:** Pin every OpenMLS crate to fork commit `6daabe33ddb616a6ed54b511d333e691db18a99f`. A joining endpoint prepares one KeyPackage, obtains canonical stripped bytes, embeds an APF-style signed admission certificate over their digest, finalizes the same frozen key material, and independently verifies the certificate from the serialized final KeyPackage before admission. Existing group Add/Welcome and removal/UpdatePath flows remain unchanged and become downstream compatibility gates.

**Tech Stack:** Rust 1.91.1, OpenMLS fork based on 0.9.0, SQLite authority kernel, Python acceptance harness.

**Spec:** `docs/specification.md`, `docs/OPENMLS-INTEGRATION-READY.md`, and the fork's `CONTRACT.md`.

## Global Constraints

- Use only the normal OpenMLS feature surface; do not enable draft, virtual-client, or test-only features.
- Pin the fork by exact commit SHA, never by a moving branch.
- The binding must be inside the final KeyPackage, not an outer sidecar.
- The verifier must independently recompute canonical stripped bytes from the final KeyPackage.
- Existing Add/Welcome behavior and retained-key exclusion after removal must remain green.
- Do not claim the complete LAP-MLS construction beyond the executable gates actually implemented here.

---

### Task 1: Dependency and Baseline Gate

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Consumes: OpenMLS fork commit `6daabe33ddb616a6ed54b511d333e691db18a99f`.
- Produces: one locked dependency graph in which `openmls`, `openmls_traits`, `openmls_rust_crypto`, and `openmls_basic_credential` originate from that exact Git revision.

- [x] Run the current `cargo test --locked --test mls_contract` baseline against stock 0.9.0.
- [x] Replace the four registry dependency specifications with the exact Git revision.
- [x] Regenerate `Cargo.lock` and inspect all four source entries.
- [x] Run the unchanged MLS contract to prove ordinary API compatibility.

### Task 2: Embedded Admission Binding

**Files:**
- Modify: `tests/mls_contract.rs`
- Modify: `src/mls.rs`

**Interfaces:**
- Consumes: `KeyPackageBuilder::prepare`, `PreparedKeyPackage::canonical_binding_bytes`, `PreparedKeyPackage::with_external_binding`, `BoundKeyPackage::finalize`, and `KeyPackage::canonical_binding_bytes`.
- Produces: staged construction for every new member and an independent verifier over the serialized final KeyPackage and trusted APF verification key.

- [x] Add a test requiring a joined member's final KeyPackage to contain a verifiable certificate bound to independently recomputed canonical bytes.
- [x] Run the focused test and retain the expected failure against the current one-shot builder.
- [x] Implement a versioned canonical admission-certificate payload binding group, subject, generation, and SHA-256 of the stripped KeyPackage bytes; sign it with the laboratory APF key.
- [x] Replace one-shot joining-member construction with prepare, certificate issuance, binding insertion, and finalize.
- [x] Parse the serialized final KeyPackage, recompute its stripped bytes, verify the certificate signature and fields, and reject admission on any mismatch.
- [x] Run the focused test until green without weakening its assertions.

### Task 3: End-to-End LAP Gate and Claim Update

**Files:**
- Modify: `tests/mls_contract.rs`
- Modify: `docs/openmls-compatibility.md`
- Modify: `docs/OPENMLS-INTEGRATION-READY.md`
- Modify: `README.md`
- Modify: `evidence/manifest.json`

**Interfaces:**
- Consumes: verified staged admission from Task 2 and the existing real MLS group laboratory.
- Produces: executable evidence for canonical equality, embedded-certificate verification, Add/Welcome compatibility, removal with successor UpdatePath, revoked retained-key exclusion, and continuing-member progress.

- [x] Add a negative certificate-substitution or tampering test that fails for the intended binding reason.
- [x] Run it red, implement only the verifier behavior required, then run it green.
- [x] Run all MLS tests, including existing Add/Welcome and removal cases.
- [x] Update compatibility and manifest claims with the pinned SHA and exact gate boundary.
- [x] Run `cargo fmt --all -- --check`, `cargo build --locked`, `cargo test --locked --all-targets`, the Python harness, `python3 scripts/verify.py`, and `git diff --check`.
