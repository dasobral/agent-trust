# Authority Gap Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the two confirmed APF authorization gaps without changing the approved invocation-provenance architecture.

**Architecture:** Keep authorization decisions in `src/authority.rs`. A read revocation fences the group only when it affects a current roster reader; a release accepts only content rights (`read` or `write`) and rejects administrative rights. Preserve the existing durable state, hash chain, invocation records, and MLS boundary.

**Tech Stack:** Rust 1.91.1, Cargo, rusqlite, serde_json, Python `unittest` CLI harness.

**Spec:** `docs/confused-deputy.md` and the recovered `AGENT-TRUST-HANDOFF.md`; the changes are limited to the confirmed gaps recorded in the recovered project context.

## Global Constraints

- Continue `agent-trust` only; do not modify or publish the separate OpenMLS repository.
- Preserve `full_lap_mls=false`; do not claim authenticated MLS integration or production readiness.
- Use TDD: each production fix needs a regression test that fails before the fix.
- Do not weaken existing assertions or alter the invocation-chain semantics.
- Do not force-push or invent an upstream repository URL/branch.

---

### Task 1: Add regression tests for the confirmed authority gaps

**Files:**
- Modify: `tests/authority_contract.rs`

**Interfaces:**
- Consume the existing `Authority` JSON command interface and test helpers in `tests/authority_contract.rs`.
- Produce two failing tests: non-roster read revocation leaves `read_fenced` false and preserves an authorized release; administrative release rights are rejected without consuming the reservation.

- [x] **Step 1: Write the failing tests**

Add tests named `revoking_non_roster_read_does_not_fence_the_group` and `release_rejects_administrative_rights` using the existing `Store`, `init`, `grant`, `checkpoint`, `allocate`, `release`, and `code` helpers. The first grants `alice` read without admitting her, revokes that read grant, asserts `read_fenced == false`, allocates a root operation, and releases it with the root cover. The second initializes and allocates an operation, submits a release with `right: "admin"`, asserts `unauthorized`, and then releases the same operation with `right: "write"` to prove the failed request did not consume it.

- [x] **Step 2: Run the focused tests and verify RED**

Run:

```bash
RUSTUP_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/rustup \
CARGO_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/cargo \
cargo test --locked --test authority_contract revoking_non_roster_read_does_not_fence_the_group -- --exact
RUSTUP_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/rustup \
CARGO_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/cargo \
cargo test --locked --test authority_contract release_rejects_administrative_rights -- --exact
```

Expected: the first fails because the current implementation sets `read_fenced` for every read revocation; the second fails because the current implementation accepts `admin` as a release right.

### Task 2: Implement the minimal authority fixes

**Files:**
- Modify: `src/authority.rs`

**Interfaces:**
- Preserve all public commands and JSON response shapes.
- `revoke` changes only the condition that sets `read_fenced`.
- `release` continues to require executor `write` authority and additionally rejects administrative requested rights (`admin` and `admit`).

- [x] **Step 1: Restrict the read fence to current roster readers**

Change the `revoke` branch so `s.read_fenced = true` is set only when `right == "read"` and the revoked subject is present in `s.roster`. Keep the existing cascading deactivation and revision/event behavior unchanged.

- [x] **Step 2: Restrict release to content rights**

After parsing `right` in `release`, return `Err("unauthorized".into())` when `right` is neither `read` nor `write`. Keep the existing executor-write check, frontier validation, invocation validation, cover checking, and state transition order intact.

- [x] **Step 3: Run both focused tests and verify GREEN**

Run the two commands from Task 1. Expected: both pass.

### Task 3: Verify the complete recovered implementation

**Files:**
- No production file changes.

**Interfaces:**
- Verify the Rust authority and MLS suites, Python CLI harness, formatting, build, and whitespace checks.

- [x] **Step 1: Run the complete matrix**

```bash
RUSTUP_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/rustup \
CARGO_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/cargo \
cargo fmt --all -- --check
RUSTUP_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/rustup \
CARGO_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/cargo \
cargo build --locked
RUSTUP_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/rustup \
CARGO_HOME=/workspace/scratch/497b97a1cafd/rust-toolchain/cargo \
cargo test --locked --all-targets
python3 -m unittest discover -s harness -v
git diff --check
```

- [x] **Step 2: Review the final diff and repository boundary**

Confirm only `agent-trust` files changed, `full_lap_mls` remains false, no credentials are present, the OpenMLS workspace is untouched, and the repository still has no invented remote or force-push operation.

### Task 4: Prepare publication without publishing blindly

**Files:**
- Modify only if needed: `AGENT-TRUST-HANDOFF.md`

**Interfaces:**
- Preserve the existing publication procedure and credential warning.

- [x] **Step 1: Inspect status, staged content, and remotes**

```bash
git status --short --branch
git diff --stat
git remote -v
```

- [x] **Step 2: Stop before publication because the repository URL or target branch is not explicitly available**

The recovered context supplies neither. Do not infer them from the OpenMLS fork and do not push until Daniel supplies or configures the correct `agent-trust` remote and branch.
