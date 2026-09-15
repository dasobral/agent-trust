# Agent Trust — Confused-Deputy Implementation Handoff

## Scope

Continue the `agent-trust` project only.

Do not modify, merge into, or push anything to the OpenMLS repository. The OpenMLS staged-KeyPackage work is a separate project and is already present in its own fork and branch.

## Objective completed in this session

The APF now protects against multi-agent confused-deputy and authority-laundering attacks.

The enforced rule is:

```text
effective authority = executor authority ∩ invocation authority
```

For multi-hop calls, invocation authority is bounded by the complete authenticated APF-issued invocation chain. A higher-authority executor cannot recover rights or resources removed by a lower-authority origin or an intermediate attenuation step.

The APF still permits an independently initiated operation by a privileged parent.

## Implementation

Primary file:

```text
src/authority.rs
```

Added:

- durable `Invocation` records containing origin, executor, permitted rights, permitted resources, optional parent invocation, and active state;
- APF `invoke` command for issuing invocation capabilities;
- subset-only forwarding from parent invocations;
- invocation binding on operation allocation;
- recursive invocation validation during release;
- origin and executor authorization checks at release time;
- revocation revalidation through the existing effective-authority machinery;
- invocation provenance in checkpoints and release results.

The caller cannot choose an arbitrary `original_agent` field. Invocation IDs are APF-generated and the executor is bound to the stored invocation record.

## Acceptance behavior

```text
child(read) -> parent(read,write) -> WRITE
    => DENY: unauthorized

parent(read,write) -> WRITE independently
    => ALLOW
```

Also covered: legitimate child-originated reads through a parent, resource laundering, multi-hop privilege laundering, attenuation followed by attempted restoration, revocation of the originating authority, and JSONL CLI behavior.

## Tests and evidence

Rust tests: `tests/confused_deputy_red.rs`

CLI test: `harness/test_confused_deputy_cli.py`

Design note: `docs/confused-deputy.md`

Evidence:

- `evidence/confused-deputy-red.txt`
- `evidence/confused-deputy-green.txt`
- `evidence/confused-deputy-cli.txt`

Verified results before the final repair:

- `cargo fmt --all -- --check` passed;
- `cargo build --locked` passed;
- all 31 Rust tests passed;
- the CLI provenance test passed;
- `git diff --cached --check` passed.

Post-recovery repairs applied on 2026-09-15:

- revoking `read` from a subject outside the current roster no longer fences
  the group;
- `release` accepts content rights (`read` and `write`) but rejects the
  administrative rights `admin` and `admit`;
- current verification reports 10 adversarial, 14 authority-contract, 5
  confused-deputy, and 4 MLS tests passing (33 integration tests total).

Run again before publishing:

```bash
cargo fmt --all -- --check
cargo build --locked
cargo test --locked --all-targets
python3 -m unittest discover -s harness -v
git diff --check
```

## Current recovered workspace

The implementation is currently in:

```text
/workspace/scratch/497b97a1cafd/agent-trust
```

This workspace was reconstructed from the persistent recovery package. It has a local Git repository, but it does not have the correct upstream remote configured and has no project-specific commit history yet. The recovered files are staged as the current baseline plus implementation.

Before committing, inspect:

```bash
cd /workspace/scratch/497b97a1cafd/agent-trust
git status
git diff --cached --stat
git diff --cached --check
```

Do not discard or reset the current staged state without first preserving the recovered implementation.

## Upstream publication procedure

The correct repository URL and target branch for `agent-trust` must be configured. Do not infer them from the OpenMLS fork.

After confirming the repository URL and branch:

```bash
git remote add origin <AGENT_TRUST_REPOSITORY_URL>
git branch -M <AGENT_TRUST_BRANCH>
git status
```

Create a commit containing only the `agent-trust` implementation and evidence:

```bash
git commit -m "feat: enforce invocation provenance in APF"
```

Fetch before pushing and inspect divergence:

```bash
git fetch origin <AGENT_TRUST_BRANCH>
git log --oneline --decorate --graph --all -20
git rev-list --left-right --count HEAD...origin/<AGENT_TRUST_BRANCH>
```

If the remote branch contains unrelated work, integrate it normally. Never force-push without explicit approval.

Then publish:

```bash
git push -u origin HEAD:<AGENT_TRUST_BRANCH>
```

## Authentication warning

The GitHub token supplied during the previous session was exposed in the conversation and must be revoked. Use a newly generated token or configured SSH credentials for the `agent-trust` repository. Do not place credentials in the repository, commit messages, scripts, or handoff files.

## Boundary of the claim

This implementation does not detect prompt injection or semantic maliciousness by an otherwise-authorized agent. It enforces the narrower authorization property that a lower-authority agent cannot gain additional authority merely by routing an operation through a more privileged agent.
