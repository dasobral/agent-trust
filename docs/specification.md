# agent-trust — implementation specification draft

11 September 2026 · Revision 0.1 · Awaiting Daniel’s confirmation

## 1. Goal and implementation boundary

Build an experimental realization of Authorization–Capability Coherence (ACC), using the LAP-MLS construction from the **Third Edition Study Notes, 5 September 2026**, particularly chapters 7–11. The second edition remains a historical checkpoint. The accompanying Article Draft, sections 5–7, supports the mapping. Theory remains an independent research artifact; implementation findings feed back as evidence or counterexamples.

The experiment must reproduce the failure of independent authorization and group membership, then demonstrate enforcement, revocation, recovery, and useful authorized progress. Tests establish behavior in specified executions. They do not discharge the open `Bridge_remove^ETK` cryptographic proof obligation.

**Recommended stack:** Rust, OpenMLS, a transactional SQLite-backed authority, and an external Python acceptance harness. OpenMLS supplies RFC 9420 group cryptography and replaceable storage/randomness interfaces ([OpenMLS documentation](https://book.openmls.tech/), [provider traits](https://book.openmls.tech/traits/traits.html)); MLS processing follows [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html). After approval, an executable compatibility gate will verify the exact extension, external-proposal, persistence, and pre-signing APIs before versions are pinned. An unsupported binding is reported, never silently omitted.

A model-only implementation would accelerate scheduling tests but would not test retained-key exclusion. A replicated authority would add distributed-failure work before establishing the core contract. Use a model for the independent oracle and **real MLS with a single authority** for the first implementation. Replication and alternate revocation cuts are later work.

The authority is trusted for policy, signing keys, and durable history. Its single-writer transaction order realizes the experimental linearizable interface; this is not a quorum or high-availability deployment. Client crashes and client snapshot rollback are in scope. Rollback or compromise of the authority’s own durable store is outside this profile. No offline protected operations, retrospective plaintext erasure, FHE, or GPU work is included.

## 2. Components and behavioral contract

**Authority, Permit, and Fence service (APF).** Own policy revisions, identities, right generations, delegations, read fences, operation reservations, signed release records, per-recipient consumption, canonical MLS frontiers, and authenticated release/spent history. Expose `PolicyCommit`, `Preallocate`, `AuthorizeRelease`, `Consume`, `Canonicalize`, and `Checkpoint`, with explicit identity-enrollment and delegation operations. State changes are atomic; acknowledgements follow durable commit. Repeated requests cannot create a second release or consumption.

**MLS adapters and sequencer.** Mandatory adapters guard honest emission and application acceptance. A parent compare-and-swap selects at most one canonical successor. Epoch identity includes group, epoch number, tree hash, and confirmed transcript hash. Bind the policy in `acc_context` and the identity/generation vector in `authz_incarnation`. Public preimages exclude their own certificate, hash, and enclosing signatures. Retain authenticated support covers, exclusions, and monotonic client checkpoints. APF must validate covers against canonical state; it cannot trust a caller’s omission of readers.

Use one MLS group per read-authorization domain. Group readers possess group secrets; resource-specific read restrictions cannot be represented merely as ACLs on ciphertext within that same group. Initially use exact resource identifiers and one group, with no path-pattern policy language.

**Operation order:** preallocate identifiers → freeze content and context → atomically authorize release → protect once with MLS → durably store exact envelope → emit → verify and consume before application delivery. The signed certificate binds frozen content, context, cover, generations, and the pre-release frontier. The ciphertext authenticates the certificate hash. Release/spent history has authenticated inclusion and continuity evidence.

The successful `AuthorizeRelease` transaction is the revocation cut. A denial ordered before it blocks that operation. A previously released immutable object is not retroactively unauthorized because transmission occurs later. Consumption is a replay barrier, not another authorization cut. The experimental delivery profile is conservative: application delivery requires a locally ready client, the current canonical epoch/branch, current applicable actor and recipient generations, a valid immutable release, and an unspent recipient cell. Failure rejects delivery without changing the historical release decision. Thus a pre-denial release can be delivered later only while these conditions still hold; delivery across an epoch change is rejected. No guarantee of delivering every pre-cut object is made, and an already exposed old ciphertext can remain decryptable by its former readers.

Retransmission is byte-identical. On recovery, a released operation with no durably saved exact envelope is terminally abandoned: record abandonment at APF when reachable, retain its identifier permanently, and never protect or emit under that permit again. APF unreachability keeps recovery fenced. At-most-once consumption may lose delivery after a crash; arbitrary external effects are not promised exactly-once execution.

**Four rights:** read, write, admin, and admit remain distinct. Read denial atomically closes the group’s read-release fence. Reopening requires exact affected-leaf/generation removal, fresh UpdatePath, policy binding at least as recent as denial, a winning regular Commit, successful RFC processing and confirmation, and durable installation at each resuming client. A proposal alone is insufficient. A designated honest continuing repair member supplies the first experiment’s progress assumption; the public sequencer cannot independently check secret-dependent confirmation. Repair authority permits only exact removal and binding repair.

The central read fence opens after the qualifying repair is durably canonical and the designated continuing repair member has verified confirmation. Other clients do not block that central transition: each stays locally fenced until it processes and durably installs that successor. An offline client therefore cannot indefinitely block the continuing members.

Write/admin/admit denial closes the affected generation without unnecessarily removing an authorized reader. Admission checks joint authorizer-admin and candidate-admit support. Reauthorization advances the affected generation and installs fresh bound keys/credentials; old grants never become valid again. Lost authority contact or unverifiable/incomparable client state keeps the boundary unready.

**Delegation extension.** Each child has separate keys and an identity bound to its parent chain. Delegations bind issuer, subject, parent record and generations, exact resources, rights, validity interval, and remaining delegation depth. Every link must remain valid; children cannot expand rights/resources, extend validity, or increase depth. Revocation invalidates dependent descendant authority atomically and fences every affected read group. Delegation is an engineering extension requiring its own tests and explicit mapping to ACC supports, not an already-proved LAP-MLS result.

**Infrastructure demo.** Root, child, and sibling workers use authenticated broker requests. A protected backend is reachable only through the broker, which owns backend credentials. Separate container networks, service authentication, and absence of host mounts or runtime sockets enforce this boundary. Binding includes caller, resource, action, and payload. The demo uses deterministic worker processes; an LLM is unnecessary for correctness. It protects this configured resource path, not every action on the host.

**Entropy.** Default to OS CSPRNG. Introduce a replaceable source for identity keys, MLS initialization/UpdatePath randomness, and protocol values that actually require random generation. Account for randomness inside cryptographic backends too. Deterministic sources are test-only. An optional Entropy Core adapter must use a verified QRNG Open API schema; required-quality mode rejects unavailable, stale, malformed, or insufficient-quality input without silent fallback. Live integration is separately reported and requires access to a real endpoint. No new conditioning algorithm or quantum-origin claim is introduced.

## 3. Tests first, staged implementation

Before production logic for each increment, an independent test author writes executable acceptance tests and oracle expectations from this contract. Run them and record an expected behavioral failure, rather than relying on an import/build error. A separate implementer makes them pass. The main agent reviews changes, reruns the tests, and checks deliberately broken controls. Test expectations may change only with a recorded requirement correction.

| Stage | Required acceptance evidence |
|---|---|
| A — contract and compatibility | Deterministic operation traces; unique occurrence identity; missing provenance fails the oracle; joint supports are not flattened. Real MLS API checks demonstrate required bindings and removal support. |
| B — authority and release | Permit/content/context substitution fails; stale or incomplete covers fail; release-versus-denial barriers produce the declared order; replay is rejected; two sibling Commits have at most one CAS winner. |
| C — real MLS revocation | Broken API-only revocation allows a retained-key endpoint to decrypt newly protected traffic. Enforced mode fences new release until qualifying removal; the removed endpoint cannot decrypt successor test messages, while continuing members can. Pre-cut late traffic is tested separately. |
| D — rights and delegation | Independent write/admin/admit revocation; stale KeyPackage/Welcome and fresh-generation relabeling attacks; parent/child/grandchild attenuation and cascading revocation; unrelated authorized operations still work. |
| E — recovery and deployment | Crashes around each durable boundary; exact-envelope retry; client rollback; duplicate delivery; partition fail-closed; progress after repair; direct-backend and cross-identity bypass attempts fail. |

Use explicit barriers, seeded scheduling, fault injection, and independent trace replay; avoid timing sleeps as race evidence. Keep the revoked endpoint’s complete pre-removal state and exercise decryption outside the trusted adapter. Check both rejection and successful authorized work so a permanently closed fence cannot pass acceptance. Report finite schedule coverage, not an unbounded proof.

Ship source, lockfiles, container definitions, fixtures, source archive and SHA-256 checksums, concise build/run/test documentation, and a machine-readable evidence manifest. Document setup/download requirements separately from offline test execution. Record source and test revisions, commands, exit codes, toolchains, host architecture, seeds, traces, and red/green logs. ARM64 support is a target until executed there; cross-compilation alone is not runtime validation. The inspected sandbox is x86_64 and `cargo` was not found on PATH; toolchain provisioning is the first environment task after approval.

## 4. Delegation plan and evidence from this session

All six review agents below were actually dispatched with **`fork_turns: none`**. Each received only a bounded task, necessary contract excerpts, and a no-code/no-file-write instruction. They returned design reviews; no implementation or test-run evidence is claimed yet.

| Actual task ID | Model / reasoning | Result used |
|---|---|---|
| `/root/theory_contract` | Terra / high | Minimal vertical slice, six contracts, release-cut and resumption traps. |
| `/root/acceptance_tests` | Terra / high | Twelve acceptance cases, retained-key adversary, crash barriers, red/green evidence. |
| `/root/threat_review` | Terra / high | Five failure classes and mediation limits; received a corrective follow-up. |
| `/root/delegation_contract` | Terra / medium | Attenuation data model, ancestor invalidation, distinct child keys. |
| `/root/portable_delivery` | Luna / medium | Transfer package, offline boundaries, architecture-specific verification. |
| `/root/entropy_contract` | Luna / medium | Randomness boundary, quality failures, test-source isolation. |

**Main-agent verification changed the recommendations.** Source inspection of study-note pages 24–25 corrected the threat reviewer’s requirement that ciphertext exist before denial: only frozen content/context must precede release; protection follows it. The reviewer acknowledged that correction and withdrew authority-store rollback detection from scope. The acceptance proposal’s “post-cut envelope” test was narrowed to newly authorized objects and qualifying successor traffic, preserving pre-cut late messages. Delegation resources were restricted to exact domains to avoid suggesting per-record secrecy under shared MLS keys. Proposed signed release archives were reduced to checksummed archives because no release-signing identity has been established.

After confirmation, dispatch separate test-author and implementation tasks for the authority, MLS adapter, delegation, recovery harness, and infrastructure demo. Use Terra/high for security state transitions, adversarial tests, and review; Terra/medium for bounded integration; Luna/medium for fixtures, CLI, packaging, and documentation; Luna/low for mechanical evidence indexing. Each task receives only approved interfaces, relevant files, and required tests, with exclusive file ownership or an isolated worktree. No agent inherits the main thread. Record prompts, task IDs, models, reasoning settings, revisions, findings, and verification results; reasoning levels are configuration, not a promise of exact token expenditure. The main agent owns integration and final acceptance.

A final Terra/high review of this draft identified delayed-delivery ambiguity, the release-to-envelope crash gap, and possible confusion between central and local reopening. The main agent resolved these with an explicit conservative delivery predicate, terminal abandonment recorded at APF, and separate central/client readiness conditions. These are specified behaviors awaiting tests.

**Confirmation requested:** approve this scope, Rust/OpenMLS direction, single-authority experimental profile, and test-first sequence before implementation begins.
