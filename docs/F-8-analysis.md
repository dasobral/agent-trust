# F-8: kernel history cost — analysis and proposed correction R-13

31 October 2026 · Analysis of agent-trust `main` at `e774ba2` · **Approved 2026-10-31 (D-17, §10), with hardening against tampering, rollback and APF key theft.**

Finding F-8 comes from the testbed (`agent-trust-testbed/docs/findings.md`, measured by E5). This note explains why it happens, where it comes from and what it costs, and proposes a staged correction. A kernel microbenchmark reproduces the testbed's history size to within 10 % and measures each layer of the fix separately (§5).

## 1. Summary

- **Symptom.** In E5 the APF's time per request grows roughly with the square of the history length. It is 7 ms at up to 48 events and 1 058 ms at up to 481 events in the classical suite, and about twice that in the `pq` suite. The APF serializes requests, so in the `pq` suite parallel sends pass the 60 s client timeout and E5 fails.
- **Cause.** There are two independent quadratic terms, and a request pays both several times:
  1. **Storage.** Every history event embeds a full snapshot of the kernel state. The state grows linearly, because operations (with their envelope bytes), consumptions and invocations are never removed. The history is therefore quadratic in bytes: `H(n) = Σ S(k) ≈ c·n²/2`.
  2. **Reads.** Every kernel call re-reads, re-parses, re-serializes and re-hashes the whole history (`load()` → `validate_history()`). The adapter adds full `checkpoint` reads that also materialize every event. A mutating adapter request makes 3 to 4 full passes over `H(n)`.
- **Origin.** This is a design choice of the original kernel ("persist one logical state plus append-only hash-chained event records", "persistence replay validates chain before use"). Three later changes each multiplied it: R-6 put envelopes up to 2 MiB into the kernel state, C-31 added a full `checkpoint` before every mutation, and R-12 added a second `load()` per command. F-9 (ML-DSA) then made each envelope about seven times larger.
- **Fix, by measured impact.** In the microbenchmark at 502 events, the following changes bring the cost of one request from 744 ms to 2.7 ms (classical) and from 1 213 ms to 2.8 ms (`pq`), and the history from 27.8 MB and 137.7 MB to 11.3 MB in both suites:
  - validate once per call, then incrementally from a remembered tip;
  - give the adapter a `checkpoint` that returns only the head;
  - bind the envelope by digest in the kernel.

  The order matters, and it is not the order the testbed proposed. Incremental validation alone only halves the cost. The head-only `checkpoint` is the change that removes the quadratic read.
- **Not viable as proposed.** Events cannot carry only a snapshot hash. The C-37 trace export, C-32 recovery and the lab summary all read per-event snapshots. The viable format is a delta plus a state hash (stage 4).
- **Tamper detection.** The kernel's own check uses only SHA-256 with no key, so whoever can write `authority.sqlite` can rewrite the chain consistently. The only external anchor is the `kernel_event_hash` inside each APF-signed release certificate (C-14), and no code compares it with the history today. The profile also excludes compromise of the authority store. Per-request full revalidation therefore detects only corruption that was not re-chained, made while the process runs. The proposal keeps full validation at `open` and checks the tip on every request. The only change is *when* such corruption of an older, already validated event is detected.

## 2. Symptom (testbed E5)

From `agent-trust-testbed/docs/experiments/E5-scale.md` (local backend, `--release` binaries, attctl's default):

| Measure | classical | `pq` |
|---|---|---|
| APF time per request, history ≤ 48 / 192 / 336 / 481 events | 7 / 183 / 538 / 1 058 ms | — |
| APF time per request, history ≤ 335 events (median, 2026-10-25) | 716 ms | 1 576 ms |
| Clean rounds 1 → 4 | 3.9 → 14.2 → 30.8 → 51.6 s | 6.4 → 27.1 → 63.0 → 112.9 s |
| Kernel history file at the end | 31 MB | 143 MB (stopped at D3) |
| Result | PASS | FAIL: parallel sends pass the 60 s client timeout |

Between 192 and 481 events the exponent is `log(1058/183) / log(481/192) ≈ 1.9`. Round durations grow like `k²` for round `k` (3.1, 10.6, 24.3, 43.1 s against `k²·3.1` = 3.1, 12.4, 27.9, 49.6 s). History grows linearly per round, so this is what a per-request cost of `O(n²)` predicts. Summed over a run, the cost is `O(n³)`.

## 3. Mechanism

### 3.1 Storage: one full snapshot per event

`Authority::save` (`src/authority.rs:1082-1121`) writes, for every state change:

- a row in `authority_events` whose `event` is `{"kind": kind, "snapshot": <the whole State>}`, hash-chained by `SHA-256({sequence, previous, event})`;
- the same state again into `authority_meta['state']`.

`State` (`src/authority.rs:19-39`) holds `operations`, `consumed` and `invocations`, and none of them is ever pruned. Each `Operation` keeps `envelope: Option<String>`, the full envelope in hex (two characters per byte; `MAX_ENVELOPE` = 2 MiB of bytes, `src/authority.rs:12`), set by `persist` (`src/authority.rs:742`). With `m(k)` messages and `c(k)` consumptions after event `k`, the snapshot size is

```
S(k) ≈ S₀ + m(k)·(r + 2·e) + c(k)·q
```

where `r` is the size of an operation record without the envelope, `e` the envelope size in bytes, and `q` the size of a consumption record. In E5 each message adds 10 events (allocate, release, persist and 7 consumes), so `m(k) ≈ k/10` and `S(k)` is linear in `k`. The history `H(n) = Σₖ S(k)` is quadratic. The envelope term dominates: classical `2e ≈ 1 476` characters, `pq` `2e ≈ 10 900` characters.

### 3.2 Reads: whole-history passes per request

`validate_history` (`src/authority.rs:1123-1167`) selects every event, parses its JSON, re-serializes it into `HashInput`, hashes it, checks the chain, and finally compares the last snapshot with the state row. That is one pass over `H(n)`, with a JSON parse and a serialization of every byte. It runs from:

| Caller | Location | When |
|---|---|---|
| `Authority::open` | `src/authority.rs:118` | once per handle |
| `load()` via `expire()` | `src/authority.rs:171` | every `grant, delegate, revoke, admit, invoke, release, consume, rekey` with `now` (R-12, `e774ba2`) |
| `load()` via `execute_inner` | `src/authority.rs:264` | every command except `init`, `checkpoint` included |

`checkpoint()` (`src/authority.rs:1034-1065`) then makes a second pass: it reads and parses every event again and builds the whole history, every snapshot included, as one JSON `Value`.

For one mutating request, the adapter adds:

| Adapter call | Location | Kernel passes |
|---|---|---|
| C-31 intent revision (`kernel_checkpoint()["revision"]`) | `src/adapter.rs:644` | validate + full checkpoint = 2 |
| The command itself | `src/adapter.rs:695` | validate in `expire` + validate in `execute_inner` = 2 (1 for `allocate`, `persist`, `abandon`) |
| Canonical ack (commits) | `src/adapter.rs:818` | +2 |
| `issue_certificate` | `src/adapter.rs:1948`, `1955` | `subject_status` 1 + checkpoint 2 |
| `subject_known` (grants) | `src/adapter.rs:1069` | +2 |
| `frontier()` | `src/adapter.rs:1920` | +2 |
| Repair plan, `confirm_repair`, rekey | `src/adapter.rs:2758`, `2802`, `2825`, `2957`, `3265` | +2 each |
| C-32 recovery, per intent | `src/adapter.rs:3756` | +2 (reads the history: needed) |

So a `release` or `consume` costs about 4 passes over `H(n)` and an `allocate` or `persist` about 3. Of all these readers, only C-32 recovery, `release_response` (`src/adapter.rs:3721`) and the lab's `summary` (`src/lab.rs:825`) use `history`. Every other caller reads head fields: `revision`, `policy_revision`, `policy_digest`, `epoch`, `branch`, `roster`, `grants`, `read_fenced`, `repair_pending`.

### 3.3 Why it becomes a liveness failure

The APF holds one lock around the adapter, so requests from the eight agents queue behind each other. A round sends 8 messages and so makes about 80 mutating requests. At 1 s each in `pq`, a round takes minutes, and a send that waits behind the round's other requests passes the client's 60 s timeout. Safety holds throughout: every check still runs, just slowly. This is the "liveness only" failure that the testbed observed.

### 3.4 Why `pq` is about twice as steep

The kernel stores the envelope bytes. A `pq` envelope carries two ML-DSA-44 signatures of 2 420 bytes each (the release certificate and the MLS message signature): median 5 450 bytes against 738. Every later snapshot repeats it in hex. In the benchmark this gives a history 4.95 times larger at the same event count (137.7 MB against 27.8 MB). Time grows less than the bytes do, by about 1.6 times, because part of each pass is per-event and per-field overhead, not raw bytes. The rest of the testbed's `pq` gap is ML-DSA signing and verification, MLS and the adapter store, which the kernel benchmark does not include (§5).

## 4. Origin

| Commit | What it added | Effect on F-8 |
|---|---|---|
| `542b326` (2026-09-15, restores the 2026-09-13 kernel) | Snapshot per event; `load()` validates the whole chain; a full-history `checkpoint` | The quadratic base. `docs/authority-contract.md:13` and `:18`: "Persist one logical state plus append-only hash-chained event records if that is simplest"; "persistence replay validates chain before use". `evidence/authority-impl-report.md:3`: "Every request reloads and validates committed state … each event embeds the post-transition snapshot, so replay binds the current snapshot to the durable history." |
| `faea9db` (phase 4.0, R-6) | Raises the envelope bound from 256 characters (the shared identifier bound, `docs/authority-contract.md:79`) to 2 MiB (`MAX_ENVELOPE`). Envelopes had been in the kernel state since `542b326`. | The dominant constant. The contract already noted the cost (`docs/authority-contract.md:81`): "Large envelopes therefore grow the history roughly quadratically. Phase 4.3 should keep exact envelope bytes in the adapter store and give the kernel only bounded data." Phase 4.3 never did this. Before R-6, a `pq` envelope would have been refused outright. |
| `bd0efef` (phase 4.5, C-31, C-32) | A full `checkpoint` before every mutation, to record the intent's revision | 2 extra passes per request |
| `e774ba2` (R-12, D-16) | `expire()` loads the state before the step | 1 extra validation per mutating command with `now` |
| C-42 (F-9, D-13) | ML-DSA-44 everywhere | Envelopes about 7 times larger, history about 5 times larger |

Why no test saw it: kernel and adapter tests run histories of tens of events, and the cost is invisible below about 100 events (8 ms in the benchmark at 82). The design is sound for the profile it was built for: a trusted, single-node correctness kernel. The cost only shows under a workload that the profile did not size.

## 5. Measurements

### 5.1 Method

The benchmark is a standalone crate that compiles a verbatim copy of `src/authority.rs` (`e774ba2`) next to a patched copy, using the same `rusqlite`, `serde_json` and `sha2` versions. Nothing in this repository changed. The workload matches E5's message flow:

- `init`;
- 7 readers each granted `read` and `admit`, then admitted (22 events: 1 + 7 × 3);
- then messages, each made of `allocate`, `release` (cover: the root writer and 8 readers), `persist` (envelope of `e` bytes) and 7 `consume`s.

`adapter` mode issues one `checkpoint` before each mutation, as C-31 does. In both modes, `release` first reads a full checkpoint for its frontier. The testbed no longer does this: its APF view reads the state row instead (`att-node/src/apf.rs:309`). So even the "kernel only" figures include one full checkpoint per 10 requests, an artifact of the bench. The value is the mean time per mutating request over each window of 60 events, in release mode on the development host. These are kernel-only floors: no MLS, no signatures and no adapter store.

Sources, the prototype patch and the recorded runs are in `evidence/f8-bench/`, whose README gives the build and run commands:

```bash
F8_LAYERS=<layers> f8bench <base|fix> adapter <envelope bytes> 48
```

Layers in the patched copy:

- **a**: validate once per `execute`, at the start of the transaction;
- **b**: validate incrementally from the last validated `(sequence, hash)`;
- **c**: `checkpoint` with `"history":"none"` returns the head only;
- **d**: `persist` stores `SHA-256(envelope)` instead of the envelope.

### 5.2 Baseline reproduces the testbed

| Events | History, classical | History, `pq` | ms/request classical (kernel* / with C-31 checkpoint) | ms/request `pq` (kernel* / with C-31 checkpoint) |
|---|---|---|---|---|
| 82 | 0.6 MB | 2.4 MB | 3.8 / 8.0 | 5.4 / 10.6 |
| 202 | 4.2 MB | 20.0 MB | 37 / 83 | 66 / 137 |
| 322 | 11.1 MB | 54.4 MB | 110 / 242 | 198 / 409 |
| 502 | 27.8 MB | 137.7 MB | 285 / 744 | 528 / 1 213 |

\* includes the release frontier checkpoint (§5.1).

The testbed reports 31 MB (classical) and 143 MB (`pq`) at the end of E5 (about 480 to 500 events). The C-31 checkpoint alone more than doubles the cost of a request.

### 5.3 What each layer buys (adapter mode, ms per request, cumulative)

| Layers | 82 events | 202 | 322 | 502 | History at 502 | Growth |
|---|---|---|---|---|---|---|
| base, classical | 8.1 | 83.5 | 242 | 744 | 27.8 MB | quadratic |
| a | 6.6 | 70.0 | 202 | 613 | 27.8 MB | quadratic |
| a b | 3.2 | 32.0 | 92.9 | 331 | 27.8 MB | quadratic |
| a b c | 0.46 | 1.24 | 2.12 | 3.26 | 27.8 MB | linear |
| a b c d | 0.43 | 1.05 | 1.71 | 2.67 | 11.3 MB | linear |
| base, `pq` | 10.7 | 137 | 409 | 1 213 | 137.7 MB | quadratic |
| a, `pq` | 9.2 | 110 | 323 | 991 | 137.7 MB | quadratic |
| a b, `pq` | 3.6 | 41.1 | 125 | 447 | 137.7 MB | quadratic |
| a b c, `pq` | 0.71 | 2.61 | 4.48 | 7.14 | 137.7 MB | linear |
| a b c d, `pq` | 0.47 | 1.10 | 1.75 | 2.81 | 11.3 MB | linear |
| c only, classical | 5.2 | 52.5 | 149 | 386 | 27.8 MB | quadratic |
| a c, classical (stage 1) | 3.9 | 37.9 | 109 | 281 | 27.8 MB | quadratic |

Reading:

- **a** removes the R-12 double load: about 18 % less, still quadratic.
- **b** halves what remains. It is still quadratic, because the checkpoint reads every event.
- **c** is the decisive change: it brings the cost of one request down by two orders of magnitude, and growth becomes linear. **b** and **c** are needed together, because each removes one of the two whole-history reads.
- **c** without **b** (rows "c only" and "a c") is still quadratic: 281 ms at 502 events, the same as the kernel alone without the C-31 read (§5.2). Stage 1 alone is therefore not enough.
- **d** removes the envelope term: the history shrinks by 2.5 times in classical and by about 12 times in `pq`. With all four layers, `pq` costs the same as classical (2.81 ms against 2.67 ms, both 11.3 MB). The linear cost that remains comes from the state row: `operations` and `consumed` are serialized and compared on every request (§9).

## 6. Assessment of the testbed's proposal

The testbed proposed (`findings.md`, F-8):

1. "events carry a hash of the snapshot (or a delta) instead of the full snapshot";
2. "validate the chain fully at `open` and then incrementally";
3. "`checkpoint` gains an option to return only the last event".

| Item | Verdict | Reason |
|---|---|---|
| 1, hash only | **Not viable alone** | Four readers need past snapshots. C-37 `export_v2_trace` (`src/lab.rs:1126-1134`, `read_history` `src/lab.rs:1039`) derives each v2 event from the difference between consecutive snapshots. C-32 `recover()` (`src/adapter.rs:3756-3770`) reads each later event's `snapshot.revision`. `release_response` (`src/adapter.rs:3721`) reads the last event's `snapshot.operations`. The lab `summary` (`src/lab.rs:825`) reads the last snapshot's `consumed`. |
| 1, delta | **Viable** | It must carry a state hash so that the state row stays bound to the chain. The export rebuilds snapshots by applying the deltas. This is stage 4 below. |
| 2 | **Right, but not enough alone** | Measured: 2× (§5.3, row a b). |
| 3 | **Right idea, wrong shape** | Most readers need the head, not the last event. Recovery needs every event *after* a revision (R-12 `expire` events can precede the step's event, C-45). The option should be `"history": "none"`, or `{"since": <sequence>}`. |

The measurements put the items in the reverse order of the list: 3 (reshaped) and 2 remove the quadratic time, and 1 (as a delta) removes the quadratic storage.

## 7. Tamper detection: what changes, and why it is acceptable

**What full revalidation per request buys today.**

- Each event hash is `SHA-256({sequence, previous, event})` (`src/authority.rs:1173`), with no key and no signature. Anyone who can write `authority.sqlite` can edit an event, recompute every later hash with the same function, and rewrite the state row to match. `validate_history`, at `open` or per request, accepts the result, because it checks only that the chain is consistent with itself.
- There is one external anchor, and nothing uses it. Since C-14, every APF-signed release certificate carries the kernel `event_hash` of its release (`src/wire.rs:627`). That hash covers the whole history up to that release. A rewrite of any earlier event changes every later hash, so it no longer matches the certificates already issued. Copies of those certificates are kept in `adapter_operations.certificate` and travel in every envelope, and nobody can sign a new one without the APF key. But no code in the adapter, the lab, the oracle or the testbed compares a held certificate's `kernel_event_hash` with the history. Events after the last release are not covered at all. And the APF key (`apf-signing-key`) sits in the same directory as `authority.sqlite`. (The "not signed" row in `docs/adapter-contract.md:28` describes commit `3e332a2`, before C-14.)
- `docs/specification.md:17` puts "rollback or compromise of the authority's own durable store" outside the profile.
- So revalidating on every request (which checks the chain against itself, not against the certificates) detects only corruption that was **not** re-chained, made **while the process runs**: a disk fault, or a naive edit of an older row.
- It does not check that a transition was legal. Each snapshot is hashed, never checked against the previous one under the kernel rules.

**What the proposal keeps.**

- **At `open`:** the full chain validation and the state-row comparison, unchanged. This is the moment the contract's "replay validates chain before use" refers to. The existing test, `checkpoint_history_is_ordered_hash_chained_and_disk_tampering_is_detected` (`tests/authority_contract.rs:553`), tampers with the store and expects `Authority::open` to fail, and it is unaffected.
- **On every request,** at the start of the transaction:
  - the stored row at the remembered tip sequence must still have the remembered hash, so truncation, a rollback of the file and a rewrite of the tip are all detected;
  - every row after the tip is validated against it, which covers appends by another handle (the multi-handle rule in `docs/authority-contract.md:13`, including the second handle opened at `src/adapter.rs:2204`);
  - the state row must equal the last snapshot (or, in stage 4, match the last state hash).
- **The tip** advances only during validation at the start of a call, over committed rows. A row that a step's `ROLLBACK TO step` removed never enters it, so the tip needs no bookkeeping for savepoints.

**What is given up.** If an event older than the tip is edited, and not re-chained, while the process runs, the edit is detected at the next `open` instead of at the next request. An adversary gains nothing: a consistent rewrite passes the kernel's check under both schemes. Only a comparison with the signed certificates catches it, and neither scheme makes one. The difference is only how soon accidental corruption is noticed.

**Optional, stronger than today.** Three additions would give stronger detection than the current per-request check. The proposal does not depend on any of them.

- At `open`, check each release certificate in `adapter_operations` against the history: its `kernel_event_hash` must be the hash of the event at that release. This uses the anchor that already exists, and it catches any rewrite of an event before the last release, unless the APF key is also compromised.

- A read-only `verify` command that runs the full validation on demand. The lab or the APF can call it periodically.
- The C-31 intent records the kernel's `history_root` together with the revision. Then the adapter store anchors the kernel tip, and a rollback of `authority.sqlite` between restarts becomes detectable at `Adapter::open`.

## 8. Proposed correction R-13 (for D-17)

Four stages, each test first (`AGENTS.md`). Each stage can be approved, and can land, separately. Stages 1 to 3 together close F-8 for the testbed's workloads. Stage 4 removes quadratic storage, so that runs far longer than E5 open quickly.

### Stage 1 (R-13a): no change to the format or to detection

1. `Authority::execute` validates once, after `BEGIN IMMEDIATE`. `expire()` and `execute_inner` use the state that was loaded. Both run in the same immediate transaction, so nothing can change between them.
2. `checkpoint` gains an optional field, `history`:
   - absent or `"all"`: today's response, unchanged; harness `test_cli.py:113` and about 10 Rust tests read `history` and `history_root`;
   - `"none"`: the head fields and `history_root`, with no `history`;
   - `{"since": <sequence>}`: only the events after that sequence.
3. The adapter uses `"none"` everywhere except C-32 recovery, which uses `since`. `release_response` reads the last event only. `Adapter::checkpoint()` (the trusted lab read) and the C-37 export are unchanged.

Expected effect: the C-31 pass and the R-12 double load disappear, but one full validation per kernel call remains. So stage 1 alone stays quadratic, with a smaller constant: measured 744 → 281 ms at 502 events (§5.3, row "a c"). Stage 2 is required to close F-8.

### Stage 2 (R-13b): incremental validation (changes when corruption is detected; §7)

This stage depends on stage 1 item 1: the single validation point at the start of the transaction. Without it, a validation inside the step would advance the tip over uncommitted rows, and §7's "no savepoint bookkeeping" would not hold. The handle remembers `(tip_sequence, tip_hash)`, set by the full validation at `open` and advanced by each validation at the start of a call. Validation checks the tip row, then validates the rows after it, then compares the state row with the last snapshot. Contract text: `docs/authority-contract.md:18` becomes "the chain is validated in full at `open`; each request validates the stored tip and every event after it before use".

### Stage 3 (R-13c): the kernel binds the envelope by digest

This is the correction that `docs/authority-contract.md:81` already scheduled.

- `Operation.envelope` becomes `envelope_digest = SHA-256(envelope bytes)`.
- `persist` and `emit` compare digests.
- The `emit` response still echoes the envelope it was given.
- The adapter already stores the exact bytes in `adapter_operations.envelope` (`src/adapter.rs:3508-3513`).
- The C-37 export takes the envelope from there, not from the snapshot (`src/lab.rs:1382`, `src/lab.rs:1671`). The v2 trace format is unchanged.
- A store from before stage 3 keeps its old operations as they are. The kernel accepts either field on read.

### Stage 4 (R-13d): delta events (a format version)

- Event format v2: `{"kind", "version": 2, "delta", "state_hash"}`, where `state_hash = SHA-256(canonical state)` and the delta is a field-level patch:
  - scalar fields that changed;
  - appended elements of `operations`, `consumed`, `invocations`, `delegations`, `grants` and `roster`;
  - elements changed in place, by index.
- Validation at `open` replays the deltas from genesis and checks every `state_hash`. Stage-1 to stage-3 stores keep their v1 events. The validator accepts a v1 prefix followed by v2 events.
- `checkpoint` with `"all"` rebuilds the snapshots for its existing response shape, so the tests and the harness stay unchanged. The C-37 export, C-32 recovery and `summary` read the rebuilt snapshots, or the deltas directly.
- Optional, later: replay can check that each delta is a legal transition under the kernel rules. That would be stronger than anything the chain checks today.

### Not in R-13: the remaining linear term

`operations` and `consumed` grow without bound. The `consume` replay check is a linear scan (`src/authority.rs:807`), and the state row is serialized on every save. After stages 1 to 3 this is the only growth left (2.7 ms per request at 502 events, linear). If runs grow by orders of magnitude, the next step is SQLite tables keyed by `op` and `(op, recipient)`, with a state row that holds only policy and the frontier.

## 9. Tests to write first (test author)

- **Stage 1:**
  - `checkpoint` with `"history":"none"` returns exactly today's head fields and `history_root`;
  - `{"since": s}` returns exactly the events after `s`;
  - a mutating command validates the chain once, which a test can observe only through a test hook that counts passes (or through the cost test below);
  - C-32 recovery with R-12 `expire` events before the step's event still decides `applied` correctly when it reads `since`.
- **Stage 2:**
  - tamper with the tip row, truncate, or replace the file with an older copy while a handle is open: the next request fails with `corrupt_history`;
  - another handle appends events: the first handle accepts them;
  - a step that fails after R-12 `expire` events (savepoint rollback) leaves a valid tip;
  - **changed behavior**, owned by the test author: an edit to a non-tip, older event while a handle is open is detected at the next `open`.
- **Stage 3:**
  - a persisted envelope is bound by digest: `persist` with other bytes gives `binding_mismatch`, and `emit` with other bytes gives `binding_mismatch`;
  - the C-37 export of a run is byte-identical before and after stage 3.
- **Cost (all stages):** a bounded-growth test. Run N messages, measure the median time per request in two windows, and assert a ratio well below the quadratic one (for example, at most 3 times when N doubles). Use counts of rows read, not wall-clock time, if CI timing noise is a concern.
- **Testbed:** E5 in the `pq` suite passes its bound (`SCALE=pq scripts/ci.sh`). The F-8 row in `findings.md` moves to Implemented.

## 10. Decision D-17 (approved 2026-10-31 by Daniel)

Asked to approve the stages, Daniel answered: "I approve but we must harden the implementation the most. Any kind of attack should be possible." The coordinator reads the last sentence as "should **not** be possible", because it comes with the call to harden. Asked which attacks the implementation must defend against, Daniel chose **"Tamper + rollback + key theft"**:

- tampering with the store by anyone without the APF key;
- rollback of the whole data directory to an older consistent copy;
- an attacker who also holds the APF key.

Consequences:

1. Stages 1 to 4 (R-13a to R-13d) are approved. They are implemented test-first, in order, one commit each.
2. The approval brings compromise and rollback of the authority's own durable store into the threat model. This changes `docs/specification.md:17`, which today puts it "outside this profile". The hardening layers and their claim boundary are specified as R-13 contract text in `docs/adapter-contract.md` §10 before stage 4, because the stage 4 event format has to carry the hardening fields (one migration, not two).
3. No implementation can make every attack impossible. One attacker defeats any check on that host: root on the APF host holding the APF key **and** every actor key. Another needs an outside witness: the APF's own clock (`now`), which nobody signs. The contract text states these residuals explicitly.

## 11. Production design (after D-17)

On 2026-10-31 Daniel added: "We must find the way to fully optimize memory growth. Your benchmarks are not promising for production use." He also rejected any design that gives up defending against APF key theft. This section supersedes stages 2 and 4 of §8. Stages 1 and 3 stay as they are.

### 11.1 Why stages 1 to 3 are not enough

After layers a to d, a request still costs time linear in the history: 2.7 ms at 502 events. Storage stays quadratic: 11.3 MB at 502 events, `c ≈ 90` bytes per event² from `H ≈ c·n²/2`. At 100 000 events this extrapolates to about 0.5 s per request, a 9 MB state copy and about 450 GB of history.

| Growth source | Today | Production fix |
|---|---|---|
| One full state copy per event | Storage quadratic | Compact events: the kernel request, its effects, and commitments. No state copy. |
| `operations`, `consumed` and `invocations` never shrink, and the whole state is loaded, serialized and compared on every request | O(n) per request and in memory | SQLite tables keyed by `op`, `(op, recipient)` and invocation id. Memory holds only the policy (roster, grants, delegations, frontier, counters), bounded by members. |
| Dead operations stay live (abandoned, fully consumed, or past the frontier: F-7 makes them unconsumable) | The live set grows with history | Garbage collection into tombstones of about 100 bytes, which keep the error codes `replay`, `binding_mismatch` and `duplicate_operation`. The log keeps the full record. |
| The adapter keeps every envelope, and `checkpoint` builds the whole history in RAM | O(n) storage and memory spikes | Envelopes of dead operations leave the hot store with the operation. Head-only `checkpoint` (stage 1). |

Target: the live set is bounded by members plus messages in flight; time per request is flat in the history length; the log grows by a constant number of bytes per event; memory use is flat. A growth test asserts these figures at 10k–100k events.

### 11.2 Integrity without re-reading the history, including against APF key theft

- **Event format v2:** `{version, kind, request, effects, cause, commitment, rules_version}`.
  - `request` is the normalized kernel request, including `now`.
  - `cause` is the SHA-256 of the actor-signed `SignedRequest` that caused the event. It is null for genesis and for R-12 `expire` events, whose cause is the step that triggered them.
  - `commitment` commits to the policy and to every live table, and is updated incrementally per row.
  - The hash chain covers each event.
- **Signed head:** the APF signs `{group, sequence, hash}` after each mutation. Only the latest signed head is stored. It is returned to the client.
- **Actor-signed anchors:**
  - Every client request carries `known_head`, the latest head the client has seen, inside the body that the actor signs. Clients therefore co-sign the history continuously.
  - The adapter refuses a request whose `known_head` is ahead of the history, or whose hash differs at that sequence (`fork_detected`). This refusal is what detects rollback and forks.
- **Checkpoints:** periodic events that commit to the full live state.
- **At `open`:**
  1. Recompute the chain from the latest checkpoint to the tip, and require that it matches at least one actor-signed `known_head` at or after the checkpoint. Any rewrite before that anchor, the checkpoint included, breaks the hash that the actors signed.
  2. Check the live tables against the checkpoint commitment.
  3. Replay every event after the checkpoint under the kernel rules: legality, the actor signature on its `cause` under the key history, and monotonic `now`.
  4. Check every stored release certificate's `kernel_event_hash`.

  The cost of `open` is O(events since the checkpoint plus the live state). It does not grow with the total history.
- **Offline:** `verify --full` replays from genesis.
- **APF key:** refused at `open` unless the file's mode is 0600 and it belongs to the user running the APF. A path override keeps the key out of the data directory.

| Attacker | Detected | When |
|---|---|---|
| Writes `authority.sqlite` or `adapter.sqlite` without the APF key | Yes | Next request (signed head and commitment) or `open` |
| Rolls back the whole data directory | Yes | First request from any client that saw a later head |
| Holds the APF key and rewrites, forges or truncates history | Yes | `open` (actor-signed anchors, actor signatures on each `cause`) or the next client request |
| Holds the APF key and moves `now` | Partly | Monotonic `now` at replay. A time witness is outside the profile. |
| Holds the APF key and the keys of the actors involved | No | Their signatures *are* those actors. A limit set by who holds the keys. |

## 12. Progress

| Stage | Commit | ms per request at 502 events (classical / `pq`, adapter mode, §5.1) | History at 502 events | Growth |
|---|---|---|---|---|
| Before R-13 | `e774ba2` | 744 / 1 213 | 27.8 / 137.7 MB | quadratic |
| R-13a + R-13c | `efc0892` | 239 / 238 | 11.6 / 11.6 MB | quadratic, and the same in both suites |
| R-13d | next | target: flat | target: constant per event | target: bounded live set |

The figures for `efc0892` are measured on the committed `src/authority.rs` (`evidence/f8-bench/`, with the committed kernel as `authority_base.rs`). The verifier passed every gate after each stage (`evidence/r13a-green.txt`, `evidence/r13c-green.txt`).
