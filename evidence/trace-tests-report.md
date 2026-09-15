# Independent trace-oracle test report

## Scope

This test suite was written solely from `AGENTS.md` and `docs/trace-contract.md`. It does not read, import, or rely on production modules. The target interface is `harness.oracle.check_trace(events)`, which must return an ordered `list` of `{"index", "code"}` dictionaries.

Owned test files:

- `harness/test_oracle.py`
- `harness/fixtures.py`
- `harness/__init__.py`

`harness/fixtures.py` also contains `permissive_check_trace`, an intentionally unsafe test-only negative-control stub. It returns `[]` for every input and is selected only by `AGENT_TRUST_ORACLE=permissive`.

## Test coverage

The 20 `unittest` methods cover:

| Area | Assertions |
| --- | --- |
| Valid non-vacuous traces | Valid write release/persist/emit/consume, byte-identical repeated emits, and valid read cover/consume. |
| Empty and invalid schema | Empty, malformed, and unknown-event traces are rejected. |
| Event identity | Duplicate event IDs yield `duplicate_event`. |
| Operations | Reallocating an operation ID yields `duplicate_operation`; abandon is idempotent but permanently prevents persist. |
| Read revocation | A read fence blocks all fresh read/write releases and delivery. A pre-cut persisted release may still emit, but its later consume is fenced. |
| Provenance | Read cover must include every roster reader. A support for a denied subject is `unsound_cover`, including a joint support when other valid alternatives are present. |
| Binding | A wrong persist digest is `binding_mismatch`; after a successful persist, a differing envelope is also `binding_mismatch`. |
| Replay | A second `(op, recipient)` consume is `replay`. |
| Crash/recovery | Crash clears readiness; consume fails `not_ready` until an exact recovery. |
| Schema/numbers | Booleans are rejected where nonnegative integer revision values are required. |
| Frontier | Recovery on an old epoch and emit on a superseded epoch/branch are `stale_frontier`. |
| Repair/reopen | Incomplete removal and missing update path are `invalid_repair`; complete repair plus recovery permits a new operation. |
| Generations/reauthorization | Reusing the denied generation is `invalid_generation`; a higher reauthorization generation can later support `admit`. |

## Negative-control execution

Command:

```sh
AGENT_TRUST_ORACLE=permissive python -m unittest -v harness.test_oracle
```

Result: **exit code 1**, 20 tests run, 17 failures, 3 passes. The full output is in `evidence/trace-red.txt` and includes the exit code.

This is an **oracle-test negative control**, not a production-code red result. The expected failures demonstrate that the assertions reject an oracle that silently accepts invalid traces. The three passing cases are the suite's valid-trace scenarios and therefore are also accepted by the deliberately permissive stub.

## Contract interpretation notes

- The contract names exact codes for the tested failures, so those are asserted. It does not prescribe whether one invalid event can produce multiple violations; tests require the named violation but allow others.
- The controlled fixture profile clarifies that a closed central read fence blocks every fresh read or write release. Write provenance remains the actor's singleton write grant; this does not reopen delivery while the fence is closed.
- The contract calls a release's digest an immutable content/context identifier but does not define separate content fields. Binding tests therefore use the defined frozen `digest` and `envelope` fields rather than inventing a payload schema.
- `admit` requires an already allowed active read generation but does not state that its own event carries a revision. The reauthorization/admission positive trace uses the prescribed fields only.
