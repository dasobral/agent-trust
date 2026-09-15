# Independent oracle review

## Result: changes requested

### Major — `repair` removes a reader who is currently authorized

`docs/trace-contract.md` requires repair to permit **no removal of continuing
authorized readers**.  `harness/oracle.py` checks that `removed` equals the
pending set, but it never verifies that each removed subject still lacks an
active read grant.

Concrete accepted trace:

1. Initialize the fixture.
2. Deny `bob#1` read, which fences the group and records Bob as pending.
3. Allow `bob#1` read at fresh generation `2`.
4. Repair at revision `2`, removing `bob#1`.

The focused probe returned `[]`, so this forbidden repair is accepted.  It
silently removes an active generation-2 reader and clears the central fence.
The existing 20-test green run does not cover this transition.

Required change: while validating `repair`, reject with `invalid_repair` if
any member in `removed` has an active current read grant.  Add a contract test
for the trace above.  If reallowing a pending reader is intended to affect the
pending-removal state, define and implement that transition explicitly; the
current behavior satisfies neither interpretation safely.

## Other review notes

The implementation otherwise matches the reviewed cover clarification: it
rejects duplicate grant atoms inside one support, accepts an atom reused across
distinct supports, and validates every supplied atom against the current
generation.  It keeps invalid post-init events from committing candidate state,
uses frozen release state for persistence/emission/consume, and has non-vacuous
success paths exercised by the recorded test run.

## Validation performed

Focused reproduction (exit `0`):

```sh
python - <<'PY'
from harness.fixtures import init_event
from harness.oracle import check_trace

events = [
    init_event(),
    {"event_id": "e-deny", "type": "deny", "subject": "bob#1", "right": "read"},
    {"event_id": "e-allow", "type": "allow", "subject": "bob#1", "right": "read", "generation": 2, "fresh_keys": True},
    {"event_id": "e-repair", "type": "repair", "parent_branch": "main", "new_branch": "repaired", "epoch": 1, "revision": 2, "removed": ["bob#1"], "update_path": True, "confirmed": True, "durable": True},
]
print(check_trace(events))
PY
```

Observed output: `[]`.
