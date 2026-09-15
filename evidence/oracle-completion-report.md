# Oracle completion report

## Scope

Implemented the independent deterministic trace oracle in `harness/oracle.py` without production-protocol imports. Test assertions and fixture constructors were not changed.

## Root causes corrected

- `consume` read `event["right"]`, although consume events do not have a right. It now evaluates the frozen released operation's right.
- A read denial of a subject outside the current roster incorrectly closed the central fence. It now records a fence and pending removal only for a roster member with an active read grant.
- Fresh `release` evaluated a stale frontier before a closed central fence. The fence now takes precedence.
- `consume` evaluated an invalid/unreleased operation before a closed central fence. The fence now takes precedence for delivery.
- Initial traces now require exactly revision `0` and epoch `0`, with booleans excluded as integers.
- Right validation first checks string type, so list/dict values cannot raise `TypeError` through set membership.
- Cover validation rejects a duplicated grant within one support and duplicate complete supports. It allows the same active authority atom in two distinct supports, as directed; all supplied atoms still require active exact-generation authorization.

## Evidence

- Initial red run: `python -m unittest -v harness.test_oracle`; output and the five errors/two failures are recorded in `evidence/oracle-resume-red.txt`.
- Final green run: `python -m unittest -v harness.test_oracle`; exit `0`, 20 tests passed. Output is in `evidence/trace-green.txt`.
- Additional inline probes exited `0`: list/dict `right` and `type` values do not raise; nonzero initial revision/epoch are malformed; a shared atom across distinct supports is accepted; a repeated atom inside one support is malformed.

## Contract clarification recorded

The wording “Duplicate supports/grants are malformed” is ambiguous about the scope of “grants.” This implementation follows the assigned clarification: duplicate grants are malformed within a support, while the same grant atom may occur in different, otherwise distinct supports.

## Repair regression completion

Repair now rejects a requested removal when that subject has a current active read grant, even if the subject remains in the pending-removal set from an earlier denial. This enforces the contract's prohibition on removing a continuing authorized reader. The reviewer regression first failed and is recorded in `evidence/oracle-repair-red.txt`; the combined 21-test green run is recorded in `evidence/oracle-repair-green.txt`.

Limitation: this subject-only fixture requires repair before a read reallow can lead to normal progress. It does not model simultaneous multiple leaf generations for one subject.
