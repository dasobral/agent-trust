"""Independent contract tests for trace contract version 2 (R-5).

The normative text is ``docs/trace-contract.md``, section "version 2".
Run with: python3 -m unittest -v harness.test_oracle_v2

Broken-control tests end each trace at the rejected event and compare the
complete violation list, so the accepted prefix is also pinned as clean.
"""

from __future__ import annotations

import unittest

from harness.oracle import check_trace


# ---------------------------------------------------------------------------
# Version 2 event constructors
# ---------------------------------------------------------------------------

def grant(subject, right, generation=0):
    return {"subject": subject, "right": right, "generation": generation}


def v2_init(roster=("alice#1", "bob#1"), event_id="v2-init"):
    """Alice is the root; Bob is a writer; Carol, Dave and Erin are candidates."""
    roster = list(roster)
    grants = [
        grant("alice#1", "read"), grant("alice#1", "write"),
        grant("alice#1", "admin"), grant("alice#1", "admit"),
        grant("bob#1", "read"), grant("bob#1", "write"),
        grant("carol#1", "read"), grant("carol#1", "admit"),
        grant("dave#1", "read"), grant("dave#1", "admit"),
        grant("erin#1", "read"), grant("erin#1", "admit"),
    ]
    return {
        "event_id": event_id, "type": "init", "version": 2, "group": "group-v2",
        "policy_revision": 0, "epoch": 0, "branch": "b0", "roster": roster,
        "keys": {member: "key-" + member.split("#")[0] + "-1" for member in roster},
        "grants": grants,
    }


def admit(subject, epoch, parent, new, *, actor="alice#1", generation=0,
          key=None, key_package=None, event_id=None):
    name = subject.split("#")[0]
    return {
        "event_id": event_id or f"v2-admit-{name}-{epoch}", "type": "admit",
        "actor": actor, "subject": subject, "generation": generation,
        "parent_branch": parent, "new_branch": new, "epoch": epoch,
        "key": key or f"key-{name}-1", "key_package": key_package or f"kp-{name}-{epoch}",
    }


def recover(client, epoch, branch, event_id=None):
    return {"event_id": event_id or f"v2-recover-{client}-{epoch}", "type": "recover",
            "client": client, "epoch": epoch, "branch": branch}


def allocate(op, event_id=None):
    return {"event_id": event_id or f"v2-allocate-{op}", "type": "allocate", "op": op}


def release(op, *, actor="alice#1", right="write", policy_revision=0, epoch=0,
            branch="b0", digest=None, readers=(), writer_generation=0,
            reader_generations=None, cover=None, event_id=None):
    if cover is None:
        reader_generations = reader_generations or {}
        cover = [[grant(actor, "write", writer_generation)]]
        cover += [[grant(member, "read", reader_generations.get(member, 0))]
                  for member in readers]
    return {"event_id": event_id or f"v2-release-{op}", "type": "release", "op": op,
            "actor": actor, "right": right, "policy_revision": policy_revision,
            "epoch": epoch, "branch": branch, "digest": digest or f"digest-{op}",
            "cover": cover}


def persist(op, envelope=None, digest=None, event_id=None):
    return {"event_id": event_id or f"v2-persist-{op}", "type": "persist", "op": op,
            "envelope": envelope or f"envelope-{op}", "digest": digest or f"digest-{op}"}


def emit(op, envelope=None, event_id=None):
    return {"event_id": event_id or f"v2-emit-{op}", "type": "emit", "op": op,
            "envelope": envelope or f"envelope-{op}"}


def consume(op, recipient, event_id=None):
    return {"event_id": event_id or f"v2-consume-{op}-{recipient}", "type": "consume",
            "op": op, "recipient": recipient}


def deny(subject, right="read", event_id=None):
    return {"event_id": event_id or f"v2-deny-{subject}-{right}", "type": "deny",
            "subject": subject, "right": right}


def allow(subject, right, generation, event_id=None):
    return {"event_id": event_id or f"v2-allow-{subject}-{right}-{generation}",
            "type": "allow", "subject": subject, "right": right, "generation": generation}


def repair_stage(removed, epoch, parent, new, *, actor="alice#1", policy_revision=1,
                 event_id=None):
    return {"event_id": event_id or f"v2-stage-{new}", "type": "repair_stage",
            "actor": actor, "parent_branch": parent, "new_branch": new, "epoch": epoch,
            "policy_revision": policy_revision, "removed": list(removed)}


def confirm(actor, branch, hash_value, event_id=None):
    return {"event_id": event_id or f"v2-confirm-{actor}-{branch}-{hash_value}",
            "type": "confirm", "actor": actor, "branch": branch, "hash": hash_value}


def repair_open(branch, evidence, event_id=None):
    return {"event_id": event_id or f"v2-open-{branch}-{evidence}", "type": "repair_open",
            "branch": branch, "evidence": evidence}


def rekey(subject, right, generation, epoch, parent, new, new_key, *, actor="alice#1",
          event_id=None):
    return {"event_id": event_id or f"v2-rekey-{subject}-{right}-{epoch}", "type": "rekey",
            "actor": actor, "subject": subject, "right": right, "generation": generation,
            "parent_branch": parent, "new_branch": new, "epoch": epoch, "new_key": new_key}


def v(index, code):
    return {"index": index, "code": code}


def admitted_four():
    """Genesis plus two real admissions: roster alice, bob, carol, dave at (2, b2)."""
    return [
        v2_init(),
        admit("carol#1", 1, "b0", "b1"),
        admit("dave#1", 2, "b1", "b2"),
    ]


def end_to_end_trace():
    four = ["alice#1", "bob#1", "carol#1", "dave#1"]
    three = ["alice#1", "bob#1", "carol#1"]
    return admitted_four() + [
        *[recover(member, 2, "b2") for member in four],                       # 3-6
        allocate("op-1"),                                                     # 7
        release("op-1", epoch=2, branch="b2", readers=four),                  # 8
        persist("op-1"),                                                      # 9
        emit("op-1"),                                                         # 10
        consume("op-1", "bob#1"),                                             # 11
        deny("dave#1"),                                                       # 12
        repair_stage(["dave#1"], 3, "b2", "b3", policy_revision=1),           # 13
        confirm("alice#1", "b3", "auth-b3"),                                  # 14
        confirm("bob#1", "b3", "auth-b3"),                                    # 15
        repair_open("b3", "pair"),                                            # 16
        *[recover(member, 3, "b3") for member in three],                      # 17-19
        allocate("op-2"),                                                     # 20
        release("op-2", policy_revision=1, epoch=3, branch="b3", readers=three),  # 21
        persist("op-2"),                                                      # 22
        emit("op-2"),                                                         # 23
        consume("op-2", "carol#1"),                                           # 24
        deny("bob#1", "write"),                                               # 25 policy 2
        rekey("bob#1", "write", 1, 4, "b3", "b4", "key-bob-2"),               # 26 policy 3
        recover("alice#1", 4, "b4"),                                          # 27
        recover("bob#1", 4, "b4"),                                            # 28
        allocate("op-3"),                                                     # 29
        release("op-3", actor="bob#1", policy_revision=3, epoch=4, branch="b4",
                readers=three, writer_generation=1),                          # 30
        persist("op-3"),                                                      # 31
        emit("op-3"),                                                         # 32
        consume("op-3", "alice#1"),                                           # 33
    ]


class OracleV2Base(unittest.TestCase):
    maxDiff = None

    def violations(self, events):
        answer = check_trace(events)
        self.assertIsInstance(answer, list)
        for item in answer:
            self.assertIsInstance(item, dict)
            self.assertEqual(set(item), {"index", "code"})
            self.assertIs(type(item["index"]), int)
            self.assertIsInstance(item["code"], str)
        return answer

    def assert_exact(self, events, expected):
        self.assertEqual(self.violations(events), expected)


# ---------------------------------------------------------------------------
# Good version 2 traces
# ---------------------------------------------------------------------------

class GoodV2TraceTests(OracleV2Base):
    def test_v2_init_alone_is_clean(self):
        self.assert_exact([v2_init()], [])

    def test_end_to_end_admit_release_repair_confirm_open_rekey_is_clean(self):
        self.assert_exact(end_to_end_trace(), [])

    def test_stacked_repair_confirms_only_latest_branch_and_reopens(self):
        events = admitted_four() + [
            deny("bob#1"),                                                   # 3 policy 1
            repair_stage(["bob#1"], 3, "b2", "b3", policy_revision=1),       # 4
            confirm("carol#1", "b3", "auth-b3"),                             # 5
            deny("dave#1"),                                                  # 6 policy 2
            repair_stage(["dave#1"], 4, "b3", "b4", policy_revision=2),      # 7 stacked
            confirm("carol#1", "b4", "auth-b4"),                             # 8 non-committer first
            confirm("alice#1", "b4", "auth-b4"),                             # 9
            repair_open("b4", "pair"),                                       # 10
            recover("alice#1", 4, "b4"),
            recover("carol#1", 4, "b4"),
            allocate("op-1"),
            release("op-1", policy_revision=2, epoch=4, branch="b4",
                    readers=["alice#1", "carol#1"]),
            persist("op-1"),
            emit("op-1"),
            consume("op-1", "carol#1"),
        ]
        self.assert_exact(events, [])

    def test_single_continuing_member_opens_with_single_evidence(self):
        events = [v2_init(), deny("bob#1"),
                  repair_stage(["bob#1"], 1, "b0", "b1", policy_revision=1),
                  confirm("alice#1", "b1", "auth-b1"),
                  repair_open("b1", "single")]
        self.assert_exact(events, [])

    def test_identical_confirmation_resend_is_idempotent(self):
        events = admitted_four()[:2] + [
            deny("carol#1"),
            repair_stage(["carol#1"], 2, "b1", "b2", policy_revision=1),
            confirm("alice#1", "b2", "auth-b2"),
            confirm("alice#1", "b2", "auth-b2", event_id="v2-confirm-resend"),
            confirm("bob#1", "b2", "auth-b2"),
            repair_open("b2", "pair"),
        ]
        self.assert_exact(events, [])

    def test_removed_reader_rejoins_with_new_generation_same_key_and_fresh_key_package(self):
        events = [v2_init(), deny("bob#1"),
                  repair_stage(["bob#1"], 1, "b0", "b1", policy_revision=1),
                  confirm("alice#1", "b1", "auth-b1"),
                  repair_open("b1", "single"),
                  allow("bob#1", "read", 1),                               # policy 2
                  allow("bob#1", "admit", 0),                              # policy 3
                  admit("bob#1", 2, "b1", "b2", generation=1, key="key-bob-1",
                        key_package="kp-bob-rejoin")]
        self.assert_exact(events, [])


# ---------------------------------------------------------------------------
# Broken controls (exact code and index)
# ---------------------------------------------------------------------------

class BrokenControlV2Tests(OracleV2Base):
    def test_fresh_release_after_read_denial_is_read_fenced(self):
        events = [v2_init(), deny("bob#1"), allocate("op-1"),
                  release("op-1", policy_revision=1, readers=["alice#1", "bob#1"])]
        self.assert_exact(events, [v(3, "read_fenced")])

    def test_fresh_release_after_actor_write_denial_is_unauthorized(self):
        events = [v2_init(), deny("alice#1", "write"), allocate("op-1"),
                  release("op-1", policy_revision=1, readers=["alice#1", "bob#1"])]
        self.assert_exact(events, [v(3, "unauthorized_release")])

    def test_release_at_policy_revision_before_denial_is_stale(self):
        events = [v2_init(), deny("carol#1", "admit"), allocate("op-1"),
                  release("op-1", policy_revision=0, readers=["alice#1", "bob#1"])]
        self.assert_exact(events, [v(3, "stale_frontier")])

    def test_api_only_removal_repair_open_without_staged_repair_is_rejected(self):
        events = [v2_init(), deny("bob#1"), repair_open("b0", "single")]
        self.assert_exact(events, [v(2, "invalid_repair")])
        still_fenced = events + [allocate("op-1"),
                                 release("op-1", policy_revision=1, readers=["alice#1"])]
        self.assert_exact(still_fenced, [v(2, "invalid_repair"), v(4, "read_fenced")])

    def test_repair_omitting_a_revoked_reader_is_rejected(self):
        events = admitted_four() + [deny("bob#1"), deny("carol#1"),
                                    repair_stage(["bob#1"], 3, "b2", "b3", policy_revision=2)]
        self.assert_exact(events, [v(5, "invalid_repair")])

    def test_repair_removing_a_continuing_reader_is_rejected(self):
        events = admitted_four() + [deny("bob#1"),
                                    repair_stage(["bob#1", "carol#1"], 3, "b2", "b3")]
        self.assert_exact(events, [v(4, "invalid_repair")])

    def test_re_encryption_under_one_operation_is_binding_mismatch(self):
        events = [v2_init(), allocate("op-1"), release("op-1", readers=["alice#1", "bob#1"]),
                  persist("op-1", envelope="envelope-a"),
                  persist("op-1", envelope="envelope-b", event_id="v2-persist-again")]
        self.assert_exact(events, [v(4, "binding_mismatch")])

    def test_spent_cell_replay_is_rejected(self):
        events = [v2_init(), allocate("op-1"), release("op-1", readers=["alice#1", "bob#1"]),
                  persist("op-1"), emit("op-1"), consume("op-1", "bob#1"),
                  consume("op-1", "bob#1", event_id="v2-consume-again")]
        self.assert_exact(events, [v(6, "replay")])

    def test_reopening_without_any_confirmation_is_unconfirmed(self):
        events = [v2_init(), deny("bob#1"),
                  repair_stage(["bob#1"], 1, "b0", "b1", policy_revision=1),
                  repair_open("b1", "single")]
        self.assert_exact(events, [v(3, "unconfirmed")])

    def test_reopening_with_committer_confirmation_only_is_unconfirmed(self):
        events = admitted_four() + [deny("dave#1"),
                                    repair_stage(["dave#1"], 3, "b2", "b3"),
                                    confirm("alice#1", "b3", "auth-b3"),
                                    repair_open("b3", "pair")]
        self.assert_exact(events, [v(6, "unconfirmed")])

    def test_reopening_with_non_committer_confirmation_only_is_unconfirmed(self):
        events = admitted_four() + [deny("dave#1"),
                                    repair_stage(["dave#1"], 3, "b2", "b3"),
                                    confirm("bob#1", "b3", "auth-b3"),
                                    confirm("carol#1", "b3", "auth-b3"),
                                    repair_open("b3", "pair")]
        self.assert_exact(events, [v(7, "unconfirmed")])

    def test_single_evidence_with_two_continuing_members_is_unconfirmed(self):
        events = admitted_four()[:2] + [deny("carol#1"),
                                        repair_stage(["carol#1"], 2, "b1", "b2"),
                                        confirm("alice#1", "b2", "auth-b2"),
                                        repair_open("b2", "single")]
        self.assert_exact(events, [v(5, "unconfirmed")])

    def test_mismatched_confirmation_hash_is_binding_mismatch(self):
        events = admitted_four()[:2] + [deny("carol#1"),
                                        repair_stage(["carol#1"], 2, "b1", "b2"),
                                        confirm("alice#1", "b2", "auth-b2"),
                                        confirm("bob#1", "b2", "auth-other")]
        self.assert_exact(events, [v(5, "binding_mismatch")])

    def test_opening_on_superseded_branch_confirmations_is_unconfirmed(self):
        events = admitted_four() + [
            deny("bob#1"),                                                   # 3
            repair_stage(["bob#1"], 3, "b2", "b3", policy_revision=1),       # 4
            confirm("alice#1", "b3", "auth-b3"),                             # 5
            confirm("carol#1", "b3", "auth-b3"),                             # 6
            deny("dave#1"),                                                  # 7
            repair_stage(["dave#1"], 4, "b3", "b4", policy_revision=2),      # 8
            repair_open("b4", "pair"),                                       # 9
        ]
        self.assert_exact(events, [v(9, "unconfirmed")])

    def test_confirming_or_opening_a_superseded_branch_is_invalid_repair(self):
        prefix = admitted_four() + [
            deny("bob#1"),
            repair_stage(["bob#1"], 3, "b2", "b3", policy_revision=1),
            deny("dave#1"),
            repair_stage(["dave#1"], 4, "b3", "b4", policy_revision=2),
        ]
        self.assert_exact(prefix + [confirm("alice#1", "b3", "auth-b3")],
                          [v(7, "invalid_repair")])
        self.assert_exact(prefix + [repair_open("b3", "pair")], [v(7, "invalid_repair")])

    def test_stacked_repair_without_new_removals_is_invalid_repair(self):
        events = admitted_four() + [deny("bob#1"),
                                    repair_stage(["bob#1"], 3, "b2", "b3"),
                                    repair_stage([], 4, "b3", "b4")]
        self.assert_exact(events, [v(5, "invalid_repair")])

    def test_rekey_reusing_the_subjects_current_key_is_stale_key(self):
        events = [v2_init(), deny("bob#1", "write"),
                  rekey("bob#1", "write", 1, 1, "b0", "b1", "key-bob-1")]
        self.assert_exact(events, [v(2, "stale_key")])

    def test_rekey_reusing_another_subjects_key_is_stale_key(self):
        events = [v2_init(), deny("bob#1", "write"),
                  rekey("bob#1", "write", 1, 1, "b0", "b1", "key-alice-1")]
        self.assert_exact(events, [v(2, "stale_key")])

    def test_rekey_reusing_a_retired_key_is_stale_key(self):
        events = [v2_init(), deny("bob#1", "write"),
                  rekey("bob#1", "write", 1, 1, "b0", "b1", "key-bob-2"),
                  deny("bob#1", "write", event_id="v2-deny-bob-write-again"),
                  rekey("bob#1", "write", 2, 2, "b1", "b2", "key-bob-1")]
        self.assert_exact(events, [v(4, "stale_key")])

    def test_admission_reusing_a_key_package_is_stale_key(self):
        events = [v2_init(), admit("carol#1", 1, "b0", "b1", key_package="kp-shared"),
                  admit("dave#1", 2, "b1", "b2", key_package="kp-shared")]
        self.assert_exact(events, [v(2, "stale_key")])

    def test_admission_with_another_subjects_key_is_stale_key(self):
        events = [v2_init(), admit("carol#1", 1, "b0", "b1", key="key-bob-1")]
        self.assert_exact(events, [v(1, "stale_key")])

    def test_admission_without_epoch_advance_is_stale_frontier(self):
        events = [v2_init(), admit("carol#1", 0, "b0", "b1")]
        self.assert_exact(events, [v(1, "stale_frontier")])

    def test_admission_on_a_superseded_parent_is_stale_frontier(self):
        events = [v2_init(), admit("carol#1", 1, "b0", "b1"),
                  admit("dave#1", 2, "b0", "b2")]
        self.assert_exact(events, [v(2, "stale_frontier")])

    def test_admission_reusing_a_seen_branch_is_invalid_transition(self):
        events = [v2_init(), admit("carol#1", 1, "b0", "b1"),
                  admit("dave#1", 2, "b1", "b0")]
        self.assert_exact(events, [v(2, "invalid_transition")])

    def test_admission_while_fenced_is_read_fenced(self):
        events = [v2_init(), deny("bob#1"), admit("carol#1", 1, "b0", "b1")]
        self.assert_exact(events, [v(2, "read_fenced")])

    def test_admission_by_non_admin_is_unauthorized(self):
        events = [v2_init(), admit("carol#1", 1, "b0", "b1", actor="bob#1")]
        self.assert_exact(events, [v(1, "unauthorized")])

    def test_admission_with_stale_read_generation_is_invalid_generation(self):
        events = [v2_init(), admit("carol#1", 1, "b0", "b1", generation=1)]
        self.assert_exact(events, [v(1, "invalid_generation")])

    def test_rekey_while_fenced_or_repair_pending_is_read_fenced(self):
        fenced = [v2_init(roster=("alice#1", "bob#1")), admit("carol#1", 1, "b0", "b1"),
                  deny("carol#1"), deny("bob#1", "write"),
                  rekey("bob#1", "write", 1, 2, "b1", "b2", "key-bob-2")]
        self.assert_exact(fenced, [v(4, "read_fenced")])
        pending = fenced[:3] + [repair_stage(["carol#1"], 2, "b1", "b2"),
                                deny("bob#1", "write"),
                                rekey("bob#1", "write", 1, 3, "b2", "b3", "key-bob-2")]
        self.assert_exact(pending, [v(5, "read_fenced")])

    def test_rekey_with_wrong_generation_or_read_right_is_rejected(self):
        events = [v2_init(), deny("bob#1", "write"),
                  rekey("bob#1", "write", 2, 1, "b0", "b1", "key-bob-2")]
        self.assert_exact(events, [v(2, "invalid_generation")])
        read = [v2_init(), rekey("bob#1", "read", 1, 1, "b0", "b1", "key-bob-2")]
        self.assert_exact(read, [v(1, "malformed")])

    def test_consume_of_release_from_before_rekey_frontier_is_stale(self):
        events = [v2_init(), allocate("op-1"),
                  release("op-1", actor="bob#1", readers=["alice#1", "bob#1"]),
                  persist("op-1"), deny("bob#1", "write"),
                  rekey("bob#1", "write", 1, 1, "b0", "b1", "key-bob-2"),
                  recover("alice#1", 1, "b1"), consume("op-1", "alice#1")]
        self.assert_exact(events, [v(7, "stale_frontier")])

    def test_v2_release_requires_writer_and_every_reader_singleton(self):
        missing_reader = [v2_init(), allocate("op-1"), release("op-1", readers=["alice#1"])]
        self.assert_exact(missing_reader, [v(2, "unsound_cover")])
        read_without_writer = [v2_init(), allocate("op-1"),
                               release("op-1", right="read", cover=[
                                   [grant("alice#1", "read")], [grant("bob#1", "read")]])]
        self.assert_exact(read_without_writer, [v(2, "unsound_cover")])
        extra = [v2_init(), allocate("op-1"),
                 release("op-1", readers=["alice#1", "bob#1", "carol#1"])]
        self.assert_exact(extra, [v(2, "unsound_cover")])

    def test_release_and_consume_during_pending_repair_are_read_fenced(self):
        events = [v2_init(), allocate("op-1"), release("op-1", readers=["alice#1", "bob#1"]),
                  persist("op-1"), deny("bob#1"),
                  repair_stage(["bob#1"], 1, "b0", "b1"),
                  recover("alice#1", 1, "b1"), consume("op-1", "alice#1"),
                  allocate("op-2"),
                  release("op-2", policy_revision=1, epoch=1, branch="b1", readers=["alice#1"])]
        self.assert_exact(events, [v(7, "read_fenced"), v(9, "read_fenced")])


# ---------------------------------------------------------------------------
# Version 2 schema
# ---------------------------------------------------------------------------

class SchemaV2Tests(OracleV2Base):
    def test_invalid_version_values_are_malformed(self):
        for value in (1, 3, "2", True, None):
            with self.subTest(version=value):
                bad = v2_init()
                bad["version"] = value
                self.assert_exact([bad], [v(0, "malformed"), v(1, "not_initialized")])

    def test_v2_init_requires_keys_for_exactly_the_roster(self):
        missing = v2_init()
        del missing["keys"]["bob#1"]
        self.assert_exact([missing], [v(0, "malformed"), v(1, "not_initialized")])
        shared = v2_init()
        shared["keys"]["bob#1"] = shared["keys"]["alice#1"]
        self.assert_exact([shared], [v(0, "malformed"), v(1, "not_initialized")])

    def test_v2_init_with_v1_revision_field_is_malformed(self):
        bad = v2_init()
        bad["revision"] = 0
        self.assert_exact([bad], [v(0, "malformed"), v(1, "not_initialized")])

    def test_v1_boolean_repair_is_malformed_in_v2(self):
        events = [v2_init(), deny("bob#1"),
                  {"event_id": "v2-legacy-repair", "type": "repair", "parent_branch": "b0",
                   "new_branch": "b1", "epoch": 1, "revision": 1, "removed": ["bob#1"],
                   "update_path": True, "confirmed": True, "durable": True}]
        self.assert_exact(events, [v(2, "malformed")])

    def test_evidence_booleans_and_legacy_fields_are_malformed_in_v2(self):
        with_revision = release("op-1", readers=["alice#1", "bob#1"])
        with_revision["revision"] = 0
        self.assert_exact([v2_init(), allocate("op-1"), with_revision], [v(2, "malformed")])
        boolean_admit = admit("carol#1", 1, "b0", "b1")
        boolean_admit["fresh_keys"] = True
        self.assert_exact([v2_init(), boolean_admit], [v(1, "malformed")])
        boolean_open = repair_open("b1", "pair")
        boolean_open["confirmed"] = True
        events = [v2_init(), deny("bob#1"), repair_stage(["bob#1"], 1, "b0", "b1"),
                  confirm("alice#1", "b1", "auth-b1"), boolean_open]
        self.assert_exact(events, [v(4, "malformed")])
        boolean_allow = allow("carol#1", "write", 0)
        boolean_allow["fresh_keys"] = True
        self.assert_exact([v2_init(), boolean_allow], [v(1, "malformed")])

    def test_unknown_evidence_label_is_malformed(self):
        events = [v2_init(), deny("bob#1"), repair_stage(["bob#1"], 1, "b0", "b1"),
                  confirm("alice#1", "b1", "auth-b1"), repair_open("b1", "trusted")]
        self.assert_exact(events, [v(4, "malformed")])

    def test_allow_to_current_member_is_invalid_transition(self):
        events = [v2_init(), deny("bob#1", "write"), allow("bob#1", "write", 1)]
        self.assert_exact(events, [v(2, "invalid_transition")])


# ---------------------------------------------------------------------------
# Version 1 traces keep their version 1 results
# ---------------------------------------------------------------------------

def v1_init():
    return {
        "event_id": "e-init", "type": "init", "group": "group-1", "revision": 0,
        "epoch": 0, "branch": "main", "roster": ["alice#1", "bob#1"],
        "grants": [
            {"subject": "alice#1", "right": "read", "generation": 1},
            {"subject": "bob#1", "right": "read", "generation": 1},
            {"subject": "alice#1", "right": "write", "generation": 1},
            {"subject": "alice#1", "right": "admin", "generation": 1},
            {"subject": "carol#1", "right": "read", "generation": 1},
        ],
    }


def v1_release(op="op-1", *, revision=0, epoch=0, branch="main", digest="digest-1",
               event_id="e-release"):
    return {"event_id": event_id, "type": "release", "op": op, "actor": "alice#1",
            "right": "write", "revision": revision, "epoch": epoch, "branch": branch,
            "digest": digest,
            "cover": [[{"subject": "alice#1", "right": "write", "generation": 1}]]}


V1_ALLOC = {"event_id": "e-allocate", "type": "allocate", "op": "op-1"}
V1_PERSIST = {"event_id": "e-persist", "type": "persist", "op": "op-1",
              "envelope": "bytes-1", "digest": "digest-1"}
V1_EMIT = {"event_id": "e-emit", "type": "emit", "op": "op-1", "envelope": "bytes-1"}
V1_CONSUME = {"event_id": "e-consume", "type": "consume", "op": "op-1", "recipient": "bob#1"}
V1_DENY = {"event_id": "e-deny", "type": "deny", "subject": "bob#1", "right": "read"}
V1_REPAIR = {"event_id": "e-repair", "type": "repair", "parent_branch": "main",
             "new_branch": "repaired", "epoch": 1, "revision": 1, "removed": ["bob#1"],
             "update_path": True, "confirmed": True, "durable": True}


class VersionOneRegressionTests(OracleV2Base):
    def test_v1_good_write_trace_stays_clean(self):
        self.assert_exact([v1_init(), V1_ALLOC, v1_release(), V1_PERSIST, V1_EMIT,
                           V1_CONSUME], [])

    def test_v1_read_deny_fence_results_are_unchanged(self):
        events = [v1_init(), V1_DENY, V1_ALLOC, v1_release(), V1_PERSIST, V1_EMIT, V1_CONSUME]
        self.assert_exact(events, [v(3, "read_fenced"), v(4, "invalid_transition"),
                                   v(5, "read_fenced"), v(6, "read_fenced")])

    def test_v1_boolean_repair_and_abstract_admit_stay_valid(self):
        admission = {"event_id": "e-admit", "type": "admit", "subject": "carol#1",
                     "generation": 1, "fresh_keys": True}
        allow_bob = {"event_id": "e-allow", "type": "allow", "subject": "bob#1",
                     "right": "read", "generation": 2, "fresh_keys": True}
        self.assert_exact([v1_init(), V1_DENY, V1_REPAIR, allow_bob, admission], [])

    def test_v1_repair_then_recovery_reopens(self):
        events = [v1_init(), V1_DENY, V1_REPAIR,
                  {"event_id": "e-recover", "type": "recover", "client": "alice#1",
                   "epoch": 1, "branch": "repaired"},
                  {"event_id": "e-allocate-2", "type": "allocate", "op": "op-2"},
                  v1_release("op-2", revision=1, epoch=1, branch="repaired",
                             digest="digest-2", event_id="e-release-2"),
                  {"event_id": "e-persist-2", "type": "persist", "op": "op-2",
                   "envelope": "bytes-2", "digest": "digest-2"},
                  {"event_id": "e-emit-2", "type": "emit", "op": "op-2", "envelope": "bytes-2"},
                  {"event_id": "e-consume-2", "type": "consume", "op": "op-2",
                   "recipient": "alice#1"}]
        self.assert_exact(events, [])

    def test_v1_replay_and_rebinding_results_are_unchanged(self):
        replay = [v1_init(), V1_ALLOC, v1_release(), V1_PERSIST, V1_EMIT, V1_CONSUME,
                  {**V1_CONSUME, "event_id": "e-consume-again"}]
        self.assert_exact(replay, [v(6, "replay")])
        rebind = [v1_init(), V1_ALLOC, v1_release(), V1_PERSIST,
                  {**V1_PERSIST, "event_id": "e-persist-other", "envelope": "other-bytes"}]
        self.assert_exact(rebind, [v(4, "binding_mismatch")])

    def test_v1_trace_rejects_v2_only_events(self):
        for event in (repair_open("main", "single"), confirm("alice#1", "main", "h"),
                      rekey("alice#1", "write", 2, 1, "main", "b1", "key-new")):
            with self.subTest(type=event["type"]):
                self.assert_exact([v1_init(), event], [v(1, "malformed")])

    def test_empty_trace_is_still_not_initialized(self):
        self.assert_exact([], [v(0, "not_initialized")])


if __name__ == "__main__":
    unittest.main()
