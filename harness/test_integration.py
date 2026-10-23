"""Black-box integration harness for the phase 4.7b lab (adapter contract C-36 to C-38).

The tests drive the built binary ``target/debug/agent-trust`` through
``agent-trust lab --dir PATH --seed N`` and ``agent-trust export-trace --dir PATH``,
and check every exported trace with the independent oracle
(``harness.oracle.check_trace``, trace contract version 2). They import no
production code. Build first with ``cargo build --locked``; a missing binary is a
failure, not a skip.

Lab line protocol, as pinned by these tests (C-36, resolved by the test author):

- One JSON object per request line: ``{"op": "<request>", "args": {...}}``. The
  request parameters sit under ``args`` because the ``send`` parameter ``op`` (the
  operation id) would otherwise collide with the request name ``op``. Only
  ``encode_request`` builds request lines.
- One response line per request, exactly ``{"ok": ...}`` or ``{"error": "<code...>"}``.
  An error code may carry detail after the code (``"read_fenced: ..."``). The exit
  status is 0 at end of input, and no response ever mentions ``full_lap_mls``.
- ``send`` payloads are even-length lowercase hex strings, so they read the same as
  hex bytes or as text. A sent envelope is queued for every roster reader except
  the sender, which cannot decrypt its own MLS application message.
- ``deliver`` returns ``{"ok": [{"to", "op", "outcome"}, ...]}``, one item per
  delivery attempt in schedule order. ``outcome`` is ``"delivered"`` (receive,
  consume and deliver all succeeded), ``"dropped"`` (the attempt was lost and the
  entry stays queued), or any other string, which is the rejection code of that
  attempt. A round over an empty queue returns ``[]``.
- ``summary`` returns ``{members, epoch, branch, delivered, duplicate_deliveries,
  deliveries_without_consume}``; ``delivered`` is the number of application
  deliveries.
- ``export_trace`` returns ``{"trace": [...]}``, and ``export-trace --dir`` prints the
  same JSON array.
- The lab creates a new adapter at ``genesis`` (C-36 "a new adapter"); a ``genesis``
  over an existing adapter directory is refused and leaves it unchanged (C-5, C-8).

Run from the repository root with: python3 -m unittest harness.test_integration -v
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import unittest

from harness.oracle import check_trace
from harness.test_verify import (
    FakeGates,
    INTEGRATION_MODULE,
    ManifestAssertions,
    harness_test_modules,
    run_sandboxed,
)


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "agent-trust"
RESPONSE_TIMEOUT = 60
GROUP = "lab-group"
ROOT_SUBJECT = "alice"
MAX_DELIVER_ROUNDS = 64

# Seeds of the delivery schedule (test 4). They are printed in the test output, which
# is the evidence record of the seeds exercised.
SEEDS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 17, 23, 42, 99, 1234, 65535,
         4294967297, 18446744073709551615]


def encode_request(name, args):
    return json.dumps({"op": name, "args": args}) + "\n"


def grant(subject, right, generation):
    return {"subject": subject, "right": right, "generation": generation}


def v(index, code):
    return {"index": index, "code": code}


# ---------------------------------------------------------------------------
# Lab process driver
# ---------------------------------------------------------------------------

class LabSession:
    """One ``agent-trust lab`` process, driven one request line at a time."""

    def __init__(self, test, directory, seed):
        self.test = test
        self.closed = False
        self.process = subprocess.Popen(
            [os.fspath(BINARY), "lab", "--dir", os.fspath(directory), "--seed", str(seed)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        test.addCleanup(self._kill)
        self.lines = queue.Queue()
        self.stderr = []
        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _pump_stderr(self):
        for line in self.process.stderr:
            self.stderr.append(line)

    def _kill(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def _diagnostic(self):
        return f"exit status {self.process.poll()}, stderr: {''.join(self.stderr).strip()!r}"

    def call(self, name, args=None):
        """Send one request and return its parsed response object."""
        try:
            self.process.stdin.write(encode_request(name, args or {}))
            self.process.stdin.flush()
        except OSError as error:
            self.process.wait(timeout=RESPONSE_TIMEOUT)
            self.test.fail(f"lab stopped before request {name!r} ({error}); {self._diagnostic()}")
        try:
            line = self.lines.get(timeout=RESPONSE_TIMEOUT)
        except queue.Empty:
            self.test.fail(f"lab gave no response to {name!r} within {RESPONSE_TIMEOUT}s")
        if line is None:
            self.process.wait(timeout=RESPONSE_TIMEOUT)
            self.test.fail(f"lab exited without answering {name!r}; {self._diagnostic()}")
        self.test.assertNotIn("full_lap_mls", line, "the lab never reports full_lap_mls (C-36)")
        try:
            response = json.loads(line)
        except ValueError:
            self.test.fail(f"lab response to {name!r} is not JSON: {line!r}")
        self.test.assertIsInstance(response, dict, line)
        self.test.assertIn(set(response), ({"ok"}, {"error"}), f"{name}: {line!r}")
        if "error" in response:
            self.test.assertIsInstance(response["error"], str, line)
            self.test.assertTrue(response["error"], line)
        return response

    def ok(self, name, args=None):
        response = self.call(name, args)
        self.test.assertIn("ok", response, f"request {name} {args} was refused: {response}")
        return response["ok"]

    def error(self, name, args, code):
        response = self.call(name, args)
        self.test.assertIn("error", response, f"request {name} {args} must be refused with {code}")
        self.test.assertTrue(response["error"].startswith(code),
                             f"request {name} {args}: expected {code}, got {response['error']!r}")
        return response["error"]

    def close(self):
        """End input; require exit status 0 and no unanswered output lines."""
        self.process.stdin.close()
        status = self.process.wait(timeout=RESPONSE_TIMEOUT)
        extra = []
        while True:
            line = self.lines.get(timeout=RESPONSE_TIMEOUT)
            if line is None:
                break
            extra.append(line)
        self.test.assertEqual(extra, [], "one response line per request (C-36)")
        self.test.assertEqual(status, 0, f"the lab exits 0 at end of input; {self._diagnostic()}")


# ---------------------------------------------------------------------------
# Test-side trace model (independent of the oracle's internals)
# ---------------------------------------------------------------------------

def replay(trace):
    """Return the frontier, roster, grants, keys and fence after an accepted v2 trace."""
    state = {"policy_revision": 0, "epoch": None, "branch": None, "roster": [], "grants": {},
             "keys": {}, "fenced": False}
    for event in trace:
        kind = event.get("type")
        if kind == "init":
            state["epoch"], state["branch"] = event["epoch"], event["branch"]
            state["roster"] = list(event["roster"])
            state["keys"] = dict(event["keys"])
            state["grants"] = {(g["subject"], g["right"]): [g["generation"], True] for g in event["grants"]}
        elif kind == "allow":
            state["grants"][(event["subject"], event["right"])] = [event["generation"], True]
            state["policy_revision"] += 1
        elif kind == "deny":
            record = state["grants"].get((event["subject"], event["right"]))
            if record and record[1]:
                record[1] = False
                state["policy_revision"] += 1
                if event["right"] == "read" and event["subject"] in state["roster"]:
                    state["fenced"] = True
        elif kind == "admit":
            state["roster"].append(event["subject"])
            state["keys"][event["subject"]] = event["key"]
            state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
        elif kind == "repair_stage":
            state["roster"] = [m for m in state["roster"] if m not in event["removed"]]
            for member in event["removed"]:
                state["keys"].pop(member, None)
            state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
        elif kind == "repair_open":
            state["fenced"] = False
        elif kind == "rekey":
            state["grants"][(event["subject"], event["right"])] = [event["generation"], True]
            state["keys"][event["subject"]] = event["new_key"]
            state["policy_revision"] += 1
            state["epoch"], state["branch"] = event["epoch"], event["new_branch"]
    return state


def forged_release(prefix, op, actor, tag):
    """An allocate plus a fresh release at the current frontier after ``prefix``."""
    state = replay(prefix)
    writer = state["grants"].get((actor, "write"), [0, False])[0]
    cover = [[grant(actor, "write", writer)]]
    cover += [[grant(member, "read", state["grants"].get((member, "read"), [0, False])[0])]
              for member in state["roster"]]
    return [
        {"event_id": f"forged-allocate-{tag}", "type": "allocate", "op": op},
        {"event_id": f"forged-release-{tag}", "type": "release", "op": op, "actor": actor,
         "right": "write", "policy_revision": state["policy_revision"], "epoch": state["epoch"],
         "branch": state["branch"], "digest": f"forged-digest-{tag}", "cover": cover},
    ]


def events_of(trace, kind):
    return [event for event in trace if event.get("type") == kind]


def index_of(test, trace, predicate, label):
    for index, event in enumerate(trace):
        if predicate(event):
            return index
    test.fail(f"the exported trace has no {label}: {[e.get('type') for e in trace]}")


# ---------------------------------------------------------------------------
# Shared test base
# ---------------------------------------------------------------------------

class LabTestBase(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"agent-trust binary is missing: {BINARY} (run cargo build --locked)")

    def temp_dir(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def export_cli(self, directory):
        result = subprocess.run(
            [os.fspath(BINARY), "export-trace", "--dir", os.fspath(directory)],
            text=True, capture_output=True, timeout=RESPONSE_TIMEOUT, check=False,
        )
        self.assertEqual(result.returncode, 0, f"export-trace failed: {result.stderr.strip()}")
        trace = json.loads(result.stdout)
        self.assertIsInstance(trace, list, result.stdout)
        return trace

    def lab_trace(self, session):
        exported = session.ok("export_trace")
        self.assertIsInstance(exported, dict, exported)
        self.assertEqual(set(exported), {"trace"}, exported)
        self.assertIsInstance(exported["trace"], list, exported)
        return exported["trace"]

    def drain(self, session):
        """Run deliver rounds until the queue is empty; return the nonempty rounds."""
        rounds = []
        for _ in range(MAX_DELIVER_ROUNDS):
            attempts = session.ok("deliver")
            self.assertIsInstance(attempts, list, f"deliver returns a list of attempts: {attempts!r}")
            for attempt in attempts:
                self.assertIsInstance(attempt, dict, attempt)
                self.assertEqual(set(attempt), {"to", "op", "outcome"}, attempt)
                for field in ("to", "op", "outcome"):
                    self.assertIsInstance(attempt[field], str, attempt)
                    self.assertTrue(attempt[field], attempt)
            if not attempts:
                return rounds
            rounds.append(attempts)
        self.fail(f"the delivery queue did not drain within {MAX_DELIVER_ROUNDS} rounds")

    def check_attempts(self, rounds, expected_pairs):
        """Every expected (op, reader) is delivered exactly once; only duplicates are rejected."""
        delivered = Counter()
        for attempts in rounds:
            for attempt in attempts:
                pair = (attempt["op"], attempt["to"])
                self.assertIn(pair, expected_pairs, f"attempt for an unauthorized pair: {attempt}")
                if attempt["outcome"] == "dropped":
                    continue
                if attempt["outcome"] == "delivered":
                    self.assertNotIn(pair, delivered, f"{pair} delivered twice: {attempt}")
                    delivered[pair] += 1
                else:
                    self.assertIn(pair, delivered,
                                  f"an honest first copy was rejected (only duplicates may be): {attempt}")
        self.assertEqual(set(delivered), set(expected_pairs), "every authorized pair is delivered once")
        return delivered

    def assert_clean_summary(self, summary, members, epoch, delivered):
        self.assertIsInstance(summary, dict, summary)
        self.assertEqual(set(summary), {"members", "epoch", "branch", "delivered",
                                        "duplicate_deliveries", "deliveries_without_consume"}, summary)
        self.assertEqual(sorted(summary["members"]), sorted(members), summary)
        self.assertEqual(summary["epoch"], epoch, summary)
        self.assertIsInstance(summary["branch"], str, summary)
        self.assertEqual(summary["delivered"], delivered, summary)
        self.assertEqual(summary["duplicate_deliveries"], 0, summary)
        self.assertEqual(summary["deliveries_without_consume"], 0, summary)

    def setup_group(self, session, subjects):
        """Genesis by alice, then delegate and admit each ``(subject, rights)`` in order."""
        session.ok("genesis", {"group": GROUP, "root": ROOT_SUBJECT})
        for subject, rights in subjects:
            session.ok("delegate", {"subject": subject, "rights": rights})
        for subject, _ in subjects:
            session.ok("admit", {"subject": subject, "by": ROOT_SUBJECT})


FULL = ["read", "write", "admit"]
READER = ["read", "admit"]
MEMBERS = [("bob", FULL), ("carol", FULL), ("dave", READER)]


# ---------------------------------------------------------------------------
# Tests 1 and 2: reference scenario, oracle acceptance and broken controls
# ---------------------------------------------------------------------------

class LabIntegrationTests(LabTestBase):

    # (request, args, expected error prefix or None, readers that must receive a send)
    SCRIPT = [
        ("send", {"from": "alice", "op": "op-1", "payload": "a1a1"}, None, {"bob", "carol", "dave"}),
        ("send", {"from": "bob", "op": "op-2", "payload": "b2b2"}, None, {"alice", "carol", "dave"}),
        ("drain", None, None, None),
        ("revoke", {"subject": "bob", "right": "read"}, None, None),
        ("send", {"from": "alice", "op": "op-3", "payload": "a3a3"}, "read_fenced", None),
        ("repair", {"by": "alice"}, None, None),
        ("send", {"from": "alice", "op": "op-4", "payload": "a4a4"}, None, {"carol", "dave"}),
        ("send", {"from": "carol", "op": "op-5", "payload": "c5c5"}, None, {"alice", "dave"}),
        ("drain", None, None, None),
        ("revoke", {"subject": "carol", "right": "write"}, None, None),
        ("send", {"from": "carol", "op": "op-6", "payload": "c6c6"}, "unauthorized", None),
        ("rekey", {"subject": "carol", "right": "write", "generation": 1}, None, None),
        ("send", {"from": "carol", "op": "op-7", "payload": "c7c7"}, None, {"alice", "dave"}),
        ("send", {"from": "dave", "op": "op-8", "payload": "d8d8"}, "unauthorized", None),
        ("drain", None, None, None),
    ]
    SENT = ["op-1", "op-2", "op-4", "op-5", "op-7"]
    SENDERS = {"op-1": "alice", "op-2": "bob", "op-4": "alice", "op-5": "carol", "op-7": "carol"}
    REFUSED = ["op-3", "op-6", "op-8"]

    def run_reference_scenario(self, seed=1):
        """Run the scripted scenario; return (trace, delivered pairs, summary).

        The trace from ``export_trace`` must equal the ``export-trace --dir`` output.
        """
        directory = self.temp_dir()
        session = LabSession(self, directory, seed)
        self.setup_group(session, MEMBERS)
        expected, rounds = set(), []
        for request, args, error, readers in self.SCRIPT:
            if request == "drain":
                rounds += self.drain(session)
            elif error is not None:
                session.error(request, args, error)
            else:
                session.ok(request, args)
                if readers:
                    expected |= {(args["op"], reader) for reader in readers}
        delivered = self.check_attempts(rounds, expected)
        summary = session.ok("summary")
        trace = self.lab_trace(session)
        session.close()
        cli_trace = self.export_cli(directory)
        self.assertEqual(cli_trace, trace, "export_trace and export-trace --dir must agree")
        return trace, set(delivered), summary

    def assert_reference_shape(self, trace, delivered):
        """The accepted trace must describe the scenario, not a vacuous prefix."""
        self.assertTrue(trace, "empty trace")
        init = trace[0]
        self.assertEqual(init.get("type"), "init", init)
        self.assertEqual(init.get("version"), 2, init)
        self.assertEqual(init.get("group"), GROUP, init)
        self.assertEqual(init.get("roster"), [ROOT_SUBJECT], init)
        self.assertEqual(set(init.get("keys", {})), {ROOT_SUBJECT}, init)

        self.assertEqual(
            [(e["subject"], e["right"], e["generation"]) for e in events_of(trace, "allow")],
            [("bob", "read", 0), ("bob", "write", 0), ("bob", "admit", 0),
             ("carol", "read", 0), ("carol", "write", 0), ("carol", "admit", 0),
             ("dave", "read", 0), ("dave", "admit", 0)],
            "one allow per delegated right, in right-code order (C-37)")
        admits = events_of(trace, "admit")
        self.assertEqual([(e["actor"], e["subject"], e["epoch"]) for e in admits],
                         [("alice", "bob", 1), ("alice", "carol", 2), ("alice", "dave", 3)])
        self.assertEqual([(e["subject"], e["right"]) for e in events_of(trace, "deny")],
                         [("bob", "read"), ("carol", "write")])

        stages = events_of(trace, "repair_stage")
        self.assertEqual(len(stages), 1, stages)
        self.assertEqual((stages[0]["actor"], stages[0]["removed"], stages[0]["epoch"]),
                         ("alice", ["bob"], 4))
        confirms = events_of(trace, "confirm")
        self.assertEqual(len(confirms), 2, confirms)
        self.assertEqual({e["branch"] for e in confirms}, {stages[0]["new_branch"]})
        confirmers = {e["actor"] for e in confirms}
        self.assertIn("alice", confirmers, "the committer confirms")
        self.assertEqual(len((confirmers - {"alice"}) & {"carol", "dave"}), 1,
                         f"one other continuing member confirms: {confirmers}")
        opens = events_of(trace, "repair_open")
        self.assertEqual([(e["branch"], e["evidence"]) for e in opens], [(stages[0]["new_branch"], "pair")])

        rekeys = events_of(trace, "rekey")
        self.assertEqual([(e["actor"], e["subject"], e["right"], e["generation"], e["epoch"]) for e in rekeys],
                         [("alice", "carol", "write", 1, 5)])

        self.assertEqual([(e["op"], e["actor"]) for e in events_of(trace, "release")],
                         [(op, self.SENDERS[op]) for op in self.SENT])
        self.assertEqual([e["op"] for e in events_of(trace, "persist")], self.SENT)
        self.assertEqual({e["op"] for e in events_of(trace, "emit")}, set(self.SENT))
        consumes = [(e["op"], e["recipient"]) for e in events_of(trace, "consume")]
        self.assertEqual(len(consumes), len(set(consumes)), "one consume per pair")
        self.assertEqual(set(consumes), delivered, "every delivery is backed by exactly one consume")
        released = {e["op"] for e in events_of(trace, "release")}
        self.assertEqual(released & set(self.REFUSED), set(), "refused sends are never exported as releases")

        kinds = [e.get("type") for e in trace]
        order = [kinds.index("repair_stage"), kinds.index("confirm"), kinds.index("repair_open")]
        self.assertEqual(order, sorted(order), kinds)
        deny_bob = index_of(self, trace, lambda e: e.get("type") == "deny" and e["subject"] == "bob", "bob deny")
        release_4 = index_of(self, trace, lambda e: e.get("type") == "release" and e["op"] == "op-4", "op-4")
        self.assertLess(deny_bob, order[0])
        self.assertLess(order[2], release_4)

    def test_lab_scenario_trace_is_accepted_by_oracle(self):
        trace, delivered, summary = self.run_reference_scenario()
        self.assertEqual(check_trace(trace), [], "the oracle must accept the exported lab trace")
        self.assert_reference_shape(trace, delivered)
        final = replay(trace)
        self.assert_clean_summary(summary, ["alice", "carol", "dave"], 5, 12)
        self.assertEqual((summary["epoch"], summary["branch"]), (final["epoch"], final["branch"]))

    def test_broken_controls_are_rejected_by_oracle(self):
        trace, _, _ = self.run_reference_scenario(seed=2)
        self.assertEqual(check_trace(trace), [], "precondition: the real exported trace is accepted")

        def at(predicate, label):
            return index_of(self, trace, predicate, label)

        deny_read = at(lambda e: e.get("type") == "deny" and e["subject"] == "bob", "read deny of bob")
        deny_write = at(lambda e: e.get("type") == "deny" and e["subject"] == "carol", "write deny of carol")
        stage = at(lambda e: e.get("type") == "repair_stage", "repair_stage")
        opened = at(lambda e: e.get("type") == "repair_open", "repair_open")
        first_release = at(lambda e: e.get("type") == "release", "release")
        first_persist = at(lambda e: e.get("type") == "persist", "persist")
        first_consume = at(lambda e: e.get("type") == "consume", "consume")
        rekey = at(lambda e: e.get("type") == "rekey", "rekey")

        controls = {}

        # Fresh release after the read denial of a roster member.
        prefix = trace[:deny_read + 1]
        controls["post-denial release (read)"] = (
            prefix + forged_release(prefix, "op-forged-read", "alice", "read"), len(prefix) + 1, "read_fenced")

        # Fresh release after the actor's own write denial.
        prefix = trace[:deny_write + 1]
        controls["post-denial release (write)"] = (
            prefix + forged_release(prefix, "op-forged-write", "carol", "write"), len(prefix) + 1,
            "unauthorized_release")

        # API-only removal: open the fence with no staged repair (and so no confirmations).
        mutated = [e for e in trace[:opened + 1] if e.get("type") not in ("repair_stage", "confirm")]
        controls["API-only removal"] = (mutated, len(mutated) - 1, "invalid_repair")

        # Omitted-reader cover: drop one reader's singleton from a real release.
        mutated = deepcopy(trace[:first_release + 1])
        release = mutated[-1]
        omitted = [support for support in release["cover"]
                   if support[0]["right"] == "read" and support[0]["subject"] != release["actor"]]
        self.assertTrue(omitted, f"the first release has no other reader: {release}")
        release["cover"].remove(omitted[0])
        controls["omitted-reader cover"] = (mutated, len(mutated) - 1, "unsound_cover")

        # Repair that omits the revoked reader.
        mutated = deepcopy(trace[:stage + 1])
        mutated[-1]["removed"] = []
        controls["repair omitting the revoked reader"] = (mutated, len(mutated) - 1, "invalid_repair")

        # Re-encryption under one operation: a second, different persisted envelope.
        original = trace[first_persist]
        envelope = original["envelope"]
        changed = envelope[:-1] + ("1" if envelope[-1] != "1" else "0")
        second = dict(original, event_id=original["event_id"] + "-reencrypted", envelope=changed)
        mutated = trace[:first_persist + 1] + [second]
        controls["re-encryption under one op"] = (mutated, len(mutated) - 1, "binding_mismatch")

        # Spent-cell replay: the same (op, recipient) consumed again.
        original = trace[first_consume]
        mutated = trace[:first_consume + 1] + [dict(original, event_id=original["event_id"] + "-replay")]
        controls["spent-cell replay"] = (mutated, len(mutated) - 1, "replay")

        # Reopening without confirmation.
        mutated = [e for e in trace[:opened + 1] if e.get("type") != "confirm"]
        controls["reopening without confirmation"] = (mutated, len(mutated) - 1, "unconfirmed")

        # Rekey that reuses a key: carol's admitted key.
        carol_key = next(e["key"] for e in events_of(trace, "admit") if e["subject"] == "carol")
        mutated = deepcopy(trace[:rekey + 1])
        mutated[-1]["new_key"] = carol_key
        controls["rekey reusing a key"] = (mutated, len(mutated) - 1, "stale_key")

        for label, (events, index, code) in controls.items():
            with self.subTest(control=label):
                self.assertEqual(check_trace(events), [v(index, code)])


# ---------------------------------------------------------------------------
# Test 3: restart preserves the persisted frontier and fence
# ---------------------------------------------------------------------------

class LabRestartTests(LabTestBase):

    def test_process_restart_preserves_frontier_and_fence(self):
        base = self.temp_dir()
        first, fresh = base / "first", base / "fresh"
        first.mkdir()
        fresh.mkdir()

        session = LabSession(self, first, seed=3)
        self.setup_group(session, [("bob", FULL), ("carol", FULL)])
        session.ok("send", {"from": "alice", "op": "op-1", "payload": "a1a1"})
        self.check_attempts(self.drain(session), {("op-1", "bob"), ("op-1", "carol")})
        session.ok("revoke", {"subject": "bob", "right": "read"})
        session.error("send", {"from": "alice", "op": "op-2", "payload": "a2a2"}, "read_fenced")
        summary = session.ok("summary")
        lab_trace = self.lab_trace(session)
        session.close()
        self.assert_clean_summary(summary, ["alice", "bob", "carol"], 2, 2)

        # After the process ended, the persisted directory alone gives the same state.
        persisted = self.export_cli(first)
        self.assertEqual(persisted, lab_trace)
        self.assertEqual(check_trace(persisted), [])
        state = replay(persisted)
        self.assertEqual((state["epoch"], state["branch"]), (summary["epoch"], summary["branch"]))
        self.assertEqual(sorted(state["roster"]), ["alice", "bob", "carol"])
        self.assertTrue(state["fenced"], "the read denial of bob leaves the group fenced")
        self.assertEqual(events_of(persisted, "repair_stage") + events_of(persisted, "repair_open"), [])
        # The oracle confirms the fence: a fresh release on the persisted frontier is read_fenced.
        probe = persisted + forged_release(persisted, "op-probe", "alice", "probe")
        self.assertEqual(check_trace(probe), [v(len(persisted) + 1, "read_fenced")])

        # The lab creates a new adapter at genesis; it refuses to overwrite an existing one.
        again = LabSession(self, first, seed=3)
        response = again.call("genesis", {"group": GROUP, "root": ROOT_SUBJECT})
        self.assertIn("error", response, "genesis over an existing adapter directory must be refused")
        again.close()
        self.assertEqual(self.export_cli(first), persisted, "a refused genesis leaves the directory unchanged")

        # A new lab process on a fresh directory is independent.
        other = LabSession(self, fresh, seed=3)
        other.ok("genesis", {"group": GROUP, "root": ROOT_SUBJECT})
        other_summary = other.ok("summary")
        other_trace = self.lab_trace(other)
        other.close()
        self.assert_clean_summary(other_summary, ["alice"], 0, 0)
        self.assertEqual(check_trace(other_trace), [])
        self.assertEqual([e.get("type") for e in other_trace], ["init"], other_trace)
        self.assertNotEqual(other_trace[0]["branch"], persisted[0]["branch"], "fresh genesis frontier")
        self.assertNotEqual(other_trace[0]["keys"][ROOT_SUBJECT], persisted[0]["keys"][ROOT_SUBJECT],
                            "fresh root key")
        self.assertEqual(self.export_cli(fresh), other_trace)
        self.assertEqual(self.export_cli(first), persisted, "the first directory is untouched")


# ---------------------------------------------------------------------------
# Test 4: seeded reorder, drop and duplicate schedules
# ---------------------------------------------------------------------------

class SeededScheduleTests(LabTestBase):

    SENDS = [("alice", "op-s1"), ("bob", "op-s2"), ("carol", "op-s3"),
             ("alice", "op-s4"), ("bob", "op-s5"), ("carol", "op-s6")]

    def run_seed(self, seed):
        directory = self.temp_dir()
        session = LabSession(self, directory, seed)
        self.setup_group(session, MEMBERS)
        roster = {"alice", "bob", "carol", "dave"}
        expected = set()
        for index, (sender, op) in enumerate(self.SENDS):
            session.ok("send", {"from": sender, "op": op, "payload": f"{index:02x}" * 4})
            expected |= {(op, reader) for reader in roster - {sender}}
        rounds = self.drain(session)
        summary = session.ok("summary")
        trace = self.lab_trace(session)
        session.close()

        self.check_attempts(rounds, expected)
        self.assert_clean_summary(summary, sorted(roster), 3, len(expected))
        self.assertEqual(check_trace(trace), [], f"seed {seed}: the oracle must accept the export")
        consumes = [(e["op"], e["recipient"]) for e in events_of(trace, "consume")]
        self.assertEqual(len(consumes), len(set(consumes)), f"seed {seed}")
        self.assertEqual(set(consumes), expected, f"seed {seed}: one consume per delivered pair")
        return rounds

    def features(self, rounds):
        order = {op: index for index, (_, op) in enumerate(self.SENDS)}
        dropped = any(a["outcome"] == "dropped" for attempts in rounds for a in attempts)
        copies = Counter((a["op"], a["to"]) for attempts in rounds for a in attempts
                         if a["outcome"] != "dropped")
        duplicated = any(count > 1 for count in copies.values())
        reordered = False
        for attempts in rounds:
            per_reader = {}
            for attempt in attempts:
                ops = per_reader.setdefault(attempt["to"], [])
                if attempt["op"] not in ops:
                    ops.append(attempt["op"])
            reordered = reordered or any(ops != sorted(ops, key=order.__getitem__)
                                         for ops in per_reader.values())
        return {"reorder": reordered, "drop": dropped, "duplicate": duplicated}

    def test_seeded_schedules_reorder_drop_and_duplicate(self):
        self.assertGreaterEqual(len(SEEDS), 20)
        self.assertEqual(len(SEEDS), len(set(SEEDS)))
        print(f"\nseeded delivery schedules, seeds: {SEEDS}")
        exercised = {"reorder": [], "drop": [], "duplicate": []}
        schedules = {}
        for seed in SEEDS:
            with self.subTest(seed=seed):
                rounds = self.run_seed(seed)
                schedules[seed] = [[(a["to"], a["op"], a["outcome"]) for a in attempts] for attempts in rounds]
                features = self.features(rounds)
                for name, present in features.items():
                    if present:
                        exercised[name].append(seed)
                attempts = sum(len(r) for r in rounds)
                print(f"seed {seed}: rounds={len(rounds)} attempts={attempts} "
                      + " ".join(f"{name}={'yes' if present else 'no'}" for name, present in features.items()))
        print(f"seeds exercising each fault: {exercised}")
        for name, seeds in exercised.items():
            self.assertTrue(seeds, f"no seed exercised {name}: {exercised}")

        # The seed alone fixes the schedule: rerunning one seed repeats it exactly.
        if schedules:
            seed = (exercised["drop"] or exercised["duplicate"] or list(schedules))[0]
            rerun = [[(a["to"], a["op"], a["outcome"]) for a in attempts] for attempts in self.run_seed(seed)]
            self.assertEqual(rerun, schedules[seed], f"seed {seed} must give the same schedule")


# ---------------------------------------------------------------------------
# Test 6: the verifier runs every adapter gate and fails closed on each
# ---------------------------------------------------------------------------

class VerifierGateTests(ManifestAssertions, unittest.TestCase):
    """C-38 with a faked runner; no binary needed. Infrastructure: harness.test_verify."""

    maxDiff = None

    def test_verify_runs_adapter_gates_and_fails_closed(self):
        runner = FakeGates()
        status, output, manifest = run_sandboxed(self, runner)
        modules = harness_test_modules()
        for required in ("test_rand_inventory", "test_oracle_v2", INTEGRATION_MODULE, "test_cli", "test_verify"):
            self.assertIn(required, modules)
        self.assertEqual(set(modules) - runner.collected(), set(),
                         "the verifier must collect every harness test, not only test_oracle*")
        self.assertEqual(len(runner.rust_commands()), 1, runner.calls)
        self.assertIn("--locked", runner.rust_commands()[0])
        self.assertIn("--all-targets", runner.rust_commands()[0])
        self.assertEqual(status, 0, output)
        self.assert_boundary(manifest, True)

        for module in modules:
            with self.subTest(failing_module=module):
                status, output, manifest = run_sandboxed(self, FakeGates(failing={module}))
                self.assert_fails_closed(status, output, manifest)


if __name__ == "__main__":
    unittest.main()
