"""Black-box tests for lab entropy selection (adapter contract C-40).

The tests drive the built binary ``target/debug/agent-trust lab`` with the entropy
source selected only through the environment (``AGENT_TRUST_ENTROPY_SOURCE`` or
``AGENT_TRUST_ENTROPY_CONFIG``). The ``mock`` source is openmls-qrand ``MockEntropy``: a
seeded stream that is NOT random. With a fixed mock seed every lab identity key is a
function of that seed, so two runs that agree on every exported key show that no key
came from another source. HPKE randomness is outside the seam (section 8) and no
assertion here depends on it.

Every ``AGENT_TRUST_*`` variable is removed from the subprocess environment first, so
a developer's shell cannot change what these tests select. They import no production
code. Build first with ``cargo build --locked``; a missing binary is a failure.

Run from the repository root with: python3 -m unittest harness.test_entropy_lab -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

from harness.oracle import check_trace


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "debug" / "agent-trust"
TIMEOUT = 120
GROUP = "lab-group"

# Genesis, admission, a send, delivery, a revocation and repair, and a rekey: every
# lab step that creates an identity key or an MLS commit.
SCENARIO = [
    ("genesis", {"group": GROUP, "root": "alice"}),
    ("delegate", {"subject": "bob", "rights": ["read", "write", "admit"]}),
    ("delegate", {"subject": "carol", "rights": ["read", "write", "admit"]}),
    ("delegate", {"subject": "dave", "rights": ["read", "admit"]}),
    ("admit", {"subject": "bob", "by": "alice"}),
    ("admit", {"subject": "carol", "by": "alice"}),
    ("admit", {"subject": "dave", "by": "alice"}),
    ("send", {"from": "alice", "op": "op-1", "payload": "a1a1"}),
    ("deliver", {}),
    ("deliver", {}),
    ("revoke", {"subject": "bob", "right": "read"}),
    ("repair", {"by": "alice"}),
    ("revoke", {"subject": "carol", "right": "write"}),
    ("rekey", {"subject": "carol", "right": "write", "generation": 1}),
    ("send", {"from": "carol", "op": "op-2", "payload": "c2c2"}),
    ("deliver", {}),
    ("deliver", {}),
]


def clean_env(**extra):
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_TRUST_")}
    env.update(extra)
    return env


def closed_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class EntropyLabTests(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail(f"CLI binary is missing: {BINARY}; run cargo build --locked first")

    def temp_dir(self):
        handle = tempfile.TemporaryDirectory(prefix="agent-trust-entropy-")
        self.addCleanup(handle.cleanup)
        return Path(handle.name)

    def run_lab(self, requests, env, seed=1):
        """Run one lab process over ``requests``; return (exit code, responses, stderr)."""
        directory = self.temp_dir() / "lab"
        lines = "".join(json.dumps({"op": op, "args": args}) + "\n" for op, args in requests)
        result = subprocess.run(
            [os.fspath(BINARY), "lab", "--dir", os.fspath(directory), "--seed", str(seed)],
            input=lines, text=True, capture_output=True, timeout=TIMEOUT, env=env, check=False,
        )
        responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return result.returncode, responses, result.stderr

    def run_ok(self, requests, env, seed=1):
        code, responses, stderr = self.run_lab(requests, env, seed)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(responses), len(requests), stderr)
        for (op, args), response in zip(requests, responses):
            self.assertIn("ok", response, f"{op} {args} was refused: {response}")
        return [response["ok"] for response in responses]

    def scenario(self, env):
        """Run SCENARIO with an ``entropy`` report after each step; return (reports, trace)."""
        requests = [("entropy", {})]
        for step in SCENARIO:
            requests += [step, ("entropy", {})]
        requests.append(("export_trace", {}))
        results = self.run_ok(requests, env)
        reports = [results[0]] + results[2:-1:2]
        return reports, results[-1]["trace"]

    def keys_of(self, trace):
        """Every identity key in an exported trace, in event order."""
        keys = []
        for event in trace:
            if event["type"] == "init":
                keys += sorted(event["keys"].items())
            elif event["type"] == "admit":
                keys.append((event["subject"], event["key"]))
            elif event["type"] == "rekey":
                keys.append((event["subject"], event["new_key"]))
        return keys

    # ------------------------------------------------------------------

    def test_no_selection_uses_the_os_source(self):
        reports, trace = self.scenario(clean_env())
        self.assertEqual(reports, [{"source": "os"}] * len(reports))
        self.assertEqual(check_trace(trace), [])

    def test_mock_source_draws_at_every_step_and_the_oracle_accepts_the_trace(self):
        reports, trace = self.scenario(clean_env(AGENT_TRUST_ENTROPY_SOURCE="mock"))
        self.assertEqual(reports[0], {"source": "mock", "requests": 0, "bytes": 0, "failures": 0})
        for report in reports:
            self.assertEqual(set(report), {"source", "requests", "bytes", "failures"}, report)
            self.assertEqual(report["source"], "mock", report)
            self.assertEqual(report["failures"], 0, report)
        drawing = {"genesis", "delegate", "admit", "send", "repair", "rekey"}
        for index, (op, args) in enumerate(SCENARIO):
            before, after = reports[index], reports[index + 1]
            if op in drawing:
                self.assertGreater(after["requests"], before["requests"], f"{op} {args} drew no mock entropy")
            self.assertGreaterEqual(after["bytes"], before["bytes"])
        self.assertEqual(check_trace(trace), [], "the oracle must accept a mock-entropy lab trace")
        self.assertIn("rekey", {event["type"] for event in trace})

    def test_every_identity_key_is_a_function_of_the_mock_seed(self):
        def keys(seed):
            env = clean_env(AGENT_TRUST_ENTROPY_SOURCE="mock", AGENT_TRUST_MOCK_SEED=str(seed))
            return self.keys_of(self.scenario(env)[1])

        first, again, other = keys(11), keys(11), keys(12)
        subjects = [subject for subject, _ in first]
        self.assertEqual(sorted(set(subjects)), ["alice", "bob", "carol", "dave"])
        self.assertEqual(subjects.count("carol"), 2, "carol's admission key and her rekey key")
        self.assertEqual(first, again, "the same mock seed must give the same keys, rekey included")
        self.assertEqual(len({key for _, key in first}), len(first), "keys are distinct")
        self.assertTrue(all(a[1] != b[1] for a, b in zip(first, other)),
                        "another mock seed must change every key")
        # The OS source does not repeat keys across runs.
        os_first = self.keys_of(self.scenario(clean_env())[1])
        os_again = self.keys_of(self.scenario(clean_env())[1])
        self.assertTrue(all(a[1] != b[1] for a, b in zip(os_first, os_again)))

    def test_config_file_selects_the_mock_source(self):
        config = self.temp_dir() / "entropy.toml"
        config.write_text('source = "mock"\n[mock]\nseed = 11\n')
        from_file = self.keys_of(self.scenario(clean_env(AGENT_TRUST_ENTROPY_CONFIG=os.fspath(config)))[1])
        from_env = self.keys_of(self.scenario(
            clean_env(AGENT_TRUST_ENTROPY_SOURCE="mock", AGENT_TRUST_MOCK_SEED="11"))[1])
        self.assertEqual(from_file, from_env)

    def test_mock_outage_mid_session_fails_closed_and_recovers(self):
        env = clean_env(AGENT_TRUST_ENTROPY_SOURCE="mock")
        code, responses, stderr = self.run_lab([
            ("genesis", {"group": GROUP, "root": "alice"}),
            ("summary", {}),
            ("entropy_outage", {"available": False}),
            ("delegate", {"subject": "bob", "rights": ["read", "write", "admit"]}),
            ("send", {"from": "alice", "op": "op-1", "payload": "a1a1"}),
            ("summary", {}),
            ("entropy", {}),
            ("entropy_outage", {"available": True}),
            ("delegate", {"subject": "bob", "rights": ["read", "write", "admit"]}),
            ("admit", {"subject": "bob", "by": "alice"}),
            ("export_trace", {}),
        ], env)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(responses), 11, stderr)
        self.assertIn("ok", responses[2], responses[2])
        self.assertEqual(responses[3], {"error": "entropy_unavailable"})
        self.assertIn("error", responses[4], "a send needs fresh MLS randomness")
        self.assertEqual(responses[5], responses[1], "a refused step changes no lab state")
        self.assertEqual(responses[6]["ok"]["source"], "mock")
        self.assertGreaterEqual(responses[6]["ok"]["failures"], 1)
        for response in responses[7:]:
            self.assertIn("ok", response, response)
        self.assertEqual(check_trace(responses[10]["ok"]["trace"]), [])

    def test_admit_refused_by_an_outage_keeps_the_candidate_identity(self):
        env = clean_env(AGENT_TRUST_ENTROPY_SOURCE="mock")
        code, responses, stderr = self.run_lab([
            ("genesis", {"group": GROUP, "root": "alice"}),
            ("delegate", {"subject": "carol", "rights": ["read", "write", "admit"]}),
            ("summary", {}),
            ("entropy_outage", {"available": False}),
            ("admit", {"subject": "carol", "by": "alice"}),
            ("summary", {}),
            ("entropy_outage", {"available": True}),
            ("admit", {"subject": "carol", "by": "alice"}),
            ("summary", {}),
            ("export_trace", {}),
        ], env)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(responses), 10, stderr)
        self.assertEqual(responses[4], {"error": "entropy_unavailable"},
                         "the candidate's KeyPackage draw fails with the section 12 code")
        self.assertEqual(responses[5], responses[2], "a refused admit changes no lab state")
        self.assertIn("ok", responses[7], "the same candidate is admitted after recovery")
        self.assertEqual(responses[8]["ok"]["members"], ["alice", "carol"])
        trace = responses[9]["ok"]["trace"]
        self.assertEqual(check_trace(trace), [])

        # Carol is admitted with the key delegated before the outage: the same mock seed
        # without an outage admits the same key.
        reference = self.run_ok([
            ("genesis", {"group": GROUP, "root": "alice"}),
            ("delegate", {"subject": "carol", "rights": ["read", "write", "admit"]}),
            ("admit", {"subject": "carol", "by": "alice"}),
            ("export_trace", {}),
        ], env)
        self.assertEqual(self.keys_of(trace), self.keys_of(reference[-1]["trace"]))

    def test_mls_draws_refused_by_an_outage_are_entropy_unavailable(self):
        env = clean_env(AGENT_TRUST_ENTROPY_SOURCE="mock")
        code, responses, stderr = self.run_lab([
            ("genesis", {"group": GROUP, "root": "alice"}),
            ("delegate", {"subject": "bob", "rights": ["read", "write", "admit"]}),
            ("delegate", {"subject": "carol", "rights": ["read", "write", "admit"]}),
            ("admit", {"subject": "bob", "by": "alice"}),
            ("summary", {}),
            ("entropy_outage", {"available": False}),
            ("send", {"from": "alice", "op": "op-1", "payload": "a1a1"}),
            ("admit", {"subject": "carol", "by": "alice"}),
            ("revoke", {"subject": "bob", "right": "read"}),
            ("repair", {"by": "alice"}),
            ("summary", {}),
            ("entropy_outage", {"available": True}),
            ("repair", {"by": "alice"}),
            ("admit", {"subject": "carol", "by": "alice"}),
            ("send", {"from": "alice", "op": "op-2", "payload": "a2a2"}),
            ("export_trace", {}),
        ], env)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(responses), 16, stderr)
        for index, step in [(6, "send"), (7, "admit"), (9, "repair")]:
            self.assertEqual(responses[index], {"error": "entropy_unavailable"},
                             f"{step}: an MLS draw refused by the source is entropy_unavailable")
        self.assertIn("ok", responses[8], responses[8])
        self.assertEqual(responses[10], responses[4], "refused MLS steps change no lab state")
        for response in responses[11:]:
            self.assertIn("ok", response, response)
        self.assertEqual(check_trace(responses[15]["ok"]["trace"]), [])

    def test_outage_control_needs_the_mock_source(self):
        code, responses, stderr = self.run_lab([("entropy_outage", {"available": False})], clean_env())
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(responses), 1)
        self.assertTrue(responses[0].get("error", "").startswith("unsupported"), responses)

    def test_invalid_or_unreachable_sources_fail_before_any_request(self):
        port = closed_port()
        config = self.temp_dir() / "entropy.toml"
        config.write_text('source = "qrng"\n')
        cases = {
            "unknown source": clean_env(AGENT_TRUST_ENTROPY_SOURCE="urandom"),
            "invalid file": clean_env(AGENT_TRUST_ENTROPY_CONFIG=os.fspath(config)),
            "file and source": clean_env(AGENT_TRUST_ENTROPY_CONFIG=os.fspath(config),
                                         AGENT_TRUST_ENTROPY_SOURCE="mock"),
            "qrng without URL": clean_env(AGENT_TRUST_ENTROPY_SOURCE="qrng"),
            "unreachable qrng": clean_env(AGENT_TRUST_ENTROPY_SOURCE="qrng",
                                          AGENT_TRUST_QRNG_BASE_URL=f"http://127.0.0.1:{port}"),
        }
        for label, env in cases.items():
            with self.subTest(label):
                code, responses, stderr = self.run_lab([("genesis", {"group": GROUP, "root": "alice"})], env)
                self.assertNotEqual(code, 0, f"{label}: the lab must not start")
                self.assertEqual(responses, [], f"{label}: no request may be processed")
                self.assertTrue(stderr.startswith("entropy_unavailable"), stderr)
                self.assertNotIn(str(port), stderr, "stderr must not name the endpoint")
                self.assertNotIn("127.0.0.1", stderr, "stderr must not name the endpoint")


if __name__ == "__main__":
    unittest.main()
