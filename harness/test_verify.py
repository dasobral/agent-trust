"""Contract tests for the fail-closed public verification entrypoint.

The phase 4.7b claim gate is ``docs/adapter-contract.md`` C-38 and section 11:
``scripts/verify.py`` runs ``cargo test --locked --all-targets``, every Python
harness test and the integration harness, and records ``full_lap_mls`` in the
evidence manifest. ``full_lap_mls`` is ``true`` only when every gate passed in
that run, including the integration harness's oracle acceptance and
broken-control tests. Any unmet or failed gate records ``false`` and exits
nonzero.

The runner is faked. ``FakeGates`` answers each verifier command from what the
command would really run: a ``cargo test`` command reports a Rust result, and a
``python -m unittest`` command reports the result of the harness modules that
it would collect from ``harness/``. A command that the fake does not recognise
fails the test, so the verifier cannot pass by running nothing.

Interface pinned here (C-38, resolved by the test author):

- ``verify.MANIFEST_PATH`` is the manifest that ``run_verification`` writes,
  read at call time. Tests patch it, so a fake run never touches
  ``evidence/manifest.json``.
- The manifest keeps its other top-level records. Its ``claim_boundary`` object
  carries ``full_lap_mls`` (a boolean) and the fixed fields
  ``bridge_remove_etk: "open"``, ``live_entropy_core: "unmet"`` and
  ``hpke_randomness: "excluded"``, on every run, passing or not.
- The integration harness counts as passed only when its run reports both
  ``test_lab_scenario_trace_is_accepted_by_oracle ... ok`` and
  ``test_broken_controls_are_rejected_by_oracle ... ok`` (unittest verbose
  lines). A skipped or absent named test is not a pass.

Standard library only. Run from the repository root with:
python3 -m unittest harness.test_verify -v
"""

from __future__ import annotations

from fnmatch import fnmatch
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from unittest.mock import Mock

from scripts import verify


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "harness"
REAL_MANIFEST = ROOT / "evidence" / "manifest.json"
CARGO = "/bin/cargo"

INTEGRATION_MODULE = "test_integration"
NAMED_INTEGRATION_TESTS = (
    "test_lab_scenario_trace_is_accepted_by_oracle",
    "test_broken_controls_are_rejected_by_oracle",
)
BOUNDARY_FIELDS = {
    "bridge_remove_etk": "open",
    "live_entropy_core": "unmet",
    "hpke_randomness": "excluded",
}
GATE_FAILURE_LINE = re.compile(r"^(FAIL|UNMET)\b", re.MULTILINE)


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def harness_test_modules():
    """Every harness test module on disk, for example ``test_rand_inventory``."""
    return sorted(path.stem for path in HARNESS.glob("test_*.py"))


_VALUE_FLAGS = {"-k", "-s", "-p", "-t", "--start-directory", "--pattern", "--top-level-directory"}


def _harness_stem(argument):
    """Map a unittest name or path argument to a harness module name, if it names one."""
    if argument.endswith(".py"):
        path = (ROOT / argument).resolve()
        return path.stem if path.parent == HARNESS and path.stem.startswith("test") else None
    for part in argument.split("."):
        if part.startswith("test") and (HARNESS / f"{part}.py").is_file():
            return part
    return None


def collected_modules(command):
    """Return the harness test modules that this Python command would run."""
    if "unittest" not in command:
        scripts = [_harness_stem(part) for part in command[1:] if part.endswith(".py")]
        return {stem for stem in scripts if stem}
    arguments = command[command.index("unittest") + 1:]
    if "discover" in arguments:
        rest = arguments[arguments.index("discover") + 1:]
        start, pattern, positional = ".", "test*.py", []
        index = 0
        while index < len(rest):
            argument = rest[index]
            if argument in ("-s", "--start-directory"):
                start, index = rest[index + 1], index + 2
            elif argument in ("-p", "--pattern"):
                pattern, index = rest[index + 1], index + 2
            elif argument in _VALUE_FLAGS:
                index += 2
            elif argument.startswith("-"):
                index += 1
            else:
                positional.append(argument)
                index += 1
        if positional:
            start = positional[0]
        if len(positional) > 1:
            pattern = positional[1]
        directory = (ROOT / start).resolve()
        if directory != HARNESS:
            return set()
        return {path.stem for path in HARNESS.glob("*.py") if fnmatch(path.name, pattern)}
    modules, index = set(), 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in _VALUE_FLAGS:
            index += 2
            continue
        index += 1
        if argument.startswith("-"):
            continue
        stem = _harness_stem(argument)
        if stem:
            modules.add(stem)
    return modules


class FakeGates:
    """A command-aware fake ``subprocess.run`` for the verifier's gates.

    ``failing`` names harness modules whose tests fail in every command that
    collects them. ``python_tests`` is the ``Ran N tests`` count of every Python
    command. ``rust_returncode`` and ``rust_passed`` shape the ``cargo test``
    result. ``integration_named`` is ``"ok"``, ``"skipped"`` or ``"absent"`` for
    the named integration tests. Other cargo commands (for example a
    ``cargo build --locked`` before the harness) succeed silently.
    """

    def __init__(self, *, failing=(), python_tests=21, rust_returncode=0, rust_passed=30,
                 integration_named="ok"):
        self.failing = set(failing)
        self.python_tests = python_tests
        self.rust_returncode = rust_returncode
        self.rust_passed = rust_passed
        self.integration_named = integration_named
        self.calls = []

    # -- inspection -------------------------------------------------------
    def kinds(self):
        return [call["kind"] for call in self.calls]

    def count(self, kind):
        return self.kinds().count(kind)

    def collected(self):
        modules = set()
        for call in self.calls:
            modules |= call["modules"]
        return modules

    def rust_commands(self):
        return [call["command"] for call in self.calls if call["kind"] == "rust"]

    # -- fake subprocess.run ----------------------------------------------
    def __call__(self, command, **kwargs):
        command = [os.fspath(part) for part in command]
        if command and command[0] == CARGO:
            kind = "rust" if command[1:2] == ["test"] else "cargo"
            self.calls.append({"kind": kind, "command": command, "kwargs": kwargs, "modules": set()})
            if kind == "cargo":
                return completed(command)
            if self.rust_returncode != 0:
                return completed(command, self.rust_returncode,
                                 stderr="test result: FAILED. 29 passed; 1 failed\n")
            return completed(command, stdout=f"test result: ok. {self.rust_passed} passed; 0 failed\n")
        if command and (command[0] == sys.executable or Path(command[0]).name.startswith("python")):
            modules = collected_modules(command)
            self.calls.append({"kind": "python", "command": command, "kwargs": kwargs, "modules": modules})
            return self._python_result(command, modules)
        raise AssertionError(f"unexpected verifier command: {command}")

    def _python_result(self, command, modules):
        if not modules:
            return completed(command, 5, stderr="\n" + "-" * 70 + "\nRan 0 tests in 0.000s\n\nNO TESTS RAN\n")
        if self.python_tests == 0:
            return completed(command, stderr="\n" + "-" * 70 + "\nRan 0 tests in 0.000s\n\nOK\n")
        lines, failed, skipped = [], False, 0
        for module in sorted(modules):
            status = "FAIL" if module in self.failing else "ok"
            failed = failed or module in self.failing
            lines.append(f"test_gate (harness.{module}.GateTests.test_gate) ... {status}")
            if module == INTEGRATION_MODULE and self.integration_named != "absent":
                for name in NAMED_INTEGRATION_TESTS:
                    if module in self.failing:
                        named = "FAIL"
                    elif self.integration_named == "skipped":
                        named, skipped = "skipped 'agent-trust binary missing'", skipped + 1
                    else:
                        named = "ok"
                    lines.append(f"{name} (harness.{module}.LabIntegrationTests.{name}) ... {named}")
        summary = "FAILED (failures=1)" if failed else (f"OK (skipped={skipped})" if skipped else "OK")
        text = "\n".join(lines) + "\n\n" + "-" * 70 + f"\nRan {self.python_tests} tests in 0.1s\n\n{summary}\n"
        return completed(command, 1 if failed else 0, stderr=text)


def seed_manifest():
    """A manifest whose stale claim is ``true``, so a failing run must overwrite it."""
    return {
        "schema_version": 1,
        "project": "agent-trust",
        "recovery": {"historical_objects_available": False},
        "claim_boundary": {"full_lap_mls": True, "reason": "stale value from an earlier run"},
    }


def run_sandboxed(test, runner, *, which=lambda _: CARGO):
    """Run the verifier with ``MANIFEST_PATH`` in a temporary directory.

    Returns ``(status, output, manifest)``; ``manifest`` is None when the file is
    missing or not JSON. The repository manifest must stay byte-identical.
    """
    before = REAL_MANIFEST.read_bytes() if REAL_MANIFEST.exists() else None
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "manifest.json"
        path.write_text(json.dumps(seed_manifest(), indent=2) + "\n")
        output = io.StringIO()
        with mock.patch.object(verify, "MANIFEST_PATH", path, create=True):
            status = verify.run_verification(runner=runner, which=which, out=output)
        try:
            manifest = json.loads(path.read_text())
        except (OSError, ValueError):
            manifest = None
    after = REAL_MANIFEST.read_bytes() if REAL_MANIFEST.exists() else None
    test.assertEqual(after, before, "a verifier under test must write verify.MANIFEST_PATH, "
                                    "never the repository evidence/manifest.json")
    return status, output.getvalue(), manifest


class ManifestAssertions:
    def assert_boundary(self, manifest, full_lap_mls):
        self.assertIsInstance(manifest, dict, "the verifier must write a JSON manifest on every run")
        boundary = manifest.get("claim_boundary")
        self.assertIsInstance(boundary, dict, manifest)
        self.assertIs(boundary.get("full_lap_mls"), full_lap_mls, boundary)
        for field, value in BOUNDARY_FIELDS.items():
            self.assertEqual(boundary.get(field), value, f"claim_boundary.{field}: {boundary}")
        self.assertEqual(manifest.get("project"), "agent-trust", "unrelated records must be kept")
        self.assertEqual(manifest.get("recovery"), {"historical_objects_available": False},
                         "unrelated records must be kept")

    def assert_fails_closed(self, status, output, manifest):
        self.assertNotEqual(status, 0, output)
        self.assertRegex(output, GATE_FAILURE_LINE)
        self.assert_boundary(manifest, False)


class VerificationEntrypointTests(unittest.TestCase):
    """The original fail-closed checks, with a command-aware fake runner.

    The fake now answers by command instead of by call position, because C-38
    adds gates. What each test checks is unchanged: both public gates pass with
    nonempty counts and each runs once; missing cargo is unmet before any
    command; a Python gate failure stops before ``cargo test``; a Rust failure is
    not success; zero executed tests fail closed and stop.
    """

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = mock.patch.object(verify, "MANIFEST_PATH", Path(directory.name) / "manifest.json",
                                    create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.real_manifest = REAL_MANIFEST.read_bytes() if REAL_MANIFEST.exists() else None
        self.addCleanup(self._real_manifest_unchanged)

    def _real_manifest_unchanged(self):
        after = REAL_MANIFEST.read_bytes() if REAL_MANIFEST.exists() else None
        self.assertEqual(after, self.real_manifest, "tests must never write evidence/manifest.json")

    def assert_stopped_at_last_call(self, runner):
        self.assertTrue(runner.calls, "the failing gate must have run")
        last = runner.calls[-1]
        self.assertEqual(last["kind"], "python", "nothing may run after the failing Python gate")
        self.assertEqual(runner.count("rust"), 0, "cargo test must not run after a Python gate failure")

    def test_both_nonempty_public_gates_pass(self):
        runner = FakeGates()
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: CARGO, out=output)

        self.assertEqual(status, 0, output.getvalue())
        self.assertIn("PASS python-oracle (21 tests)", output.getvalue())
        self.assertIn("PASS rust (30 tests)", output.getvalue())
        self.assertEqual(runner.count("rust"), 1, runner.calls)
        self.assertGreaterEqual(runner.count("python"), 1, runner.calls)

    def test_missing_cargo_is_an_explicit_unmet_gate(self):
        runner = Mock()
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: None, out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("UNMET rust: cargo not found", output.getvalue())
        runner.assert_not_called()

    def test_python_gate_failure_stops_before_rust(self):
        runner = FakeGates(failing={"test_oracle_v2"})
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: CARGO, out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("FAIL python-oracle", output.getvalue())
        self.assert_stopped_at_last_call(runner)

    def test_rust_gate_failure_is_not_reported_as_success(self):
        runner = FakeGates(rust_returncode=101)
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: CARGO, out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("FAIL rust", output.getvalue())

    def test_zero_test_success_codes_fail_closed(self):
        runner = FakeGates(python_tests=0)
        output = io.StringIO()

        status = verify.run_verification(runner=runner, which=lambda _: CARGO, out=output)

        self.assertNotEqual(status, 0)
        self.assertIn("FAIL python-oracle: no tests executed", output.getvalue())
        self.assert_stopped_at_last_call(runner)


class ClaimGateTests(ManifestAssertions, unittest.TestCase):
    """C-38 and section 11: the manifest claim follows the gates of the same run."""

    maxDiff = None

    def test_full_lap_mls_is_true_only_when_every_gate_passes(self):
        status, output, manifest = run_sandboxed(self, FakeGates())
        self.assertEqual(status, 0, output)
        self.assert_boundary(manifest, True)

        failing_runs = {
            "cargo missing": (FakeGates(), lambda _: None),
            "a Rust suite failing": (FakeGates(rust_returncode=101), lambda _: CARGO),
            "zero Rust tests executed": (FakeGates(rust_passed=0), lambda _: CARGO),
            "a harness test failing": (FakeGates(failing={"test_rand_inventory"}), lambda _: CARGO),
            "the integration harness failing": (FakeGates(failing={INTEGRATION_MODULE}), lambda _: CARGO),
            "zero Python tests executed": (FakeGates(python_tests=0), lambda _: CARGO),
        }
        for label, (runner, which) in failing_runs.items():
            with self.subTest(gate=label):
                status, output, manifest = run_sandboxed(self, runner, which=which)
                self.assert_fails_closed(status, output, manifest)
        self.assertEqual(failing_runs["cargo missing"][0].calls, [],
                         "with cargo missing no gate may run")

    def test_skipped_or_absent_integration_controls_do_not_count(self):
        for mode in ("skipped", "absent"):
            with self.subTest(named_integration_tests=mode):
                status, output, manifest = run_sandboxed(self, FakeGates(integration_named=mode))
                self.assert_fails_closed(status, output, manifest)

    def test_cargo_gate_is_locked_and_covers_all_targets(self):
        runner = FakeGates()
        status, output, manifest = run_sandboxed(self, runner)
        self.assertEqual(status, 0, output)
        self.assertEqual(len(runner.rust_commands()), 1, runner.calls)
        command = runner.rust_commands()[0]
        self.assertIn("--locked", command)
        self.assertIn("--all-targets", command)
        for call in runner.calls:
            cwd = call["kwargs"].get("cwd")
            self.assertIsNotNone(cwd, f"every gate runs from the repository root: {call['command']}")
            self.assertEqual(Path(cwd).resolve(), ROOT, call["command"])

    def test_every_harness_module_and_the_integration_harness_are_collected(self):
        runner = FakeGates()
        status, output, _ = run_sandboxed(self, runner)
        self.assertEqual(status, 0, output)
        on_disk = set(harness_test_modules())
        self.assertTrue({"test_rand_inventory", "test_oracle_v2", INTEGRATION_MODULE, "test_verify",
                         "test_cli"} <= on_disk, on_disk)
        self.assertEqual(on_disk - runner.collected(), set(),
                         "every harness test module must be run, not only test_oracle*")


if __name__ == "__main__":
    unittest.main()
