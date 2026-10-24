#!/usr/bin/env python3
"""Fail-closed public verification and the ``full_lap_mls`` claim gate.

Normative source: ``docs/adapter-contract.md`` C-38, C-39 and section 11. The gates
run in this order, and the first failing gate stops the run:

1. ``build``: ``cargo build --locked`` (the integration harness drives the binary);
2. ``python-oracle``: the independent oracle tests (``harness/test_oracle*.py``);
3. ``rust``: ``cargo test --locked --all-targets``;
4. ``harness``: every Python harness test (``unittest discover -s harness``);
5. ``integration``: ``harness.test_integration``, which passes only if its named
   oracle-acceptance and broken-control tests ran and passed.

Every gate must also execute a nonzero number of tests. Each run writes
``MANIFEST_PATH`` (read at call time): ``claim_boundary.full_lap_mls`` is ``true``
only when every gate passed in this run, and the fixed boundary fields are recorded
on every run. Other manifest records are kept.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evidence" / "manifest.json"
PYTHON_TESTS = re.compile(r"Ran (\d+) tests?\b")
RUST_TESTS = re.compile(r"test result: ok\. (\d+) passed;")
INTEGRATION_MODULE = "harness.test_integration"
NAMED_INTEGRATION_TESTS = (
    "test_lab_scenario_trace_is_accepted_by_oracle",
    "test_broken_controls_are_rejected_by_oracle",
)
GATES = ("build", "python-oracle", "rust", "harness", "integration")
BOUNDARY_FIELDS = {
    "bridge_remove_etk": "open",
    "live_entropy_core": "unmet",
    "hpke_randomness": "drbg_seeded_from_source",
}


def _run(command, *, runner, out):
    try:
        result = runner(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        print(f"FAIL command: {error}", file=out)
        return None
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n", file=out)
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=out)
    return result


def _output(result):
    return (result.stdout or "") + (result.stderr or "")


def _python_gate(name, command, *, runner, out):
    """Run a unittest command; return its executed test count, or None on failure."""
    result = _run(command, runner=runner, out=out)
    if result is None or result.returncode != 0:
        print(f"FAIL {name}", file=out)
        return None
    counts = [int(value) for value in PYTHON_TESTS.findall(_output(result))]
    if not counts or sum(counts) == 0:
        print(f"FAIL {name}: no tests executed", file=out)
        return None
    return sum(counts), result


def _missing_named_tests(text):
    """Names of the required integration tests missing an ``... ok`` verbose line."""
    missing = []
    for name in NAMED_INTEGRATION_TESTS:
        pattern = re.compile(rf"^{re.escape(name)} \([^)]*\) \.\.\. ok$", re.MULTILINE)
        if not pattern.search(text):
            missing.append(name)
    return missing


def _write_manifest(gates, full_lap_mls, reason, out):
    """Record the claim boundary of this run in ``MANIFEST_PATH``, keeping other records."""
    path = Path(MANIFEST_PATH)
    manifest = {}
    try:
        loaded = json.loads(path.read_text())
        if isinstance(loaded, dict):
            manifest = loaded
    except (OSError, ValueError):
        manifest = {}
    manifest["claim_boundary"] = {
        "full_lap_mls": bool(full_lap_mls),
        **BOUNDARY_FIELDS,
        "gates": {gate: gates.get(gate, "not_run") for gate in GATES},
        "reason": reason,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2) + "\n")
    except OSError as error:
        print(f"FAIL manifest: {error}", file=out)
        return False
    return True


def _gates(cargo, gates, *, runner, out):
    """Run every gate in order; record each outcome in ``gates``; stop at the first failure."""
    build = _run([cargo, "build", "--locked"], runner=runner, out=out)
    if build is None or build.returncode != 0:
        gates["build"] = "fail"
        print("FAIL build", file=out)
        return "the build gate failed"
    gates["build"] = "pass"
    print("PASS build", file=out)

    oracle = _python_gate(
        "python-oracle",
        [sys.executable, "-m", "unittest", "discover", "-s", "harness", "-p",
         "test_oracle*.py", "-v"],
        runner=runner, out=out,
    )
    if oracle is None:
        gates["python-oracle"] = "fail"
        return "the python-oracle gate failed"
    gates["python-oracle"] = "pass"
    print(f"PASS python-oracle ({oracle[0]} tests)", file=out)

    rust = _run([cargo, "test", "--locked", "--all-targets"], runner=runner, out=out)
    if rust is None or rust.returncode != 0:
        gates["rust"] = "fail"
        print("FAIL rust", file=out)
        return "the rust gate failed"
    rust_counts = [int(value) for value in RUST_TESTS.findall(_output(rust))]
    if not rust_counts or sum(rust_counts) == 0:
        gates["rust"] = "fail"
        print("FAIL rust: no tests executed", file=out)
        return "the rust gate executed no tests"
    gates["rust"] = "pass"
    print(f"PASS rust ({sum(rust_counts)} tests)", file=out)

    harness = _python_gate(
        "harness",
        [sys.executable, "-m", "unittest", "discover", "-s", "harness", "-v"],
        runner=runner, out=out,
    )
    if harness is None:
        gates["harness"] = "fail"
        return "the harness gate failed"
    gates["harness"] = "pass"
    print(f"PASS harness ({harness[0]} tests)", file=out)

    integration = _python_gate(
        "integration",
        [sys.executable, "-m", "unittest", INTEGRATION_MODULE, "-v"],
        runner=runner, out=out,
    )
    if integration is None:
        gates["integration"] = "fail"
        return "the integration gate failed"
    missing = _missing_named_tests(_output(integration[1]))
    if missing:
        gates["integration"] = "fail"
        print(f"FAIL integration: named tests did not run and pass: {', '.join(missing)}",
              file=out)
        return "the integration oracle acceptance or broken controls did not pass"
    gates["integration"] = "pass"
    print(f"PASS integration ({integration[0]} tests, named oracle controls passed)", file=out)
    return None


def run_verification(*, runner=subprocess.run, which=shutil.which, out=sys.stdout):
    gates = {}
    cargo = which("cargo")
    if cargo is None:
        gates["build"] = gates["rust"] = "unmet"
        print("UNMET rust: cargo not found", file=out)
        failure = "cargo not found"
    else:
        failure = _gates(cargo, gates, runner=runner, out=out)
    passed = failure is None
    reason = ("every gate passed in this run; Bridge_remove^ETK remains an open proof "
              "obligation and HPKE randomness is DRBG output seeded from the selected source" if passed else failure)
    if not _write_manifest(gates, passed, reason, out):
        return 1
    print(f"claim_boundary.full_lap_mls: {'true' if passed else 'false'}", file=out)
    return 0 if passed else 1


def main():
    return run_verification()


if __name__ == "__main__":
    raise SystemExit(main())
