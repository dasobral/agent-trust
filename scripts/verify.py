#!/usr/bin/env python3
"""Fail-closed public verification for the independent oracle and Rust gates."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PYTHON_TESTS = re.compile(r"Ran (\d+) tests?\b")
RUST_TESTS = re.compile(r"test result: ok\. (\d+) passed;")


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


def run_verification(*, runner=subprocess.run, which=shutil.which, out=sys.stdout):
    cargo = which("cargo")
    if cargo is None:
        print("UNMET rust: cargo not found", file=out)
        return 1

    python_command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        "harness",
        "-p",
        "test_oracle*.py",
        "-v",
    ]
    python = _run(python_command, runner=runner, out=out)
    if python is None or python.returncode != 0:
        print("FAIL python-oracle", file=out)
        return 1
    python_counts = [int(value) for value in PYTHON_TESTS.findall(python.stdout + python.stderr)]
    if not python_counts or sum(python_counts) == 0:
        print("FAIL python-oracle: no tests executed", file=out)
        return 1
    print(f"PASS python-oracle ({sum(python_counts)} tests)", file=out)

    rust_command = [cargo, "test", "--locked", "--all-targets"]
    rust = _run(rust_command, runner=runner, out=out)
    if rust is None or rust.returncode != 0:
        print("FAIL rust", file=out)
        return 1
    rust_counts = [int(value) for value in RUST_TESTS.findall(rust.stdout + rust.stderr)]
    if not rust_counts or sum(rust_counts) == 0:
        print("FAIL rust: no tests executed", file=out)
        return 1
    print(f"PASS rust ({sum(rust_counts)} tests)", file=out)
    return 0


def main():
    return run_verification()


if __name__ == "__main__":
    raise SystemExit(main())
