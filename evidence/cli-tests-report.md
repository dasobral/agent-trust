# CLI test report

The black-box CLI suite is ready in `harness/test_cli.py` (5 tests, standard-library `unittest`). It covers:

- JSON-line malformed input recovery and one response per input line;
- state persistence across process reopen;
- complete allocate/release/persist/consume replay with nested cover supports and checkpoint history fields;
- invalid arguments and authority store startup failures;
- the exact `mls-demo` summary.

The suite intentionally fails when `target/debug/agent-trust` is absent. Initial red run:

```text
python3 -m unittest harness.test_cli
Ran 5 tests in 0.001s
FAILED (failures=5)
exit=1
```

All five failures were the expected missing-binary setup failure; no tests were skipped.
