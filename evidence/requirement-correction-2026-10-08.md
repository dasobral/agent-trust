# Requirement correction — 2026-10-08

Test: `harness/test_cli.py::test_mls_demo_reports_the_required_experiment_summary`

Requirement change: Daniel asked for the laboratory entropy source to be
selectable through a configuration file or environment variables. `mls-demo`
must therefore report which source it used.

Expectation change:
- added `"entropy_source": "os"` to the exact summary;
- `run_cli` removes `AGENT_TRUST_ENTROPY_CONFIG` and `AGENT_TRUST_QRNG_BASE_URL`
  from the subprocess environment so the default-source expectation is deterministic.

No existing assertion was removed or relaxed. The previous red for this test
(an unexpected `entropy_source` key) is the expected consequence of the change.
