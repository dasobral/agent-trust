# Frozen pre-fork verification record

Prior chat evidence records the pre-fork `agent-trust` checkpoint as commit `fff718a`, with original recovered HEAD `22e6cb3603ec0f06a3326d8915c9aa1cf3c9897f`.

The recorded fresh gates were:

| Command | Exit | Recorded result |
|---|---:|---|
| `cargo test --locked --all-targets` | 0 | 30 Rust tests passed |
| `python3 -m unittest discover -s harness -v` | 0 | 31 Python tests passed |
| `python3 scripts/verify.py` | 0 | Both public gates passed |
| `python3 -m unittest -v harness.test_verify` | 0 | 5 verifier tests passed |
| `cargo build --locked` | 0 | Build succeeded |

The original Git objects and this document's original bytes were not recoverable. This file preserves the recorded result without claiming that the historical commit was cryptographically reconstructed. Current verification is recorded separately.
