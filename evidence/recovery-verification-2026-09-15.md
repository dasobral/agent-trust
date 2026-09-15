# Recovery verification — 2026-09-15

All commands ran in the reconstructed `agent-trust` repository with Rust 1.91.1 and the locked dependency graph.

| Gate | Exit | Result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | Formatting clean |
| `cargo build --locked` | 0 | Build succeeded |
| `cargo test --locked --all-targets` | 0 | 37 Rust tests passed |
| `python3 -m unittest discover -s harness -v` | 0 | 32 Python tests passed |
| `python3 scripts/verify.py` | 0 | Python oracle: 21; Rust: 37 |
| `git diff --check` | 0 | No whitespace errors |

Rust test distribution:

- authority adversarial: 10;
- authority contract: 14;
- recovered authority-gap contract: 4;
- confused-deputy adversarial: 5;
- OpenMLS contract: 4.

The authority-gap suite was first run against the exact interim checkpoint. It exited 101 with three expected failures and one guard pass. After the minimum APF repairs, all four passed.

Explicit APF demonstration:

```text
child(read) -> parent(read,write) -> WRITE
=> DENY {"error":"unauthorized"}

parent(read,write) -> WRITE
=> ALLOW {"executor":"parent","invocation":null,"effective_right":"write","resource":"group-a"}
```

The denial uses valid principals and credentials. The decision differs because the first operation is bound to an APF-issued read-only invocation while the second has no invocation and is independently authorized for the parent.
