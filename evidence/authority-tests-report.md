# Authority integration tests

- Owned file: `tests/authority_contract.rs`
- Test count: 11 integration tests
- Test level: public `Authority::open` / `Authority::execute(serde_json::Value)` only; no production stubs or source assertions.
- Temporary state: standard-library unique temporary directory (PID, nanoseconds, atomic counter), so no `tempfile` dependency is required.

## Required dependencies

The crate needs its normal direct `serde_json` dependency because it is part of the specified public API. No additional dev-dependency is needed by these tests.

## Red evidence

The coordinator must add the Rust crate scaffold before these tests can be executed. At authoring time `cargo test --test authority_contract` cannot start because this repository contains no `Cargo.toml`; that is a setup failure, not behavioral red evidence. Once the scaffold is present, run:

```sh
RUSTUP_HOME=/workspace/scratch/ba7b9f83b536/.toolchain-probe/rustup \
CARGO_HOME=/workspace/scratch/ba7b9f83b536/.toolchain-probe/cargo \
PATH="$CARGO_HOME/bin:$PATH" \
cargo test --test authority_contract
```

The test is expected to be red until the public authority implementation is complete.
