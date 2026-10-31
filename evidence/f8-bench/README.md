# F-8 kernel microbenchmark

Supports `docs/F-8-analysis.md` §5. Not part of the crate or the verifier.

Reproduce, from the repository root:

```bash
B=$(mktemp -d) && mkdir -p "$B/src" && cp evidence/f8-bench/Cargo.toml.txt "$B/Cargo.toml" && cp Cargo.lock evidence/f8-bench/main.rs "$B/" && mv "$B/main.rs" "$B/src/" && cp src/authority.rs "$B/src/authority_base.rs" && cp src/authority.rs "$B/src/authority_fix.rs" && patch -d "$B/src" authority_fix.rs < evidence/f8-bench/layers.patch && cargo build --release --manifest-path "$B/Cargo.toml"
```

Then run `"$B/target/release/f8bench" base adapter 738 48`, or
`F8_LAYERS=abcd "$B/target/release/f8bench" fix adapter 5450 48`.
Arguments: `base|fix`, `kernel|adapter`, envelope bytes (738 classical, 5450 `pq`), messages.
`layers.patch` is a prototype for measurement only, not the proposed implementation.
`results.txt` holds the recorded runs.
