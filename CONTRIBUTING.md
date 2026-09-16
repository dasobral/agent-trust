# Contributing

Thank you for looking at `agent-trust`. This is a small experimental laboratory
with a strict claim boundary. Please read the README before sending a change.

## Ownership

Daniel Sobral Blanco ([@dasobral](https://github.com/dasobral)) owns the
repository. See
[`MAINTAINERS`](MAINTAINERS) and [`.github/CODEOWNERS`](.github/CODEOWNERS).

## Before you start

1. Read [`docs/specification.md`](docs/specification.md) and the contract that
   matches your change ([`docs/authority-contract.md`](docs/authority-contract.md),
   [`docs/trace-contract.md`](docs/trace-contract.md), or
   [`docs/confused-deputy.md`](docs/confused-deputy.md)).
2. Keep source and documentation portable. Do not put absolute machine paths in
   runtime commands, tests, or public docs.
3. Do not put private keys, real credentials, or live endpoint details in
   evidence, fixtures, or pull requests.

## Development

Requires Rust 1.91 or newer and Python 3.

```bash
cargo build --locked
cargo test --locked --all-targets
python3 -m unittest discover -s harness -v
python3 scripts/verify.py
```

`scripts/verify.py` is the public fail-closed verifier. A missing toolchain, a
failed gate, or a gate that executes no tests must fail.

## Tests and claims

- Test authors own their assertions. Do not weaken, skip, or rewrite tests to
  make an implementation pass.
- Record genuine command output and exit codes. Distinguish a behavioral
  failure from a build or setup failure.
- Do not present simulated MLS as real MLS, or treat a boolean flag as a
  security proof. `full_lap_mls` remains `false` until the durable authority
  kernel is actually coupled to the complete qualifying MLS policy binding.

## Pull requests

Use the repository pull-request template. Include the verification commands you
ran and their exit codes. Call out any change to the public claim boundary.
