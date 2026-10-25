# F-9 evidence: post quantum probe (2026-10-25)

Scratch builds, not the pinned stack. Nothing here is merged into agent-trust or the
OpenMLS fork. The reports in `2026-10-25-pq-local/` name the testbed revision as
`6e0c58e…-dirty` and agent-trust as `0.1.0` (a path dependency), because the probe
replaced the pinned agent-trust with a local copy.

## What changed for the probe

`2026-10-25-pq-probe/probe.diff`, against agent-trust `5cf724e`:

- every OpenMLS crate gets the feature `draft-ietf-mls-pq-ciphersuites`;
- the lab ciphersuite changes from `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
  (`0x0001`) to `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` (`0x004F`): hybrid
  ML-KEM-768 and X25519 key exchange, the same AES-128-GCM, SHA-256 and Ed25519.

The testbed copy differs only in its `Cargo.toml`: agent-trust from that local copy, and
the same feature on its OpenMLS crates.

## Results

| Check | Result |
|---|---|
| agent-trust `cargo test --release`, adapter, authority, entropy and durable suites | 164 of 164 pass (`2026-10-25-pq-probe/cargo-test.txt`) |
| agent-trust legacy `MlsLab` suite (`tests/mls_contract.rs`, `mls-demo` only) | 1 of 6 pass; Add fails with `InvalidAddProposalCiphersuiteOrVersion`. Not investigated: this lab uses the RustCrypto provider and is not on the adapter path |
| Testbed E1, E1-mtls, E2, E3, E4, E7, local backend, oracle and broken controls included | All pass, same steps as the classical runs (`2026-10-25-pq-local/`) |
| Python integration harness and `scripts/verify.py` (the `full_lap_mls` gate) | Not run |
| E5, compose, k3s | Not run |

Build trap: with the feature on `openmls` and `openmls_libcrux_crypto` only,
`openmls_rust_crypto` does not compile (a `match` over `HpkeKemType` misses the new
variants). Enable the feature on every OpenMLS crate.

## Sizes (bytes, E1, local backend, read from the relay)

| Object | Classical `0x0001` | Hybrid `0x004F` | Factor |
|---|---|---|---|
| KeyPackage | 542 | 2912 | 5.4 |
| Commit (admission, repair, rekey) | 537 to 1130 | 3996 to 8144 | 7.2 to 7.4 |
| Welcome | 1027 to 1346 | 5671 to 8360 | 5.5 to 6.2 |
| APF ack | 310 | 310 | 1 |
| Application envelope | 306 to 321 | 306 to 321 | 1 |

Run time (one run each, not a benchmark): E1 9.5 s against 6.9 s classical; the other
five within 1.2 s of their classical runs.
