# Entropy source

The MLS laboratory takes a replaceable randomness source (specification §2,
"Entropy"). `MlsLab::new()` keeps the default OS-seeded source.
`MlsLab::with_entropy(EntropySource::Qrng(client))` draws randomness from a QRNG
Open API endpoint through
[`openmls-qrand`](https://github.com/dasobral/openmls-qrand), pinned at commit
`dc8dced82e1edbe13579cc64ad2e1fcc348d8a72`.

## Dependency unification

`openmls-qrand` depends on the crates.io `openmls_traits = "0.6.0"`, while this
project pins the OpenMLS fork. A `[patch.crates-io]` entry in `Cargo.toml`
redirects that dependency to the fork revision. The graph then contains a single
`openmls_traits` and a single `OpenMlsRand`. Check this with
`cargo tree -i openmls_traits`.

## What the QRNG source covers

| Randomness | Source under `EntropySource::Qrng` |
| --- | --- |
| OpenMLS protocol randomness requested via `OpenMlsRand`: KeyPackage init-key IKM (`openmls/src/key_packages/mod.rs`), leaf encryption key pairs (`treesync/node/leaf_node.rs`), UpdatePath path secrets (`treesync/mod.rs`), and the group init secret (`group/mls_group/creation.rs`) at the pinned fork revision | QRNG |
| Ed25519 signature-key seeds for laboratory members and the laboratory APF key | QRNG (32-byte seed, then `SignatureKeyPair::from_raw`) |
| HPKE encapsulation randomness inside hpke-rs, and RustCrypto's internal ChaCha20 RNG | **Not** QRNG |
| Durable APF kernel (`src/authority.rs`) | Not affected by this change |

The laboratory derives signature keys from the selected source.
`SignatureKeyPair::new` in OpenMLS 0.9.0 always uses `OsRng`, so it is not
called. This repository makes no claim that every random choice in the
cryptographic stack comes from the QRNG.

## Fail-closed behavior

The laboratory has no fallback. If the QRNG cannot supply entropy, group
creation, admission, and removal return an error, and the group stays at its
previous epoch and roster. When entropy is available again, the same operation
succeeds. `tests/mls_entropy.rs` checks this offline against a local fake QRNG
Open API server. The fake server's byte stream is deterministic and exists only
for tests.

## Live Entropy Core

The live test is ignored by default, and its results are claimed only after it
has actually run:

```bash
QRNG_LIVE_BASE_URL=http://<host>:<port> \
  cargo test --locked --test mls_entropy -- --ignored --nocapture
```

Do not record live endpoint details or credentials in `evidence/`.

## Claim boundary

This change does not alter `full_lap_mls`, which stays `false`. It does not
introduce conditioning, and it makes no quantum-origin claim beyond what the
configured endpoint provides.
