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

## Configuration

The entropy source is chosen by configuration, so moving from the development
fake server to a real Entropy Core endpoint needs no code change.
`src/entropy.rs` resolves it in this order:

1. `agent-trust mls-demo --entropy-config PATH`;
2. `AGENT_TRUST_ENTROPY_CONFIG=PATH`, a TOML file;
3. `AGENT_TRUST_QRNG_BASE_URL=URL`, a shorthand where `http://` means plain
   HTTP, `https://` means TLS with webpki roots, and no API authentication is
   used;
4. otherwise the OS source. Setting both variables is an error.

See [`config/entropy.example.toml`](../config/entropy.example.toml) for the file
format. Certificate paths are relative to the file. Unknown fields are rejected,
so a credential cannot be stored in the file. Bearer and `X-API-KEY`
authentication take the *name* of an environment variable (`auth_secret_env`),
and that variable is read at connect time. Any configuration or connection
error is fatal. Nothing falls back to the OS source.

`mls-demo` reports the source it used as `"entropy_source": "os" | "qrng"`.

## Development fake QRNG server

`scripts/fake_qrng.py` is a stdlib-only fake QRNG Open API server for
development. Its bytes are **not random**: they are a deterministic SHA-256
counter stream.

```bash
python3 scripts/fake_qrng.py --port 8002 &
agent-trust mls-demo --entropy-config config/entropy.example.toml
```

The Rust tests use an equivalent in-process fake (`tests/common/mod.rs`). The
CLI harness (`harness/test_entropy_cli.py`) starts the Python fake and covers
each selection path, as well as failing closed when the configured endpoint is
unreachable or the configuration is invalid.

## Live Entropy Core

The live test is ignored by default and reads the same configuration as the
laboratory. A live result is claimed only after the test has run against a real
endpoint:

```bash
AGENT_TRUST_ENTROPY_CONFIG=/path/to/entropy.toml \
  cargo test --locked --test mls_entropy -- --ignored --nocapture
```

Pointing this command at the fake server checks only the test plumbing. It is
not a live result. Do not record live endpoint details or credentials in
`evidence/`.

## Claim boundary

This change does not alter `full_lap_mls`, which stays `false`. It does not
introduce conditioning, and it makes no quantum-origin claim beyond what the
configured endpoint provides.
