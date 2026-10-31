# agent-trust

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A research laboratory for **may–can concordance**: an authority decides who
*may* act on a group, MLS decides who *can*, and the two must agree at the
instant each action is released. Here the actors are agents, each a member of
an [OpenMLS](https://github.com/openmls/openmls) group. The theory is in
[`formal/`](formal/): the paper *Two clocks, one cut: may–can concordance and
revocation in MLS groups* and its exhaustive model check.

Authorization (who may read or write) and MLS group membership (who holds the
keys) usually change independently, so they can drift apart: a revoked agent can
still decrypt, or a key holder can act without permission. agent-trust binds the
two together. Every membership change and every protected message must pass
through one authority, and an independent oracle checks the resulting traces.

This is research software, not a production identity, authorization or
messaging system.

**Owner:** [Daniel Sobral Blanco](https://github.com/dasobral)
([ORCID](https://orcid.org/0000-0001-9559-3651)) · **License:** [MIT](LICENSE)

## Status

| Claim | Result |
| --- | --- |
| `full_construction_mls` | **`true`**, recorded 2026-10-31 on `main` (R-11, R-12) with the OpenMLS fork at `93ad743e`, the integration gate run in both suites, `pq` and `classical` ([log](evidence/verify-2026-10-31-fork-93ad743.txt)) |
| Post quantum suite | **Default** in the lab: MLS `0x0052`, X-Wing key exchange (ML-KEM-768 with X25519) and ML-DSA-44 signatures for every identity and the APF ([C-42](docs/adapter-contract.md#83-post-quantum-suite-c-42-d-13)); `classical` (`0x0001`) stays available |
| Key confinement, computational ([Proposition 3](formal/README.md#status-of-each-claim); the Third Edition's `Bridge_remove^ETK`) | **Conditional.** Derived from ETK Theorem 1 under K1–K5, and checked against ETK's full version (v2.0): its statement, predicates, corruption interfaces and proof structure ([record](formal/notes/etk-full-check.md)); not every case of its Appendix J was re-verified. Since R-11 every commit the code produces is an operation ETK models, so the result covers the code as well as the construction. One item is open: ETK's proof holds against classical adversaries only, so with the post-quantum suite the result is classical (the quantum version is a conjecture with five checks, [`etk-qrom`](formal/notes/etk-qrom.tex)). The strong unforgeability of ML-DSA-44 that ETK needs is written out as a reduction, not mechanized ([`ml-dsa-suf`](formal/notes/ml-dsa-suf.tex)). |
| Live Entropy Core run | **Not yet run** |
| HPKE encapsulation randomness | **Derived** from the selected source: HMAC-DRBG output seeded from it ([§8](docs/adapter-contract.md#8-entropy-seam)) |

`full_construction_mls` is `true` because one recorded run of `python3 scripts/verify.py`
passed every gate of the claim gate
([`docs/adapter-contract.md`](docs/adapter-contract.md) §11): the build, every
Rust and Python test, and the lab integration run, once in each suite. In that run the independent
oracle accepted the exported lab traces and rejected the deliberately broken
ones. The claim covers the executed schedules only; it is not a proof. Any later
verifier run that fails a gate resets it to `false` in
[`evidence/manifest.json`](evidence/manifest.json).

## How it works

```text
            signed requests                          kernel commands
 Client ─────────────────────────▶  Adapter  ─────────────────────────▶  Kernel
 (MLS group,  ◀── acks, release ──  (APF key, sequencer =                (SQLite,
  own keys)       certificates      OpenMLS PublicGroup)                  hash chain)
```

- **Kernel** ([`src/authority.rs`](src/authority.rs)): the Authority, Permit and
  Fence (APF) kernel. It orders policy, delegation, invocation, release,
  consumption and revocation in SQLite, with a hash-chained history. It holds no
  keys and no MLS state.
- **Adapter** ([`src/adapter.rs`](src/adapter.rs)): the only caller of the
  kernel. It authenticates every request and validates every MLS commit with its
  own OpenMLS `PublicGroup`. The kernel's epoch, roster and repair state
  therefore come only from real commits. It signs admission and release
  certificates and acknowledgements.
- **Client endpoint** ([`src/client.rs`](src/client.rs)): one MLS member with its
  own keys and storage. It encrypts only under an APF-signed release certificate.
- **Oracle** ([`harness/oracle.py`](harness/oracle.py)): an independent Python
  checker for exported traces. It imports no production code.

Properties exercised by the tests include:

- Revocation fences reads until a repair commit removes the reader. The removed
  member's retained key state then fails on later traffic.
- Re-granted write, admin or admit rights require fresh keys (rekey).
- A privileged intermediary cannot widen or launder an invocation's authority
  ([`docs/confused-deputy.md`](docs/confused-deputy.md)).
- The adapter recovers from crashes at every recorded barrier.

## Quick start

You need Rust **1.91** or newer and Python **3**. The first build fetches the
pinned OpenMLS fork and [openmls-qrand](https://github.com/dasobral/openmls-qrand)
from GitHub.

```bash
cargo build --locked
python3 scripts/verify.py
```

The verifier runs every gate. It fails closed when a gate fails or runs no
tests, and it rewrites the claim in `evidence/manifest.json`.

### Run the lab

`agent-trust lab` reads one JSON request per line and writes one JSON response
per line. It drives a real adapter and real OpenMLS clients through admission,
sending, delivery, revocation, repair and rekey. `--seed` fixes the simulated
network's reordering, loss and duplication.

```bash
lab_dir="$(mktemp -d)/lab"
AGENT_TRUST_ENTROPY_SOURCE=mock ./target/debug/agent-trust lab --dir "$lab_dir" --seed 1 < examples/lab-session.jsonl
./target/debug/agent-trust export-trace --dir "$lab_dir"
```

Each run needs a new `--dir`: `genesis` refuses a directory that already holds a
lab. The request set is specified in
[`docs/adapter-contract.md`](docs/adapter-contract.md) (C-36, C-39, C-40).

### Entropy source

The lab draws every key and every OpenMLS random value from one source, chosen
at startup. Keys and values OpenMLS requests through `OpenMlsRand` are direct
draws. Randomness inside crypto operations, such as HPKE encapsulation, comes
from the lab crypto provider (the OpenMLS libcrux provider), whose HMAC-DRBG is
seeded from the same source when it is connected:

| Source | Select with | Use |
| --- | --- | --- |
| `os` | nothing (default) | The OS RNG: OS-seeded RustCrypto for direct draws, the OS RNG for the crypto provider's DRBG |
| `mock` | `AGENT_TRUST_ENTROPY_SOURCE=mock`, optional `AGENT_TRUST_MOCK_SEED=N` | Seeded, **not random**. For development and tests: the same seed gives the same keys. |
| `qrng` | `AGENT_TRUST_ENTROPY_SOURCE=qrng` and `AGENT_TRUST_QRNG_BASE_URL` | A QRNG Open API endpoint such as Quside Entropy Core. Over TLS it prefers the post quantum key exchange `X25519MLKEM768` and accepts a classical group from a server without it (`pq-preferred`, the default; `pq-only` refuses that server). The lab `entropy` report shows the negotiated group (`key_exchange`, `post_quantum`) |

A TOML file named by `AGENT_TRUST_ENTROPY_CONFIG` can select the source instead;
see [`config/entropy.example.toml`](config/entropy.example.toml). A source that
cannot be selected or reached stops the lab before the first request, with no
fallback to another source.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/` | Kernel, adapter, client endpoint, wire encodings, lab and CLI. `src/mls.rs` is the earlier in-memory MLS lab behind `mls-demo`. |
| `tests/` | Rust contract, adversarial and recovery tests |
| `harness/` | Python oracle and black-box tests of the CLI and lab |
| `scripts/verify.py` | Fail-closed public verifier |
| `formal/` | Paper, finite-state model, alignment notes |
| `docs/` | Specification and contracts |
| `evidence/` | Recorded red/green runs, verifier logs and the claim manifest |
| `examples/`, `config/` | A sample lab session and an entropy configuration |

## Documentation

| Document | Contents |
| --- | --- |
| [`formal/README.md`](formal/README.md) | The paper, the model check and the status of each claim |
| [`formal/LEXICON.md`](formal/LEXICON.md) | Names used by the theory and the code |
| [`docs/adapter-contract.md`](docs/adapter-contract.md) | Adapter, client and lab contract; entropy seam; claim gate |
| [`docs/authority-contract.md`](docs/authority-contract.md) | APF kernel commands |
| [`docs/trace-contract.md`](docs/trace-contract.md) | Trace format the oracle checks |
| [`docs/confused-deputy.md`](docs/confused-deputy.md) | Invocation provenance |
| [`docs/specification.md`](docs/specification.md) | Original specification |
| [`docs/openmls-compatibility.md`](docs/openmls-compatibility.md) | OpenMLS API notes |

[`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to propose changes, and
[`SECURITY.md`](SECURITY.md) how to report a vulnerability. If you use this
laboratory, please cite it with [`CITATION.cff`](CITATION.cff).

## License

Copyright © 2026 Daniel Sobral Blanco. Released under the [MIT License](LICENSE).
The pinned OpenMLS crates remain under their own licenses; see [`NOTICE`](NOTICE).
