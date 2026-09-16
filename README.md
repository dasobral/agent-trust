# agent-trust

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Experimental laboratory for **Authorization–Capability Coherence (ACC)**:
cryptographic agent principals, attenuated delegation, revocation, frozen
operation release, OpenMLS authorization domains, and authenticated invocation
provenance.

This is research software. It is not a production identity, authorization, or
messaging system. Passing tests show that the executed gates passed; they do
not discharge open cryptographic proof obligations.

**Owner:** [Daniel Sobral Blanco](https://github.com/dasobral)
([ORCID](https://orcid.org/0000-0001-9559-3651)) · **License:** [MIT](LICENSE)

## What it does

The laboratory studies the failure of *independent* authorization and MLS group
membership, then enforces a narrower contract:

- A trusted-local **Authority, Permit, and Fence (APF)** kernel orders policy,
  delegation, release, consumption, and revocation in SQLite.
- A real **OpenMLS** adapter exercises admission binding and retained-key
  exclusion after removal.
- An independent **Python oracle** checks deterministic traces without importing
  production modules.
- **Invocation provenance** bounds usable authority by the executor *and* the
  complete APF-issued invocation chain, so a privileged intermediary cannot
  launder rights.

The authority CLI is a trusted administrative local interface. It is not a
network service.

## Status and claim boundary

| Claim | Current result |
| --- | --- |
| Public verifier fails closed | Yes, via `python3 scripts/verify.py` |
| Confused-deputy / invocation provenance | Enforced in the APF kernel |
| Staged OpenMLS KeyPackage admission binding | Verified against a pinned fork |
| `full_lap_mls` | **`false`** |

`full_lap_mls` remains `false`: this milestone does not yet couple the durable
authority kernel to `acc_context`, `authz_incarnation`, and the complete
qualifying policy-bound repair transition. The CLI reports the narrower
`staged_keypackage_binding_verified` result separately.

The OpenMLS dependency is pinned at commit
`6daabe33ddb616a6ed54b511d333e691db18a99f`. Joining members use staged
KeyPackage construction and carry an embedded, signed APF admission certificate
whose stripped KeyPackage preimage is independently recomputed before
admission.

## Confused-deputy property

When an executor acts under an APF-issued invocation, usable authority is
bounded by both the executor and the complete invocation chain. A privileged
intermediary cannot strip the origin, widen rights or resources, or restore an
attenuated capability.

```text
child(read) -> parent(read,write) -> WRITE  => DENY
parent(read,write) -> WRITE                => ALLOW
```

See [`docs/confused-deputy.md`](docs/confused-deputy.md) for the enforcement
design and [`docs/recovery-coverage.md`](docs/recovery-coverage.md) for
reconstruction provenance.

## Requirements

- Rust **1.91** or newer (`cargo`)
- Python **3**

Network access is required on first build to fetch the pinned OpenMLS git
dependency.

## Verify

Run these from the repository root. The public verifier fails closed when Cargo
is unavailable, a gate fails, or a gate executes no tests.

```bash
cargo build --locked
cargo test --locked --all-targets
python3 -m unittest discover -s harness -v
python3 scripts/verify.py
```

## Layout

| Path | Role |
| --- | --- |
| `src/authority.rs` | Durable APF kernel |
| `src/mls.rs` | In-memory OpenMLS laboratory |
| `src/main.rs` | Local `authority` and `mls-demo` CLI |
| `tests/` | Rust contract and adversarial tests |
| `harness/` | Independent Python oracle and CLI tests |
| `scripts/verify.py` | Fail-closed public verifier |
| `docs/` | Specification, contracts, and design notes |
| `evidence/` | Recorded red/green runs and manifests |

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/specification.md`](docs/specification.md) | Implementation specification |
| [`docs/authority-contract.md`](docs/authority-contract.md) | APF command contract |
| [`docs/trace-contract.md`](docs/trace-contract.md) | Independent oracle contract |
| [`docs/confused-deputy.md`](docs/confused-deputy.md) | Invocation provenance |
| [`docs/OPENMLS-INTEGRATION-READY.md`](docs/OPENMLS-INTEGRATION-READY.md) | Staged KeyPackage milestone |
| [`docs/openmls-compatibility.md`](docs/openmls-compatibility.md) | Adapter compatibility notes |
| [`docs/implementation-plan.md`](docs/implementation-plan.md) | Staged work plan |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to propose changes |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting |
| [`MAINTAINERS`](MAINTAINERS) | Ownership |

## Citation

If you use this laboratory, please cite it. Machine-readable metadata is in
[`CITATION.cff`](CITATION.cff).

## License

Copyright © 2026 Daniel Sobral Blanco. Released under the [MIT License](LICENSE).
The pinned OpenMLS crates remain under their own licenses; see [`NOTICE`](NOTICE).
