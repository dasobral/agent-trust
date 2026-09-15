# agent-trust

Experimental authorization/capability consistency laboratory for cryptographic agent principals, attenuated delegation, revocation, frozen operation release, OpenMLS authorization domains, and authenticated invocation provenance.

## Verify

Requires Rust 1.91 or newer and Python 3.

```bash
cargo build --locked
cargo test --locked --all-targets
python3 -m unittest discover -s harness -v
python3 scripts/verify.py
```

The public verifier fails closed when Cargo is unavailable, a gate fails, or a gate executes no tests.

## Confused-deputy property

When an executor acts under an APF-issued invocation, usable authority is bounded by both the executor and the complete invocation chain. A privileged intermediary cannot strip the origin, widen rights/resources, or restore an attenuated capability.

```text
child(read) -> parent(read,write) -> WRITE  => DENY
parent(read,write) -> WRITE                => ALLOW
```

See `docs/confused-deputy.md` for the enforcement design and `docs/recovery-coverage.md` for reconstruction provenance.

## Claim boundary

The laboratory pins the custom OpenMLS fork at commit `6daabe33ddb616a6ed54b511d333e691db18a99f`. Joining members now use staged KeyPackage construction and carry an embedded, signed APF admission certificate whose stripped KeyPackage preimage is independently recomputed before admission. Add/Welcome interoperability and retained-key exclusion after removal are exercised end to end.

`full_lap_mls` remains `false`: the executable milestone does not yet couple the durable authority kernel to `acc_context`, `authz_incarnation`, and the complete qualifying policy-bound repair transition. The CLI reports the narrower `staged_keypackage_binding_verified` result separately.
