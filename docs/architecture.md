# Architecture

This document explains how the Agent Trust stack builds up into the testbed: what
each layer adds, where each trust boundary is, and which part of the agent-trust
contract each network flow implements.

## 1. Layers

```text
 L4  Control plane     attctl: topologies, deploy backends, experiments, oracle, reports
                       ─────────────── HTTP control API (control token) ───────────────
 L3  Testbed services  att-node apf │ att-node agent (one per agent) │ att-node relay │ att-node qrng-mock
                       ─────────────── HTTP data plane: JSON, hex bytes ───────────────
 L2  agent-trust       Adapter (APF key, kernel, sequencer) │ ClientEndpoint (one MLS member)
                       wire encodings │ lab entropy selection │ trace export │ oracle (Python)
 L1  OpenMLS fork      MlsGroup, PublicGroup, staged KeyPackages, libcrux crypto provider
 L0  Entropy           openmls-qrand: QRNG Open API client, EntropyRng, MockEntropy
                       ─────────────── QRNG Open API (HTTP) ───────────────
                       qrng-mock service, or a real endpoint such as Quside Entropy Core
```

| Layer | Repository | Pinned at | What it gives the layer above |
|---|---|---|---|
| L0 | `dasobral/openmls-qrand` | `a102450` | `OpenMlsRand` over a QRNG Open API endpoint; fail closed |
| L1 | `dasobral/openmls` (`agent-trust/integration`) | `dd33278` | MLS groups, the public sequencer, staged KeyPackages, a DRBG seeded from L0 |
| L2 | `dasobral/agent-trust` | `5cf724e` (branch `feat/durable-lab-provider`: `9af877c` plus the durable provider, F-2) | The APF kernel and adapter, the client endpoint, the trace export and the oracle |
| L3 | this repository, `crates/att-node` | | The L2 parties as separate network processes |
| L4 | this repository, `controller/attctl` | | Deployment, control, experiments, evidence |

All pins live in one place: `[workspace.dependencies]` in `Cargo.toml`. agent-trust
pins its own OpenMLS and openmls-qrand revisions, and `Cargo.lock` records the
resolved graph. The control plane loads the oracle from the agent-trust checkout
that Cargo resolved (`cargo metadata`), so the services and the oracle always come
from the same revision. `report.json` of every run records the revisions it used.

## 2. Components and trust

```text
                    ┌──────────── control plane (attctl) ────────────┐
                    │ control token: /control/* on every service      │
                    └───┬─────────────┬──────────────┬───────────┬───┘
                        │             │              │           │
  application ── app ── ▼             ▼              ▼           ▼
  (any agent)   token  agent ─signed requests─▶  apf ─────────▶ qrng
                       sidecar ◀─certs, acks──  (Adapter)       (QRNG Open API)
                        │  ▲                                    ▲
                        ▼  │ commits, acks, Welcomes,           │ keys and MLS
                       relay  KeyPackages, envelopes            │ randomness
                    (untrusted, faults)                 every agent and the apf
```

| Service | Holds | Trusted for | Not trusted for |
|---|---|---|---|
| `apf` | APF signing key, kernel database, public sequencer, adapter store (on disk) | Authorization decisions, frontier sequencing, certificates | Group secrets: it never has them |
| `agent` | Its own signature key, its MLS group state, its bookkeeping (on disk) | Its own confidentiality | Anything about other agents |
| `relay` | Opaque bytes only | Nothing. It may drop, duplicate, reorder, delay, misroute and leak | |
| `qrng` | Nothing secret | Supplying randomness (the mock: OS RNG bytes) | |
| `attctl` | The per deployment tokens | Operating the testbed | It holds no agent key and cannot sign for an agent |

What a malicious relay can and cannot do:

- It can hold, drop, duplicate and reorder envelopes, and copy them to any agent.
  E1 does all of this on purpose.
- It cannot forge a commit, an ack, a release certificate or a consume receipt: the
  APF signs them and every agent verifies them under the APF key.
- It can stop the group from making progress (liveness), for example by hiding a
  handshake entry. It cannot make an agent accept a successor epoch that the APF did
  not ack (adapter contract §4.6).

### 2.1 Trust assumptions of the testbed

These are explicit choices of this testbed, not properties of agent-trust:

1. **APF public key distribution.** An agent pins the key from `ATT_APF_PUBLIC_KEY`
   when it is set. Otherwise the root learns it at genesis and the other agents
   fetch it once from `GET /v1/info` (trust on first use). A production deployment
   must pin it.
2. **Key enrollment.** `delegate` carries the subject's public key (contract C-1). The
   control plane reads that public key from the subject's sidecar and hands it to the
   delegating agent. The subject's secret key never leaves its sidecar.
3. **Public policy view.** `GET /v1/state` on the APF returns the frontier, the
   policy revision, the roster and the grants. Agents need these values to build a
   release cover and digest. The view is advisory: the kernel checks every value
   again at `release` and `consume`. The contract has no worker request for it yet
   (see `docs/findings.md`).
4. **Transport security.** Each deployment generates three random tokens: `control`
   (control plane), `app` (applications), `bootstrap` (genesis, held only by the APF
   and the root agent). Request authenticity towards the APF never depends on
   transport: every worker request is signed (contract §4.8), with ML-DSA-44 in the
   default `pq` suite (agent-trust C-42). With `[tls] enabled` in the topology, every
   connection is mutual TLS 1.3, the QRNG traffic included: between services an
   ML-DSA-44 certificate of the deployment's post quantum CA over the hybrid key
   exchange `X25519MLKEM768`, with no classical fallback (`docs/deployment.md`). Services
   bind the peer's certificate name to the protocol identity:

   | Service | Accepts only |
   |---|---|
   | APF `POST /v1/request` | the agent that signed the request |
   | APF genesis | the configured root |
   | relay mailbox read and ack | the mailbox owner |
   | relay KeyPackage publication | the subject |
   | every `/control/*` | `attctl` |
   | agent `/app/*` | `<agent>-app` or `attctl` |

   A certificate of the classical CA (for a control plane without post quantum TLS) is
   accepted only for `attctl` and `<agent>-app`, and a post quantum certificate only
   over `X25519MLKEM768`. Transport keys come from the OS RNG (rcgen over aws-lc-rs);
   they are outside the agent-trust entropy seam, which covers MLS and identity keys.
5. **Time.** The APF uses the system clock (`SystemClock`). Delegations expire after
   `ttl_secs` (default 30 days).

## 3. Flows

Each flow is the in-process agent-trust flow, cut at the party boundaries. Section
numbers refer to `docs/adapter-contract.md` in agent-trust.

### 3.1 Genesis (§5.1)

1. `attctl` calls `POST /control/genesis` on the root agent.
2. The root sidecar sends its public key to `POST /v1/genesis/begin` with the
   bootstrap token. The APF checks the configured group and root, draws the APF key
   from its entropy source and returns the founder certificate and `acc_context`.
3. The root founds the MLS group (`ClientEndpoint::found`) and sends the GroupInfo
   and ratchet tree to `POST /v1/genesis/complete`. The APF builds its sequencer,
   validates the group and calls kernel `init`.

### 3.2 Admission (§5.2)

1. `attctl` reads the subject's public key and asks an admin agent to `delegate`.
2. The subject sidecar (`/control/join`) prepares a KeyPackage with its
   `authz_incarnation`, obtains the admission certificate from the APF with a signed
   `admission_certificate` request, finalizes the KeyPackage and publishes it on the
   relay.
3. The admin sidecar (`/control/add`) fetches the KeyPackage, stages one Add with a
   forced UpdatePath, and submits it (`submit_commit`, kind admit). The APF
   sequencer validates it and the kernel admits under compare and swap. The admin
   applies the ack and appends `{commit, ack, Welcome, joiner}` to the relay's
   ordered handshake log.
4. Every member applies the commit under the ack. The joiner joins from the Welcome
   and checks the ack.

### 3.3 Send and receive (§5.3)

`POST /app/send` on the sender sidecar runs: sync the handshake log, `allocate`,
read the policy view, build the honest cover and the digest, `release`, verify the
certificate, `protect`, `persist`, `emit`, then post the envelope to the mailbox of
every reader in the certificate except the sender.

The receiver's background loop fetches its mailbox and runs `receive` (certificate,
AAD, sender incarnation, readers, frontier, digest), then `consume` at the APF, then
`deliver` under the signed consume receipt. Only then does the message enter the
application inbox (`GET /app/inbox`). A copy that fails any check is recorded as a
rejection with its error code and is never delivered.

### 3.4 Revocation and repair (§5.4, C-20 to C-27)

1. A `revoke` of a roster reader's read right closes the APF read fence. Every new
   release and every consume is `read_fenced`.
2. A continuing member (`/control/repair`) asks for the `repair_plan`, stages the
   Remove commit, submits it (kind repair), applies the ack, publishes the commit
   and confirms.
3. Every other continuing member applies the commit and confirms automatically. The
   APF opens the fence on the committer's confirmation plus one matching
   confirmation (`evidence: pair`).
4. The removed member's sidecar applies its own removal and becomes inactive.

### 3.5 Rekey (§5.5, C-28)

A `grant` of write, admin or admit to a current member is only an offer
(`{pending: true}`). The subject sidecar (`/control/rekey`) generates a new signature
key from its entropy source, stages `self_update_with_new_signer` with the new
`authz_incarnation`, and submits it (kind update). The APF replaces the registered
key; the old key no longer authenticates.

### 3.6 Durability and delivery guarantees

- **APF.** The adapter directory is on disk (a volume in containers); a restarted APF
  reopens it and recovers interrupted requests (contract C-31 to C-34).
- **Agents.** With `ATT_DATA_DIR` a sidecar stores its identity (`identity.json`, mode
  0600, restored with agent-trust `ClientIdentity::restore`), its MLS state
  (agent-trust `LabEntropy::durable_provider`, one SQLite file) and its bookkeeping
  (`state.json`). The request sequence is written before each request is sent, so a
  restart never reuses one. A restarted agent resumes as the same member.
- **Mailbox: at least once.** A fetch leases the returned messages; the agent
  acknowledges them only after it has processed them and saved its state. A lease
  that ends sends the messages again.
- **Delivery: at most once.** A copy that MLS already decrypted fails again
  (`undecryptable`); a consumed pair is never consumed twice (`replay`). Crash windows
  can lose a message (B4, B5), never duplicate one.
- **APF outage.** A consumption that fails in transport is retried every poll with
  the decrypted message held; nothing is delivered before the APF consents.
- **Epoch changes.** Before applying a commit, an agent drains its mailbox at the
  current epoch; an envelope of a later epoch waits in a buffer until the commit
  arrives. A message still unconsumed when the APF's epoch moves cannot be delivered
  (finding F-7): the kernel binds `consume` to its current epoch.
- **Commit log.** The relay's handshake log is untrusted. An entry applies only under
  an APF ack whose parent is the member's frontier; an older parent is skipped, a
  newer one waits for the missing commit, and the cursor moves only over a contiguous
  run of resolved indices, so a hidden entry is fetched once it appears (E4).

### 3.7 Adversary mode

`POST /control/adversary {retain: true}` turns an agent into the retained key
adversary of contract §5.4: it stops applying commits, keeps the keys of its last
epoch, and for every envelope that reaches it (the relay can be told to leak copies
with `tap`) it tries a raw OpenMLS `process_message`, bypassing every agent-trust
check, and tries `consume` at the APF anyway. Both outcomes are recorded.

## 4. Integration seam

An application integrates with exactly two calls on its own sidecar:
`POST /app/send` and `GET /app/inbox`, both with the app token
(`examples/echo_agent.py`). The application never handles keys, MLS state, the APF
protocol or the relay. Any agent framework in any language can therefore sit on
top, and the trust stack under it can change (another entropy source, another
deployment backend, another APF revision) without a change in the application.

## 5. Determinism and randomness

- Keys, MLS secrets and HPKE randomness come from the selected entropy source on
  every node (agent-trust C-40). With `source = "qrng"` that is the QRNG service over
  the network. The `qrng-mock` service serves OS RNG bytes: it is a mock, and no
  quantum origin is claimed for any run that uses it.
- The relay fault schedule comes from a SplitMix64 stream seeded by the experiment.
  It never touches cryptography. Thread timing still varies between runs, so a seed
  fixes the fault decisions per fetch, not the global interleaving.
