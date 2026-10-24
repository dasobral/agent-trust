# Service protocol reference

All services speak HTTP with JSON bodies. Byte strings are lowercase hex.

- A protocol outcome is HTTP 200 with `{"ok": value}` or `{"error": "<code>: <detail>"}`.
  The codes are the agent-trust error codes (`unauthorized`, `read_fenced`,
  `binding_mismatch`, `undecryptable`, `noncanonical_commit`, `stale_frontier`,
  `entropy_unavailable`, ...), plus `not_ready` and `transport`.
- A transport problem uses a 4xx status: `401` for a missing or wrong token, `404`
  for an unknown path, `400` for a body that is not JSON.
- `GET /healthz` answers `{"ok": "<role>"}` on every service.
- `Authorization: Bearer <token>` carries a token. A service that has no token
  configured accepts every call on that API.

## Common configuration

| Variable | Services | Meaning |
|---|---|---|
| `ATT_LISTEN` | all | Listen address (defaults: apf `0.0.0.0:7000`, relay `:7100`, qrng `:7200`, agent `:7300`) |
| `ATT_CONTROL_TOKEN` | all | Token of the `/control/*` API |
| `AGENT_TRUST_ENTROPY_SOURCE` | apf, agent | `os`, `mock` or `qrng` (agent-trust C-40) |
| `AGENT_TRUST_MOCK_SEED` | apf, agent | Seed of the `mock` source |
| `AGENT_TRUST_QRNG_BASE_URL` | apf, agent | QRNG Open API base URL for `qrng` |
| `AGENT_TRUST_QRNG_*` | apf, agent | TLS material and API secrets of a real endpoint (agent-trust `src/entropy.rs`) |
| `AGENT_TRUST_ENTROPY_CONFIG` | apf, agent | A TOML file instead of the variables above |

A node whose entropy source cannot be selected or reached exits before it serves
any request, with no fallback (C-40).

## `att-node apf`

| Variable | Meaning |
|---|---|
| `ATT_GROUP`, `ATT_ROOT` | The only group and root that genesis accepts |
| `ATT_STATE_DIR` | Adapter directory: `authority.sqlite`, `adapter.sqlite`, `sequencer.sqlite`, `apf-signing-key` (mode 0600). Reopened on restart. |
| `ATT_BOOTSTRAP_TOKEN` | Token of the genesis endpoints |

| Method and path | Token | Body → result |
|---|---|---|
| `GET /v1/info` | none | `{group, root, state: waiting\|pending\|ready, apf_public_key, apf_key_id, entropy}` |
| `GET /v1/state` | none | Policy view: `{group, epoch, branch, policy_revision, read_fenced, repair_pending, roster, grants}` |
| `POST /v1/request` | none (signed) | `{actor, sequence, body, signature}` → the adapter result. `body` is the hex of the exact signed JSON bytes, `signature` the Ed25519 signature over `RequestTBS` (contract §4.8). |
| `POST /v1/genesis/begin` | bootstrap | `{group, root, root_key}` → `{apf_public_key, founder_certificate, acc_context}` |
| `POST /v1/genesis/complete` | bootstrap | `{group_info, ratchet_tree}` → `{epoch, branch}` |
| `GET /control/checkpoint` | control | Full kernel checkpoint, history included |
| `GET /control/trace` | control | `{trace}`: the C-37 trace contract v2 export |
| `GET /control/adapter-trace` | control | Raw adapter trace `{actor, sequence, command, outcome}` |
| `GET /control/entropy` | control | `{source, requests, bytes, failures}` |

Routed commands of `POST /v1/request` are the adapter's: `grant`, `delegate`,
`revoke`, `invoke`, `allocate`, `release`, `persist`, `emit`, `consume`, `abandon`,
`admission_certificate`, `submit_commit`, `repair_plan`, `confirm_repair`.

## `att-node relay`

| Variable | Meaning |
|---|---|
| `ATT_SEED` | Initial seed of the fault schedule |

| Method and path | Token | Body → result |
|---|---|---|
| `POST /v1/groups/{g}/handshake` | none | Any JSON object → `{index}`; the relay adds `index` |
| `GET /v1/groups/{g}/handshake?after=N` | none | Entries with `index >= N`, in order. Never faulted. |
| `PUT /v1/keypackages/{subject}` | none | `{key_package}` |
| `GET /v1/keypackages/{subject}` | none | The stored object, removed on read |
| `POST /v1/mailbox/{to}` | none | `{from, op, envelope}` |
| `GET /v1/mailbox/{to}` | none | Queued messages, with the faults applied (below) |
| `POST /control/faults` | control | `{drop, duplicate, reorder, seed}`: percentages 0 to 100 |
| `POST /control/hold` | control | `{mailbox, held}`: a held mailbox returns nothing |
| `POST /control/tap` | control | `{victim, observer, enabled}`: copy every message for the victim to the observer, marked `tapped_from` |
| `GET /control/stats` | control | `{posted, fetched, dropped, duplicated, tapped, queued, pending, held, handshake, key_packages, faults}` |

Fault model at fetch time, per queued message: with probability `drop` the attempt
is lost and the message stays queued (the next fetch retransmits the same bytes);
otherwise the message is returned and, with probability `duplicate`, one extra copy
stays queued (a copy is never duplicated again, so every queue drains). With
`reorder` each returned batch is shuffled.

## `att-node agent`

| Variable | Meaning |
|---|---|
| `ATT_NAME`, `ATT_GROUP` | Subject name and group |
| `ATT_APF_URL`, `ATT_RELAY_URL` | Service addresses |
| `ATT_APP_TOKEN` | Token of the application API |
| `ATT_BOOTSTRAP_TOKEN` | Root agent only |
| `ATT_APF_PUBLIC_KEY` | Optional pinned APF public key (hex) |
| `ATT_POLL_MS` | Relay poll interval, default 100 |

At start the sidecar connects its entropy source and generates its identity. Its
key never leaves the process.

Application API (app token):

| Method and path | Body → result |
|---|---|
| `POST /app/send` | `{text}` or `{payload_hex}`, optional `content_type`, `op` → `{op, recipients, epoch}` or the refusal code |
| `GET /app/inbox?after=N` | Delivered messages `{seq, op, from, content_type, payload_hex, text}` |
| `GET /app/status` | Same as `/control/status` |

Control API (control token):

| Method and path | Body → result |
|---|---|
| `GET /control/status` | `{name, public_key, membership: candidate\|joining\|member\|removed, epoch, branch, cursor, retain, polls, sequence, inbox, rejections, adversary, confirmations, errors, entropy}` |
| `GET /control/entropy` | Entropy report |
| `POST /control/genesis` | Root only (§3.1 of architecture.md) |
| `POST /control/delegate` | `{subject, subject_key, rights, resources?, ttl_secs?, depth?}` |
| `POST /control/request` | `{body}`: any routed APF command, signed by this agent |
| `POST /control/join` | Candidate: prepare, certify and publish a KeyPackage |
| `POST /control/add` | `{subject}`: admit a published KeyPackage |
| `POST /control/repair` | Plan, commit, publish and confirm a repair |
| `POST /control/rekey` | `{right, generation}`: after an offer, commit a new key |
| `POST /control/sync` | Apply the handshake log now; returns the status |
| `POST /control/adversary` | `{retain}`: retained key adversary mode |

## `att-node qrng-mock`

**A mock.** It serves the QRNG Open API with bytes from the OS RNG.

| Method and path | Token | Body → result |
|---|---|---|
| `GET /capabilities` | none | Block sizes 1 to 1024, one block per request |
| `POST /entropy` | none | `{block_size, block_count: 1}` → `{entropy: [base64]}`; 503 during an outage |
| `GET /healthtest` | none | Empty health report; 503 during an outage |
| `POST /control/outage` | control | `{available}` |
| `GET /control/stats` | control | `{mock: true, available, requests, bytes, refused, clients}` (bytes per client address) |
