//! Lab driver and trace export (`docs/adapter-contract.md` C-36, C-37, C-39).
//!
//! The lab drives the adapter and client endpoints only through their public APIs;
//! the export reads only the persisted kernel history and adapter store.
//!
//! Randomness: the adapter, every client and every lab identity key draw from one
//! selected entropy source (C-40, `crate::entropy`): the OS-seeded RustCrypto rand by
//! default, the in-process `MockEntropy` (NOT random), or a QRNG Open API endpoint. The
//! lab seed drives only the delivery schedule (`Schedule`), a deterministic test-only
//! generator that is never used for cryptography. Time comes from a fixed clock.
//!
//! Suite: every lab identity, and so the group and the APF key, belongs to one selected
//! suite (C-42): `pq` (ML-DSA-44 and X-Wing) or `classical` (Ed25519 and X25519).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, Write};
use std::path::Path;

use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::adapter::{Adapter, ClientIdentity, Clock, SignedRequest, ADAPTER_FILE, AUTHORITY_FILE};
use crate::client::{ClientEndpoint, JoinCandidate, PreparedJoin, StagedAdd};
use crate::entropy::{LabEntropy, LabProvider};
use crate::suite::Suite;
use crate::wire::{operation_digest, Frontier, ReleaseCertificate, Right, SignedStructure};

/// The lab's fixed trusted time (C-36).
const LAB_NOW: u64 = 1_000_000;
/// Expiry of every lab delegation: far after `LAB_NOW`, within the root's `u64::MAX`.
const DELEGATION_EXPIRES: u64 = 4_102_444_800;
/// Delegation depth of every lab subject (the root's depth is 8).
const DELEGATION_DEPTH: u64 = 4;
/// Content type of every lab application message.
const CONTENT_TYPE: &[u8] = b"application/octet-stream";
/// The root's generation-0 rights created by kernel `init`, in right-code order.
const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];
/// Percent of delivery attempts that the schedule drops.
const DROP_PERCENT: u64 = 20;
/// Percent of delivery attempts that the schedule also duplicates later in the round.
const DUPLICATE_PERCENT: u64 = 20;

type Provider = LabProvider;
type Endpoint = ClientEndpoint<Provider>;

/// The fixed lab clock.
#[derive(Clone, Copy, Debug)]
struct LabClock;

impl Clock for LabClock {
    fn now(&self) -> u64 {
        LAB_NOW
    }
}

/// Deterministic, test-only delivery schedule generator (SplitMix64). It decides only
/// the order, loss and duplication of queued envelopes; it is never used for keys.
struct Schedule(u64);

impl Schedule {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..bound` (`bound > 0`); the modulo bias is irrelevant here.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

// ---------------------------------------------------------------------------
// Lab protocol (C-36, C-39)
// ---------------------------------------------------------------------------

/// Runs the line-delimited JSON lab protocol (C-36) against a new adapter in `dir`,
/// with the OS entropy source. `seed` drives only the delivery schedule.
pub fn run_lab(
    dir: &Path,
    seed: u64,
    input: impl BufRead,
    output: impl Write,
) -> Result<(), String> {
    run_lab_with(dir, seed, LabEntropy::os()?, input, output)
}

/// [`run_lab`] with the selected entropy source (C-40), in the `classical` suite. Kept for
/// existing callers; [`run_lab_with_suite`] selects the suite (C-42).
pub fn run_lab_with(
    dir: &Path,
    seed: u64,
    entropy: LabEntropy,
    input: impl BufRead,
    output: impl Write,
) -> Result<(), String> {
    run_lab_with_suite(dir, seed, entropy, Suite::Classical, input, output)
}

/// [`run_lab`] with the selected entropy source (C-40) and suite (C-42).
pub fn run_lab_with_suite(
    dir: &Path,
    seed: u64,
    entropy: LabEntropy,
    suite: Suite,
    input: impl BufRead,
    mut output: impl Write,
) -> Result<(), String> {
    let mut lab = Lab {
        dir,
        schedule: Schedule(seed),
        entropy,
        suite,
        world: None,
    };
    for line in input.lines() {
        let line = line.map_err(|err| format!("failed to read lab input: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match lab.handle_line(&line) {
            Ok(value) => json!({ "ok": value }),
            Err(error) if error.is_empty() => json!({ "error": "malformed" }),
            Err(error) => json!({ "error": error }),
        };
        serde_json::to_writer(&mut output, &response)
            .map_err(|err| format!("failed to write lab output: {err}"))?;
        output
            .write_all(b"\n")
            .and_then(|()| output.flush())
            .map_err(|err| format!("failed to write lab output: {err}"))?;
    }
    Ok(())
}

struct Lab<'a> {
    dir: &'a Path,
    schedule: Schedule,
    entropy: LabEntropy,
    /// The suite of every lab identity (C-42).
    suite: Suite,
    world: Option<World>,
}

impl Lab<'_> {
    fn handle_line(&mut self, line: &str) -> Result<Value, String> {
        let request: Value =
            serde_json::from_str(line).map_err(|_| "malformed: request is not JSON")?;
        let object = request.as_object().ok_or("malformed: request object")?;
        if object.keys().any(|key| key != "op" && key != "args") {
            return Err("malformed: request fields".into());
        }
        let name = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or("malformed: op")?;
        let args = match object.get("args") {
            None => Map::new(),
            Some(Value::Object(args)) => args.clone(),
            Some(_) => return Err("malformed: args".into()),
        };
        match name {
            "genesis" => return self.genesis(&args),
            "entropy" => {
                only(&args, &[])?;
                return Ok(self.entropy.report());
            }
            "suite" => {
                only(&args, &[])?;
                let ciphersuite = u16::from(self.suite.ciphersuite());
                return Ok(json!({
                    "suite": self.suite.name(),
                    "ciphersuite": format!("0x{ciphersuite:04x}"),
                }));
            }
            "entropy_outage" => {
                only(&args, &["available"])?;
                let available = args
                    .get("available")
                    .and_then(Value::as_bool)
                    .ok_or("malformed: available")?;
                self.entropy.set_available(available)?;
                return Ok(self.entropy.report());
            }
            _ => {}
        }
        let Some(world) = self.world.as_mut() else {
            return Err("uninitialized: no lab group".into());
        };
        let failures = self.entropy.failures();
        let result = match name {
            "delegate" => world.delegate(&args),
            "admit" => world.admit(&args),
            "send" => world.send(&args),
            "deliver" => {
                only(&args, &[])?;
                world.deliver(&mut self.schedule)
            }
            "revoke" => world.revoke(&args),
            "repair" => world.repair(&args),
            "rekey" => world.rekey(&args),
            "export_trace" => {
                only(&args, &[])?;
                Ok(json!({ "trace": export_v2_trace(self.dir)? }))
            }
            "summary" => {
                only(&args, &[])?;
                world.summary()
            }
            _ => Err("malformed: unknown request".into()),
        };
        // A step that fails while the source refuses a draw is `entropy_unavailable`
        // (§12), also where OpenMLS reports the refusal as another error (C-40). The `os`
        // source keeps no failure count.
        match (result, failures, self.entropy.failures()) {
            (Err(_), Some(before), Some(after)) if after > before => {
                Err("entropy_unavailable".into())
            }
            (result, _, _) => result,
        }
    }

    /// `genesis {group, root}`: a new full adapter (§5.1). An existing adapter directory
    /// is refused by `begin_genesis` before anything is written (C-5, C-8, C-39).
    fn genesis(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["group", "root"])?;
        if self.world.is_some() {
            return Err("already_initialized: the lab already has a group".into());
        }
        let group = text(args, "group")?;
        let root = text(args, "root")?;
        std::fs::create_dir_all(self.dir)
            .map_err(|err| format!("malformed: lab directory: {err}"))?;
        let root_provider = self.entropy.provider();
        let identity = ClientIdentity::generate_for(self.suite, root_provider.rand())?;
        let signer = identity.signer().clone();
        let pending = Adapter::begin_genesis(
            self.dir,
            &group,
            &root,
            identity.public_key(),
            self.entropy.provider(),
            LabClock,
        )?;
        let apf_public = pending.apf_public_key().to_vec();
        let founder_certificate = pending.founder_certificate().to_vec();
        let apf_anchor = pending.apf_anchor().to_vec();
        let endpoint = ClientEndpoint::found(
            &group,
            &root,
            &ROOT_RIGHTS,
            identity,
            root_provider,
            &founder_certificate,
            &apf_anchor,
            &apf_public,
        )?;
        let group_info = endpoint.export_group_info()?;
        let ratchet_tree = endpoint.export_ratchet_tree()?;
        let mut adapter = pending.complete(&group_info, &ratchet_tree)?;
        let frontier = adapter.frontier()?;
        let mut actors = BTreeMap::new();
        actors.insert(
            root.clone(),
            Actor {
                signer,
                sequence: 0,
                candidate: None,
                endpoint: Some(endpoint),
            },
        );
        self.world = Some(World {
            entropy: self.entropy.clone(),
            suite: self.suite,
            adapter,
            group: group.clone(),
            root: root.clone(),
            apf_public,
            crypto: RustCrypto::default(),
            actors,
            queue: Vec::new(),
            delivered_pairs: BTreeSet::new(),
            delivered: 0,
            duplicate_deliveries: 0,
        });
        Ok(json!({
            "group": group, "root": root, "epoch": frontier.epoch, "branch": frontier.branch
        }))
    }
}

/// One lab principal: its registered request key and, once admitted, its endpoint.
struct Actor {
    /// The currently registered request key (the leaf signature key once admitted).
    signer: SignatureKeyPair,
    /// The last request sequence used (§4.8).
    sequence: u64,
    /// A delegated subject's own identity and provider, until it is admitted.
    candidate: Option<(ClientIdentity, Provider)>,
    endpoint: Option<Endpoint>,
}

/// One queued copy of an emitted envelope for one recipient.
#[derive(Clone)]
struct Queued {
    to: String,
    op: String,
    envelope: Vec<u8>,
    payload: Vec<u8>,
}

/// One scheduled delivery attempt of a queue entry.
enum Attempt {
    Drop(usize),
    Copy(usize),
}

struct World {
    /// The selected entropy source for new providers and identities.
    entropy: LabEntropy,
    /// The suite of every new identity (C-42).
    suite: Suite,
    adapter: Adapter<Provider, LabClock>,
    group: String,
    root: String,
    apf_public: Vec<u8>,
    /// Signature verification only; never used to generate keys.
    crypto: RustCrypto,
    actors: BTreeMap<String, Actor>,
    queue: Vec<Queued>,
    /// `(op, recipient)` pairs delivered to the application.
    delivered_pairs: BTreeSet<(String, String)>,
    /// Application deliveries.
    delivered: u64,
    /// Application deliveries of an already delivered pair.
    duplicate_deliveries: u64,
}

impl World {
    /// Signs `body` as `actor` with its registered key at its next sequence and handles it.
    fn request(&mut self, actor: &str, body: Value) -> Result<Value, String> {
        let entry = self
            .actors
            .get_mut(actor)
            .ok_or_else(|| format!("unauthorized: {actor} has no lab identity"))?;
        entry.sequence += 1;
        let request =
            SignedRequest::sign(&self.group, actor, entry.sequence, &body, &entry.signer)?;
        self.adapter.handle(&request)
    }

    fn endpoint_mut(&mut self, name: &str) -> Result<&mut Endpoint, String> {
        self.actors
            .get_mut(name)
            .and_then(|actor| actor.endpoint.as_mut())
            .ok_or_else(|| format!("unauthorized: {name} is not a lab member"))
    }

    /// Applies an acked commit at every endpoint of `parent_roster` except `skip`.
    fn apply_to_members(
        &mut self,
        parent_roster: &[String],
        skip: &str,
        commit: &[u8],
        ack: &[u8],
    ) -> Result<(), String> {
        for name in parent_roster {
            if name == skip {
                continue;
            }
            if let Some(endpoint) = self
                .actors
                .get_mut(name)
                .and_then(|actor| actor.endpoint.as_mut())
            {
                endpoint
                    .apply_ack(commit, ack)
                    .map_err(|err| format!("{err} (member {name} applying the ack)"))?;
            }
        }
        Ok(())
    }

    /// Submits a staged commit as `committer`; a refused commit is cleared at the client.
    fn submit(
        &mut self,
        committer: &str,
        kind: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> Result<(Frontier, Vec<u8>), String> {
        let body = json!({
            "command": "submit_commit", "kind": kind, "parent_epoch": parent.epoch,
            "parent_branch": parent.branch, "commit": hex::encode(commit)
        });
        match self.request(committer, body) {
            Ok(response) => {
                let frontier = Frontier {
                    epoch: response["epoch"].as_u64().ok_or("malformed: ack epoch")?,
                    branch: response["branch"]
                        .as_str()
                        .ok_or("malformed: ack branch")?
                        .to_owned(),
                };
                Ok((frontier, hex_field(&response, "ack")?))
            }
            Err(error) => {
                if let Ok(endpoint) = self.endpoint_mut(committer) {
                    let _ = endpoint.discard_pending();
                }
                Err(error)
            }
        }
    }

    /// `delegate {subject, rights}` by the root on the group resource. The subject's own
    /// provider generates its key; the root submits only the public half (C-1).
    fn delegate(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["subject", "rights"])?;
        let subject = text(args, "subject")?;
        let rights = texts(args, "rights")?;
        let provider = self.entropy.provider();
        let identity = ClientIdentity::generate_for(self.suite, provider.rand())?;
        let body = json!({
            "command": "delegate", "subject": subject, "rights": rights,
            "resources": [self.group], "expires_at": DELEGATION_EXPIRES, "not_before": 0,
            "depth": DELEGATION_DEPTH, "subject_key": hex::encode(identity.public_key())
        });
        let root = self.root.clone();
        let response = self.request(&root, body)?;
        self.actors.entry(subject).or_insert(Actor {
            signer: identity.signer().clone(),
            sequence: 0,
            candidate: Some((identity, provider)),
            endpoint: None,
        });
        Ok(response)
    }

    /// `admit {subject, by}`: the full candidate flow (§5.2); every current member and
    /// the joiner apply the ack.
    fn admit(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["subject", "by"])?;
        let subject = text(args, "subject")?;
        let by = text(args, "by")?;
        self.endpoint_mut(&by)?;
        let actor = self
            .actors
            .get_mut(&subject)
            .ok_or_else(|| format!("unauthorized: {subject} has no lab identity"))?;
        if actor.endpoint.is_some() {
            return Err(format!("invalid_transition: {subject} is already a member"));
        }
        let (identity, provider) = actor.candidate.take().ok_or_else(|| {
            format!("invalid_transition: {subject} has no unused candidate identity")
        })?;
        let checkpoint = self.adapter.checkpoint()?;
        let parent_roster = roster_of(&checkpoint)?;
        let rights = active_rights(&checkpoint, &subject)?;
        // Until the Add is acked, a refused step leaves the subject a candidate with the
        // identity whose key the kernel registered at `delegate` (C-40).
        let prepared = match PreparedJoin::try_prepare(
            &self.group,
            &subject,
            &rights,
            identity,
            provider,
            &self.apf_public,
        ) {
            Ok(prepared) => prepared,
            Err(unprepared) => {
                self.restore_candidate(&subject, unprepared.identity, unprepared.provider);
                return Err(unprepared.error);
            }
        };
        let body = json!({
            "command": "admission_certificate",
            "key_package_preimage": hex::encode(prepared.preimage())
        });
        let certificate = match self
            .request(&subject, body)
            .and_then(|response| hex_field(&response, "certificate"))
        {
            Ok(certificate) => certificate,
            Err(error) => {
                let (identity, provider) = prepared.abandon();
                self.restore_candidate(&subject, identity, provider);
                return Err(error);
            }
        };
        let candidate = prepared.finalize(&certificate)?;
        let (staged, (frontier, ack)) = match self.stage_and_submit_add(&by, &candidate) {
            Ok(acked) => acked,
            Err(error) => {
                // The old provider's storage holds the dropped KeyPackage's private keys.
                let (identity, _) = candidate.abandon();
                let provider = self.entropy.provider();
                self.restore_candidate(&subject, identity, provider);
                return Err(error);
            }
        };
        self.endpoint_mut(&by)?.apply_ack(&staged.commit, &ack)?;
        self.apply_to_members(&parent_roster, &by, &staged.commit, &ack)?;
        let joined = candidate.join(&staged.welcome, &ack)?;
        if joined.frontier()? != frontier {
            return Err("binding_mismatch: joined frontier".into());
        }
        if let Some(actor) = self.actors.get_mut(&subject) {
            actor.endpoint = Some(joined);
        }
        Ok(json!({ "subject": subject, "epoch": frontier.epoch, "branch": frontier.branch }))
    }

    /// `by` stages the candidate's Add and submits it; returns the staged Add and its ack.
    fn stage_and_submit_add(
        &mut self,
        by: &str,
        candidate: &JoinCandidate<Provider>,
    ) -> Result<(StagedAdd, (Frontier, Vec<u8>)), String> {
        let staged = self.endpoint_mut(by)?.stage_add(candidate.key_package())?;
        let acked = self.submit(by, "admit", &staged.parent, &staged.commit)?;
        Ok((staged, acked))
    }

    /// Gives `subject` its unused candidate identity and provider back.
    fn restore_candidate(&mut self, subject: &str, identity: ClientIdentity, provider: Provider) {
        if let Some(actor) = self.actors.get_mut(subject) {
            actor.candidate = Some((identity, provider));
        }
    }

    /// `send {from, op, payload}`: allocate, release with an honest cover, protect,
    /// persist and emit, then queue the envelope for every roster reader except the sender.
    fn send(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["from", "op", "payload"])?;
        let from = text(args, "from")?;
        let op = text(args, "op")?;
        let payload = hex_payload(&text(args, "payload")?)?;
        self.endpoint_mut(&from)?;

        self.request(&from, json!({ "command": "allocate", "op": op }))?;
        let checkpoint = self.adapter.checkpoint()?;
        let frontier = frontier_of(&checkpoint)?;
        let policy_revision = checkpoint["policy_revision"]
            .as_u64()
            .ok_or("malformed: kernel policy_revision")?;
        // The writer singleton plus every roster reader singleton (C-14), each at the
        // grant record's generation; the kernel decides whether they are active.
        let mut cover = vec![json!([{
            "subject": from, "right": "write",
            "generation": generation_of(&checkpoint, &from, "write")?.unwrap_or(0)
        }])];
        for reader in roster_of(&checkpoint)? {
            let generation = generation_of(&checkpoint, &reader, "read")?.unwrap_or(0);
            cover.push(json!([{ "subject": reader, "right": "read", "generation": generation }]));
        }
        let digest = operation_digest(
            &op,
            &self.group,
            CONTENT_TYPE,
            &payload,
            &frontier,
            policy_revision,
        )?;
        let body = json!({
            "command": "release", "op": op, "right": "write", "digest": digest, "cover": cover,
            "policy_revision": policy_revision, "epoch": frontier.epoch, "branch": frontier.branch
        });
        let response = self.request(&from, body)?;
        let certificate = hex_field(&response, "certificate")?;
        let released = ReleaseCertificate::verify(&certificate, &self.apf_public, &self.crypto)?;
        let envelope = self
            .endpoint_mut(&from)?
            .protect(&certificate, CONTENT_TYPE, &payload)?;
        let envelope_hex = hex::encode(&envelope);
        self.request(
            &from,
            json!({ "command": "persist", "op": op, "envelope": envelope_hex }),
        )?;
        self.request(
            &from,
            json!({ "command": "emit", "op": op, "envelope": envelope_hex }),
        )?;
        let recipients: Vec<String> = released
            .readers
            .iter()
            .map(|(reader, _)| reader.clone())
            .filter(|reader| *reader != from)
            .collect();
        for to in &recipients {
            self.queue.push(Queued {
                to: to.clone(),
                op: op.clone(),
                envelope: envelope.clone(),
                payload: payload.clone(),
            });
        }
        Ok(json!({ "op": op, "recipients": recipients }))
    }

    /// `deliver {}`: one seeded round over the queue. The round shuffles the queue
    /// (reorder), drops some attempts (the entry stays queued and is later retransmitted
    /// byte-identically) and repeats some copies at the end of the round (duplicate).
    /// Each copy runs receive, consume and deliver. A copy that was attempted leaves the
    /// queue, whether it was delivered or rejected.
    fn deliver(&mut self, schedule: &mut Schedule) -> Result<Value, String> {
        let count = self.queue.len();
        let mut order: Vec<usize> = (0..count).collect();
        for index in (1..count).rev() {
            let other = schedule.below(index as u64 + 1) as usize;
            order.swap(index, other);
        }
        let mut plan = Vec::with_capacity(count);
        let mut duplicates = Vec::new();
        for index in order {
            let roll = schedule.below(100);
            if roll < DROP_PERCENT {
                plan.push(Attempt::Drop(index));
            } else {
                plan.push(Attempt::Copy(index));
                if roll < DROP_PERCENT + DUPLICATE_PERCENT {
                    duplicates.push(index);
                }
            }
        }
        plan.extend(duplicates.into_iter().map(Attempt::Copy));

        let mut attempted = vec![false; count];
        let mut attempts = Vec::with_capacity(plan.len());
        for step in plan {
            let (index, outcome) = match step {
                Attempt::Drop(index) => (index, "dropped".to_owned()),
                Attempt::Copy(index) => {
                    let entry = self.queue[index].clone();
                    attempted[index] = true;
                    let outcome = match self.attempt(&entry) {
                        Ok(()) => "delivered".to_owned(),
                        Err(error) => error_code(&error),
                    };
                    (index, outcome)
                }
            };
            let entry = &self.queue[index];
            attempts.push(json!({ "to": entry.to, "op": entry.op, "outcome": outcome }));
        }
        let mut index = 0;
        self.queue.retain(|_| {
            let keep = !attempted[index];
            index += 1;
            keep
        });
        Ok(Value::Array(attempts))
    }

    /// Receive, consume and deliver one copy (§5.3 step 7, C-15, C-18).
    fn attempt(&mut self, entry: &Queued) -> Result<(), String> {
        let pending = self
            .actors
            .get_mut(&entry.to)
            .and_then(|actor| actor.endpoint.as_mut())
            .ok_or("not_ready: no endpoint")?
            .receive(&entry.envelope)?;
        if pending.op() != entry.op {
            return Err("binding_mismatch: operation".into());
        }
        let response = self.request(&entry.to, json!({ "command": "consume", "op": entry.op }))?;
        let (content_type, payload) = pending.deliver(&hex_field(&response, "receipt")?)?;
        if content_type != CONTENT_TYPE || payload != entry.payload {
            return Err("binding_mismatch: delivered content".into());
        }
        if !self
            .delivered_pairs
            .insert((entry.op.clone(), entry.to.clone()))
        {
            self.duplicate_deliveries += 1;
        }
        self.delivered += 1;
        Ok(())
    }

    /// `revoke {subject, right}` by the root.
    fn revoke(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["subject", "right"])?;
        let body = json!({
            "command": "revoke", "subject": text(args, "subject")?, "right": text(args, "right")?
        });
        let root = self.root.clone();
        self.request(&root, body)
    }

    /// `repair {by}`: plan, stage, submit, every member applies the ack, then the
    /// committer and one other continuing member confirm (or the committer alone).
    fn repair(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["by"])?;
        let by = text(args, "by")?;
        self.endpoint_mut(&by)?;
        let plan = self.request(&by, json!({ "command": "repair_plan" }))?;
        let removed: Vec<String> = plan["removed"]
            .as_array()
            .ok_or("malformed: repair plan removed")?
            .iter()
            .map(|name| name.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or("malformed: repair plan removed")?;
        let parent_roster = roster_of(&self.adapter.checkpoint()?)?;
        let staged = self.endpoint_mut(&by)?.stage_repair(&removed)?;
        let (frontier, ack) = self.submit(&by, "repair", &staged.parent, &staged.commit)?;
        self.endpoint_mut(&by)?.apply_ack(&staged.commit, &ack)?;
        let continuing: Vec<String> = parent_roster
            .iter()
            .filter(|name| !removed.contains(name))
            .cloned()
            .collect();
        self.apply_to_members(&continuing, &by, &staged.commit, &ack)?;
        // A removed member accepts its own removal under the repair ack (C-26) and has
        // no further role in the lab; its endpoint is dropped either way.
        for name in &removed {
            if let Some(actor) = self.actors.get_mut(name) {
                if let Some(mut endpoint) = actor.endpoint.take() {
                    let _ = endpoint.apply_ack(&staged.commit, &ack);
                }
            }
        }

        let mut response = self.confirm(&by)?;
        if response["opened"] != json!(true) {
            let other = roster_of(&self.adapter.checkpoint()?)?
                .into_iter()
                .find(|name| {
                    *name != by
                        && self
                            .actors
                            .get(name)
                            .is_some_and(|actor| actor.endpoint.is_some())
                })
                .ok_or("unconfirmed: no other continuing member")?;
            response = self.confirm(&other)?;
            if response["opened"] != json!(true) {
                return Err("unconfirmed: the fence stayed closed".into());
            }
        }
        Ok(json!({
            "removed": removed, "epoch": frontier.epoch, "branch": frontier.branch,
            "evidence": response["evidence"]
        }))
    }

    fn confirm(&mut self, member: &str) -> Result<Value, String> {
        let confirmation = self.endpoint_mut(member)?.confirmation()?;
        self.request(
            member,
            json!({ "command": "confirm_repair", "confirmation": hex::encode(confirmation) }),
        )
    }

    /// `rekey {subject, right, generation}`: the root's offer, `stage_rekey` with a new
    /// identity, submit, and every member applies the ack (C-28).
    fn rekey(&mut self, args: &Map<String, Value>) -> Result<Value, String> {
        only(args, &["subject", "right", "generation"])?;
        let subject = text(args, "subject")?;
        let right_name = text(args, "right")?;
        let right = Right::from_name(&right_name).ok_or("malformed: right")?;
        let generation = args
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or("malformed: generation")?;
        self.endpoint_mut(&subject)?;
        if !roster_of(&self.adapter.checkpoint()?)?.contains(&subject) {
            return Err(format!(
                "invalid_transition: {subject} is not a current member"
            ));
        }
        let body = json!({
            "command": "grant", "subject": subject, "right": right_name,
            "generation": generation, "fresh_keys": true
        });
        let root = self.root.clone();
        if self.request(&root, body)? != json!({ "pending": true }) {
            return Err("invalid_transition: the grant was not a rekey offer".into());
        }
        let checkpoint = self.adapter.checkpoint()?;
        let parent_roster = roster_of(&checkpoint)?;
        let mut rights: Vec<(Right, u64)> = active_rights(&checkpoint, &subject)?
            .into_iter()
            .filter(|(held, _)| *held != right)
            .collect();
        rights.push((right, generation));
        rights.sort();
        let new_identity = ClientIdentity::generate_for(self.suite, &self.entropy.rand())?;
        let new_signer = new_identity.signer().clone();
        let staged = self
            .endpoint_mut(&subject)?
            .stage_rekey(new_identity, &rights)?;
        let (frontier, ack) = self.submit(&subject, "update", &staged.parent, &staged.commit)?;
        // The adapter replaced the registered key in the same step (C-28 step 7).
        if let Some(actor) = self.actors.get_mut(&subject) {
            actor.signer = new_signer;
        }
        self.endpoint_mut(&subject)?
            .apply_ack(&staged.commit, &ack)?;
        self.apply_to_members(&parent_roster, &subject, &staged.commit, &ack)?;
        Ok(json!({
            "subject": subject, "right": right_name, "generation": generation,
            "epoch": frontier.epoch, "branch": frontier.branch
        }))
    }

    /// `summary {}`. `deliveries_without_consume` counts delivered pairs that the kernel
    /// has no consumption record for.
    fn summary(&mut self) -> Result<Value, String> {
        let checkpoint = self.adapter.checkpoint()?;
        let frontier = frontier_of(&checkpoint)?;
        let consumed: BTreeSet<(String, String)> = checkpoint["history"]
            .as_array()
            .and_then(|history| history.last())
            .map(|last| consumed_of(&last["event"]["snapshot"]))
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .collect();
        let without_consume = self
            .delivered_pairs
            .iter()
            .filter(|pair| !consumed.contains(*pair))
            .count();
        Ok(json!({
            "members": roster_of(&checkpoint)?,
            "epoch": frontier.epoch,
            "branch": frontier.branch,
            "delivered": self.delivered,
            "duplicate_deliveries": self.duplicate_deliveries,
            "deliveries_without_consume": without_consume,
        }))
    }
}

// ---------------------------------------------------------------------------
// Argument and checkpoint helpers
// ---------------------------------------------------------------------------

fn only(args: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    match args.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(format!("malformed: unexpected argument {key}")),
        None => Ok(()),
    }
}

fn text(args: &Map<String, Value>, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("malformed: {key}"))
}

fn texts(args: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    args.get(key)
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| format!("malformed: {key}"))
}

/// C-39: an even-length lowercase hex payload.
fn hex_payload(payload: &str) -> Result<Vec<u8>, String> {
    if !payload.len().is_multiple_of(2)
        || !payload
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("malformed: payload must be even-length lowercase hex".into());
    }
    hex::decode(payload).map_err(|_| "malformed: payload".to_string())
}

fn hex_field(value: &Value, key: &str) -> Result<Vec<u8>, String> {
    value[key]
        .as_str()
        .and_then(|text| hex::decode(text).ok())
        .ok_or_else(|| format!("malformed: response {key}"))
}

/// The code that begins an error string (`"read_fenced: detail"` → `"read_fenced"`).
fn error_code(error: &str) -> String {
    let code = error.split(':').next().unwrap_or(error).trim();
    if code.is_empty() {
        "rejected".to_owned()
    } else {
        code.to_owned()
    }
}

fn frontier_of(checkpoint: &Value) -> Result<Frontier, String> {
    Ok(Frontier {
        epoch: checkpoint["epoch"]
            .as_u64()
            .ok_or("malformed: kernel epoch")?,
        branch: checkpoint["branch"]
            .as_str()
            .ok_or("malformed: kernel branch")?
            .to_owned(),
    })
}

fn roster_of(state: &Value) -> Result<Vec<String>, String> {
    state["roster"]
        .as_array()
        .and_then(|roster| {
            roster
                .iter()
                .map(|name| name.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| "malformed: kernel roster".to_string())
}

/// One kernel grant record.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GrantRecord {
    subject: String,
    right: String,
    generation: u64,
    active: bool,
}

fn grants_of(state: &Value) -> Result<Vec<GrantRecord>, String> {
    state["grants"]
        .as_array()
        .ok_or("malformed: kernel grants")?
        .iter()
        .map(|grant| {
            Some(GrantRecord {
                subject: grant["subject"].as_str()?.to_owned(),
                right: grant["right"].as_str()?.to_owned(),
                generation: grant["generation"].as_u64()?,
                active: grant["active"].as_bool()?,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "malformed: kernel grant".to_string())
}

fn generation_of(state: &Value, subject: &str, right: &str) -> Result<Option<u64>, String> {
    Ok(grants_of(state)?
        .into_iter()
        .find(|grant| grant.subject == subject && grant.right == right)
        .map(|grant| grant.generation))
}

/// The subject's active rights and generations, in right-code order.
fn active_rights(state: &Value, subject: &str) -> Result<Vec<(Right, u64)>, String> {
    let mut rights = grants_of(state)?
        .into_iter()
        .filter(|grant| grant.subject == subject && grant.active)
        .map(|grant| {
            Right::from_name(&grant.right)
                .map(|right| (right, grant.generation))
                .ok_or_else(|| "malformed: kernel right".to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    rights.sort();
    Ok(rights)
}

fn consumed_of(state: &Value) -> Result<Vec<(String, String)>, String> {
    state["consumed"]
        .as_array()
        .and_then(|consumed| {
            consumed
                .iter()
                .map(|entry| {
                    Some((
                        entry["op"].as_str()?.to_owned(),
                        entry["recipient"].as_str()?.to_owned(),
                    ))
                })
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| "corrupt_history: consumed".to_string())
}

// ---------------------------------------------------------------------------
// Trace export (C-37)
// ---------------------------------------------------------------------------

/// The kernel's hash-chain input; the field order is the kernel's serialization order.
#[derive(Serialize)]
struct ChainInput<'a> {
    sequence: u64,
    previous: &'a str,
    event: &'a Value,
}

/// One accepted or rejected adapter request (C-5).
struct TraceRow {
    id: i64,
    actor: Option<String>,
    command: Option<String>,
    outcome: String,
}

fn open_read_only(path: &Path) -> Result<Connection, String> {
    if !path.is_file() {
        return Err(format!(
            "uninitialized: {} is missing",
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
    }
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sql)
}

fn sql(err: rusqlite::Error) -> String {
    format!("malformed: export database {err}")
}

/// The kernel history as `(kind, snapshot)`, after checking its hash chain.
fn read_history(kernel: &Connection) -> Result<Vec<(String, Value)>, String> {
    let mut statement = kernel
        .prepare("SELECT sequence, previous, hash, event FROM authority_events ORDER BY sequence")
        .map_err(sql)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql)?;
    let mut history = Vec::new();
    let mut previous_hash = String::new();
    for row in rows {
        let (sequence, previous, hash, raw) = row.map_err(sql)?;
        let event: Value =
            serde_json::from_str(&raw).map_err(|_| "corrupt_history: event".to_string())?;
        let expected = u64::try_from(history.len()).map_err(|_| "corrupt_history")?;
        let input = serde_json::to_vec(&ChainInput {
            sequence: expected,
            previous: &previous,
            event: &event,
        })
        .map_err(|_| "corrupt_history: event".to_string())?;
        if u64::try_from(sequence).ok() != Some(expected)
            || previous != previous_hash
            || hex::encode(Sha256::digest(input)) != hash
        {
            return Err("corrupt_history: hash chain".into());
        }
        let kind = event["kind"]
            .as_str()
            .ok_or("corrupt_history: kind")?
            .to_owned();
        history.push((kind, event["snapshot"].clone()));
        previous_hash = hash;
    }
    Ok(history)
}

fn read_trace(store: &Connection) -> Result<Vec<TraceRow>, String> {
    let mut statement = store
        .prepare("SELECT id, actor, command, outcome FROM adapter_trace ORDER BY id")
        .map_err(sql)?;
    let rows = statement
        .query_map([], |row| {
            Ok(TraceRow {
                id: row.get(0)?,
                actor: row.get(1)?,
                command: row.get(2)?,
                outcome: row.get(3)?,
            })
        })
        .map_err(sql)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sql)
}

/// The kernel history kinds that one accepted adapter command can append, and whether it
/// always appends one. `confirm_repair` also exports its confirmation, and `emit` has no
/// kernel event (kernel `emit` is a read).
fn kernel_kinds(command: &str) -> Result<(&'static [&'static str], bool), String> {
    Ok(match command {
        "delegate" => (&["delegate"], true),
        "invoke" => (&["invoke"], true),
        "allocate" => (&["allocate"], true),
        "release" => (&["release"], true),
        "consume" => (&["consume"], true),
        "submit_commit" => (&["admit", "repair_stage", "rekey"], true),
        // A grant to a current member is a rekey offer (C-28); an ineffective revoke, an
        // identical persist and a repeated abandon change nothing (kernel contract).
        "grant" => (&["grant"], false),
        "revoke" => (&["revoke"], false),
        "persist" => (&["persist"], false),
        "abandon" => (&["abandon"], false),
        "confirm_repair" => (&["repair_open"], false),
        "emit" | "admission_certificate" | "repair_plan" => (&[], false),
        other => {
            return Err(format!(
                "malformed: trace command {other} has no export mapping"
            ))
        }
    })
}

/// Derives a trace contract v2 trace of accepted transitions from an adapter directory (C-37).
///
/// The adapter trace gives the order. Each accepted request (`ok` or `recovered`) is
/// matched to the next kernel history event of a kind that request can append; a
/// request that must append one and has none, or a kernel event that no accepted
/// request explains, fails the export. Each kernel event maps to v2 events from the
/// difference between its snapshot and the previous one, with identifiers, keys,
/// certificates, committers, confirmations and evidence from the adapter store.
pub fn export_v2_trace(dir: &Path) -> Result<Vec<Value>, String> {
    let kernel = open_read_only(&dir.join(AUTHORITY_FILE))?;
    let store = open_read_only(&dir.join(ADAPTER_FILE))?;
    let history = read_history(&kernel)?;
    let trace = read_trace(&store)?;
    let apf_public: String = store
        .query_row(
            "SELECT v FROM adapter_meta WHERE k = 'apf_public_key'",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    let apf_public = hex::decode(apf_public).map_err(|_| "malformed: adapter APF key")?;

    let mut export = Export {
        store: &store,
        apf_public,
        crypto: RustCrypto::default(),
        events: Vec::new(),
        policy_events: 0,
        ready: HashSet::new(),
        persisted: Vec::new(),
        emitted: HashSet::new(),
        confirmed: BTreeMap::new(),
        offer_admins: Vec::new(),
    };
    let mut history = history.into_iter().peekable();
    let (kind, mut current) = history
        .next()
        .ok_or("uninitialized: empty kernel history")?;
    if kind != "init" {
        return Err("corrupt_history: the first kernel event is not init".into());
    }
    export.init(&current)?;

    for row in trace {
        if row.outcome != "ok" && row.outcome != "recovered" {
            continue;
        }
        let command = row
            .command
            .as_deref()
            .ok_or("malformed: accepted trace event without a command")?;
        let actor = row
            .actor
            .as_deref()
            .ok_or("malformed: accepted trace event without an actor")?;
        let (kinds, mandatory) = kernel_kinds(command)?;
        match command {
            "emit" => {
                export.emit(actor, &current)?;
                continue;
            }
            "confirm_repair" => {
                // Only the confirmation that completes the evidence opens the fence (C-23).
                if export.confirm(actor, &current)? {
                    match history.next() {
                        Some((kind, next)) if kind == "repair_open" => {
                            export.transition(&kind, actor, &current, &next)?;
                            current = next;
                        }
                        _ => {
                            return Err(format!(
                                "binding_mismatch: confirmation {} completed the evidence \
                                 without a kernel repair_open",
                                row.id
                            ))
                        }
                    }
                }
                continue;
            }
            _ => {}
        }
        if history
            .peek()
            .is_some_and(|(kind, _)| kinds.contains(&kind.as_str()))
        {
            let (kind, next) = history.next().ok_or("corrupt_history")?;
            export.transition(&kind, actor, &current, &next)?;
            current = next;
        } else if mandatory {
            return Err(format!(
                "binding_mismatch: accepted trace event {} ({command}) has no kernel event",
                row.id
            ));
        } else if command == "grant" {
            export.offer_admins.push(actor.to_owned());
        }
    }
    if let Some((kind, _)) = history.next() {
        return Err(format!(
            "binding_mismatch: kernel event {kind} has no accepted trace event"
        ));
    }
    Ok(export.events)
}

struct Export<'a> {
    store: &'a Connection,
    apf_public: Vec<u8>,
    crypto: RustCrypto,
    events: Vec<Value>,
    /// Exported allow, deny and rekey events: the v2 `policy_revision`.
    policy_events: u64,
    /// Clients with an exported `recover` at the current frontier.
    ready: HashSet<String>,
    /// Persisted operations, in persist order.
    persisted: Vec<String>,
    emitted: HashSet<String>,
    /// Exported confirmation hashes by `(branch, actor)`.
    confirmed: BTreeMap<(String, String), Vec<u8>>,
    /// Admins of accepted grants that reached no kernel event: rekey offers (C-28).
    offer_admins: Vec<String>,
}

impl Export<'_> {
    fn push(&mut self, kind: &str, fields: Value) {
        let mut event = Map::new();
        event.insert(
            "event_id".into(),
            json!(format!("{:04}-{kind}", self.events.len())),
        );
        event.insert("type".into(), json!(kind));
        if let Value::Object(fields) = fields {
            event.extend(fields);
        }
        self.events.push(Value::Object(event));
    }

    /// `(signature key, certificate)` retained for `subject` at the frontier `branch` (§4.3).
    fn certificate_at(&self, subject: &str, branch: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.store
            .query_row(
                "SELECT signature_key, certificate FROM adapter_certificates
                 WHERE subject = ?1 AND branch = ?2 ORDER BY id LIMIT 1",
                [subject, branch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| format!("binding_mismatch: no retained key of {subject} at {branch}"))
    }

    fn init(&mut self, state: &Value) -> Result<(), String> {
        if state["policy_revision"].as_u64() != Some(0) || state["epoch"].as_u64() != Some(0) {
            return Err("corrupt_history: init frontier".into());
        }
        let branch = snapshot_str(state, "branch")?;
        let roster = roster_of(state)?;
        let mut keys = Map::new();
        for member in &roster {
            let (key, _) = self.certificate_at(member, &branch)?;
            keys.insert(member.clone(), json!(hex::encode(key)));
        }
        let grants: Vec<Value> = grants_of(state)?
            .into_iter()
            .filter(|grant| grant.active)
            .map(|grant| {
                json!({"subject": grant.subject, "right": grant.right, "generation": grant.generation})
            })
            .collect();
        self.push(
            "init",
            json!({
                "version": 2, "group": snapshot_str(state, "group")?, "policy_revision": 0,
                "epoch": 0, "branch": branch, "roster": roster, "keys": keys, "grants": grants
            }),
        );
        Ok(())
    }

    fn transition(
        &mut self,
        kind: &str,
        actor: &str,
        previous: &Value,
        next: &Value,
    ) -> Result<(), String> {
        match kind {
            "grant" | "delegate" => {
                let allowed = activated(previous, next)?;
                if allowed.is_empty() {
                    return Err(format!("corrupt_history: {kind} activated no grant"));
                }
                for grant in allowed {
                    self.policy_events += 1;
                    self.push(
                        "allow",
                        json!({"subject": grant.subject, "right": grant.right, "generation": grant.generation}),
                    );
                }
            }
            "revoke" => {
                let denied = deactivated(previous, next)?;
                if denied.is_empty() {
                    return Err("corrupt_history: revoke deactivated no grant".into());
                }
                for grant in denied {
                    self.policy_events += 1;
                    self.push(
                        "deny",
                        json!({"subject": grant.subject, "right": grant.right}),
                    );
                }
            }
            // Invocations are out of scope for v2; only the renumbering accounts for them.
            "invoke" => {}
            "allocate" => {
                let before = operations_of(previous)?;
                let added: Vec<String> = operations_of(next)?
                    .into_iter()
                    .filter(|(op, _)| !before.iter().any(|(known, _)| known == op))
                    .map(|(op, _)| op)
                    .collect();
                if added.is_empty() {
                    return Err("corrupt_history: allocate added no operation".into());
                }
                for op in added {
                    self.push("allocate", json!({ "op": op }));
                }
            }
            "release" => {
                for (op, operation) in changed_status(previous, next, "allocated", "released")? {
                    self.release(&op, &operation)?;
                }
            }
            "persist" => {
                for (op, operation) in changed_status(previous, next, "released", "persisted")? {
                    let envelope = operation["envelope"]
                        .as_str()
                        .ok_or("corrupt_history: persisted envelope")?;
                    let digest = operation["digest"]
                        .as_str()
                        .ok_or("corrupt_history: persisted digest")?;
                    self.persisted.push(op.clone());
                    self.push(
                        "persist",
                        json!({ "op": op, "envelope": envelope, "digest": digest }),
                    );
                }
            }
            "abandon" => {
                for (op, _) in changed_status(previous, next, "released", "abandoned")? {
                    self.push("abandon", json!({ "op": op }));
                }
            }
            "consume" => {
                let before: HashSet<(String, String)> =
                    consumed_of(previous)?.into_iter().collect();
                let added: Vec<(String, String)> = consumed_of(next)?
                    .into_iter()
                    .filter(|pair| !before.contains(pair))
                    .collect();
                if added.is_empty() {
                    return Err("corrupt_history: consume recorded nothing".into());
                }
                let epoch = snapshot_u64(next, "epoch")?;
                let branch = snapshot_str(next, "branch")?;
                for (op, recipient) in added {
                    // C-37: the accepted consume is the evidence that the recipient had
                    // applied the canonical frontier.
                    if self.ready.insert(recipient.clone()) {
                        self.push(
                            "recover",
                            json!({ "client": recipient, "epoch": epoch, "branch": branch }),
                        );
                    }
                    self.push("consume", json!({ "op": op, "recipient": recipient }));
                }
            }
            "admit" => self.admit(actor, previous, next)?,
            "repair_stage" => self.repair_stage(previous, next)?,
            "repair_open" => {
                let branch = snapshot_str(previous, "repair_pending")?;
                let evidence: Option<String> = self
                    .store
                    .query_row(
                        "SELECT evidence FROM adapter_repairs WHERE branch = ?1",
                        [&branch],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql)?
                    .flatten();
                let evidence = evidence
                    .ok_or_else(|| format!("unconfirmed: no recorded evidence for {branch}"))?;
                self.push(
                    "repair_open",
                    json!({ "branch": branch, "evidence": evidence }),
                );
            }
            "rekey" => self.rekey(previous, next)?,
            other => {
                return Err(format!(
                    "malformed: kernel event {other} has no version 2 mapping"
                ))
            }
        }
        Ok(())
    }

    /// A kernel release, with the cover rebuilt from the stored, verified release
    /// certificate and checked against the kernel's frozen release state.
    fn release(&mut self, op: &str, operation: &Value) -> Result<(), String> {
        let certificate: Option<Vec<u8>> = self
            .store
            .query_row(
                "SELECT certificate FROM adapter_operations WHERE op = ?1",
                [op],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .flatten();
        let certificate =
            certificate.ok_or_else(|| format!("not_persisted: no release certificate for {op}"))?;
        let released = ReleaseCertificate::verify(&certificate, &self.apf_public, &self.crypto)?;
        let mut kernel_readers: Vec<(String, u64)> = operation["roster"]
            .as_array()
            .and_then(|readers| {
                readers
                    .iter()
                    .map(|reader| {
                        Some((
                            reader["subject"].as_str()?.to_owned(),
                            reader["generation"].as_u64()?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or("corrupt_history: release readers")?;
        kernel_readers.sort();
        if released.op != op
            || operation["actor"].as_str() != Some(released.actor.as_str())
            || operation["right"].as_str() != Some(released.right.name())
            || operation["epoch"].as_u64() != Some(released.frontier.epoch)
            || operation["branch"].as_str() != Some(released.frontier.branch.as_str())
            || operation["digest"].as_str() != Some(released.digest.as_str())
            || operation["writer_generation"].as_u64() != Some(released.writer_generation)
            || kernel_readers != released.readers
        {
            return Err(format!(
                "binding_mismatch: release certificate of {op} differs from the kernel"
            ));
        }
        let mut cover = vec![json!([{
            "subject": released.actor, "right": "write", "generation": released.writer_generation
        }])];
        for (reader, generation) in &released.readers {
            cover.push(json!([{ "subject": reader, "right": "read", "generation": generation }]));
        }
        self.push(
            "release",
            json!({
                "op": op, "actor": released.actor, "right": released.right.name(),
                "policy_revision": self.policy_events, "epoch": released.frontier.epoch,
                "branch": released.frontier.branch, "digest": released.digest, "cover": cover
            }),
        );
        Ok(())
    }

    fn admit(&mut self, actor: &str, previous: &Value, next: &Value) -> Result<(), String> {
        let before = roster_of(previous)?;
        let added: Vec<String> = roster_of(next)?
            .into_iter()
            .filter(|member| !before.contains(member))
            .collect();
        let [subject] = added.as_slice() else {
            return Err("corrupt_history: admit must add exactly one member".into());
        };
        let new_branch = snapshot_str(next, "branch")?;
        let generation = grants_of(next)?
            .into_iter()
            .find(|grant| grant.subject == *subject && grant.right == "read" && grant.active)
            .map(|grant| grant.generation)
            .ok_or("corrupt_history: admitted member without a read grant")?;
        let (key, certificate) = self.certificate_at(subject, &new_branch)?;
        self.ready.clear();
        self.push(
            "admit",
            json!({
                "actor": actor, "subject": subject, "generation": generation,
                "parent_branch": snapshot_str(previous, "branch")?, "new_branch": new_branch,
                "epoch": snapshot_u64(next, "epoch")?, "key": hex::encode(key),
                "key_package": hex::encode(Sha256::digest(&certificate))
            }),
        );
        Ok(())
    }

    fn repair_stage(&mut self, previous: &Value, next: &Value) -> Result<(), String> {
        let new_branch = snapshot_str(next, "branch")?;
        let parent_branch = snapshot_str(previous, "branch")?;
        let (committer, recorded_parent): (String, String) = self
            .store
            .query_row(
                "SELECT committer, parent_branch FROM adapter_repairs WHERE branch = ?1",
                [&new_branch],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| format!("binding_mismatch: no repair record for {new_branch}"))?;
        if recorded_parent != parent_branch {
            return Err("binding_mismatch: repair record parent".into());
        }
        let after = roster_of(next)?;
        let mut removed: Vec<String> = roster_of(previous)?
            .into_iter()
            .filter(|member| !after.contains(member))
            .collect();
        removed.sort();
        self.ready.clear();
        self.push(
            "repair_stage",
            json!({
                "actor": committer, "parent_branch": parent_branch, "new_branch": new_branch,
                "epoch": snapshot_u64(next, "epoch")?, "policy_revision": self.policy_events,
                "removed": removed
            }),
        );
        Ok(())
    }

    fn rekey(&mut self, previous: &Value, next: &Value) -> Result<(), String> {
        let changed = activated(previous, next)?;
        let [grant] = changed.as_slice() else {
            return Err("corrupt_history: rekey must change exactly one grant".into());
        };
        // The offer row is deleted when the rekey completes (C-28 step 7), so the admin
        // comes from the latest accepted grant that reached no kernel event.
        let admin = self
            .offer_admins
            .pop()
            .ok_or("binding_mismatch: rekey without an accepted offer")?;
        let new_branch = snapshot_str(next, "branch")?;
        let (new_key, _) = self.certificate_at(&grant.subject, &new_branch)?;
        self.policy_events += 1;
        self.ready.clear();
        self.push(
            "rekey",
            json!({
                "actor": admin, "subject": grant.subject, "right": grant.right,
                "generation": grant.generation, "parent_branch": snapshot_str(previous, "branch")?,
                "new_branch": new_branch, "epoch": snapshot_u64(next, "epoch")?,
                "new_key": hex::encode(new_key)
            }),
        );
        Ok(())
    }

    /// An accepted `confirm_repair`: the stored hash of `actor` for the pending repair.
    /// An identical resend changes nothing and is not exported again. Returns whether
    /// this confirmation completed the C-23 evidence, which is when the adapter opens
    /// the fence: the committer's hash, and either the committer as the only continuing
    /// member or another continuing member with an equal hash.
    fn confirm(&mut self, actor: &str, current: &Value) -> Result<bool, String> {
        let branch = snapshot_str(current, "repair_pending")?;
        let key = (branch.clone(), actor.to_owned());
        if self.confirmed.contains_key(&key) {
            return Ok(false);
        }
        let hash: Vec<u8> = self
            .store
            .query_row(
                "SELECT hash FROM adapter_confirmations WHERE branch = ?1 AND actor = ?2",
                [&branch, actor],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| format!("binding_mismatch: no stored confirmation of {actor}"))?;
        self.push(
            "confirm",
            json!({ "actor": actor, "branch": branch, "hash": hex::encode(&hash) }),
        );
        self.confirmed.insert(key, hash);

        let committer: String = self
            .store
            .query_row(
                "SELECT committer FROM adapter_repairs WHERE branch = ?1",
                [&branch],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?
            .ok_or_else(|| format!("binding_mismatch: no repair record for {branch}"))?;
        let Some(reference) = self.confirmed.get(&(branch.clone(), committer.clone())) else {
            return Ok(false);
        };
        let roster = roster_of(current)?;
        if roster == [committer.clone()] {
            return Ok(true);
        }
        Ok(roster.iter().any(|member| {
            *member != committer
                && self.confirmed.get(&(branch.clone(), member.clone())) == Some(reference)
        }))
    }

    /// An accepted `emit`. The trace does not name the operation, so it is the actor's
    /// earliest persisted, not yet emitted operation at the current frontier (the only
    /// ones kernel `emit` accepts), or else a byte-identical re-emission of the latest.
    fn emit(&mut self, actor: &str, current: &Value) -> Result<(), String> {
        let epoch = snapshot_u64(current, "epoch")?;
        let branch = snapshot_str(current, "branch")?;
        let candidates: BTreeMap<String, String> = operations_of(current)?
            .into_iter()
            .filter(|(_, operation)| {
                operation["actor"].as_str() == Some(actor)
                    && operation["status"].as_str() == Some("persisted")
                    && operation["epoch"].as_u64() == Some(epoch)
                    && operation["branch"].as_str() == Some(branch.as_str())
            })
            .filter_map(|(op, operation)| {
                operation["envelope"]
                    .as_str()
                    .map(|envelope| (op, envelope.to_owned()))
            })
            .collect();
        let op = self
            .persisted
            .iter()
            .find(|op| candidates.contains_key(*op) && !self.emitted.contains(*op))
            .or_else(|| {
                self.persisted
                    .iter()
                    .rev()
                    .find(|op| candidates.contains_key(*op))
            })
            .cloned()
            .ok_or_else(|| format!("binding_mismatch: emit by {actor} with nothing persisted"))?;
        self.emitted.insert(op.clone());
        let envelope = candidates[&op].clone();
        self.push("emit", json!({ "op": op, "envelope": envelope }));
        Ok(())
    }
}

fn snapshot_str(state: &Value, key: &str) -> Result<String, String> {
    state[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("corrupt_history: {key}"))
}

fn snapshot_u64(state: &Value, key: &str) -> Result<u64, String> {
    state[key]
        .as_u64()
        .ok_or_else(|| format!("corrupt_history: {key}"))
}

/// Code of a right name, for right-code ordering (C-9).
fn right_code(right: &str) -> u8 {
    Right::from_name(right).map(Right::code).unwrap_or(u8::MAX)
}

/// Grants active in `next` that were absent, inactive or at another generation in
/// `previous`, sorted by subject and right code.
fn activated(previous: &Value, next: &Value) -> Result<Vec<GrantRecord>, String> {
    let before = grants_of(previous)?;
    let mut out: Vec<GrantRecord> = grants_of(next)?
        .into_iter()
        .filter(|grant| {
            grant.active
                && !before.iter().any(|old| {
                    old.subject == grant.subject
                        && old.right == grant.right
                        && old.active
                        && old.generation == grant.generation
                })
        })
        .collect();
    out.sort_by(|a, b| {
        (a.subject.as_str(), right_code(&a.right)).cmp(&(b.subject.as_str(), right_code(&b.right)))
    });
    Ok(out)
}

/// Grants active in `previous` and inactive in `next`, sorted by subject and right code.
fn deactivated(previous: &Value, next: &Value) -> Result<Vec<GrantRecord>, String> {
    let after = grants_of(next)?;
    let mut out: Vec<GrantRecord> = grants_of(previous)?
        .into_iter()
        .filter(|grant| {
            grant.active
                && after.iter().any(|new| {
                    new.subject == grant.subject && new.right == grant.right && !new.active
                })
        })
        .collect();
    out.sort_by(|a, b| {
        (a.subject.as_str(), right_code(&a.right)).cmp(&(b.subject.as_str(), right_code(&b.right)))
    });
    Ok(out)
}

/// The kernel operations of a snapshot, in kernel order.
fn operations_of(state: &Value) -> Result<Vec<(String, Value)>, String> {
    state["operations"]
        .as_array()
        .and_then(|operations| {
            operations
                .iter()
                .map(|operation| Some((operation["op"].as_str()?.to_owned(), operation.clone())))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| "corrupt_history: operations".to_string())
}

/// Operations whose status moved from `from` to `to`, in kernel order; at least one.
fn changed_status(
    previous: &Value,
    next: &Value,
    from: &str,
    to: &str,
) -> Result<Vec<(String, Value)>, String> {
    let before = operations_of(previous)?;
    let changed: Vec<(String, Value)> = operations_of(next)?
        .into_iter()
        .filter(|(op, operation)| {
            operation["status"].as_str() == Some(to)
                && before
                    .iter()
                    .any(|(old, state)| old == op && state["status"].as_str() == Some(from))
        })
        .collect();
    if changed.is_empty() {
        return Err(format!("corrupt_history: no operation moved to {to}"));
    }
    Ok(changed)
}
