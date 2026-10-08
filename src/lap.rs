//! LAP-MLS adapter: the trusted in-process coupling between the durable APF
//! kernel ([`crate::authority`]) and the real OpenMLS laboratory
//! ([`crate::mls`]). See `docs/lap-mls.md` for the profile and claim boundary.
//!
//! The adapter is the only path that drives kernel membership transitions and
//! releases. It derives every transition's evidence from real OpenMLS objects,
//! and it never forwards caller-chosen booleans to the kernel. The laboratory
//! process holds the APF signing key.

use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::authority::{canonical_frontier_id, Authority};
use crate::mls::{EntropySource, MlsFrontier, MlsLab, TransitionEvidence, TransitionSpec};

/// APF group (and resource) name of the LAP laboratory.
pub const LAP_GROUP: &str = "agent-trust-lap";

/// Kernel commands that only the adapter may issue.
const ADAPTER_ONLY: &[&str] = &[
    "admit",
    "repair",
    "confirm_repair",
    "release",
    "persist",
    "emit",
    "consume",
    "abandon",
];

/// Outcome of a qualifying repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    pub removed: Vec<String>,
    pub designated: String,
    /// The designated member confirmed and the central fence is open.
    pub confirmed: bool,
    pub epoch: u64,
}

pub struct LapMls {
    apf: Authority,
    lab: MlsLab,
    pending_designated: Option<String>,
}

impl LapMls {
    /// In-memory kernel and endpoints.
    pub fn in_memory(entropy: EntropySource) -> Result<Self, String> {
        let lab = MlsLab::create_bound(entropy, None, LAP_GROUP)?;
        Self::init(Authority::open(":memory:")?, lab)
    }

    /// Durable kernel (`<dir>/apf.sqlite`) and endpoints (`<dir>/members/`).
    pub fn durable(dir: &Path, entropy: EntropySource) -> Result<Self, String> {
        let apf_path = dir.join("apf.sqlite");
        let members = dir.join("members");
        if apf_path.exists() || members.exists() {
            return Err("LAP state already exists; it is not reused".into());
        }
        std::fs::create_dir(&members).map_err(|e| format!("create members dir: {e}"))?;
        let lab = MlsLab::create_bound(entropy, Some(&members), LAP_GROUP)?;
        Self::init(Authority::open(apf_path)?, lab)
    }

    fn init(mut apf: Authority, lab: MlsLab) -> Result<Self, String> {
        let frontier = lab
            .frontier("alice")
            .ok_or_else(|| "founder endpoint missing".to_owned())?;
        apf.execute(
            json!({"command": "init", "group": LAP_GROUP, "root": "alice",
                           "frontier": frontier_json(&frontier)}),
        )?;
        Ok(Self {
            apf,
            lab,
            pending_designated: None,
        })
    }

    /// Trusted administrative interface (grant, delegate, invoke, revoke,
    /// allocate, checkpoint). Commands reserved to the adapter are refused.
    pub fn authority(&mut self, request: Value) -> Result<Value, String> {
        let command = request.get("command").and_then(Value::as_str).unwrap_or("");
        if ADAPTER_ONLY.contains(&command) {
            return Err(format!("unauthorized: {command} is adapter-only"));
        }
        self.apf.execute(request)
    }

    pub fn checkpoint(&mut self) -> Result<Value, String> {
        self.apf.execute(json!({"command": "checkpoint"}))
    }

    /// The MLS laboratory, for inspection and adversarial experiments.
    pub fn lab(&mut self) -> &mut MlsLab {
        &mut self.lab
    }

    /// Admits `subject` with a real Add commit by `actor`, canonicalized by
    /// the kernel against the commit's own frontier and `acc_context`.
    pub fn admit(&mut self, actor: &str, subject: &str, now: u64) -> Result<Value, String> {
        let checkpoint = self.checkpoint()?;
        let generation = read_generation(&checkpoint, subject).ok_or("unauthorized")?;
        let mut roster = roster_with_generations(&checkpoint)?;
        roster.push((subject.to_owned(), generation));
        let spec = TransitionSpec {
            add: Some((subject, generation)),
            remove: &[],
            acc_revision: revision(&checkpoint)?,
            acc_roster: roster,
        };
        let apf = &mut self.apf;
        self.lab.transition(actor, spec, |evidence| {
            let (added, added_generation) = evidence
                .added
                .clone()
                .ok_or_else(|| "Add commit carries no admission".to_owned())?;
            if added != subject {
                return Err("binding_mismatch: Add proposal names another subject".into());
            }
            apf.execute(json!({
                "command": "admit", "actor": actor, "subject": subject, "now": now,
                "parent": frontier_id(&evidence.parent),
                "successor": frontier_json(&evidence.successor),
                "acc_revision": evidence.acc_revision,
                "acc_roster": roster_json(&evidence.acc_roster),
                "generation": added_generation,
                "commit": hex::encode(&evidence.commit),
            }))
        })
    }

    /// Removes every roster member whose read authority is no longer active,
    /// with one regular commit (UpdatePath + `acc_context` at the current
    /// revision), then asks the designated continuing member to confirm.
    pub fn repair(&mut self, committer: &str, _now: u64) -> Result<RepairReport, String> {
        let checkpoint = self.checkpoint()?;
        let roster = string_list(&checkpoint["roster"])?;
        let removed: Vec<String> = roster
            .iter()
            .filter(|name| read_generation(&checkpoint, name).is_none())
            .cloned()
            .collect();
        let remaining: Vec<(String, u64)> = roster_with_generations(&checkpoint)?
            .into_iter()
            .filter(|(name, _)| !removed.contains(name))
            .collect();
        let designated = remaining
            .iter()
            .map(|(name, _)| name.clone())
            .find(|name| name != committer && self.lab.frontier(name).is_some())
            .unwrap_or_else(|| committer.to_owned());
        let removed_refs: Vec<&str> = removed.iter().map(String::as_str).collect();
        let spec = TransitionSpec {
            add: None,
            remove: &removed_refs,
            acc_revision: revision(&checkpoint)?,
            acc_roster: remaining,
        };
        let apf = &mut self.apf;
        let designated_for_apf = designated.clone();
        let repaired = self
            .lab
            .transition(committer, spec, |evidence: &TransitionEvidence| {
                apf.execute(json!({
                    "command": "repair",
                    "parent": frontier_id(&evidence.parent),
                    "successor": frontier_json(&evidence.successor),
                    "removed": evidence.removed,
                    "update_path": evidence.update_path,
                    "acc_revision": evidence.acc_revision,
                    "acc_roster": roster_json(&evidence.acc_roster),
                    "designated": designated_for_apf,
                    "commit": hex::encode(&evidence.commit),
                }))
            })?;
        self.pending_designated = Some(designated.clone());
        let confirmed = self.confirm().is_ok();
        Ok(RepairReport {
            removed,
            designated,
            confirmed,
            epoch: repaired["epoch"].as_u64().unwrap_or_default(),
        })
    }

    /// Asks the designated member of the pending repair to confirm with its
    /// own installed frontier; opens the central fence on success.
    pub fn confirm(&mut self) -> Result<(), String> {
        let member = self
            .pending_designated
            .clone()
            .ok_or_else(|| "invalid_repair: no repair awaits confirmation".to_owned())?;
        let installed = self
            .lab
            .frontier(&member)
            .ok_or_else(|| format!("invalid_repair: {member} is offline"))?;
        self.apf
            .execute(json!({"command": "confirm_repair", "member": member,
                                "installed": frontier_json(&installed)}))?;
        self.pending_designated = None;
        Ok(())
    }

    /// Releases and protects `payload` as an independent operation of `sender`.
    pub fn send(
        &mut self,
        sender: &str,
        op: &str,
        payload: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, String> {
        self.send_inner(sender, op, None, payload, now)
    }

    /// Releases and protects `payload` under an APF-issued invocation.
    pub fn send_invoked(
        &mut self,
        sender: &str,
        op: &str,
        invocation: &str,
        payload: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, String> {
        self.send_inner(sender, op, Some(invocation), payload, now)
    }

    fn send_inner(
        &mut self,
        sender: &str,
        op: &str,
        invocation: Option<&str>,
        payload: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, String> {
        let mut allocate = json!({"command": "allocate", "actor": sender, "op": op});
        if let Some(invocation) = invocation {
            allocate["invocation"] = json!(invocation);
        }
        self.apf.execute(allocate)?;
        let checkpoint = self.checkpoint()?;
        let digest = hex::encode(Sha256::digest(payload));
        let writer = grant_generation(&checkpoint, sender, "write").ok_or("unauthorized")?;
        let mut cover = vec![json!([{"subject": sender, "right": "write", "generation": writer}])];
        for (subject, generation) in roster_with_generations(&checkpoint)? {
            cover.push(json!([{"subject": subject, "right": "read", "generation": generation}]));
        }
        let release = self.apf.execute(json!({
            "command": "release", "actor": sender, "op": op, "right": "write",
            "revision": checkpoint["revision"], "epoch": checkpoint["epoch"],
            "branch": checkpoint["branch"], "digest": digest, "cover": cover, "now": now,
        }))?;
        let branch = release["branch"].as_str().unwrap_or_default().to_owned();

        let protected = (|| {
            let local = self
                .lab
                .frontier(sender)
                .ok_or_else(|| "locally_fenced: sender is offline".to_owned())?;
            if frontier_id(&local) != branch {
                return Err("locally_fenced: sender is not at the canonical frontier".into());
            }
            let body = json!({"group": LAP_GROUP, "release": release, "cover": cover});
            let body = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
            let signature = self.lab.apf_sign(&body)?;
            let certificate = encode_certificate(&body, &signature)?;
            let aad = Sha256::digest(&certificate);
            let wire = self.lab.protect(sender, payload, &aad)?;
            Ok::<_, String>(join_envelope(&certificate, &wire))
        })();
        let envelope = match protected {
            Ok(envelope) => envelope,
            Err(failure) => {
                // Released but never protected: terminally abandoned.
                let _ = self.apf.execute(json!({"command": "abandon", "op": op}));
                return Err(failure);
            }
        };
        let hex_envelope = hex::encode(&envelope);
        self.apf
            .execute(json!({"command": "persist", "op": op, "digest": digest,
                                "envelope": hex_envelope}))?;
        self.apf
            .execute(json!({"command": "emit", "op": op, "envelope": hex_envelope}))?;
        Ok(envelope)
    }

    /// Verifies, decrypts, consumes, and only then delivers an envelope.
    pub fn receive(
        &mut self,
        recipient: &str,
        envelope: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, String> {
        let (certificate, wire) = split_envelope(envelope)?;
        let (body, signature) = decode_certificate(certificate)?;
        if !self.lab.apf_verify(body, signature) {
            return Err("invalid release certificate signature".into());
        }
        let body: Value =
            serde_json::from_slice(body).map_err(|_| "malformed release certificate")?;
        if body["group"] != LAP_GROUP {
            return Err("release certificate names another group".into());
        }
        let release = &body["release"];
        let op = release["op"]
            .as_str()
            .ok_or("malformed release certificate")?;
        let branch = release["branch"]
            .as_str()
            .ok_or("malformed release certificate")?;
        let digest = release["digest"]
            .as_str()
            .ok_or("malformed release certificate")?;

        let local = self
            .lab
            .frontier(recipient)
            .ok_or_else(|| "locally_fenced: recipient is offline".to_owned())?;
        if frontier_id(&local) != branch {
            return Err("locally_fenced: recipient is not at the release frontier".into());
        }
        let (plaintext, aad) = self.lab.decrypt(recipient, wire)?;
        if aad != Sha256::digest(certificate).as_slice() {
            return Err(
                "binding_mismatch: AAD does not authenticate the release certificate".into(),
            );
        }
        if hex::encode(Sha256::digest(&plaintext)) != digest {
            return Err("binding_mismatch: content digest".into());
        }
        self.apf
            .execute(json!({"command": "consume", "op": op, "recipient": recipient, "now": now}))?;
        Ok(plaintext)
    }
}

/// `u32 certificate length ‖ certificate ‖ MLS ciphertext`.
pub fn join_envelope(certificate: &[u8], wire: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(4 + certificate.len() + wire.len());
    envelope.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
    envelope.extend_from_slice(certificate);
    envelope.extend_from_slice(wire);
    envelope
}

/// Splits an envelope into `(certificate, MLS ciphertext)`.
pub fn split_envelope(envelope: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let (length, rest) = envelope
        .split_first_chunk::<4>()
        .ok_or("malformed envelope")?;
    let length = u32::from_be_bytes(*length) as usize;
    if rest.len() < length || rest.len() == length {
        return Err("malformed envelope".into());
    }
    Ok(rest.split_at(length))
}

/// `u32 body length ‖ body (canonical JSON) ‖ APF Ed25519 signature`.
fn encode_certificate(body: &[u8], signature: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(body.len()).map_err(|_| "certificate too large")?;
    let mut certificate = length.to_be_bytes().to_vec();
    certificate.extend_from_slice(body);
    certificate.extend_from_slice(signature);
    Ok(certificate)
}

fn decode_certificate(certificate: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let (length, rest) = certificate
        .split_first_chunk::<4>()
        .ok_or("malformed release certificate")?;
    let length = u32::from_be_bytes(*length) as usize;
    if rest.len() != length + 64 {
        return Err("malformed release certificate".into());
    }
    Ok(rest.split_at(length))
}

fn frontier_json(frontier: &MlsFrontier) -> Value {
    json!({
        "epoch": frontier.epoch,
        "tree_hash": hex::encode(&frontier.tree_hash),
        "confirmed_transcript_hash": hex::encode(&frontier.confirmed_transcript_hash),
    })
}

fn frontier_id(frontier: &MlsFrontier) -> String {
    canonical_frontier_id(
        LAP_GROUP,
        frontier.epoch,
        &frontier.tree_hash,
        &frontier.confirmed_transcript_hash,
    )
}

fn roster_json(roster: &[(String, u64)]) -> Value {
    Value::Array(
        roster
            .iter()
            .map(|(subject, generation)| json!({"subject": subject, "generation": generation}))
            .collect(),
    )
}

fn revision(checkpoint: &Value) -> Result<u64, String> {
    checkpoint["revision"]
        .as_u64()
        .ok_or_else(|| "malformed checkpoint".to_owned())
}

fn string_list(value: &Value) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or("malformed checkpoint")?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "malformed checkpoint".to_owned())
        })
        .collect()
}

fn grant_generation(checkpoint: &Value, subject: &str, right: &str) -> Option<u64> {
    checkpoint["grants"].as_array()?.iter().find_map(|grant| {
        (grant["subject"] == subject && grant["right"] == right && grant["active"] == true)
            .then(|| grant["generation"].as_u64())
            .flatten()
    })
}

fn read_generation(checkpoint: &Value, subject: &str) -> Option<u64> {
    grant_generation(checkpoint, subject, "read")
}

/// Current roster with active read generations, as `acc_context` binds it.
/// Members without an active read grant are omitted.
fn roster_with_generations(checkpoint: &Value) -> Result<Vec<(String, u64)>, String> {
    Ok(string_list(&checkpoint["roster"])?
        .into_iter()
        .filter_map(|name| read_generation(checkpoint, &name).map(|generation| (name, generation)))
        .collect())
}

/// Runs the LAP-MLS acceptance scenario in a fresh durable laboratory under
/// `dir` and reports every gate. `full_lap_mls` is true only if all gates hold.
pub fn run_demo(dir: &Path, entropy: EntropySource) -> Result<Value, String> {
    let mut lap = LapMls::durable(dir, entropy)?;
    let admin = |lap: &mut LapMls, request: Value| lap.authority(request);
    for subject in ["bob", "carol", "dave"] {
        for right in ["read", "write", "admit"] {
            admin(
                &mut lap,
                json!({"command": "grant", "actor": "alice", "subject": subject,
                                   "right": right, "generation": 0, "fresh_keys": true,
                                   "now": 10}),
            )?;
        }
        lap.admit("alice", subject, 20)?;
    }

    let checkpoint = lap.checkpoint()?;
    let branch = checkpoint["branch"].as_str().unwrap_or_default().to_owned();
    let roster = roster_with_generations(&checkpoint)?;
    let mut members_bound = true;
    for name in ["alice", "bob", "carol", "dave"] {
        let frontier_ok = lap
            .lab
            .frontier(name)
            .is_some_and(|frontier| frontier_id(&frontier) == branch);
        let acc_ok = lap
            .lab
            .acc_context(name)
            .is_some_and(|(_, acc)| acc == crate::mls::sorted_roster(&roster));
        let mut incarnations = lap.lab.incarnations(name);
        incarnations.sort();
        members_bound &=
            frontier_ok && acc_ok && incarnations == crate::mls::sorted_roster(&roster);
    }

    let first = lap.send("alice", "op-1", b"bound release", 30)?;
    let delivered = lap.receive("bob", &first, 31)? == b"bound release";
    let second = lap.send("alice", "op-2", b"second release", 30)?;
    let spliced = join_envelope(split_envelope(&second)?.0, split_envelope(&first)?.1);
    let release_binding_enforced = lap
        .receive("carol", &spliced, 31)
        .is_err_and(|e| e.contains("binding_mismatch"));
    lap.lab.retain_storage_copy("dave", "dave-before")?;
    let replay_target = lap.receive("dave", &first, 31)? == b"bound release";
    lap.lab.restore_member_from("dave", "dave-before")?;
    let replay_rejected = replay_target
        && lap
            .receive("dave", &first, 32)
            .is_err_and(|e| e.contains("replay"));

    let (revision, _) = lap.lab.acc_context("carol").ok_or("acc_context missing")?;
    let forged = lap.lab.sign_acc_context(
        revision,
        &[("alice", 0), ("bob", 0), ("carol", 0), ("dave", 0)],
    );
    let rogue = lap.lab.adversarial_commit("bob", forged, &["alice"])?;
    let forged_acc_context_rejected = lap
        .lab
        .process_commit_as("carol", &rogue)
        .is_err_and(|e| e.contains("coherence"));

    lap.lab.snapshot_member("bob", "bob-retained")?;
    let pre_cut = lap.send("alice", "op-pre", b"pre-cut", 40)?;
    admin(
        &mut lap,
        json!({"command": "revoke", "actor": "alice", "subject": "bob",
                           "right": "read", "now": 41}),
    )?;
    let fenced_until_repair = lap
        .send("alice", "op-fenced", b"blocked", 42)
        .is_err_and(|e| e.contains("read_fenced"));
    let bypass = lap.lab.protect("alice", b"api-only", b"")?;
    let api_only_revocation_leaks = lap.lab.decrypt("bob-retained", &bypass).is_ok();

    let report = lap.repair("alice", 50)?;
    let qualifying_repair_confirmed = report.confirmed && report.removed == ["bob"];
    let post = lap.send("alice", "op-post", b"successor", 51)?;
    let continuing_reader_decrypts = lap.receive("carol", &post, 52)? == b"successor";
    let post_wire = split_envelope(&post)?.1.to_vec();
    let removed_retained_state_rejected = lap.lab.decrypt("bob-retained", &post_wire).is_err()
        && lap.lab.decrypt("bob", &post_wire).is_err();
    let pre_cut_rejected_after_repair = lap.receive("dave", &pre_cut, 52).is_err();

    let gates = json!({
        "members_bound_to_apf_frontier_and_acc_context": members_bound,
        "authorized_release_delivered": delivered,
        "release_binding_enforced": release_binding_enforced,
        "rolled_back_client_replay_rejected": replay_rejected,
        "forged_acc_context_rejected": forged_acc_context_rejected,
        "fenced_until_qualifying_repair": fenced_until_repair,
        "qualifying_repair_confirmed": qualifying_repair_confirmed,
        "removed_retained_state_rejected": removed_retained_state_rejected,
        "continuing_reader_decrypts": continuing_reader_decrypts,
        "pre_cut_release_rejected_after_repair": pre_cut_rejected_after_repair,
    });
    let all = gates
        .as_object()
        .is_some_and(|gates| gates.values().all(|gate| gate == true));
    Ok(json!({
        "gates": gates,
        // Baseline (broken mode), expected true: API-only revocation without
        // MLS removal leaves the retained reader able to decrypt.
        "api_only_revocation_leaks": api_only_revocation_leaks,
        "full_lap_mls": all && api_only_revocation_leaks,
        "profile": "single authority, trusted in-process adapter, designated honest continuing member, simulated crashes; Bridge_remove^ETK proof obligation open",
    }))
}
