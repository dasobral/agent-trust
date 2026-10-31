//! Durable, trusted-local authority kernel.  Authentication and MLS validation live in adapters.
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::rc::Rc;

const MAX_ID: usize = 256;
const MAX_PAYLOAD: usize = 4096;
/// Maximum `persist`/`emit` envelope length in hex characters (1 MiB of bytes).
const MAX_ENVELOPE: usize = 2_097_152;

pub struct Authority {
    conn: Connection,
    /// R-13d: the chain tip `(sequence, hash)` this handle last validated.
    anchor: Option<(u64, String)>,
    /// R-13d: the working set as loaded, or as last saved, in this request, with its head.
    base: Option<(State, Head)>,
    /// R-13d: the request that the events appended by `save` record, and its cause.
    recorded: Value,
    cause: Option<String>,
    /// R-13d.2: the Merkle tree over the event hashes as this handle validated them.
    mmr: Mmr,
    /// R-13d.5: a scratch kernel that `replay` drives; see `Authority::scratch`.
    replaying: bool,
}

/// The kernel tables.
const TABLES: &str = "CREATE TABLE IF NOT EXISTS authority_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS authority_events (sequence INTEGER PRIMARY KEY, previous TEXT NOT NULL, hash TEXT NOT NULL, event TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS authority_ops (op TEXT PRIMARY KEY, row TEXT NOT NULL, written INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS authority_invocations (ordinal INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, record TEXT NOT NULL, written INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS authority_mmr (height INTEGER NOT NULL, idx INTEGER NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(height, idx));";

/// R-13d.2: an append-only Merkle tree (a Merkle mountain range) over the event hashes,
/// kept as its peaks. Leaf `i` is the hash of event `i`.
#[derive(Clone, Default)]
struct Mmr {
    leaves: u64,
    peaks: Vec<[u8; 32]>,
}

impl Mmr {
    fn append(&mut self, leaf: [u8; 32]) {
        let mut node = leaf;
        let mut n = self.leaves;
        while n & 1 == 1 {
            let left = self.peaks.pop().unwrap_or([0; 32]);
            node = mmr_node(&left, &node);
            n >>= 1;
        }
        self.peaks.push(node);
        self.leaves += 1;
    }

    fn root(&self) -> [u8; 32] {
        mmr_root(self.leaves, &self.peaks)
    }
}

/// R-13d: the bounded part of the state, kept in `authority_meta['state']`. Operations
/// and invocations live in their own tables; a request loads only the ones it names.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Head {
    group: String,
    revision: u64,
    epoch: u64,
    branch: String,
    read_fenced: bool,
    roster: Vec<String>,
    grants: Vec<Grant>,
    delegations: Vec<Delegation>,
    policy_revision: u64,
    fence_revision: Option<u64>,
    repair_pending: Option<String>,
    invocations_count: u64,
    /// Running commitment to every invocation, in creation order.
    invocations_root: String,
}

/// R-13d: one row of `authority_ops`: an operation and the recipients that consumed it,
/// in consumption order.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OpRow {
    operation: Operation,
    consumed_by: Vec<String>,
}

/// R-13d: what one event changed. `before` holds the old values of exactly the fields and
/// rows that `after` sets; a new operation's `before` row is null.
#[derive(Default, Serialize, Deserialize)]
struct Effects {
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    head: serde_json::Map<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ops: BTreeMap<String, Option<OpRow>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    invocations: Vec<Invocation>,
}

/// R-13d: a v2 history event. Its hash covers its exact stored bytes (`event_hash_v2`).
#[derive(Serialize, Deserialize)]
struct EventV2 {
    v: u64,
    kind: String,
    revision: u64,
    request: Value,
    cause: Option<String>,
    before: Effects,
    after: Effects,
    /// `SHA-256` of the head row after the event.
    head_hash: String,
}

const ZERO_ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct State {
    group: String,
    revision: u64,
    epoch: u64,
    branch: String,
    read_fenced: bool,
    roster: Vec<String>,
    grants: Vec<Grant>,
    delegations: Vec<Delegation>,
    operations: Vec<Operation>,
    consumed: Vec<Consumption>,
    #[serde(default)]
    invocations: Vec<Invocation>,
    #[serde(default)]
    policy_revision: u64,
    #[serde(default)]
    fence_revision: Option<u64>,
    #[serde(default)]
    repair_pending: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Grant {
    subject: String,
    right: String,
    generation: u64,
    active: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Delegation {
    subject: String,
    parent: String,
    rights: Vec<String>,
    resources: Vec<String>,
    expires_at: u64,
    not_before: u64,
    depth: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Operation {
    op: String,
    actor: String,
    status: String,
    right: Option<String>,
    revision: Option<u64>,
    epoch: Option<u64>,
    branch: Option<String>,
    digest: Option<String>,
    /// The persisted envelope's hex, kept only by stores written before R-13c.
    envelope: Option<String>,
    /// R-13c: `SHA-256` of the persisted envelope bytes (lowercase hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    envelope_digest: Option<String>,
    roster: Vec<Reader>,
    writer_generation: Option<u64>,
    resource: String,
    invocation: Option<String>,
    #[serde(default)]
    policy_revision: Option<u64>,
}
impl Operation {
    /// Whether an envelope is bound to this operation.
    fn persisted(&self) -> bool {
        self.envelope_digest.is_some() || self.envelope.is_some()
    }

    /// Whether the envelope with `digest` (SHA-256, hex) is the bound one; `None` before
    /// `persist`. R-13c binds by digest; a store written before R-13c keeps the hex.
    fn binds(&self, digest: &str) -> Option<bool> {
        match (&self.envelope_digest, &self.envelope) {
            (Some(bound), _) => Some(bound == digest),
            (None, Some(old)) => Some(
                hex::decode(old)
                    .ok()
                    .is_some_and(|bytes| hex::encode(Sha256::digest(bytes)) == digest),
            ),
            (None, None) => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Invocation {
    id: String,
    origin: String,
    executor: String,
    rights: Vec<String>,
    resources: Vec<String>,
    parent: Option<String>,
    active: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Reader {
    subject: String,
    generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Consumption {
    op: String,
    recipient: String,
}
/// Canonical policy view hashed into `policy_digest`; field order is part of the format.
#[derive(Serialize)]
struct PolicyView<'a> {
    group: &'a str,
    policy_revision: u64,
    grants: &'a [Grant],
    delegations: &'a [Delegation],
    /// R-13d: the invocations enter through their running commitment.
    invocations_count: u64,
    invocations_root: &'a str,
}
#[derive(Serialize)]
struct HashInput<'a> {
    sequence: u64,
    previous: &'a str,
    event: &'a Value,
}

impl Authority {
    /// Opens a kernel store. The whole hash chain is validated once per handle; a v1 store
    /// (a snapshot per event) is migrated to the R-13d tables in the same transaction.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(db)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(db)?;
        conn.execute_batch(TABLES).map_err(db)?;
        let mut this = Self {
            conn,
            anchor: None,
            base: None,
            recorded: Value::Null,
            cause: None,
            mmr: Mmr::default(),
            replaying: false,
        };
        this.conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        match this.open_checks() {
            Ok(()) => this.conn.execute_batch("COMMIT").map_err(db)?,
            Err(error) => {
                let _ = this.conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        Ok(this)
    }

    /// R-13d.5: re-executes every recorded request after sequence `after` (all of them
    /// when `None`) from the state as of `after`, and requires the same events, with a
    /// `now` that never goes back. v1 events, which record no request, are not replayed.
    /// The cost is the events after `after` and the rows they touch, not the history.
    pub fn replay(&mut self, after: Option<u64>) -> Result<(), String> {
        self.conn.execute_batch("BEGIN").map_err(db)?;
        let result = self.revalidate().and_then(|()| self.replay_inner(after));
        let _ = self.conn.execute_batch("COMMIT");
        result
    }

    fn replay_inner(&mut self, after: Option<u64>) -> Result<(), String> {
        let corrupt = |detail: &str| format!("corrupt_history: replay: {detail}");
        let Some((tip, _)) = self.anchor.clone() else {
            return Ok(());
        };
        let mut start = after.map_or(0, |after| after.saturating_add(1));
        while start <= tip && !is_v2(&self.event_row(start)?.2) {
            start += 1;
        }
        if start > tip {
            return Ok(());
        }
        // The state as of `start - 1`: the head and the rows the replayed events touch,
        // from their `before` values, latest event first.
        let mut head: Value =
            serde_json::from_str(&self.get_meta("state")?.ok_or_else(|| corrupt("no head"))?)
                .map_err(|_| corrupt("head"))?;
        let mut ops: BTreeMap<String, Option<Value>> = BTreeMap::new();
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT event FROM authority_events WHERE sequence >= ?1 ORDER BY sequence DESC")
                .map_err(db)?;
            let rows = stmt
                .query_map([start as i64], |r| r.get::<_, String>(0))
                .map_err(db)?;
            for raw in rows {
                let event: Value =
                    serde_json::from_str(&raw.map_err(db)?).map_err(|_| corrupt("event"))?;
                for (key, value) in event["before"]["head"].as_object().into_iter().flatten() {
                    head[key] = value.clone();
                }
                for (op, row) in event["before"]["ops"].as_object().into_iter().flatten() {
                    ops.insert(op.clone(), (!row.is_null()).then(|| row.clone()));
                }
                let request = if event["kind"] == "expire" {
                    &event["request"]["step"]
                } else {
                    &event["request"]
                };
                for key in ["invocation", "parent_invocation"] {
                    if let Some(id) = request[key].as_str() {
                        referenced.insert(id.to_owned());
                    }
                }
                for row in event["after"]["ops"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(_, r)| r)
                {
                    if let Some(id) = row["operation"]["invocation"].as_str() {
                        referenced.insert(id.to_owned());
                    }
                }
            }
        }
        let mut copy = Authority::scratch()?;
        if start > 0 {
            let head: Head = serde_json::from_value(head).map_err(|_| corrupt("head"))?;
            let written = (start - 1) as i64;
            let raw = serde_json::to_string(&head).map_err(|_| corrupt("head"))?;
            copy.conn
                .execute(
                    "INSERT INTO authority_meta(k,v) VALUES('state',?1),('format','2')",
                    [raw],
                )
                .map_err(db)?;
            for (op, row) in &ops {
                if let Some(row) = row {
                    copy.conn
                        .execute(
                            "INSERT INTO authority_ops(op,row,written) VALUES(?1,?2,?3)",
                            rusqlite::params![op, row.to_string(), written],
                        )
                        .map_err(db)?;
                }
            }
            // Invocations never change once written; those that existed at `start - 1`
            // are copied with their parent chains.
            let mut pending: Vec<String> = referenced.into_iter().collect();
            let mut copied = HashSet::new();
            while let Some(id) = pending.pop() {
                if !copied.insert(id.clone()) {
                    continue;
                }
                let row: Option<(i64, String)> = self
                    .conn
                    .query_row(
                        "SELECT ordinal, record FROM authority_invocations WHERE id=?1",
                        [&id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .map_err(db)?;
                let Some((ordinal, record)) = row else {
                    continue;
                };
                if (ordinal as u64) >= head.invocations_count {
                    continue;
                }
                let invocation: Invocation =
                    serde_json::from_str(&record).map_err(|_| corrupt("invocation"))?;
                if let Some(parent) = invocation.parent {
                    pending.push(parent);
                }
                copy.conn
                    .execute(
                        "INSERT INTO authority_invocations(ordinal,id,record,written) VALUES(?1,?2,?3,?4)",
                        rusqlite::params![ordinal, id, record, written],
                    )
                    .map_err(db)?;
            }
            let (previous, hash, raw) = self.event_row(start - 1)?;
            copy.conn
                .execute(
                    "INSERT INTO authority_events(sequence,previous,hash,event) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![written, previous, hash, raw],
                )
                .map_err(db)?;
        }
        let mut floor: Option<u64> = None;
        let mut sequence = start;
        while sequence <= tip {
            let (_, _, raw) = self.event_row(sequence)?;
            if !is_v2(&raw) {
                return Err(corrupt("a v1 event after a v2 event"));
            }
            let event: Value = serde_json::from_str(&raw).map_err(|_| corrupt("event"))?;
            let mut request = if event["kind"] == "expire" {
                event["request"]["step"].clone()
            } else {
                event["request"].clone()
            };
            if let Some(now) = request["now"].as_u64() {
                if floor.is_some_and(|floor| now < floor) {
                    return Err(corrupt("now goes back"));
                }
                floor = Some(now);
            }
            if let (Some(fields), Some(cause)) = (request.as_object_mut(), event["cause"].as_str())
            {
                fields.insert("cause".into(), json!(cause));
            }
            let _ = copy.execute(request);
            let produced = copy
                .tip()?
                .filter(|(produced, _)| *produced >= sequence && *produced <= tip)
                .ok_or_else(|| {
                    corrupt(&format!(
                        "event {sequence} is not what its request produces"
                    ))
                })?;
            if self.event_row(produced.0)?.1 != produced.1 {
                return Err(corrupt(&format!(
                    "event {sequence} is not what its request produces"
                )));
            }
            sequence = produced.0 + 1;
        }
        Ok(())
    }

    /// R-13d.5: an empty in-memory kernel that replays recorded requests: it trusts its
    /// rows, which `replay` built from validated events, and keeps no tree.
    fn scratch() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(db)?;
        conn.execute_batch(TABLES).map_err(db)?;
        Ok(Self {
            conn,
            anchor: None,
            base: None,
            recorded: Value::Null,
            cause: None,
            mmr: Mmr::default(),
            replaying: true,
        })
    }

    pub fn execute(&mut self, request: Value) -> Result<Value, String> {
        let obj = request
            .as_object()
            .ok_or_else(|| "malformed: request object".to_string())?;
        let command = req_id(obj, "command")?;
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        // R-13a, R-13d: the history is validated once per request, at the start of its
        // transaction, from the tip this handle validated last.
        if let Err(error) = self.revalidate() {
            let _ = self.conn.execute_batch("ROLLBACK");
            return Err(error);
        }
        self.recorded = recorded_request(obj);
        self.cause = obj.get("cause").and_then(Value::as_str).map(str::to_owned);
        // R-12: the expiry events come first, in the step's transaction. A failed step
        // rolls back to the savepoint only, so the expiry is recorded whatever the step's
        // outcome; a failed sweep rolls back everything.
        let swept = self
            .expire(obj, &command)
            .and_then(|()| self.conn.execute_batch("SAVEPOINT step").map_err(db));
        if let Err(error) = swept {
            let _ = self.conn.execute_batch("ROLLBACK");
            return Err(error);
        }
        match self.execute_inner(obj, &command) {
            Ok(value) => {
                self.conn
                    .execute_batch("RELEASE step; COMMIT")
                    .map_err(db)?;
                Ok(value)
            }
            Err(error) => {
                let kept = self
                    .conn
                    .execute_batch("ROLLBACK TO step; RELEASE step; COMMIT");
                if kept.is_err() {
                    let _ = self.conn.execute_batch("ROLLBACK");
                }
                Err(error)
            }
        }
    }

    /// R-12 (D-16): before a mutating step that carries `now`, one `expire` event for each
    /// delegation that is no longer valid at `now` (`now > expires_at`, as in the chain
    /// check) while its subject or a descendant still holds an active grant of one of its
    /// rights. Each event applies `revoke`'s cascade and fence rule to those rights and
    /// advances `revision` and `policy_revision` by one. Delegations are taken in stored
    /// order, so a parent's cascade usually leaves nothing for its children's own events.
    /// A step without a valid `now`, and a kernel before `init`, records nothing.
    fn expire(&mut self, o: &serde_json::Map<String, Value>, command: &str) -> Result<(), String> {
        if !EXPIRY_COMMANDS.contains(&command) || self.get_meta("state")?.is_none() {
            return Ok(());
        }
        let Some(now) = o.get("now").and_then(Value::as_u64) else {
            return Ok(());
        };
        let mut s = self.load(o)?;
        // R-13d.5: an expiry records the whole step request, so `replay` can run the step.
        let expiry = json!({"command":"expire", "now":now, "step":self.recorded.clone()});
        let step = std::mem::replace(&mut self.recorded, expiry);
        let swept = self.sweep(&mut s, now);
        self.recorded = step;
        swept
    }

    fn sweep(&mut self, s: &mut State, now: u64) -> Result<(), String> {
        let expired: Vec<(String, Vec<String>)> = s
            .delegations
            .iter()
            .filter(|d| now > d.expires_at)
            .map(|d| (d.subject.clone(), d.rights.clone()))
            .collect();
        for (subject, delegated) in expired {
            let targets = descendants(s, &subject);
            let mut changed = false;
            let mut fences = false;
            for g in &mut s.grants {
                if g.active && targets.contains(&g.subject) && delegated.contains(&g.right) {
                    g.active = false;
                    changed = true;
                    fences |= g.right == "read" && s.roster.contains(&g.subject);
                }
            }
            if changed {
                bump(s);
                bump_policy(s);
                if fences {
                    s.read_fenced = true;
                    s.fence_revision = Some(s.policy_revision);
                }
                self.save(s, "expire")?;
            }
        }
        Ok(())
    }

    fn execute_inner(
        &mut self,
        obj: &serde_json::Map<String, Value>,
        command: &str,
    ) -> Result<Value, String> {
        let initialized = self.get_meta("state")?.is_some();
        if command == "init" {
            if initialized {
                return Err("already_initialized".into());
            }
            let group = req_id(obj, "group")?;
            let root = req_id(obj, "root")?;
            let branch = opt_id(obj, "branch")?.unwrap_or_else(|| "genesis".into());
            // R-8c: optional root delegation resources; default `[group]`, must contain the group.
            let root_resources = match obj.get("resources") {
                None => vec![group.clone()],
                Some(_) => {
                    let resources = req_ids(obj, "resources")?;
                    if !resources.contains(&group) {
                        return Err("malformed: resources".into());
                    }
                    resources
                }
            };
            let state = State {
                group: group.clone(),
                revision: 0,
                epoch: 0,
                branch: branch.clone(),
                read_fenced: false,
                roster: vec![root.clone()],
                grants: rights(&["read", "write", "admin", "admit"])
                    .into_iter()
                    .map(|right| Grant {
                        subject: root.clone(),
                        right,
                        generation: 0,
                        active: true,
                    })
                    .collect(),
                delegations: vec![Delegation {
                    subject: root.clone(),
                    parent: root.clone(),
                    rights: rights(&["read", "write", "admin", "admit"]),
                    resources: root_resources,
                    expires_at: u64::MAX,
                    not_before: 0,
                    depth: 8,
                }],
                operations: vec![],
                consumed: vec![],
                invocations: vec![],
                policy_revision: 0,
                fence_revision: None,
                repair_pending: None,
            };
            self.base = None;
            self.save(&state, "init")?;
            return Ok(json!({"revision":0,"epoch":0,"branch":branch}));
        }
        if !initialized {
            return Err("uninitialized".into());
        }
        let mut state = self.load(obj)?;
        match command {
            "checkpoint" => self.checkpoint(history_selector(obj)?),
            "history_head" => self.history_head(obj),
            "grant" => self.grant(&mut state, obj),
            "delegate" => self.delegate(&mut state, obj),
            "invoke" => self.invoke(&mut state, obj),
            "revoke" => self.revoke(&mut state, obj),
            "admit" => self.admit(&mut state, obj),
            "allocate" => self.allocate(&mut state, obj),
            "release" => self.release(&mut state, obj),
            "persist" => self.persist(&mut state, obj),
            "emit" => self.emit(&state, obj),
            "consume" => self.consume(&mut state, obj),
            "abandon" => self.abandon(&mut state, obj),
            "repair" => self.repair(&mut state, obj),
            "repair_stage" => self.repair_stage(&mut state, obj),
            "repair_open" => self.repair_open(&mut state, obj),
            "rekey" => self.rekey(&mut state, obj),
            "subject_status" => subject_status(&state, obj),
            _ => Err("malformed: unknown command".into()),
        }
    }

    fn grant(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let subject = req_id(o, "subject")?;
        let right = req_right(o, "right")?;
        let generation = req_u64(o, "generation")?;
        let fresh = req_bool(o, "fresh_keys")?;
        let now = req_u64(o, "now")?;
        if !effective(s, &actor, "admin", now) {
            return Err("unauthorized".into());
        }
        match grant_mut(s, &subject, &right) {
            None => {
                if generation != 0 || !fresh {
                    return Err("invalid_generation".into());
                }
                s.grants.push(Grant {
                    subject,
                    right,
                    generation,
                    active: true,
                });
            }
            Some(g) if g.active => return Err("invalid_generation".into()),
            Some(g) => {
                if generation != g.generation.saturating_add(1) || !fresh {
                    return Err("invalid_generation".into());
                }
                g.generation = generation;
                g.active = true;
            }
        }
        bump(s);
        bump_policy(s);
        self.save(s, "grant")?;
        Ok(json!({"revision":s.revision}))
    }

    fn delegate(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let subject = req_id(o, "subject")?;
        let rs = req_rights(o, "rights")?;
        let resources = req_ids(o, "resources")?;
        let expires = req_u64(o, "expires_at")?;
        let before = req_u64(o, "not_before")?;
        let depth = req_u64(o, "depth")?;
        let now = req_u64(o, "now")?;
        if subject == actor
            || known_subject(s, &subject)
            || rs.is_empty()
            || resources.is_empty()
            || before > expires
        {
            return Err("invalid_delegation".into());
        }
        let parent = s
            .delegations
            .iter()
            .find(|d| d.subject == actor)
            .ok_or_else(|| "invalid_delegation".to_string())?;
        if depth >= parent.depth
            || before < parent.not_before
            || expires > parent.expires_at
            || !subset(&resources, &parent.resources)
        {
            return Err("invalid_delegation".into());
        }
        for r in &rs {
            if !parent.rights.contains(r) || !effective(s, &actor, r, now) {
                return Err("invalid_delegation".into());
            }
        }
        s.delegations.push(Delegation {
            subject: subject.clone(),
            parent: actor,
            rights: rs.clone(),
            resources,
            expires_at: expires,
            not_before: before,
            depth,
        });
        for right in rs {
            s.grants.push(Grant {
                subject: subject.clone(),
                right,
                generation: 0,
                active: true,
            });
        }
        bump(s);
        bump_policy(s);
        self.save(s, "delegate")?;
        Ok(json!({"revision":s.revision}))
    }

    fn revoke(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let subject = req_id(o, "subject")?;
        let right = req_right(o, "right")?;
        let now = req_u64(o, "now")?;
        if !effective(s, &actor, "admin", now) {
            return Err("unauthorized".into());
        }
        if grant_mut(s, &subject, &right).is_none() {
            return Err("invalid_transition".into());
        }
        let targets = descendants(s, &subject);
        let fences_current_reader =
            right == "read" && s.roster.iter().any(|reader| targets.contains(reader));
        let mut changed = false;
        for g in &mut s.grants {
            if g.right == right && targets.contains(&g.subject) && g.active {
                g.active = false;
                changed = true;
            }
        }
        if changed {
            bump(s);
            bump_policy(s);
            if fences_current_reader {
                s.read_fenced = true;
                s.fence_revision = Some(s.policy_revision);
            }
            self.save(s, "revoke")?;
        }
        Ok(json!({"revision":s.revision,"read_fenced":s.read_fenced}))
    }

    fn admit(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let subject = req_id(o, "subject")?;
        let now = req_u64(o, "now")?;
        let frontier = match (
            opt_id(o, "parent_branch")?,
            opt_id(o, "new_branch")?,
            opt_u64(o, "epoch")?,
        ) {
            (None, None, None) => None,
            (Some(parent), Some(new), Some(epoch)) => Some((parent, new, epoch)),
            _ => return Err("malformed: admit frontier".into()),
        };
        if !effective(s, &actor, "admin", now)
            || !effective(s, &subject, "admit", now)
            || !effective(s, &subject, "read", now)
        {
            return Err("unauthorized".into());
        }
        if s.read_fenced {
            return Err("read_fenced".into());
        }
        if s.roster.contains(&subject) {
            return Err("invalid_transition".into());
        }
        let next_epoch = s
            .epoch
            .checked_add(1)
            .ok_or_else(|| "invalid_transition".to_string())?;
        let next_branch = match frontier {
            None => format!("admit:{}:{}", next_epoch, subject),
            Some((parent, new, epoch)) => {
                if parent != s.branch || epoch != next_epoch {
                    return Err("stale_frontier".into());
                }
                if new == parent {
                    return Err("invalid_transition".into());
                }
                new
            }
        };
        s.roster.push(subject);
        s.epoch = next_epoch;
        s.branch = next_branch;
        bump(s);
        self.save(s, "admit")?;
        Ok(json!({"epoch":s.epoch,"branch":s.branch}))
    }

    fn allocate(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let op = req_id(o, "op")?;
        let resource = o
            .get("resource")
            .and_then(Value::as_str)
            .unwrap_or(&s.group)
            .to_owned();
        if resource.is_empty() || resource.len() > MAX_ID {
            return Err("malformed: resource".into());
        }
        let invocation = o
            .get("invocation")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if s.operations.iter().any(|x| x.op == op) {
            return Err("duplicate_operation".into());
        }
        if let Some(id) = &invocation {
            let token = s
                .invocations
                .iter()
                .find(|x| x.id == *id)
                .ok_or_else(|| "unauthorized".to_string())?;
            if token.executor != actor || !token.active {
                return Err("unauthorized".into());
            }
        }
        s.operations.push(Operation {
            op: op.clone(),
            actor,
            status: "allocated".into(),
            right: None,
            revision: None,
            epoch: None,
            branch: None,
            digest: None,
            envelope: None,
            envelope_digest: None,
            roster: vec![],
            writer_generation: None,
            resource,
            invocation,
            policy_revision: None,
        });
        bump(s);
        self.save(s, "allocate")?;
        Ok(json!({"op":op}))
    }

    fn invoke(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let executor = req_id(o, "executor")?;
        let requested_rights = req_rights(o, "rights")?;
        let requested_resources = req_ids(o, "resources")?;
        let now = req_u64(o, "now")?;
        if !s.roster.contains(&executor) {
            return Err("unauthorized".into());
        }
        let parent_id = o
            .get("parent_invocation")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let (origin, parent_rights, parent_resources) = if let Some(id) = &parent_id {
            let parent = s
                .invocations
                .iter()
                .find(|x| x.id == *id)
                .ok_or_else(|| "unauthorized".to_string())?;
            if !parent.active || parent.executor != actor {
                return Err("unauthorized".into());
            }
            (
                parent.origin.clone(),
                parent.rights.clone(),
                parent.resources.clone(),
            )
        } else {
            (actor.clone(), Vec::new(), Vec::new())
        };
        let rights = if parent_id.is_some() {
            if !subset(&requested_rights, &parent_rights) {
                return Err("invalid_invocation".into());
            }
            requested_rights
        } else {
            requested_rights
        };
        let resources = if parent_id.is_some() {
            if !subset(&requested_resources, &parent_resources) {
                return Err("invalid_invocation".into());
            }
            requested_resources
        } else {
            // R-9: a root invocation's resources must each be held by the origin
            // under the R-8 chain check. The executor is checked at release (R-8b).
            if !requested_resources
                .iter()
                .all(|resource| resource_held(s, &origin, resource))
            {
                return Err("invalid_invocation".into());
            }
            requested_resources
        };
        for right in &rights {
            if !effective(s, &origin, right, now) || !effective(s, &executor, right, now) {
                return Err("unauthorized".into());
            }
        }
        let id = format!("invocation:{}", s.revision.saturating_add(1));
        s.invocations.push(Invocation {
            id: id.clone(),
            origin,
            executor,
            rights,
            resources,
            parent: parent_id,
            active: true,
        });
        bump(s);
        bump_policy(s);
        self.save(s, "invoke")?;
        Ok(json!({"invocation":id}))
    }

    fn release(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let actor = req_id(o, "actor")?;
        let op = req_id(o, "op")?;
        let right = req_right(o, "right")?;
        if !matches!(right.as_str(), "read" | "write") {
            return Err("malformed: right".into());
        }
        let frontier = match (opt_u64(o, "revision")?, opt_u64(o, "policy_revision")?) {
            (Some(revision), None) => Frontier::State(revision),
            (None, Some(policy)) => Frontier::Policy(policy),
            _ => return Err("malformed: revision or policy_revision".into()),
        };
        let epoch = req_u64(o, "epoch")?;
        let branch = req_id(o, "branch")?;
        let digest = req_payload(o, "digest")?;
        let now = req_u64(o, "now")?;
        if !effective(s, &actor, "write", now) {
            return Err("unauthorized".into());
        }
        if s.read_fenced || s.repair_pending.is_some() {
            return Err("read_fenced".into());
        }
        let current = match frontier {
            Frontier::State(revision) => revision == s.revision,
            Frontier::Policy(policy) => policy == s.policy_revision,
        };
        if !current || epoch != s.epoch || branch != s.branch {
            return Err("stale_frontier".into());
        }
        let revision = s.revision;
        let policy_revision = s.policy_revision;
        if !s.roster.contains(&actor) {
            return Err("unauthorized".into());
        }
        let readers: Result<Vec<Reader>, String> = s
            .roster
            .iter()
            .map(|name| {
                active_generation(s, name, "read", now)
                    .map(|generation| Reader {
                        subject: name.clone(),
                        generation,
                    })
                    .ok_or_else(|| "unauthorized".to_string())
            })
            .collect();
        let readers = readers?;
        let writer =
            active_generation(s, &actor, "write", now).ok_or_else(|| "unauthorized".to_string())?;
        let position = s
            .operations
            .iter()
            .position(|x| x.op == op)
            .ok_or_else(|| "invalid_transition".to_string())?;
        if s.operations[position].actor != actor || s.operations[position].status != "allocated" {
            return Err("invalid_transition".into());
        }
        let operation_resource = s.operations[position].resource.clone();
        if o.get("resource")
            .and_then(Value::as_str)
            .unwrap_or(&operation_resource)
            != operation_resource
        {
            return Err("binding_mismatch".into());
        }
        // R-8a: the actor's own delegation chain must hold the operation resource.
        if !resource_held(s, &actor, &operation_resource) {
            return Err("unauthorized".into());
        }
        if let Some(invocation_id) = s.operations[position].invocation.clone() {
            if !invocation_valid(
                s,
                &invocation_id,
                &actor,
                &right,
                &operation_resource,
                now,
                &mut HashSet::new(),
            ) {
                return Err("unauthorized".into());
            }
        } else if !effective(s, &actor, &right, now) {
            return Err("unauthorized".into());
        }
        check_cover(o.get("cover"), &actor, writer, &readers)?;
        let operation = &mut s.operations[position];
        operation.status = "released".into();
        operation.right = Some(right.clone());
        operation.revision = Some(revision);
        operation.epoch = Some(epoch);
        operation.branch = Some(branch.clone());
        operation.digest = Some(digest.clone());
        operation.roster = readers;
        operation.writer_generation = Some(writer);
        operation.policy_revision = Some(policy_revision);
        bump(s);
        let event_hash = self.save(s, "release")?;
        Ok(
            json!({"op":op,"revision":revision,"policy_revision":policy_revision,"epoch":epoch,"branch":branch,"digest":digest,"event_hash":event_hash,"executor":actor,"invocation":s.operations[position].invocation,"effective_right":right,"resource":operation_resource}),
        )
    }

    fn persist(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let op = req_id(o, "op")?;
        let digest = req_payload(o, "digest")?;
        let envelope_digest = self.envelope_digest(o)?;
        let x = s
            .operations
            .iter_mut()
            .find(|x| x.op == op)
            .ok_or_else(|| "invalid_transition".to_string())?;
        if x.status == "abandoned" || x.status == "allocated" {
            return Err("invalid_transition".into());
        }
        if x.digest.as_deref() != Some(&digest) {
            return Err("binding_mismatch".into());
        }
        if let Some(bound) = x.binds(&envelope_digest) {
            if !bound {
                return Err("binding_mismatch".into());
            }
            return Ok(json!({"op":op}));
        }
        x.envelope_digest = Some(envelope_digest);
        x.status = "persisted".into();
        bump(s);
        self.save(s, "persist")?;
        Ok(json!({"op":op}))
    }

    /// R-13c: the digest of a request's envelope. A replayed `persist` (R-13d.5) carries
    /// the digest that its event recorded instead of the envelope.
    fn envelope_digest(&self, o: &serde_json::Map<String, Value>) -> Result<String, String> {
        if self.replaying && !o.contains_key("envelope") {
            return o
                .get("envelope_digest")
                .and_then(Value::as_str)
                .filter(|digest| digest.len() == 64)
                .map(str::to_owned)
                .ok_or_else(|| "malformed: envelope_digest".to_string());
        }
        let envelope = req_envelope(o, "envelope")?;
        let bytes = hex::decode(envelope).map_err(|_| "malformed: envelope".to_string())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn emit(&self, s: &State, o: &serde_json::Map<String, Value>) -> Result<Value, String> {
        let op = req_id(o, "op")?;
        let envelope = req_envelope(o, "envelope")?;
        let x = s
            .operations
            .iter()
            .find(|x| x.op == op)
            .ok_or_else(|| "not_persisted".to_string())?;
        let bytes = hex::decode(&envelope).map_err(|_| "malformed: envelope".to_string())?;
        let Some(bound) = x.binds(&hex::encode(Sha256::digest(bytes))) else {
            return Err("not_persisted".into());
        };
        if !bound || x.epoch != Some(s.epoch) || x.branch.as_deref() != Some(&s.branch) {
            return Err("binding_mismatch".into());
        }
        Ok(json!({"op":op,"envelope":envelope}))
    }

    fn consume(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let op = req_id(o, "op")?;
        let recipient = req_id(o, "recipient")?;
        let now = req_u64(o, "now")?;
        if s.repair_pending.is_some() {
            return Err("read_fenced".into());
        }
        let release = s
            .operations
            .iter()
            .find(|x| x.op == op)
            .ok_or_else(|| "not_persisted".to_string())?;
        if release.status != "persisted" || !release.persisted() {
            return Err("not_persisted".into());
        }
        if release.epoch != Some(s.epoch) || release.branch.as_deref() != Some(&s.branch) {
            return Err("binding_mismatch".into());
        }
        if s.read_fenced {
            return Err("read_fenced".into());
        }
        let actor = release.actor.clone();
        let writer_generation = release.writer_generation;
        let released_reader = release
            .roster
            .iter()
            .find(|r| r.subject == recipient)
            .cloned()
            .ok_or_else(|| "unauthorized".to_string())?;
        if !s.roster.contains(&recipient)
            || active_generation(s, &actor, "write", now) != writer_generation
            || active_generation(s, &recipient, "read", now) != Some(released_reader.generation)
        {
            return Err("unauthorized".into());
        }
        if s.consumed
            .iter()
            .any(|entry| entry.op == op && entry.recipient == recipient)
        {
            return Err("replay".into());
        }
        s.consumed.push(Consumption {
            op: op.clone(),
            recipient: recipient.clone(),
        });
        bump(s);
        self.save(s, "consume")?;
        Ok(json!({"op":op,"recipient":recipient}))
    }

    fn abandon(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let op = req_id(o, "op")?;
        let x = s
            .operations
            .iter_mut()
            .find(|x| x.op == op)
            .ok_or_else(|| "invalid_transition".to_string())?;
        if x.status == "abandoned" {
            return Ok(json!({"op":op}));
        }
        if x.status != "released" || x.persisted() {
            return Err("invalid_transition".into());
        }
        x.status = "abandoned".into();
        bump(s);
        self.save(s, "abandon")?;
        Ok(json!({"op":op}))
    }

    fn repair(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let parent = req_id(o, "parent_branch")?;
        let new = req_id(o, "new_branch")?;
        let epoch = req_u64(o, "epoch")?;
        let revision = req_u64(o, "revision")?;
        let removed = req_ids(o, "removed")?;
        if !req_bool(o, "update_path")?
            || !req_bool(o, "confirmed")?
            || !req_bool(o, "durable")?
            || s.repair_pending.is_some()
            || !s.read_fenced
            || parent != s.branch
            || new == parent
            || epoch
                != s.epoch
                    .checked_add(1)
                    .ok_or_else(|| "invalid_repair".to_string())?
            || revision != s.revision
        {
            return Err("invalid_repair".into());
        }
        let expected: BTreeSet<String> = s
            .roster
            .iter()
            .filter(|n| !active_without_time(s, n, "read"))
            .cloned()
            .collect();
        let got: BTreeSet<String> = removed.into_iter().collect();
        if expected != got || got.is_empty() {
            return Err("invalid_repair".into());
        }
        s.roster.retain(|n| !got.contains(n));
        s.epoch = epoch;
        s.branch = new;
        s.read_fenced = false;
        s.fence_revision = None;
        bump(s);
        self.save(s, "repair")?;
        Ok(json!({"epoch":s.epoch,"branch":s.branch,"revision":s.revision}))
    }

    /// D-3 step one: commit the repaired epoch and roster while the read fence stays closed.
    fn repair_stage(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let parent = req_id(o, "parent_branch")?;
        let new = req_id(o, "new_branch")?;
        let epoch = req_u64(o, "epoch")?;
        let policy_revision = req_u64(o, "policy_revision")?;
        let removed = req_ids(o, "removed")?;
        if !req_bool(o, "update_path")?
            || !req_bool(o, "durable")?
            || !s.read_fenced
            || parent != s.branch
            || new == parent
            || epoch
                != s.epoch
                    .checked_add(1)
                    .ok_or_else(|| "invalid_repair".to_string())?
            || policy_revision != s.policy_revision
            || s.fence_revision
                .is_some_and(|fence| policy_revision < fence)
        {
            return Err("invalid_repair".into());
        }
        let expected: BTreeSet<String> = s
            .roster
            .iter()
            .filter(|n| !active_without_time(s, n, "read"))
            .cloned()
            .collect();
        let got: BTreeSet<String> = removed.into_iter().collect();
        if expected != got || got.is_empty() {
            return Err("invalid_repair".into());
        }
        s.roster.retain(|n| !got.contains(n));
        s.epoch = epoch;
        s.branch = new.clone();
        s.repair_pending = Some(new);
        bump(s);
        self.save(s, "repair_stage")?;
        Ok(json!({"epoch":s.epoch,"branch":s.branch,"policy_revision":s.policy_revision}))
    }

    /// D-3 step two: open the read fence once the staged repair is confirmed.
    fn repair_open(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let branch = req_id(o, "branch")?;
        let confirmed = req_bool(o, "confirmed")?;
        if !confirmed
            || s.repair_pending.as_deref() != Some(branch.as_str())
            || branch != s.branch
            || s.roster.iter().any(|n| !active_without_time(s, n, "read"))
        {
            return Err("invalid_repair".into());
        }
        s.read_fenced = false;
        s.repair_pending = None;
        s.fence_revision = None;
        bump(s);
        self.save(s, "repair_open")?;
        Ok(json!({"epoch":s.epoch,"branch":s.branch}))
    }

    /// R-10 (D-9): adapter-only re-authorization of a current member's non-read right.
    /// It applies the `grant` rules with `fresh_keys` true and advances the frontier by
    /// CAS in the same transaction. The fresh keys are the adapter's checked new-signer
    /// update commit; this kernel sees only its successor frontier.
    fn rekey(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        // Field validation precedes every semantic check (C-29).
        let actor = req_id(o, "actor")?;
        let subject = req_id(o, "subject")?;
        let right = req_right(o, "right")?;
        if right == "read" {
            return Err("malformed: right".into());
        }
        let generation = req_u64(o, "generation")?;
        let parent = req_id(o, "parent_branch")?;
        let new = req_id(o, "new_branch")?;
        let epoch = req_u64(o, "epoch")?;
        let now = req_u64(o, "now")?;

        // The `grant` checks with fresh_keys true.
        if !effective(s, &actor, "admin", now) {
            return Err("unauthorized".into());
        }
        match s
            .grants
            .iter()
            .find(|g| g.subject == subject && g.right == right)
        {
            None if generation != 0 => return Err("invalid_generation".into()),
            Some(g) if g.active || generation != g.generation.saturating_add(1) => {
                return Err("invalid_generation".into());
            }
            _ => {}
        }
        // R-10 additions.
        if !s.roster.contains(&subject) {
            return Err("invalid_transition".into());
        }
        if s.read_fenced || s.repair_pending.is_some() {
            return Err("read_fenced".into());
        }
        let next_epoch = s
            .epoch
            .checked_add(1)
            .ok_or_else(|| "invalid_transition".to_string())?;
        if parent != s.branch || epoch != next_epoch {
            return Err("stale_frontier".into());
        }
        if new == parent {
            return Err("invalid_transition".into());
        }

        match grant_mut(s, &subject, &right) {
            Some(g) => {
                g.generation = generation;
                g.active = true;
            }
            None => s.grants.push(Grant {
                subject,
                right,
                generation,
                active: true,
            }),
        }
        s.epoch = next_epoch;
        s.branch = new;
        bump(s);
        bump_policy(s);
        self.save(s, "rekey")?;
        Ok(json!({"epoch":s.epoch,"branch":s.branch,"policy_revision":s.policy_revision}))
    }

    /// R-13a, R-13d: `history` selects which events the response carries; the head
    /// fields and `history_root` are always present. `"all"` rebuilds the v1 snapshot of
    /// every event; `{"since": s}` returns the stored events after `s` as they are.
    fn checkpoint(&self, selector: HistorySelector) -> Result<Value, String> {
        let head = &self
            .base
            .as_ref()
            .ok_or_else(|| "uninitialized".to_string())?
            .1;
        let (tip_sequence, root) = self.tip()?.ok_or_else(|| "corrupt_history".to_string())?;
        let mut response = json!({"group":head.group,"revision":head.revision,"policy_revision":head.policy_revision,"policy_digest":policy_digest(head)?,"fence_revision":head.fence_revision,"repair_pending":head.repair_pending,"epoch":head.epoch,"branch":head.branch,"read_fenced":head.read_fenced,"roster":head.roster,"grants":head.grants,"history_root":root});
        let since = match selector {
            HistorySelector::None => return Ok(response),
            HistorySelector::All => None,
            // A reader ahead of the tip saw a history this store no longer holds.
            HistorySelector::Since(since) if since > tip_sequence => {
                return Err("stale_frontier: history since is past the tip".into())
            }
            HistorySelector::Since(since) => Some(since),
        };
        response["invocations"] = Value::Array(self.all_invocations()?);
        let mut history = Vec::new();
        match since {
            None => {
                let errors = Rc::new(RefCell::new(None));
                for entry in HistoryEntries::new(&self.conn, true, Rc::clone(&errors)) {
                    history.push(entry);
                }
                let failed = errors.borrow_mut().take();
                if let Some(error) = failed {
                    return Err(error);
                }
            }
            Some(since) => {
                let mut stmt = self
                    .conn
                    .prepare("SELECT sequence,previous,hash,event FROM authority_events WHERE sequence > ?1 ORDER BY sequence")
                    .map_err(db)?;
                let after = i64::try_from(since).map_err(|_| "malformed: history".to_string())?;
                let rows = stmt
                    .query_map([after], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                        ))
                    })
                    .map_err(db)?;
                for row in rows {
                    let (sequence, previous, hash, raw) = row.map_err(db)?;
                    let event: Value =
                        serde_json::from_str(&raw).map_err(|_| "corrupt_history".to_string())?;
                    history.push(
                        json!({"sequence":sequence,"previous":previous,"hash":hash,"event":event}),
                    );
                }
            }
        }
        response["history"] = Value::Array(history);
        Ok(response)
    }

    /// R-13d.3: the tip `{sequence, hash}` validated at the start of this request, or the
    /// event at `at`, checked against the tree.
    fn history_head(&self, o: &serde_json::Map<String, Value>) -> Result<Value, String> {
        let (tip, hash) = self
            .anchor
            .clone()
            .ok_or_else(|| "corrupt_history".to_string())?;
        let Some(at) = o.get("at") else {
            return Ok(json!({"sequence":tip, "hash":hash}));
        };
        let at = at.as_u64().ok_or_else(|| "malformed: at".to_string())?;
        if at > tip {
            return Err("stale_frontier: history head past the tip".into());
        }
        let (_, hash, _) = self.event_row(at)?;
        self.verify_leaf(at, &hash)?;
        Ok(json!({"sequence":at, "hash":hash}))
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row("SELECT v FROM authority_meta WHERE k=?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)
    }

    /// R-13d: the working set of one request: the head, the operation named by `op`, and
    /// every invocation named by `invocation`, `parent_invocation` or that operation,
    /// with their parent chains. `execute` has validated the history in this transaction.
    fn load(&mut self, o: &serde_json::Map<String, Value>) -> Result<State, String> {
        let raw = self
            .get_meta("state")?
            .ok_or_else(|| "uninitialized".to_string())?;
        let head: Head = serde_json::from_str(&raw).map_err(|_| "corrupt_history".to_string())?;
        let mut s = state_from_head(&head);
        if let Some(op) = o.get("op").and_then(Value::as_str) {
            if let Some((row, written)) = self.op_row(op)? {
                if !self.replaying {
                    self.verify_op_row(op, &row, written)?;
                }
                for recipient in &row.consumed_by {
                    s.consumed.push(Consumption {
                        op: op.to_owned(),
                        recipient: recipient.clone(),
                    });
                }
                s.operations.push(row.operation);
            }
        }
        let mut pending: Vec<String> = ["invocation", "parent_invocation"]
            .iter()
            .filter_map(|k| o.get(*k).and_then(Value::as_str).map(str::to_owned))
            .collect();
        pending.extend(s.operations.iter().filter_map(|x| x.invocation.clone()));
        while let Some(id) = pending.pop() {
            if s.invocations.iter().any(|x| x.id == id) {
                continue;
            }
            if let Some((invocation, written)) = self.invocation_row(&id)? {
                if !self.replaying {
                    self.verify_invocation_row(&invocation, written)?;
                }
                if let Some(parent) = &invocation.parent {
                    pending.push(parent.clone());
                }
                s.invocations.push(invocation);
            }
        }
        self.base = Some((s.clone(), head));
        Ok(s)
    }

    /// An operation row and the sequence of the event that wrote it.
    fn op_row(&self, op: &str) -> Result<Option<(OpRow, u64)>, String> {
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT row,written FROM authority_ops WHERE op=?1",
                [op],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(raw, written)| parse_row(&raw, written))
            .transpose()
    }

    /// An invocation row and the sequence of the event that wrote it.
    fn invocation_row(&self, id: &str) -> Result<Option<(Invocation, u64)>, String> {
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT record,written FROM authority_invocations WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(raw, written)| parse_row(&raw, written))
            .transpose()
    }

    /// R-13d.2: the event that wrote a row, checked against its hash and the tree; its
    /// parsed body and whether it is v2.
    fn written_event(&self, written: u64) -> Result<(Value, bool), String> {
        let (previous, hash, raw) = self.event_row(written)?;
        if row_hash(written, &previous, &raw)? != hash {
            return Err("corrupt_history".into());
        }
        self.verify_leaf(written, &hash)?;
        let event = serde_json::from_str(&raw).map_err(|_| "corrupt_history".to_string())?;
        Ok((event, is_v2(&raw)))
    }

    /// R-13d.2: an operation row must be what the event that wrote it recorded.
    fn verify_op_row(&self, op: &str, row: &OpRow, written: u64) -> Result<(), String> {
        let corrupt = |_| "corrupt_history".to_string();
        let (event, v2) = self.written_event(written)?;
        let row = serde_json::to_value(row).map_err(corrupt)?;
        let expected = if v2 {
            event["after"]["ops"].get(op).cloned()
        } else {
            let state: State =
                serde_json::from_value(event["snapshot"].clone()).map_err(corrupt)?;
            state
                .operations
                .iter()
                .find(|x| x.op == op)
                .map(|x| serde_json::to_value(op_row_of(&state, x)))
                .transpose()
                .map_err(corrupt)?
        };
        if expected.as_ref() != Some(&row) {
            return Err("corrupt_history".into());
        }
        Ok(())
    }

    /// R-13d.2: an invocation row must be one the event that wrote it recorded.
    fn verify_invocation_row(&self, invocation: &Invocation, written: u64) -> Result<(), String> {
        let (event, v2) = self.written_event(written)?;
        let record = serde_json::to_value(invocation).map_err(|_| "corrupt_history".to_string())?;
        let written_by = if v2 {
            &event["after"]["invocations"]
        } else {
            &event["snapshot"]["invocations"]
        };
        if !written_by
            .as_array()
            .is_some_and(|records| records.contains(&record))
        {
            return Err("corrupt_history".into());
        }
        Ok(())
    }

    /// R-13d.2: leaf `index` with hash `leaf` is in the stored tree, whose peaks
    /// `revalidate` matched to this handle's root in this transaction.
    fn verify_leaf(&self, index: u64, leaf: &str) -> Result<(), String> {
        let n = u128::from(self.mmr.leaves);
        if u128::from(index) >= n {
            return Err("corrupt_history".into());
        }
        let mut node = leaf_bytes(leaf)?;
        let (mut height, mut j) = (0u32, u128::from(index));
        // The parent of (height, j) exists once both of its children are complete.
        while ((j | 1) + 1) << height <= n {
            let sibling = self.db_node(height, (j ^ 1) as u64)?;
            node = if j & 1 == 1 {
                mmr_node(&sibling, &node)
            } else {
                mmr_node(&node, &sibling)
            };
            j >>= 1;
            height += 1;
        }
        if self.db_node(height, j as u64)? != node {
            return Err("corrupt_history".into());
        }
        Ok(())
    }

    fn db_node(&self, height: u32, idx: u64) -> Result<[u8; 32], String> {
        let idx = i64::try_from(idx).map_err(|_| "corrupt_history".to_string())?;
        let hash: String = self
            .conn
            .query_row(
                "SELECT hash FROM authority_mmr WHERE height=?1 AND idx=?2",
                rusqlite::params![height, idx],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| "corrupt_history".to_string())?;
        leaf_bytes(&hash)
    }

    fn db_put(&self, height: u32, idx: u64, node: &[u8; 32]) -> Result<(), String> {
        let idx = i64::try_from(idx).map_err(|_| "corrupt_history".to_string())?;
        self.conn
            .execute(
                "INSERT INTO authority_mmr(height,idx,hash) VALUES(?1,?2,?3)",
                rusqlite::params![height, idx, hex::encode(node)],
            )
            .map_err(db)?;
        Ok(())
    }

    /// R-13d.2: appends leaf `index` to the stored tree, with every parent it completes.
    fn db_append(&self, index: u64, leaf: &str) -> Result<(), String> {
        let mut node = leaf_bytes(leaf)?;
        self.db_put(0, index, &node)?;
        let (mut height, mut j) = (0u32, index);
        while j & 1 == 1 {
            let left = self.db_node(height, j - 1)?;
            node = mmr_node(&left, &node);
            height += 1;
            j >>= 1;
            self.db_put(height, j, &node)?;
        }
        Ok(())
    }

    fn db_leaves(&self) -> Result<u64, String> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM authority_mmr WHERE height=0",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        u64::try_from(count).map_err(|_| "corrupt_history".to_string())
    }

    /// R-13d.2: the root of the stored tree over `leaves` leaves, from its peaks.
    fn db_root(&self, leaves: u64) -> Result<[u8; 32], String> {
        let mut peaks = Vec::new();
        let mut offset = 0u64;
        for height in (0..64u32).rev() {
            if leaves >> height & 1 == 1 {
                peaks.push(self.db_node(height, offset >> height)?);
                offset += 1u64 << height;
            }
        }
        Ok(mmr_root(leaves, &peaks))
    }

    /// R-13d.2: the stored tree, rebuilt from the event hashes (run after they validated).
    fn rebuild_mmr(&self) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM authority_mmr", [])
            .map_err(db)?;
        let hashes: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT hash FROM authority_events ORDER BY sequence")
                .map_err(db)?;
            let rows = stmt.query_map([], |r| r.get(0)).map_err(db)?;
            rows.collect::<rusqlite::Result<_>>().map_err(db)?
        };
        for (index, hash) in hashes.iter().enumerate() {
            self.db_append(index as u64, hash)?;
        }
        Ok(())
    }

    fn all_invocations(&self) -> Result<Vec<Value>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT record FROM authority_invocations ORDER BY ordinal")
            .map_err(db)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(db)?;
        rows.map(|raw| {
            serde_json::from_str(&raw.map_err(db)?).map_err(|_| "corrupt_history".to_string())
        })
        .collect()
    }

    /// R-13d: appends one hash-chained v2 event that records the request and the before
    /// and after values of what changed since the working set was loaded or last saved,
    /// and writes the changed rows; returns the event hash.
    fn save(&mut self, state: &State, kind: &str) -> Result<String, String> {
        let malformed = |_| "malformed".to_string();
        let (base_state, base_head) = match self.base.take() {
            Some((s, h)) => (Some(s), Some(h)),
            None => (None, None),
        };
        let known: HashSet<&str> = base_state
            .iter()
            .flat_map(|b| b.invocations.iter().map(|x| x.id.as_str()))
            .collect();
        let new_invocations: Vec<Invocation> = state
            .invocations
            .iter()
            .filter(|x| !known.contains(x.id.as_str()))
            .cloned()
            .collect();
        let first_ordinal = base_head.as_ref().map_or(0, |h| h.invocations_count);
        let mut root = base_head
            .as_ref()
            .map_or_else(|| ZERO_ROOT.to_owned(), |h| h.invocations_root.clone());
        for invocation in &new_invocations {
            root = invocation_leaf(&root, invocation)?;
        }
        let head = head_from_state(state, first_ordinal + new_invocations.len() as u64, root);
        let head_raw = serde_json::to_string(&head).map_err(malformed)?;
        let head_value = serde_json::to_value(&head).map_err(malformed)?;
        let old_head = match &base_head {
            Some(h) => serde_json::to_value(h).map_err(malformed)?,
            None => json!({}),
        };
        let mut before = Effects::default();
        let mut after = Effects::default();
        for (key, value) in head_value.as_object().into_iter().flatten() {
            let old = old_head.get(key);
            if old != Some(value) {
                if let Some(old) = old {
                    before.head.insert(key.clone(), old.clone());
                }
                after.head.insert(key.clone(), value.clone());
            }
        }
        for operation in &state.operations {
            let row = op_row_of(state, operation);
            let old = base_state.as_ref().and_then(|b| {
                b.operations
                    .iter()
                    .find(|x| x.op == operation.op)
                    .map(|x| op_row_of(b, x))
            });
            let changed = match &old {
                Some(old) => {
                    serde_json::to_value(old).map_err(malformed)?
                        != serde_json::to_value(&row).map_err(malformed)?
                }
                None => true,
            };
            if changed {
                before.ops.insert(operation.op.clone(), old);
                after.ops.insert(operation.op.clone(), Some(row));
            }
        }
        after.invocations = new_invocations;
        let (sequence, previous) = match self.tip()? {
            Some((sequence, hash)) => (sequence + 1, hash),
            None => (0, String::new()),
        };
        let event = EventV2 {
            v: 2,
            kind: kind.to_owned(),
            revision: state.revision,
            request: self.recorded.clone(),
            cause: self.cause.clone(),
            before,
            after,
            head_hash: hex::encode(Sha256::digest(head_raw.as_bytes())),
        };
        let raw = serde_json::to_string(&event).map_err(malformed)?;
        let hash = event_hash_v2(sequence, &previous, &raw);
        let written = i64::try_from(sequence).map_err(|_| "corrupt_history".to_string())?;
        self.conn
            .execute(
                "INSERT INTO authority_events(sequence,previous,hash,event) VALUES(?1,?2,?3,?4)",
                rusqlite::params![written, previous, &hash, raw],
            )
            .map_err(db)?;
        if !self.replaying {
            self.db_append(sequence, &hash)?;
        }
        self.conn.execute("INSERT INTO authority_meta(k,v) VALUES('state',?1) ON CONFLICT(k) DO UPDATE SET v=excluded.v",[&head_raw]).map_err(db)?;
        if sequence == 0 {
            self.conn
                .execute(
                    "INSERT INTO authority_meta(k,v) VALUES('format','2') ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    [],
                )
                .map_err(db)?;
        }
        for (op, row) in &event.after.ops {
            let row = serde_json::to_string(row).map_err(malformed)?;
            self.conn
                .execute(
                    "INSERT INTO authority_ops(op,row,written) VALUES(?1,?2,?3) ON CONFLICT(op) DO UPDATE SET row=excluded.row, written=excluded.written",
                    rusqlite::params![op, row, written],
                )
                .map_err(db)?;
        }
        for (index, invocation) in event.after.invocations.iter().enumerate() {
            let ordinal = i64::try_from(first_ordinal + index as u64)
                .map_err(|_| "corrupt_history".to_string())?;
            let record = serde_json::to_string(invocation).map_err(malformed)?;
            self.conn
                .execute(
                    "INSERT INTO authority_invocations(ordinal,id,record,written) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![ordinal, invocation.id, record, written],
                )
                .map_err(db)?;
        }
        self.base = Some((state.clone(), head));
        Ok(hash)
    }

    /// The last event's `(sequence, hash)`, as stored.
    fn tip(&self) -> Result<Option<(u64, String)>, String> {
        let tip: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT sequence,hash FROM authority_events ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        tip.map(|(sequence, hash)| {
            u64::try_from(sequence)
                .map(|sequence| (sequence, hash))
                .map_err(|_| "corrupt_history".to_string())
        })
        .transpose()
    }

    /// Once per handle: the whole chain, then the v1 migration if needed, then the head.
    fn open_checks(&mut self) -> Result<(), String> {
        let mut mmr = Mmr::default();
        let tip = self.validate_chain(None, &mut mmr)?;
        // R-13d.2: a store written before the tree (or with a short one) gets it rebuilt
        // from the hashes just validated; then the stored tree must match.
        if self.db_leaves()? != mmr.leaves {
            self.rebuild_mmr()?;
        }
        if self.db_root(mmr.leaves)? != mmr.root() {
            return Err("corrupt_history".into());
        }
        self.mmr = mmr;
        match tip {
            None => {
                if self.get_meta("state")?.is_some() {
                    return Err("corrupt_history".into());
                }
            }
            Some(tip) => {
                if self.get_meta("format")?.as_deref() != Some("2") {
                    self.migrate(tip.0)?;
                }
                self.anchor = Some(tip);
                self.check_head()?;
            }
        }
        Ok(())
    }

    /// R-13d: every request starts here. It checks that the event at the tip this handle
    /// validated last is unchanged, validates every event appended after it (by this
    /// handle or another), rehashes the tip, and checks the head row against the tip.
    fn revalidate(&mut self) -> Result<(), String> {
        if self.replaying {
            return Ok(());
        }
        let mut mmr = self.mmr.clone();
        let tip = self.validate_chain(self.anchor.clone(), &mut mmr)?;
        if self.db_root(mmr.leaves)? != mmr.root() {
            return Err("corrupt_history".into());
        }
        self.mmr = mmr;
        match &tip {
            Some((sequence, hash)) => {
                let (previous, stored, raw) = self.event_row(*sequence)?;
                if stored != *hash || row_hash(*sequence, &previous, &raw)? != *hash {
                    return Err("corrupt_history".into());
                }
            }
            None => {
                if self.get_meta("state")?.is_some() {
                    return Err("corrupt_history".into());
                }
            }
        }
        self.anchor = tip;
        if self.anchor.is_some() {
            self.check_head()?;
        }
        Ok(())
    }

    /// Validates the chain after `from` (or from genesis) and returns the new tip.
    fn validate_chain(
        &self,
        from: Option<(u64, String)>,
        mmr: &mut Mmr,
    ) -> Result<Option<(u64, String)>, String> {
        let (start, mut previous, mut count) = match &from {
            Some((sequence, hash)) => {
                let (_, stored, _) = self.event_row(*sequence)?;
                if stored != *hash {
                    return Err("corrupt_history".into());
                }
                (*sequence as i64, hash.clone(), sequence + 1)
            }
            None => (-1, String::new(), 0),
        };
        let mut stmt = self
            .conn
            .prepare("SELECT sequence,previous,hash,event FROM authority_events WHERE sequence > ?1 ORDER BY sequence")
            .map_err(db)?;
        let rows = stmt
            .query_map([start], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(db)?;
        for row in rows {
            let (sequence, prev, hash, raw) = row.map_err(db)?;
            let sequence: u64 = sequence
                .try_into()
                .map_err(|_| "corrupt_history".to_string())?;
            if sequence != count || prev != previous || row_hash(sequence, &prev, &raw)? != hash {
                return Err("corrupt_history".into());
            }
            mmr.append(leaf_bytes(&hash)?);
            previous = hash;
            count += 1;
        }
        Ok(if count == 0 {
            None
        } else {
            Some((count - 1, previous))
        })
    }

    fn event_row(&self, sequence: u64) -> Result<(String, String, String), String> {
        let sequence = i64::try_from(sequence).map_err(|_| "corrupt_history".to_string())?;
        self.conn
            .query_row(
                "SELECT previous,hash,event FROM authority_events WHERE sequence=?1",
                [sequence],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| "corrupt_history".to_string())
    }

    /// The head row must be the one the tip event committed to: by `head_hash` for a v2
    /// tip, by the snapshot for a v1 tip (a migrated store before its next event).
    fn check_head(&self) -> Result<(), String> {
        let (sequence, _) = self
            .anchor
            .clone()
            .ok_or_else(|| "corrupt_history".to_string())?;
        let (_, _, raw) = self.event_row(sequence)?;
        let head_raw = self
            .get_meta("state")?
            .ok_or_else(|| "corrupt_history".to_string())?;
        let event: Value = serde_json::from_str(&raw).map_err(|_| "corrupt_history".to_string())?;
        let valid = if is_v2(&raw) {
            event["head_hash"].as_str()
                == Some(hex::encode(Sha256::digest(head_raw.as_bytes())).as_str())
        } else {
            let state: State = serde_json::from_value(event["snapshot"].clone())
                .map_err(|_| "corrupt_history".to_string())?;
            let expected = full_head(&state)?;
            let actual: Value =
                serde_json::from_str(&head_raw).map_err(|_| "corrupt_history".to_string())?;
            serde_json::to_value(&expected).map_err(|_| "corrupt_history".to_string())? == actual
        };
        if !valid {
            return Err("corrupt_history".into());
        }
        Ok(())
    }

    /// R-13d: a v1 store keeps its events. Its state row must equal the last snapshot, as
    /// before; the head row and the operation and invocation tables are written from that
    /// snapshot, as written by the last v1 event.
    fn migrate(&mut self, tip: u64) -> Result<(), String> {
        let corrupt = |_| "corrupt_history".to_string();
        let (_, _, raw) = self.event_row(tip)?;
        if is_v2(&raw) {
            return Err("corrupt_history".into());
        }
        let event: Value = serde_json::from_str(&raw).map_err(corrupt)?;
        let snapshot = event
            .get("snapshot")
            .cloned()
            .ok_or_else(|| "corrupt_history".to_string())?;
        let row: Value = serde_json::from_str(
            &self
                .get_meta("state")?
                .ok_or_else(|| "corrupt_history".to_string())?,
        )
        .map_err(corrupt)?;
        if row != snapshot {
            return Err("corrupt_history".into());
        }
        let state: State = serde_json::from_value(snapshot).map_err(corrupt)?;
        let head = full_head(&state)?;
        let written = tip as i64;
        let head_raw = serde_json::to_string(&head).map_err(corrupt)?;
        self.conn.execute("INSERT INTO authority_meta(k,v) VALUES('state',?1) ON CONFLICT(k) DO UPDATE SET v=excluded.v",[&head_raw]).map_err(db)?;
        for operation in &state.operations {
            let row = serde_json::to_string(&op_row_of(&state, operation)).map_err(corrupt)?;
            self.conn
                .execute(
                    "INSERT INTO authority_ops(op,row,written) VALUES(?1,?2,?3)",
                    rusqlite::params![operation.op, row, written],
                )
                .map_err(db)?;
        }
        for (ordinal, invocation) in state.invocations.iter().enumerate() {
            let record = serde_json::to_string(invocation).map_err(corrupt)?;
            self.conn
                .execute(
                    "INSERT INTO authority_invocations(ordinal,id,record,written) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![ordinal as i64, invocation.id, record, written],
                )
                .map_err(db)?;
        }
        self.conn
            .execute(
                "INSERT INTO authority_meta(k,v) VALUES('format','2') ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                [],
            )
            .map_err(db)?;
        Ok(())
    }
}

/// R-13a: which history events a `checkpoint` response carries.
enum HistorySelector {
    All,
    None,
    Since(u64),
}

fn history_selector(o: &serde_json::Map<String, Value>) -> Result<HistorySelector, String> {
    let malformed = || "malformed: history".to_string();
    match o.get("history") {
        None => Ok(HistorySelector::All),
        Some(Value::String(name)) if name == "all" => Ok(HistorySelector::All),
        Some(Value::String(name)) if name == "none" => Ok(HistorySelector::None),
        Some(Value::Object(fields)) if fields.len() == 1 => fields
            .get("since")
            .and_then(Value::as_u64)
            .map(HistorySelector::Since)
            .ok_or_else(malformed),
        Some(_) => Err(malformed()),
    }
}

fn db(e: rusqlite::Error) -> String {
    format!("malformed: database {e}")
}
fn event_hash(seq: u64, previous: &str, event: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(&HashInput {
        sequence: seq,
        previous,
        event,
    })
    .map_err(|_| "corrupt_history".to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
/// R-13d.2: an inner tree node.
fn mmr_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// R-13d.2: the tree root, over its leaf count and its peaks from left to right.
fn mmr_root(leaves: u64, peaks: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-trust/mmr\0");
    hasher.update(leaves.to_be_bytes());
    for peak in peaks {
        hasher.update(peak);
    }
    hasher.finalize().into()
}

fn leaf_bytes(hash: &str) -> Result<[u8; 32], String> {
    hex::decode(hash)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| "corrupt_history".to_string())
}

/// A stored row and the sequence of the event that wrote it.
fn parse_row<T: serde::de::DeserializeOwned>(raw: &str, written: i64) -> Result<(T, u64), String> {
    let corrupt = || "corrupt_history".to_string();
    Ok((
        serde_json::from_str(raw).map_err(|_| corrupt())?,
        u64::try_from(written).map_err(|_| corrupt())?,
    ))
}

/// R-13d: the request an event records. A persisted envelope is recorded by its digest
/// (R-13c), and the cause is recorded beside the request.
fn recorded_request(o: &serde_json::Map<String, Value>) -> Value {
    let mut request = o.clone();
    request.remove("cause");
    if let Some(envelope) = request.remove("envelope") {
        let digest = envelope
            .as_str()
            .and_then(|hex_text| hex::decode(hex_text).ok())
            .map(|bytes| hex::encode(Sha256::digest(bytes)));
        request.insert("envelope_digest".into(), json!(digest));
    }
    Value::Object(request)
}

/// R-13d: a v2 event hash covers the exact stored bytes, so validating the chain needs
/// no JSON parsing.
fn event_hash_v2(sequence: u64, previous: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-trust/kernel-event/v2\0");
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous.as_bytes());
    hasher.update([0u8]);
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// A v2 event serializes `v` first; a v1 event starts with `kind`.
fn is_v2(raw: &str) -> bool {
    raw.starts_with("{\"v\":2,")
}

fn row_hash(sequence: u64, previous: &str, raw: &str) -> Result<String, String> {
    if is_v2(raw) {
        Ok(event_hash_v2(sequence, previous, raw))
    } else {
        let event: Value = serde_json::from_str(raw).map_err(|_| "corrupt_history".to_string())?;
        event_hash(sequence, previous, &event)
    }
}

/// R-13d: the running invocation commitment, `SHA-256(root || SHA-256(record))`.
fn invocation_leaf(root: &str, invocation: &Invocation) -> Result<String, String> {
    let record = serde_json::to_vec(invocation).map_err(|_| "malformed".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(hex::decode(root).map_err(|_| "corrupt_history".to_string())?);
    hasher.update(Sha256::digest(record));
    Ok(hex::encode(hasher.finalize()))
}

fn head_from_state(s: &State, invocations_count: u64, invocations_root: String) -> Head {
    Head {
        group: s.group.clone(),
        revision: s.revision,
        epoch: s.epoch,
        branch: s.branch.clone(),
        read_fenced: s.read_fenced,
        roster: s.roster.clone(),
        grants: s.grants.clone(),
        delegations: s.delegations.clone(),
        policy_revision: s.policy_revision,
        fence_revision: s.fence_revision,
        repair_pending: s.repair_pending.clone(),
        invocations_count,
        invocations_root,
    }
}

/// The head of a whole v1 state, every invocation folded into the commitment.
fn full_head(s: &State) -> Result<Head, String> {
    let mut root = ZERO_ROOT.to_owned();
    for invocation in &s.invocations {
        root = invocation_leaf(&root, invocation)?;
    }
    Ok(head_from_state(s, s.invocations.len() as u64, root))
}

fn state_from_head(h: &Head) -> State {
    State {
        group: h.group.clone(),
        revision: h.revision,
        epoch: h.epoch,
        branch: h.branch.clone(),
        read_fenced: h.read_fenced,
        roster: h.roster.clone(),
        grants: h.grants.clone(),
        delegations: h.delegations.clone(),
        operations: vec![],
        consumed: vec![],
        invocations: vec![],
        policy_revision: h.policy_revision,
        fence_revision: h.fence_revision,
        repair_pending: h.repair_pending.clone(),
    }
}

fn op_row_of(s: &State, operation: &Operation) -> OpRow {
    OpRow {
        operation: operation.clone(),
        consumed_by: s
            .consumed
            .iter()
            .filter(|c| c.op == operation.op)
            .map(|c| c.recipient.clone())
            .collect(),
    }
}

/// R-13d: the v1 snapshot after a v2 event, from the snapshot before it.
fn apply_v2(previous: Option<Value>, event: &Value) -> Result<Value, String> {
    let corrupt = || "corrupt_history".to_string();
    let mut snapshot =
        previous.unwrap_or_else(|| json!({"operations":[], "consumed":[], "invocations":[]}));
    let after = &event["after"];
    let object = snapshot.as_object_mut().ok_or_else(corrupt)?;
    if let Some(head) = after.get("head").and_then(Value::as_object) {
        for (key, value) in head {
            if key != "invocations_count" && key != "invocations_root" {
                object.insert(key.clone(), value.clone());
            }
        }
    }
    if let Some(ops) = after.get("ops").and_then(Value::as_object) {
        for (op, row) in ops {
            let operation = row["operation"].clone();
            let operations = object
                .get_mut("operations")
                .and_then(Value::as_array_mut)
                .ok_or_else(corrupt)?;
            match operations.iter_mut().find(|x| x["op"] == json!(op)) {
                Some(slot) => *slot = operation,
                None => operations.push(operation),
            }
            let earlier = event["before"]["ops"][op]["consumed_by"]
                .as_array()
                .map_or(0, Vec::len);
            let recipients = row["consumed_by"].as_array().ok_or_else(corrupt)?;
            let consumed = object
                .get_mut("consumed")
                .and_then(Value::as_array_mut)
                .ok_or_else(corrupt)?;
            for recipient in recipients.iter().skip(earlier) {
                consumed.push(json!({"op":op, "recipient":recipient}));
            }
        }
    }
    if let Some(invocations) = after.get("invocations").and_then(Value::as_array) {
        object
            .get_mut("invocations")
            .and_then(Value::as_array_mut)
            .ok_or_else(corrupt)?
            .extend(invocations.iter().cloned());
    }
    Ok(snapshot)
}

/// R-13d: the history as `checkpoint` entries, read one event at a time and checked
/// against the chain, with the v1 snapshot of each event rebuilt when `snapshots` is set.
/// Memory stays at one snapshot. The first error stops the iteration and is left in
/// `errors`.
struct HistoryEntries<'c> {
    conn: &'c Connection,
    next: u64,
    previous: String,
    snapshot: Option<Value>,
    snapshots: bool,
    errors: Rc<RefCell<Option<String>>>,
}

impl<'c> HistoryEntries<'c> {
    fn new(conn: &'c Connection, snapshots: bool, errors: Rc<RefCell<Option<String>>>) -> Self {
        Self {
            conn,
            next: 0,
            previous: String::new(),
            snapshot: None,
            snapshots,
            errors,
        }
    }

    fn step(&mut self) -> Result<Option<Value>, String> {
        let corrupt = || "corrupt_history".to_string();
        let sequence = i64::try_from(self.next).map_err(|_| corrupt())?;
        let row: Option<(String, String, String)> = self
            .conn
            .query_row(
                "SELECT previous,hash,event FROM authority_events WHERE sequence=?1",
                [sequence],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((previous, hash, raw)) = row else {
            return Ok(None);
        };
        if previous != self.previous || row_hash(self.next, &previous, &raw)? != hash {
            return Err(corrupt());
        }
        let mut event: Value = serde_json::from_str(&raw).map_err(|_| corrupt())?;
        if self.snapshots {
            let snapshot = if is_v2(&raw) {
                apply_v2(self.snapshot.take(), &event)?
            } else {
                event.get("snapshot").cloned().ok_or_else(corrupt)?
            };
            event["snapshot"] = snapshot.clone();
            self.snapshot = Some(snapshot);
        }
        let entry = json!({"sequence":self.next,"previous":previous,"hash":hash,"event":event});
        self.previous = hash;
        self.next += 1;
        Ok(Some(entry))
    }
}

impl Iterator for HistoryEntries<'_> {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        if self.errors.borrow().is_some() {
            return None;
        }
        match self.step() {
            Ok(entry) => entry,
            Err(error) => {
                *self.errors.borrow_mut() = Some(error);
                None
            }
        }
    }
}

/// R-13d: the kernel history of a store as `(kind, v1 snapshot)`, one event at a time,
/// checked against the hash chain (C-37 export). The first error stops the iteration and
/// is left in the returned cell, which the caller must check when it is done.
pub fn history_snapshots(
    conn: &Connection,
) -> (
    impl Iterator<Item = (String, Value)> + '_,
    Rc<RefCell<Option<String>>>,
) {
    let errors = Rc::new(RefCell::new(None));
    let entries = HistoryEntries::new(conn, true, Rc::clone(&errors));
    let failed = Rc::clone(&errors);
    let iterator = entries.map_while(move |mut entry| {
        let kind = entry["event"]["kind"].as_str().map(str::to_owned);
        let snapshot = entry["event"]
            .as_object_mut()
            .and_then(|event| event.remove("snapshot"));
        match (kind, snapshot) {
            (Some(kind), Some(snapshot)) => Some((kind, snapshot)),
            _ => {
                *failed.borrow_mut() = Some("corrupt_history: kind".into());
                None
            }
        }
    });
    (iterator, errors)
}

/// R-12: the mutating commands that carry `now`. `subject_status` also carries it but is
/// read-only (C-7), so it never records an expiry.
const EXPIRY_COMMANDS: &[&str] = &[
    "grant", "delegate", "revoke", "admit", "invoke", "release", "consume", "rekey",
];

/// `subject` and every subject delegated from it, transitively: the cascade of `revoke`.
fn descendants(s: &State, subject: &str) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    targets.insert(subject.to_owned());
    loop {
        let mut changed = false;
        for d in &s.delegations {
            if targets.contains(&d.parent) && !targets.contains(&d.subject) {
                targets.insert(d.subject.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    targets
}

fn bump(s: &mut State) {
    s.revision = s.revision.saturating_add(1);
}
fn bump_policy(s: &mut State) {
    s.policy_revision = s.policy_revision.saturating_add(1);
}
fn policy_digest(h: &Head) -> Result<String, String> {
    let bytes = serde_json::to_vec(&PolicyView {
        group: &h.group,
        policy_revision: h.policy_revision,
        grants: &h.grants,
        delegations: &h.delegations,
        invocations_count: h.invocations_count,
        invocations_root: &h.invocations_root,
    })
    .map_err(|_| "corrupt_history".to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
/// Release frontier form: baseline state `revision` or R-3 `policy_revision`.
enum Frontier {
    State(u64),
    Policy(u64),
}
fn rights(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_string()).collect()
}
fn known_subject(s: &State, x: &str) -> bool {
    s.grants.iter().any(|g| g.subject == x) || s.delegations.iter().any(|d| d.subject == x)
}
fn grant_mut<'a>(s: &'a mut State, subject: &str, right: &str) -> Option<&'a mut Grant> {
    s.grants
        .iter_mut()
        .find(|g| g.subject == subject && g.right == right)
}
fn active_generation(s: &State, subject: &str, right: &str, now: u64) -> Option<u64> {
    s.grants
        .iter()
        .find(|g| g.subject == subject && g.right == right && g.active)
        .and_then(|g| {
            if chain_valid(s, subject, right, now) {
                Some(g.generation)
            } else {
                None
            }
        })
}
fn effective(s: &State, subject: &str, right: &str, now: u64) -> bool {
    active_generation(s, subject, right, now).is_some()
}
fn active_without_time(s: &State, subject: &str, right: &str) -> bool {
    s.grants
        .iter()
        .any(|g| g.subject == subject && g.right == right && g.active)
}
fn chain_valid(s: &State, subject: &str, right: &str, now: u64) -> bool {
    let mut current = subject;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.to_string()) {
            return false;
        }
        let d = match s.delegations.iter().find(|d| d.subject == current) {
            Some(d) => d,
            None => return true,
        };
        if now < d.not_before || now > d.expires_at || !d.rights.iter().any(|r| r == right) {
            return false;
        }
        if d.parent == d.subject {
            return true;
        }
        if !s
            .grants
            .iter()
            .any(|g| g.subject == d.parent && g.right == right && g.active)
        {
            return false;
        }
        current = &d.parent;
    }
}
/// R-8: `resource` is in the `resources` of every delegation from `subject` up to the root.
/// A subject without a delegation record (a direct root-anchored grant) holds only `[group]`.
fn resource_held(s: &State, subject: &str, resource: &str) -> bool {
    let mut current = subject;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current.to_string()) {
            return false;
        }
        let d = match s.delegations.iter().find(|d| d.subject == current) {
            Some(d) => d,
            None => return current == subject && resource == s.group,
        };
        if !d.resources.iter().any(|r| r == resource) {
            return false;
        }
        if d.parent == d.subject {
            return true;
        }
        current = &d.parent;
    }
}
fn invocation_valid(
    s: &State,
    id: &str,
    executor: &str,
    right: &str,
    resource: &str,
    now: u64,
    seen: &mut HashSet<String>,
) -> bool {
    if !seen.insert(id.to_owned()) {
        return false;
    }
    let invocation = match s.invocations.iter().find(|x| x.id == id) {
        Some(x) => x,
        None => return false,
    };
    if !invocation.active
        || invocation.executor != executor
        || !invocation.rights.iter().any(|x| x == right)
        || !invocation.resources.iter().any(|x| x == resource)
    {
        return false;
    }
    if !effective(s, &invocation.origin, right, now) {
        return false;
    }
    // R-8b: origin and executor chains must both hold the resource at every hop.
    if !resource_held(s, &invocation.origin, resource)
        || !resource_held(s, &invocation.executor, resource)
    {
        return false;
    }
    if let Some(parent) = &invocation.parent {
        let parent_executor = match s.invocations.iter().find(|x| x.id == *parent) {
            Some(x) => x.executor.clone(),
            None => return false,
        };
        invocation_valid(s, parent, &parent_executor, right, resource, now, seen)
    } else {
        true
    }
}
/// C-7 `subject_status`: read-only view of one subject's grant records and delegation expiry.
/// It saves nothing, so `revision`, `policy_revision` and the history stay unchanged.
fn subject_status(s: &State, o: &serde_json::Map<String, Value>) -> Result<Value, String> {
    let subject = req_id(o, "subject")?;
    let now = req_u64(o, "now")?;
    let rights: Vec<Value> = ["read", "write", "admin", "admit"]
        .iter()
        .filter_map(|right| {
            s.grants
                .iter()
                .find(|g| g.subject == subject && g.right == *right)
                .map(|g| {
                    json!({
                        "right": right,
                        "generation": g.generation,
                        "active": g.active,
                        "effective": effective(s, &subject, right, now),
                    })
                })
        })
        .collect();
    let expires_at = s
        .delegations
        .iter()
        .find(|d| d.subject == subject)
        .map(|d| d.expires_at);
    Ok(json!({
        "subject": subject,
        "known": known_subject(s, &subject),
        "rights": rights,
        "expires_at": expires_at,
    }))
}
fn subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|x| b.contains(x))
}
fn req_id(o: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    let s = o
        .get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("malformed: {k}"))?;
    if s.is_empty() || s.len() > MAX_ID {
        return Err(format!("malformed: {k}"));
    }
    Ok(s.to_string())
}
fn opt_id(o: &serde_json::Map<String, Value>, k: &str) -> Result<Option<String>, String> {
    if o.contains_key(k) {
        req_id(o, k).map(Some)
    } else {
        Ok(None)
    }
}
fn opt_u64(o: &serde_json::Map<String, Value>, k: &str) -> Result<Option<u64>, String> {
    if o.contains_key(k) {
        req_u64(o, k).map(Some)
    } else {
        Ok(None)
    }
}
fn req_payload(o: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    let s = req_id(o, k)?;
    if s.len() > MAX_PAYLOAD {
        return Err(format!("malformed: {k}"));
    }
    Ok(s)
}
fn req_u64(o: &serde_json::Map<String, Value>, k: &str) -> Result<u64, String> {
    o.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("malformed: {k}"))
}
fn req_bool(o: &serde_json::Map<String, Value>, k: &str) -> Result<bool, String> {
    o.get(k)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("malformed: {k}"))
}
fn req_right(o: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    let x = req_id(o, k)?;
    if !matches!(x.as_str(), "read" | "write" | "admin" | "admit") {
        return Err(format!("malformed: {k}"));
    }
    Ok(x)
}
fn req_rights(o: &serde_json::Map<String, Value>, k: &str) -> Result<Vec<String>, String> {
    let a = o
        .get(k)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("malformed: {k}"))?;
    let mut out = Vec::new();
    for x in a {
        let x = x.as_str().ok_or_else(|| format!("malformed: {k}"))?;
        if !matches!(x, "read" | "write" | "admin" | "admit") || out.iter().any(|v| v == x) {
            return Err(format!("malformed: {k}"));
        }
        out.push(x.to_string());
    }
    if out.is_empty() {
        return Err(format!("malformed: {k}"));
    }
    Ok(out)
}
fn req_ids(o: &serde_json::Map<String, Value>, k: &str) -> Result<Vec<String>, String> {
    let a = o
        .get(k)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("malformed: {k}"))?;
    let mut out = Vec::new();
    for x in a {
        let s = x.as_str().ok_or_else(|| format!("malformed: {k}"))?;
        if s.is_empty() || s.len() > MAX_ID || out.iter().any(|v| v == s) {
            return Err(format!("malformed: {k}"));
        }
        out.push(s.to_string());
    }
    Ok(out)
}
fn req_envelope(o: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    let s = o
        .get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("malformed: {k}"))?;
    if s.is_empty() || s.len() > MAX_ENVELOPE || s.len() % 2 != 0 || hex::decode(s).is_err() {
        return Err(format!("malformed: {k}"));
    }
    Ok(s.to_string())
}
fn check_cover(
    raw: Option<&Value>,
    actor: &str,
    writer: u64,
    readers: &[Reader],
) -> Result<(), String> {
    let a = raw
        .and_then(Value::as_array)
        .ok_or_else(|| "malformed: cover".to_string())?;
    let mut got = BTreeSet::new();
    for support in a {
        let inner = support
            .as_array()
            .ok_or_else(|| "unsound_cover".to_string())?;
        if inner.len() != 1 {
            return Err("unsound_cover".into());
        }
        let v = inner[0]
            .as_object()
            .ok_or_else(|| "unsound_cover".to_string())?;
        let subject = req_id(v, "subject").map_err(|_| "unsound_cover".to_string())?;
        let right = req_right(v, "right").map_err(|_| "unsound_cover".to_string())?;
        let generation = req_u64(v, "generation").map_err(|_| "unsound_cover".to_string())?;
        if !got.insert((subject, right, generation)) {
            return Err("unsound_cover".into());
        }
    }
    let mut want = BTreeSet::new();
    want.insert((actor.to_string(), "write".to_string(), writer));
    for r in readers {
        want.insert((r.subject.clone(), "read".to_string(), r.generation));
    }
    if got != want {
        return Err("unsound_cover".into());
    }
    Ok(())
}
