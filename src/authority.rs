//! Durable, trusted-local authority kernel.  Authentication and MLS validation live in adapters.
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

const MAX_ID: usize = 256;
const MAX_PAYLOAD: usize = 4096;

pub struct Authority {
    conn: Connection,
}

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
    envelope: Option<String>,
    roster: Vec<Reader>,
    writer_generation: Option<u64>,
    resource: String,
    invocation: Option<String>,
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
#[derive(Serialize)]
struct HashInput<'a> {
    sequence: u64,
    previous: &'a str,
    event: &'a Value,
}

impl Authority {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(db)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS authority_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_events (sequence INTEGER PRIMARY KEY, previous TEXT NOT NULL, hash TEXT NOT NULL, event TEXT NOT NULL);")
            .map_err(db)?;
        let this = Self { conn };
        this.validate_history()?;
        Ok(this)
    }

    pub fn execute(&mut self, request: Value) -> Result<Value, String> {
        let obj = request
            .as_object()
            .ok_or_else(|| "malformed: request object".to_string())?;
        let command = req_id(obj, "command")?;
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        let result = self.execute_inner(obj, &command);
        match result {
            Ok(value) => {
                self.conn.execute_batch("COMMIT").map_err(db)?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
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
            let state = State {
                group: group.clone(),
                revision: 0,
                epoch: 0,
                branch: "genesis".into(),
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
                    resources: vec![group],
                    expires_at: u64::MAX,
                    not_before: 0,
                    depth: 8,
                }],
                operations: vec![],
                consumed: vec![],
                invocations: vec![],
            };
            self.save(&state, "init")?;
            return Ok(json!({"revision":0,"epoch":0,"branch":"genesis"}));
        }
        if !initialized {
            return Err("uninitialized".into());
        }
        let mut state = self.load()?;
        match command {
            "checkpoint" => self.checkpoint(&state),
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
        let mut targets = BTreeSet::new();
        targets.insert(subject);
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
            if fences_current_reader {
                s.read_fenced = true;
            }
            bump(s);
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
        s.roster.push(subject.clone());
        s.epoch = s
            .epoch
            .checked_add(1)
            .ok_or_else(|| "invalid_transition".to_string())?;
        s.branch = format!("admit:{}:{}", s.epoch, subject);
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
            roster: vec![],
            writer_generation: None,
            resource,
            invocation,
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
            (actor.clone(), Vec::new(), vec![s.group.clone()])
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
            if !subset(&requested_resources, &[s.group.clone()]) {
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
        let revision = req_u64(o, "revision")?;
        let epoch = req_u64(o, "epoch")?;
        let branch = req_id(o, "branch")?;
        let digest = req_payload(o, "digest")?;
        let now = req_u64(o, "now")?;
        if !effective(s, &actor, "write", now) {
            return Err("unauthorized".into());
        }
        if s.read_fenced {
            return Err("read_fenced".into());
        }
        if revision != s.revision || epoch != s.epoch || branch != s.branch {
            return Err("stale_frontier".into());
        }
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
        bump(s);
        self.save(s, "release")?;
        Ok(
            json!({"op":op,"revision":revision,"epoch":epoch,"branch":branch,"digest":digest,"executor":actor,"invocation":s.operations[position].invocation,"effective_right":right,"resource":operation_resource}),
        )
    }

    fn persist(
        &mut self,
        s: &mut State,
        o: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        let op = req_id(o, "op")?;
        let digest = req_payload(o, "digest")?;
        let envelope = req_hex(o, "envelope")?;
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
        if let Some(old) = &x.envelope {
            if old != &envelope {
                return Err("binding_mismatch".into());
            }
            return Ok(json!({"op":op}));
        }
        x.envelope = Some(envelope);
        x.status = "persisted".into();
        bump(s);
        self.save(s, "persist")?;
        Ok(json!({"op":op}))
    }

    fn emit(&self, s: &State, o: &serde_json::Map<String, Value>) -> Result<Value, String> {
        let op = req_id(o, "op")?;
        let envelope = req_hex(o, "envelope")?;
        let x = s
            .operations
            .iter()
            .find(|x| x.op == op)
            .ok_or_else(|| "not_persisted".to_string())?;
        if x.envelope.is_none() {
            return Err("not_persisted".into());
        }
        if x.envelope.as_deref() != Some(&envelope)
            || x.epoch != Some(s.epoch)
            || x.branch.as_deref() != Some(&s.branch)
        {
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
        let release = s
            .operations
            .iter()
            .find(|x| x.op == op)
            .ok_or_else(|| "not_persisted".to_string())?;
        if release.status != "persisted" || release.envelope.is_none() {
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
        if x.status != "released" || x.envelope.is_some() {
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
        bump(s);
        self.save(s, "repair")?;
        Ok(json!({"epoch":s.epoch,"branch":s.branch,"revision":s.revision}))
    }

    fn checkpoint(&self, s: &State) -> Result<Value, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT sequence,previous,hash,event FROM authority_events ORDER BY sequence")
            .map_err(db)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(db)?;
        let mut history = Vec::new();
        let mut root = String::new();
        for row in rows {
            let (sequence, previous, hash, raw) = row.map_err(db)?;
            let sequence: u64 = sequence
                .try_into()
                .map_err(|_| "corrupt_history".to_string())?;
            let event: Value =
                serde_json::from_str(&raw).map_err(|_| "corrupt_history".to_string())?;
            root = hash.clone();
            history
                .push(json!({"sequence":sequence,"previous":previous,"hash":hash,"event":event}));
        }
        Ok(
            json!({"group":s.group,"revision":s.revision,"epoch":s.epoch,"branch":s.branch,"read_fenced":s.read_fenced,"roster":s.roster,"grants":s.grants,"invocations":s.invocations,"history_root":root,"history":history}),
        )
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row("SELECT v FROM authority_meta WHERE k=?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)
    }
    fn load(&self) -> Result<State, String> {
        self.validate_history()?;
        let raw = self
            .get_meta("state")?
            .ok_or_else(|| "uninitialized".to_string())?;
        serde_json::from_str(&raw).map_err(|_| "corrupt_history".into())
    }
    fn save(&mut self, state: &State, kind: &str) -> Result<(), String> {
        let snapshot = serde_json::to_value(state).map_err(|_| "malformed".to_string())?;
        let event = json!({"kind":kind,"snapshot":snapshot});
        let seq: u64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(sequence)+1,0) FROM authority_events",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db)?
            .try_into()
            .map_err(|_| "corrupt_history".to_string())?;
        let previous = if seq == 0 {
            String::new()
        } else {
            self.conn
                .query_row(
                    "SELECT hash FROM authority_events WHERE sequence=?1",
                    [(seq - 1) as i64],
                    |r| r.get(0),
                )
                .map_err(db)?
        };
        let hash = event_hash(seq, &previous, &event)?;
        let state_raw = serde_json::to_string(state).map_err(|_| "malformed".to_string())?;
        self.conn
            .execute(
                "INSERT INTO authority_events(sequence,previous,hash,event) VALUES(?1,?2,?3,?4)",
                rusqlite::params![
                    seq as i64,
                    previous,
                    hash,
                    serde_json::to_string(&event).map_err(|_| "malformed".to_string())?
                ],
            )
            .map_err(db)?;
        self.conn.execute("INSERT INTO authority_meta(k,v) VALUES('state',?1) ON CONFLICT(k) DO UPDATE SET v=excluded.v",[state_raw]).map_err(db)?;
        Ok(())
    }
    fn validate_history(&self) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare("SELECT sequence,previous,hash,event FROM authority_events ORDER BY sequence")
            .map_err(db)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(db)?;
        let mut previous = String::new();
        let mut count = 0u64;
        let mut last_snapshot: Option<Value> = None;
        for row in rows {
            let (seq, prev, hash, raw) = row.map_err(db)?;
            let seq: u64 = seq.try_into().map_err(|_| "corrupt_history".to_string())?;
            let event: Value =
                serde_json::from_str(&raw).map_err(|_| "corrupt_history".to_string())?;
            if seq != count || prev != previous || event_hash(seq, &prev, &event)? != hash {
                return Err("corrupt_history".into());
            }
            last_snapshot = event.get("snapshot").cloned();
            previous = hash;
            count += 1;
        }
        let state = self.get_meta("state")?;
        if count == 0 {
            if state.is_some() {
                return Err("corrupt_history".into());
            }
        } else {
            let state = state.ok_or_else(|| "corrupt_history".to_string())?;
            let actual: Value =
                serde_json::from_str(&state).map_err(|_| "corrupt_history".to_string())?;
            if last_snapshot.as_ref() != Some(&actual) {
                return Err("corrupt_history".into());
            }
        }
        Ok(())
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
fn bump(s: &mut State) {
    s.revision = s.revision.saturating_add(1);
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
fn req_hex(o: &serde_json::Map<String, Value>, k: &str) -> Result<String, String> {
    let s = req_payload(o, k)?;
    if s.len() % 2 != 0 || hex::decode(&s).is_err() {
        return Err(format!("malformed: {k}"));
    }
    Ok(s)
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
