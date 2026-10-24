//! `att-node relay`: the untrusted delivery service.
//!
//! The relay stores and forwards opaque bytes. It makes no authorization decision
//! and holds no key: every byte it carries is signed by the APF or encrypted by MLS,
//! so a malicious relay can delay, drop, duplicate or misroute traffic, but cannot
//! forge it. The control plane uses that freedom on purpose (fault injection).
//!
//! Data plane:
//! - `POST /v1/groups/{g}/handshake`, `GET /v1/groups/{g}/handshake?after=N`:
//!   an ordered, reliable log of acked commits (and Welcomes).
//! - `PUT /v1/keypackages/{subject}`, `GET /v1/keypackages/{subject}` (kept until replaced).
//! - `POST /v1/mailbox/{to}`, `GET /v1/mailbox/{to}`: application envelopes, with the
//!   configured faults applied at fetch time. A fetch leases the returned messages; the
//!   reader acknowledges them with `POST /v1/mailbox/{to}/ack {ids}` once processed, and
//!   an unacknowledged message is queued again when its lease (`ATT_LEASE_MS`) ends. A
//!   reader that crashes mid-batch therefore gets the batch again.
//!
//! Control plane (control token): `POST /control/faults`, `POST /control/hold`,
//! `POST /control/tap`, `POST /control/handshake`, `GET /control/stats`.
//!
//! Handshake faults (`POST /control/handshake {action, ...}`) attack commit
//! distribution: `hide` withholds entries from one reader from an index on, `show` ends
//! it, `reverse` serves one reader its entries in reverse order, `inject` appends an
//! arbitrary entry, `replay` appends a copy of an earlier entry, and `splice` appends an
//! entry that pairs one entry's commit with another entry's ack.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::config::{self, str_field};
use crate::http::{self, Request, Response};

const ROLE: &str = "relay";

/// Fault model applied when a mailbox is fetched.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// Percent of fetch attempts that lose a message. The message stays queued, so the
    /// next fetch retransmits the identical bytes.
    drop: u64,
    /// Percent of delivered messages that are also queued again once (duplicate).
    duplicate: u64,
    /// Shuffle each fetched batch.
    reorder: bool,
}

#[derive(Clone)]
struct Message {
    id: u64,
    body: Value,
    /// A duplicate copy is never duplicated again, so every queue drains.
    copy: bool,
}

#[derive(Default)]
struct Stats {
    posted: u64,
    fetched: u64,
    dropped: u64,
    duplicated: u64,
    tapped: u64,
    expired: u64,
}

/// A fetched message waiting for its acknowledgement.
struct Leased {
    message: Message,
    until: std::time::Instant,
}

struct State {
    leased: BTreeMap<String, Vec<Leased>>,
    lease: std::time::Duration,
    handshake: BTreeMap<String, Vec<Value>>,
    key_packages: BTreeMap<String, Value>,
    mailboxes: BTreeMap<String, Vec<Message>>,
    held: BTreeSet<String>,
    /// `victim -> observers`: every message for the victim is copied to the observers.
    taps: BTreeMap<String, BTreeSet<String>>,
    /// `reader -> first hidden index` of the handshake log.
    hidden: BTreeMap<String, u64>,
    /// Readers that get their handshake entries in reverse order.
    reversed: BTreeSet<String>,
    faults: Faults,
    rng: SplitMix,
    next_id: u64,
    stats: Stats,
}

/// Deterministic SplitMix64 for the fault schedule only. It never touches keys.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

pub fn run() -> Result<(), String> {
    let listen = config::or_default("ATT_LISTEN", "0.0.0.0:7100");
    let seed = config::number("ATT_SEED", 0)?;
    let token = config::optional("ATT_CONTROL_TOKEN");
    let lease = std::time::Duration::from_millis(config::number("ATT_LEASE_MS", 3000)?);
    let state = Mutex::new(State {
        leased: BTreeMap::new(),
        lease,
        handshake: BTreeMap::new(),
        key_packages: BTreeMap::new(),
        mailboxes: BTreeMap::new(),
        held: BTreeSet::new(),
        taps: BTreeMap::new(),
        hidden: BTreeMap::new(),
        reversed: BTreeSet::new(),
        faults: Faults::default(),
        rng: SplitMix(seed),
        next_id: 0,
        stats: Stats::default(),
    });
    config::log(ROLE, "listening", json!({ "listen": listen, "seed": seed }));
    http::serve(&listen, 8, move |request| {
        let segments = request.segments();
        if segments.first() == Some(&"control") && !http::authorized(request, &token) {
            return Response::status(401, "unauthenticated: control token");
        }
        let Ok(mut state) = state.lock() else {
            return Response::status(500, "crashed: lock poisoned");
        };
        route(&mut state, request, &segments)
    })
}

fn route(state: &mut State, request: &Request, segments: &[&str]) -> Response {
    match (request.method.as_str(), segments) {
        ("GET", ["healthz"]) => Response::json(json!({ "ok": "relay" })),
        ("POST", ["v1", "groups", group, "handshake"]) => {
            let index = append(state, group, request.body.clone());
            Response::outcome(Ok(json!({ "index": index })))
        }
        ("GET", ["v1", "groups", group, "handshake"]) => {
            let after = request.query_u64("after").unwrap_or(0) as usize;
            let reader = request.query.get("reader").cloned().unwrap_or_default();
            let hidden_from = state.hidden.get(&reader).copied().unwrap_or(u64::MAX);
            let mut entries: Vec<Value> = state
                .handshake
                .get(*group)
                .map(|log| {
                    log.iter()
                        .skip(after)
                        .filter(|entry| entry["index"].as_u64().unwrap_or(0) < hidden_from)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            if state.reversed.contains(&reader) {
                entries.reverse();
            }
            Response::outcome(Ok(Value::Array(entries)))
        }
        ("PUT", ["v1", "keypackages", subject]) => {
            state
                .key_packages
                .insert((*subject).to_owned(), request.body.clone());
            Response::outcome(Ok(json!({ "stored": subject })))
        }
        // Kept after a read: an admin whose Add fails (for example, no entropy) can retry.
        ("GET", ["v1", "keypackages", subject]) => match state.key_packages.get(*subject).cloned() {
            Some(body) => Response::outcome(Ok(body)),
            None => Response::outcome(Err(format!("not_found: no KeyPackage for {subject}"))),
        },
        ("POST", ["v1", "mailbox", to]) => {
            post(state, to, request.body.clone());
            Response::outcome(Ok(json!({ "queued": true })))
        }
        ("GET", ["v1", "mailbox", to]) => Response::outcome(Ok(Value::Array(fetch(state, to)))),
        ("POST", ["v1", "mailbox", to, "ack"]) => {
            let ids: Vec<u64> = request.body["ids"]
                .as_array()
                .map(|ids| ids.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default();
            Response::outcome(Ok(json!({ "acked": ack(state, to, &ids) })))
        }
        ("POST", ["control", "faults"]) => Response::outcome(set_faults(state, &request.body)),
        ("POST", ["control", "hold"]) => Response::outcome(set_hold(state, &request.body)),
        ("POST", ["control", "tap"]) => Response::outcome(set_tap(state, &request.body)),
        ("POST", ["control", "handshake"]) => Response::outcome(handshake_fault(state, &request.body)),
        ("GET", ["control", "stats"]) => Response::outcome(Ok(stats(state))),
        _ => Response::not_found(),
    }
}

fn enqueue(state: &mut State, to: &str, body: Value, copy: bool) {
    state.next_id += 1;
    let message = Message {
        id: state.next_id,
        body,
        copy,
    };
    state.mailboxes.entry(to.to_owned()).or_default().push(message);
}

fn post(state: &mut State, to: &str, body: Value) {
    state.stats.posted += 1;
    let observers: Vec<String> = state
        .taps
        .get(to)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default();
    for observer in observers {
        state.stats.tapped += 1;
        let mut tapped = body.clone();
        if let Some(object) = tapped.as_object_mut() {
            object.insert("tapped_from".into(), json!(to));
        }
        enqueue(state, &observer, tapped, true);
    }
    enqueue(state, to, body, false);
}

/// One fetch: held mailboxes return nothing; otherwise each queued message is either
/// dropped for this attempt (kept) or returned (removed, maybe re-queued once).
fn fetch(state: &mut State, to: &str) -> Vec<Value> {
    expire_leases(state, to);
    if state.held.contains(to) {
        return Vec::new();
    }
    let queued = state.mailboxes.remove(to).unwrap_or_default();
    let faults = state.faults;
    let mut kept = Vec::new();
    let mut out = Vec::new();
    for message in queued {
        if state.rng.below(100) < faults.drop {
            state.stats.dropped += 1;
            kept.push(message);
            continue;
        }
        if !message.copy && state.rng.below(100) < faults.duplicate {
            state.stats.duplicated += 1;
            kept.push(Message {
                copy: true,
                ..message.clone()
            });
        }
        state.stats.fetched += 1;
        let until = std::time::Instant::now() + state.lease;
        state.leased.entry(to.to_owned()).or_default().push(Leased { message: message.clone(), until });
        let mut body = message.body;
        if let Some(object) = body.as_object_mut() {
            object.insert("relay_id".into(), json!(message.id));
        }
        out.push(body);
    }
    if faults.reorder {
        for index in (1..out.len()).rev() {
            let other = state.rng.below(index as u64 + 1) as usize;
            out.swap(index, other);
        }
    }
    if !kept.is_empty() {
        state.mailboxes.insert(to.to_owned(), kept);
    }
    out
}

/// Messages whose lease ended go back to the front of the queue (retransmission).
fn expire_leases(state: &mut State, to: &str) {
    let now = std::time::Instant::now();
    let Some(leased) = state.leased.get_mut(to) else { return };
    let (expired, kept): (Vec<Leased>, Vec<Leased>) = leased.drain(..).partition(|l| l.until <= now);
    *leased = kept;
    if !expired.is_empty() {
        state.stats.expired += expired.len() as u64;
        let queue = state.mailboxes.entry(to.to_owned()).or_default();
        let mut requeued: Vec<Message> = expired.into_iter().map(|l| l.message).collect();
        requeued.append(queue);
        *queue = requeued;
    }
}

fn ack(state: &mut State, to: &str, ids: &[u64]) -> usize {
    let Some(leased) = state.leased.get_mut(to) else { return 0 };
    let before = leased.len();
    leased.retain(|l| !ids.contains(&l.message.id));
    before - leased.len()
}

fn percent(body: &Value, key: &str) -> Result<u64, String> {
    match body.get(key) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .filter(|p| *p <= 100)
            .ok_or_else(|| format!("malformed: {key} must be 0..=100")),
    }
}

fn set_faults(state: &mut State, body: &Value) -> Result<Value, String> {
    state.faults = Faults {
        drop: percent(body, "drop")?,
        duplicate: percent(body, "duplicate")?,
        reorder: body.get("reorder").and_then(Value::as_bool).unwrap_or(false),
    };
    if let Some(seed) = body.get("seed").and_then(Value::as_u64) {
        state.rng = SplitMix(seed);
    }
    config::log(ROLE, "faults", body.clone());
    Ok(body.clone())
}

fn set_hold(state: &mut State, body: &Value) -> Result<Value, String> {
    let mailbox = str_field(body, "mailbox")?.to_owned();
    let held = body.get("held").and_then(Value::as_bool).ok_or("malformed: held")?;
    if held {
        state.held.insert(mailbox.clone());
    } else {
        state.held.remove(&mailbox);
    }
    config::log(ROLE, "hold", body.clone());
    Ok(json!({ "mailbox": mailbox, "held": held }))
}

fn set_tap(state: &mut State, body: &Value) -> Result<Value, String> {
    let victim = str_field(body, "victim")?.to_owned();
    let observer = str_field(body, "observer")?.to_owned();
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let observers = state.taps.entry(victim.clone()).or_default();
    if enabled {
        observers.insert(observer.clone());
    } else {
        observers.remove(&observer);
    }
    config::log(ROLE, "tap", body.clone());
    Ok(json!({ "victim": victim, "observer": observer, "enabled": enabled }))
}

fn append(state: &mut State, group: &str, mut entry: Value) -> u64 {
    let log = state.handshake.entry(group.to_owned()).or_default();
    let index = log.len() as u64;
    if let Some(object) = entry.as_object_mut() {
        object.insert("index".into(), json!(index));
    }
    log.push(entry);
    index
}

fn entry_at(state: &State, group: &str, body: &Value, key: &str) -> Result<Value, String> {
    let index = body.get(key).and_then(Value::as_u64).ok_or_else(|| format!("malformed: {key}"))?;
    state
        .handshake
        .get(group)
        .and_then(|log| log.get(index as usize))
        .cloned()
        .ok_or_else(|| format!("not_found: no handshake entry {index}"))
}

fn handshake_fault(state: &mut State, body: &Value) -> Result<Value, String> {
    let action = str_field(body, "action")?;
    let result = match action {
        "hide" => {
            let reader = str_field(body, "reader")?.to_owned();
            let from = body.get("from_index").and_then(Value::as_u64).ok_or("malformed: from_index")?;
            state.hidden.insert(reader.clone(), from);
            json!({ "reader": reader, "hidden_from": from })
        }
        "show" => {
            let reader = str_field(body, "reader")?.to_owned();
            state.hidden.remove(&reader);
            json!({ "reader": reader, "hidden_from": null })
        }
        "reverse" => {
            let reader = str_field(body, "reader")?.to_owned();
            let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
            if enabled {
                state.reversed.insert(reader.clone());
            } else {
                state.reversed.remove(&reader);
            }
            json!({ "reader": reader, "reversed": enabled })
        }
        "inject" | "replay" | "splice" => {
            let group = str_field(body, "group")?.to_owned();
            let mut entry = match action {
                "inject" => body.get("entry").cloned().ok_or("malformed: entry")?,
                "replay" => entry_at(state, &group, body, "index")?,
                _ => {
                    let mut spliced = entry_at(state, &group, body, "commit_from")?;
                    let ack = entry_at(state, &group, body, "ack_from")?["ack"].clone();
                    spliced["ack"] = ack;
                    spliced
                }
            };
            if let Some(object) = entry.as_object_mut() {
                object.insert("forged".into(), json!(action));
                // A forged entry claims no committer, so no member skips it on that ground.
                object.remove("committer");
            }
            let index = append(state, &group, entry);
            json!({ "action": action, "index": index })
        }
        _ => return Err(format!("malformed: unknown handshake action {action}")),
    };
    config::log(ROLE, "handshake_fault", body.clone());
    Ok(result)
}

fn stats(state: &State) -> Value {
    let queued: BTreeMap<&String, usize> = state
        .mailboxes
        .iter()
        .map(|(name, messages)| (name, messages.len()))
        .collect();
    let leased: usize = state.leased.values().map(Vec::len).sum();
    let pending: usize = state
        .mailboxes
        .iter()
        .filter(|(name, _)| !state.held.contains(*name))
        .map(|(_, messages)| messages.len())
        .sum::<usize>()
        + leased;
    json!({
        "posted": state.stats.posted,
        "fetched": state.stats.fetched,
        "dropped": state.stats.dropped,
        "duplicated": state.stats.duplicated,
        "tapped": state.stats.tapped,
        "expired": state.stats.expired,
        "leased": leased,
        "queued": queued,
        "pending": pending,
        "held": state.held,
        "hidden": state.hidden,
        "reversed": state.reversed,
        "handshake": state.handshake.iter().map(|(g, log)| (g.clone(), log.len())).collect::<BTreeMap<_, _>>(),
        "key_packages": state.key_packages.keys().collect::<Vec<_>>(),
        "faults": { "drop": state.faults.drop, "duplicate": state.faults.duplicate, "reorder": state.faults.reorder },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(seed: u64, drop: u64, duplicate: u64) -> State {
        State {
            leased: BTreeMap::new(),
            lease: std::time::Duration::from_secs(60),
            handshake: BTreeMap::new(),
            key_packages: BTreeMap::new(),
            mailboxes: BTreeMap::new(),
            held: BTreeSet::new(),
            taps: BTreeMap::new(),
            hidden: BTreeMap::new(),
            reversed: BTreeSet::new(),
            faults: Faults { drop, duplicate, reorder: true },
            rng: SplitMix(seed),
            next_id: 0,
            stats: Stats::default(),
        }
    }

    /// Fetches until the mailbox is empty; returns every delivered op.
    fn drain(state: &mut State, to: &str) -> Vec<String> {
        let mut out = Vec::new();
        for _ in 0..10_000 {
            let batch = fetch(state, to);
            let ids: Vec<u64> = batch.iter().map(|m| m["relay_id"].as_u64().unwrap()).collect();
            ack(state, to, &ids);
            out.extend(batch.iter().map(|m| m["op"].as_str().unwrap().to_owned()));
            if state.mailboxes.get(to).is_none() {
                return out;
            }
        }
        panic!("the mailbox never drained");
    }

    #[test]
    fn faulty_mailbox_delivers_every_message_at_least_once_and_at_most_twice() {
        for seed in 0..50 {
            let mut state = state(seed, 40, 40);
            for i in 0..20 {
                post(&mut state, "bob", json!({ "op": format!("op-{i}") }));
            }
            let delivered = drain(&mut state, "bob");
            for i in 0..20 {
                let count = delivered.iter().filter(|op| **op == format!("op-{i}")).count();
                assert!((1..=2).contains(&count), "seed {seed}: op-{i} delivered {count} times");
            }
            assert_eq!(delivered.len() as u64, 20 + state.stats.duplicated);
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_schedule() {
        let run = |seed| {
            let mut state = state(seed, 30, 30);
            for i in 0..10 {
                post(&mut state, "bob", json!({ "op": format!("op-{i}") }));
            }
            drain(&mut state, "bob")
        };
        assert_eq!(run(3), run(3));
        assert_ne!(run(3), run(4));
    }

    #[test]
    fn a_held_mailbox_keeps_its_messages_until_released() {
        let mut state = state(1, 0, 0);
        post(&mut state, "carol", json!({ "op": "m" }));
        state.held.insert("carol".into());
        assert!(fetch(&mut state, "carol").is_empty());
        assert_eq!(stats(&state)["pending"], 0);
        state.held.remove("carol");
        assert_eq!(fetch(&mut state, "carol").len(), 1);
    }

    #[test]
    fn an_unacknowledged_message_comes_back_after_its_lease() {
        let mut state = state(1, 0, 0);
        state.lease = std::time::Duration::from_millis(0);
        post(&mut state, "bob", json!({ "op": "m" }));
        assert_eq!(fetch(&mut state, "bob").len(), 1);
        assert_eq!(stats(&state)["pending"], 1, "a leased message is still pending");
        let again = fetch(&mut state, "bob");
        assert_eq!(again.len(), 1, "the expired lease retransmits the message");
        let id = again[0]["relay_id"].as_u64().unwrap();
        assert_eq!(ack(&mut state, "bob", &[id]), 1);
        assert_eq!(stats(&state)["pending"], 0);
    }

    #[test]
    fn a_tap_copies_the_victim_traffic_to_the_observer() {
        let mut state = state(1, 0, 0);
        state.taps.entry("bob".into()).or_default().insert("carol".into());
        post(&mut state, "bob", json!({ "op": "m" }));
        let copy = fetch(&mut state, "carol");
        assert_eq!(copy.len(), 1);
        assert_eq!(copy[0]["tapped_from"], "bob");
        assert_eq!(fetch(&mut state, "bob").len(), 1);
    }
}
