//! R-13d.6 (D-17): `Adapter::verify_full` runs the `open` checks over the whole history
//! and traces every registered actor key to the signed `grant` or `delegate` request that
//! registered it. An attacker with the APF key who substitutes an actor's key and signs
//! a step with it passes `open` without client anchors, and fails here.
mod common;

use agent_trust::adapter::{Adapter, SignedRequest, ADAPTER_FILE, APF_KEY_FILE, AUTHORITY_FILE};
use agent_trust::authority::Authority;
use agent_trust::wire::{HistoryHead, SignedStructure};
use common::{
    adapter_dir, lower_hex, scripted_provider, sign, DalekSigner, FixedClock, ScriptedRand,
    TestProvider,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

const GROUP: &str = "group-a";
const ROOT: &str = "root";

type TestAdapter = Adapter<TestProvider<ScriptedRand>, FixedClock>;

fn open(dir: &Path) -> Result<TestAdapter, String> {
    let (provider, _) = scripted_provider(b"verify-full");
    Adapter::open(dir, provider, FixedClock::new(10))
}

/// Root registers alice's key with a grant; alice allocates op-1.
fn honest(dir: &Path) -> (DalekSigner, DalekSigner) {
    let root = DalekSigner::from_seed([0x11; 32]);
    let alice = DalekSigner::from_seed([0x22; 32]);
    let (provider, _) = scripted_provider(b"verify-full");
    let mut adapter: TestAdapter = Adapter::create(
        dir,
        GROUP,
        ROOT,
        &root.public_key(),
        provider,
        FixedClock::new(10),
    )
    .unwrap();
    for (sequence, right) in [(1, "read"), (2, "write")] {
        let mut body = json!({"command":"grant", "subject":"alice", "right":right, "generation":0,
                              "fresh_keys":true});
        if sequence == 1 {
            body["subject_key"] = json!(lower_hex(&alice.public_key()));
        }
        adapter
            .handle(&sign(&root, GROUP, ROOT, sequence, &body))
            .unwrap();
    }
    adapter
        .handle(&sign(
            &alice,
            GROUP,
            "alice",
            1,
            &json!({"command":"allocate", "op":"op-1"}),
        ))
        .unwrap();
    (root, alice)
}

#[test]
fn an_honest_history_verifies_in_full() {
    let dir = adapter_dir();
    honest(dir.path());
    let mut adapter = open(dir.path()).unwrap();
    let report = adapter.verify_full().expect("verify_full");
    assert_eq!(report["keys_traced"], json!(1), "{report}");
    assert_eq!(report["keys_rotated"], json!([]), "{report}");
}

fn v2_hash(sequence: u64, previous: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-trust/kernel-event/v2\0");
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous.as_bytes());
    hasher.update([0u8]);
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[test]
fn a_substituted_actor_key_fails_verify_full() {
    let dir = adapter_dir();
    honest(dir.path());
    // The thief holds the APF key: it replaces alice's key, re-signs her request with the
    // new key, rewrites the cause in the kernel history and re-signs the head.
    let thief = DalekSigner::from_seed([0x66; 32]);
    let store = rusqlite::Connection::open(dir.path().join(ADAPTER_FILE)).unwrap();
    let (old_cause, body): (String, Vec<u8>) = store
        .query_row(
            "SELECT cause, body FROM adapter_requests WHERE actor = 'alice'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut tbs = SignedRequest::to_be_signed(GROUP, "alice", 1, &body).unwrap();
    let signature = {
        use openmls_traits::signatures::Signer;
        thief.sign(&tbs).unwrap()
    };
    tbs.extend(&signature);
    let new_cause = hex::encode(Sha256::digest(&tbs));
    store
        .execute(
            "UPDATE adapter_keys SET public_key = ?1 WHERE actor = 'alice'",
            [thief.public_key()],
        )
        .unwrap();
    store
        .execute(
            "UPDATE adapter_requests SET cause = ?1, signature = ?2 WHERE cause = ?3",
            rusqlite::params![new_cause, signature, old_cause],
        )
        .unwrap();
    let kernel = rusqlite::Connection::open(dir.path().join(AUTHORITY_FILE)).unwrap();
    let events: Vec<(i64, String, String)> = {
        let mut stmt = kernel
            .prepare("SELECT sequence, previous, event FROM authority_events ORDER BY sequence")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        rows.map(Result::unwrap).collect()
    };
    let start = events
        .iter()
        .position(|(_, _, raw)| raw.contains(&old_cause))
        .unwrap();
    let mut previous = events[start].1.clone();
    for (sequence, _, raw) in &events[start..] {
        let raw = raw.replace(&old_cause, &new_cause);
        let hash = v2_hash(*sequence as u64, &previous, &raw);
        kernel
            .execute(
                "UPDATE authority_events SET previous = ?1, hash = ?2, event = ?3 WHERE sequence = ?4",
                rusqlite::params![previous, hash, raw, sequence],
            )
            .unwrap();
        previous = hash;
    }
    kernel.execute("DROP TABLE authority_mmr", []).unwrap();
    drop(kernel);
    let mut authority = Authority::open(dir.path().join(AUTHORITY_FILE)).unwrap();
    let tip = authority
        .execute(json!({"command":"history_head"}))
        .unwrap();
    drop(authority);
    let seed: [u8; 32] = std::fs::read(dir.path().join(APF_KEY_FILE))
        .unwrap()
        .try_into()
        .unwrap();
    let apf = DalekSigner::from_seed(seed);
    let head = HistoryHead {
        apf_key_id: Sha256::digest(apf.public_key()).to_vec(),
        group: GROUP.to_owned(),
        sequence: tip["sequence"].as_u64().unwrap(),
        history_hash: hex::decode(tip["hash"].as_str().unwrap()).unwrap(),
    }
    .sign(&apf)
    .unwrap();
    store
        .execute(
            "UPDATE adapter_meta SET v = ?1 WHERE k = 'history_head'",
            [hex::encode(head)],
        )
        .unwrap();
    drop(store);
    // No client anchors: `open` cannot tell.
    let mut adapter = open(dir.path()).expect("without anchors, open accepts the substitution");
    let err = adapter
        .verify_full()
        .expect_err("verify_full must trace alice's key");
    assert!(err.starts_with("corrupt_history"), "{err}");
}
