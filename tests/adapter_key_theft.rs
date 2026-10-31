//! R-13d.5 (D-17): an attacker who holds the APF key and every file of the data
//! directory, but no actor key. Each kernel event records the digest of the actor-signed
//! request that caused it (`cause`); the adapter keeps those requests. `Adapter::open`
//! checks every client anchor against the history, replays the kernel after the latest
//! anchor, and requires each event after it to come from a signed request.
mod common;

use agent_trust::adapter::{Adapter, SignedRequest, ADAPTER_FILE, APF_KEY_FILE, AUTHORITY_FILE};
use agent_trust::authority::Authority;
use agent_trust::client::HeadTracker;
use agent_trust::wire::{HistoryHead, SignedStructure};
use common::{
    adapter_dir, scripted_provider, sign, DalekSigner, FixedClock, ScriptedRand, TestProvider,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const GROUP: &str = "group-a";
const ROOT: &str = "root";

type TestAdapter = Adapter<TestProvider<ScriptedRand>, FixedClock>;

fn create(dir: &Path) -> (TestAdapter, DalekSigner) {
    let root = DalekSigner::from_seed([0x11; 32]);
    let (provider, _) = scripted_provider(b"key-theft");
    let adapter = Adapter::create(
        dir,
        GROUP,
        ROOT,
        &root.public_key(),
        provider,
        FixedClock::new(10),
    )
    .expect("create");
    (adapter, root)
}

fn open(dir: &Path) -> Result<TestAdapter, String> {
    let (provider, _) = scripted_provider(b"key-theft");
    Adapter::open(dir, provider, FixedClock::new(10))
}

/// Root allocates `op` with its client's latest head; the client then takes the new head.
fn allocate(
    adapter: &mut TestAdapter,
    root: &DalekSigner,
    client: &mut HeadTracker,
    sequence: u64,
    op: &str,
) {
    let mut body = json!({"command":"allocate", "op":op});
    client.attach(&mut body);
    let request: SignedRequest = sign(root, GROUP, ROOT, sequence, &body);
    adapter.handle(&request).expect("allocate");
    client.observe(&adapter.history_head().unwrap()).unwrap();
}

/// The thief: signs the kernel tip with the stolen APF key and stores it as the head.
fn resign_head(dir: &Path) {
    let seed: [u8; 32] = std::fs::read(dir.join(APF_KEY_FILE))
        .unwrap()
        .try_into()
        .unwrap();
    let apf = DalekSigner::from_seed(seed);
    let mut kernel = Authority::open(dir.join(AUTHORITY_FILE)).unwrap();
    let tip = kernel.execute(json!({"command":"history_head"})).unwrap();
    drop(kernel);
    let head = HistoryHead {
        apf_key_id: Sha256::digest(apf.public_key()).to_vec(),
        group: GROUP.to_owned(),
        sequence: tip["sequence"].as_u64().unwrap(),
        history_hash: hex::decode(tip["hash"].as_str().unwrap()).unwrap(),
    }
    .sign(&apf)
    .unwrap();
    rusqlite::Connection::open(dir.join(ADAPTER_FILE))
        .unwrap()
        .execute(
            "UPDATE adapter_meta SET v = ?1 WHERE k = 'history_head'",
            [hex::encode(head)],
        )
        .unwrap();
}

fn refused(dir: &Path) -> String {
    let err = open(dir).err().expect("the forged directory must not open");
    assert!(err.starts_with("corrupt_history"), "{err}");
    err
}

fn last_event(dir: &Path) -> Value {
    let mut kernel = Authority::open(dir.join(AUTHORITY_FILE)).unwrap();
    let all = kernel.execute(json!({"command":"checkpoint"})).unwrap();
    all["history"].as_array().unwrap().last().unwrap()["event"].clone()
}

#[test]
fn every_kernel_event_of_a_request_records_its_signed_request() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let mut client = HeadTracker::new(adapter.apf_public_key(), GROUP);
    allocate(&mut adapter, &root, &mut client, 1, "op-1");
    drop(adapter);
    let cause = last_event(dir.path())["cause"].as_str().unwrap().to_owned();
    assert_eq!(cause.len(), 64);
    let stored: i64 = rusqlite::Connection::open(dir.path().join(ADAPTER_FILE))
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM adapter_requests WHERE cause = ?1",
            [&cause],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, 1);
    open(dir.path()).expect("an honest directory opens");
}

#[test]
fn a_step_appended_with_the_stolen_apf_key_is_refused_at_open() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let mut client = HeadTracker::new(adapter.apf_public_key(), GROUP);
    allocate(&mut adapter, &root, &mut client, 1, "op-1");
    drop(adapter);
    // A legal kernel step that no actor asked for, signed into the head.
    let mut kernel = Authority::open(dir.path().join(AUTHORITY_FILE)).unwrap();
    kernel
        .execute(json!({"command":"allocate", "actor":"root", "op":"op-thief"}))
        .unwrap();
    drop(kernel);
    resign_head(dir.path());
    refused(dir.path());
}

#[test]
fn a_signed_request_reused_for_a_second_step_is_refused_at_open() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let mut client = HeadTracker::new(adapter.apf_public_key(), GROUP);
    allocate(&mut adapter, &root, &mut client, 1, "op-1");
    drop(adapter);
    let cause = last_event(dir.path())["cause"].as_str().unwrap().to_owned();
    let mut kernel = Authority::open(dir.path().join(AUTHORITY_FILE)).unwrap();
    kernel
        .execute(json!({"command":"allocate", "actor":"root", "op":"op-thief", "cause":cause}))
        .unwrap();
    drop(kernel);
    resign_head(dir.path());
    refused(dir.path());
}

#[test]
fn an_older_kernel_store_behind_a_client_anchor_is_refused_at_open() {
    let dir = adapter_dir();
    let backup = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let mut client = HeadTracker::new(adapter.apf_public_key(), GROUP);
    allocate(&mut adapter, &root, &mut client, 1, "op-1");
    drop(adapter);
    std::fs::copy(
        dir.path().join(AUTHORITY_FILE),
        backup.path().join(AUTHORITY_FILE),
    )
    .unwrap();
    let mut adapter = open(dir.path()).unwrap();
    allocate(&mut adapter, &root, &mut client, 2, "op-2");
    // The anchor: a request that names the head after op-2.
    allocate(&mut adapter, &root, &mut client, 3, "op-3");
    drop(adapter);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.path().join(format!("{AUTHORITY_FILE}{suffix}")));
    }
    std::fs::copy(
        backup.path().join(AUTHORITY_FILE),
        dir.path().join(AUTHORITY_FILE),
    )
    .unwrap();
    resign_head(dir.path());
    refused(dir.path());
}
