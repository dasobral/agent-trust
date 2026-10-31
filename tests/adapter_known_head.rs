//! R-13d.4 (D-17): a request may carry `known_head`, the latest APF-signed history head
//! its client has seen, inside the body the actor signs. The adapter refuses it with
//! `fork_detected` when its history does not hold that head: a rollback of the whole
//! data directory, which no check on the APF host can see, fails at the first request of
//! a client that saw a later head. `HeadTracker` is the client side.
mod common;

use agent_trust::adapter::{Adapter, SignedRequest};
use agent_trust::client::HeadTracker;
use agent_trust::wire::{HistoryHead, SignedStructure};
use common::{
    adapter_dir, scripted_provider, sign, DalekSigner, FixedClock, ScriptedRand, TestProvider,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{json, Value};
use std::path::Path;

const GROUP: &str = "group-a";
const ROOT: &str = "root";

type TestAdapter = Adapter<TestProvider<ScriptedRand>, FixedClock>;

fn create(dir: &Path) -> (TestAdapter, DalekSigner) {
    let root = DalekSigner::from_seed([0x11; 32]);
    let (provider, _) = scripted_provider(b"known-head");
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

fn open(dir: &Path) -> TestAdapter {
    let (provider, _) = scripted_provider(b"known-head");
    Adapter::open(dir, provider, FixedClock::new(10)).expect("open")
}

fn request(root: &DalekSigner, sequence: u64, body: Value) -> SignedRequest {
    sign(root, GROUP, ROOT, sequence, &body)
}

fn head_of(adapter: &TestAdapter) -> HistoryHead {
    HistoryHead::verify(
        &adapter.history_head().unwrap(),
        adapter.apf_public_key(),
        &RustCrypto::default(),
    )
    .unwrap()
}

fn known(head: &HistoryHead) -> Value {
    json!({"sequence":head.sequence, "hash":hex::encode(&head.history_hash)})
}

fn code(result: Result<Value, String>, expected: &str) {
    match result {
        Err(err) => assert!(
            err == expected || err.starts_with(&format!("{expected}:")),
            "expected {expected}, got {err}"
        ),
        Ok(value) => panic!("expected {expected}, got {value}"),
    }
}

fn last_outcome(adapter: &TestAdapter) -> String {
    adapter.trace().last().unwrap()["outcome"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn a_request_with_a_head_of_this_history_is_accepted() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let head = head_of(&adapter);
    adapter
        .handle(&request(
            &root,
            1,
            json!({"command":"allocate", "op":"op-1", "known_head":known(&head)}),
        ))
        .expect("the current head");
    // An older head of the same history is still that history.
    adapter
        .handle(&request(
            &root,
            2,
            json!({"command":"allocate", "op":"op-2", "known_head":known(&head)}),
        ))
        .expect("an older head");
}

#[test]
fn a_head_this_history_does_not_hold_is_fork_detected() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let head = head_of(&adapter);
    let ahead = json!({"sequence":head.sequence + 5, "hash":hex::encode(&head.history_hash)});
    code(
        adapter.handle(&request(
            &root,
            1,
            json!({"command":"allocate", "op":"op-1", "known_head":ahead}),
        )),
        "fork_detected",
    );
    assert_eq!(last_outcome(&adapter), "fork_detected");
    let other = json!({"sequence":head.sequence, "hash":"ab".repeat(32)});
    code(
        adapter.handle(&request(
            &root,
            2,
            json!({"command":"allocate", "op":"op-1", "known_head":other}),
        )),
        "fork_detected",
    );
    // Nothing reached the kernel.
    let checkpoint = adapter.checkpoint().unwrap();
    assert_eq!(
        checkpoint["history"].as_array().unwrap().len() as u64,
        head.sequence + 1
    );
}

#[test]
fn a_malformed_known_head_is_refused() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    for (sequence, value) in [
        json!("x"),
        json!({"sequence":0}),
        json!({"sequence":-1, "hash":"ab".repeat(32)}),
        json!({"sequence":0, "hash":"zz"}),
        json!({"sequence":0, "hash":"ab".repeat(32), "extra":1}),
    ]
    .into_iter()
    .enumerate()
    {
        code(
            adapter.handle(&request(
                &root,
                sequence as u64 + 1,
                json!({"command":"allocate", "op":"op-1", "known_head":value}),
            )),
            "malformed",
        );
    }
}

#[test]
fn a_rolled_back_data_directory_is_detected_by_a_client_that_saw_a_later_head() {
    let dir = adapter_dir();
    let backup = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let mut client = HeadTracker::new(adapter.apf_public_key(), GROUP);
    client.observe(&adapter.history_head().unwrap()).unwrap();
    let mut body = json!({"command":"allocate", "op":"op-1"});
    client.attach(&mut body);
    adapter.handle(&request(&root, 1, body)).unwrap();
    client.observe(&adapter.history_head().unwrap()).unwrap();
    drop(adapter);
    // A consistent copy of the whole directory: every file, the key included.
    copy_dir(dir.path(), backup.path());
    let mut adapter = open(dir.path());
    let mut body = json!({"command":"allocate", "op":"op-2"});
    client.attach(&mut body);
    adapter.handle(&request(&root, 2, body)).unwrap();
    client.observe(&adapter.history_head().unwrap()).unwrap();
    drop(adapter);
    copy_dir(backup.path(), dir.path());
    // The rolled-back directory opens: every file agrees with every other.
    let mut adapter = open(dir.path());
    let mut body = json!({"command":"allocate", "op":"op-3"});
    client.attach(&mut body);
    code(adapter.handle(&request(&root, 3, body)), "fork_detected");
}

#[test]
fn the_tracker_verifies_heads_and_refuses_one_that_goes_back() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let first = adapter.history_head().unwrap();
    adapter
        .handle(&request(
            &root,
            1,
            json!({"command":"allocate", "op":"op-1"}),
        ))
        .unwrap();
    let second = adapter.history_head().unwrap();

    let mut client = HeadTracker::new(adapter.apf_public_key(), GROUP);
    assert_eq!(client.known_head(), None);
    client.observe(&first).unwrap();
    client.observe(&second).unwrap();
    assert_eq!(client.known_head(), Some(known(&head_of(&adapter))));
    let err = client.observe(&first).unwrap_err();
    assert!(err.starts_with("fork_detected"), "{err}");
    let mut forged = second.clone();
    *forged.last_mut().unwrap() ^= 1;
    let err = client.observe(&forged).unwrap_err();
    assert!(err.starts_with("unauthenticated"), "{err}");
    let mut stranger = HeadTracker::new(adapter.apf_public_key(), "group-b");
    let err = stranger.observe(&second).unwrap_err();
    assert!(err.starts_with("binding_mismatch"), "{err}");
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(to).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            std::fs::remove_file(path).unwrap();
        }
    }
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            std::fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
        }
    }
}
