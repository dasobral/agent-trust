//! R-13d.3 (D-17): the APF signs the kernel history tip after every request that reaches
//! the kernel and keeps the latest signature. `Adapter::open` refuses a kernel store whose
//! history does not end at the signed head: a rolled-back or substituted `authority.sqlite`
//! fails without the APF key. The APF key file must be private to its owner.
mod common;

use agent_trust::adapter::{Adapter, APF_KEY_FILE, AUTHORITY_FILE};
use agent_trust::wire::{HistoryHead, SignedStructure};
use common::{
    adapter_dir, scripted_provider, sign, DalekSigner, FixedClock, ScriptedRand, TestProvider,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const GROUP: &str = "group-a";
const ROOT: &str = "root";

type TestAdapter = Adapter<TestProvider<ScriptedRand>, FixedClock>;

fn create(dir: &Path) -> (TestAdapter, DalekSigner) {
    let root = DalekSigner::from_seed([0x11; 32]);
    let (provider, _) = scripted_provider(b"history-head");
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
    let (provider, _) = scripted_provider(b"history-head");
    Adapter::open(dir, provider, FixedClock::new(10))
}

fn allocate(adapter: &mut TestAdapter, root: &DalekSigner, sequence: u64, op: &str) {
    let request = sign(
        root,
        GROUP,
        ROOT,
        sequence,
        &json!({"command":"allocate", "op":op}),
    );
    adapter.handle(&request).expect("allocate");
}

fn head(adapter: &TestAdapter) -> HistoryHead {
    let bytes = adapter.history_head().expect("a signed history head");
    HistoryHead::verify(&bytes, adapter.apf_public_key(), &RustCrypto::default())
        .expect("the APF signed the head")
}

fn tip(adapter: &mut TestAdapter) -> (u64, Vec<u8>) {
    let checkpoint: Value = adapter.checkpoint().unwrap();
    let history = checkpoint["history"].as_array().unwrap();
    (
        history.len() as u64 - 1,
        hex::decode(checkpoint["history_root"].as_str().unwrap()).unwrap(),
    )
}

/// The kernel store as files: SQLite merges its write-ahead log when the last connection
/// closes, so this is called with no adapter open.
fn copy_kernel(from: &Path, to: &Path) {
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(to.join(format!("{AUTHORITY_FILE}{suffix}")));
    }
    std::fs::copy(from.join(AUTHORITY_FILE), to.join(AUTHORITY_FILE)).unwrap();
}

#[test]
fn the_head_is_apf_signed_and_names_the_kernel_tip() {
    let dir = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    let signed = head(&adapter);
    assert_eq!(signed.group, GROUP);
    assert_eq!(
        signed.apf_key_id,
        Sha256::digest(adapter.apf_public_key()).to_vec()
    );
    assert_eq!(
        (signed.sequence, signed.history_hash.clone()),
        tip(&mut adapter)
    );

    allocate(&mut adapter, &root, 1, "op-1");
    let next = head(&adapter);
    assert_eq!(next.sequence, signed.sequence + 1);
    assert_eq!((next.sequence, next.history_hash), tip(&mut adapter));
}

#[test]
fn a_rolled_back_kernel_store_fails_open() {
    let dir = adapter_dir();
    let backup = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    allocate(&mut adapter, &root, 1, "op-1");
    drop(adapter);
    copy_kernel(dir.path(), backup.path());
    let mut adapter = open(dir.path()).expect("reopen");
    allocate(&mut adapter, &root, 2, "op-2");
    drop(adapter);
    copy_kernel(backup.path(), dir.path());
    let err = open(dir.path())
        .err()
        .expect("a rolled-back kernel store must not open");
    assert!(err.starts_with("corrupt_history"), "{err}");
}

#[test]
fn a_substituted_kernel_history_fails_open() {
    // Another adapter of the same group and root, with a different history of the same
    // length: internally consistent, so only the signed head can tell.
    let dir = adapter_dir();
    let other = adapter_dir();
    let (mut adapter, root) = create(dir.path());
    allocate(&mut adapter, &root, 1, "op-1");
    drop(adapter);
    let (mut forged, root) = create(other.path());
    allocate(&mut forged, &root, 1, "op-forged");
    drop(forged);
    copy_kernel(other.path(), dir.path());
    let err = open(dir.path())
        .err()
        .expect("a substituted history must not open");
    assert!(err.starts_with("corrupt_history"), "{err}");
}

#[test]
fn an_apf_key_file_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = adapter_dir();
    let (adapter, _) = create(dir.path());
    drop(adapter);
    let key = dir.path().join(APF_KEY_FILE);
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for mode in [0o640, 0o604, 0o644] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let err = open(dir.path())
            .err()
            .expect("a shared key file must not open");
        assert_eq!(err, "malformed: apf key file permissions", "mode {mode:o}");
    }
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    open(dir.path()).expect("an owner-only key file opens");
}
