//! Durable lab providers and identity restore (finding F-2 of agent-trust-testbed).
//!
//! A networked agent must survive a restart: its OpenMLS state must live in a file, and
//! its registered signature key must come back. These tests pin:
//!
//! - `LabEntropy::durable_provider(path)`: the lab crypto provider and the selected rand,
//!   with `openmls_sqlite_storage` storage in one file. Reopening the same path gives the
//!   stored group back through `ClientEndpoint::load` (C-33).
//! - `ClientIdentity::restore(key_pair)`: rebuilds a stored identity. It accepts only an
//!   Ed25519 pair whose public key derives from its private seed, so it cannot attach a
//!   foreign public key to a secret. Key generation stays `ClientIdentity::generate`
//!   (C-6). The stored form in these tests is the key pair's serde JSON, the form an
//!   application writes to its own owner-only file.

mod common;

use std::path::Path;

use agent_trust::adapter::{Adapter, ClientIdentity};
use agent_trust::client::ClientEndpoint;
use agent_trust::entropy::{EntropyConfig, LabEntropy};
use agent_trust::wire::Right;
use common::{adapter_dir, code, FixedClock};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde_json::Value;

const GROUP: &str = "g";
const ROOT: &str = "root";
const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];

fn mock_entropy() -> LabEntropy {
    EntropyConfig::from_env_with(|name| match name {
        "AGENT_TRUST_ENTROPY_SOURCE" => Some("mock".to_owned()),
        "AGENT_TRUST_MOCK_SEED" => Some("7".to_owned()),
        _ => None,
    })
    .and_then(|config| config.connect())
    .expect("mock entropy")
}

/// The identity's stored form: the serde JSON of its key pair.
fn stored(identity: &ClientIdentity) -> Value {
    serde_json::to_value(identity.signer()).expect("serialize key pair")
}

fn restore(saved: &Value) -> Result<ClientIdentity, String> {
    let pair: SignatureKeyPair = serde_json::from_value(saved.clone()).expect("key pair JSON");
    ClientIdentity::restore(pair)
}

/// Founds a group with a durable root provider at `path`; returns the frontier, the
/// stored identity and the APF public key.
fn found_durable_root(
    entropy: &LabEntropy,
    path: &Path,
    dir: &Path,
) -> (agent_trust::wire::Frontier, Value, Vec<u8>) {
    let provider = entropy.durable_provider(path).expect("durable provider");
    let identity = ClientIdentity::generate(provider.rand()).expect("root identity");
    let saved = stored(&identity);
    let pending = Adapter::begin_genesis(
        dir,
        GROUP,
        ROOT,
        identity.public_key(),
        entropy.provider(),
        FixedClock::new(1_000),
    )
    .expect("begin genesis");
    let apf_public = pending.apf_public_key().to_vec();
    let root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        identity,
        provider,
        pending.founder_certificate(),
        pending.apf_anchor(),
        &apf_public,
    )
    .expect("found");
    let group_info = root.export_group_info().expect("group info");
    let tree = root.export_ratchet_tree().expect("ratchet tree");
    pending
        .complete(&group_info, &tree)
        .expect("complete genesis");
    (root.frontier().expect("frontier"), saved, apf_public)
}

#[test]
fn a_reopened_durable_provider_reloads_the_founded_group() {
    let entropy = mock_entropy();
    let dir = adapter_dir();
    let files = adapter_dir();
    let path = files.path().join("root.sqlite");
    let (frontier, saved, apf_public) = found_durable_root(&entropy, &path, dir.path());

    // The endpoint and its provider were dropped: a restart.
    let provider = entropy
        .durable_provider(&path)
        .expect("reopen durable provider");
    let identity = restore(&saved).expect("restore identity");
    let root = ClientEndpoint::load(GROUP, ROOT, identity, provider, &apf_public, None, None)
        .expect("load the stored group");
    assert_eq!(root.frontier().expect("frontier"), frontier);
    assert_eq!(
        serde_json::to_value(root.identity().public_key()).unwrap(),
        saved["public"]
    );
}

#[test]
fn a_new_durable_file_holds_no_group() {
    let entropy = mock_entropy();
    let dir = adapter_dir();
    let files = adapter_dir();
    let (_, saved, apf_public) =
        found_durable_root(&entropy, &files.path().join("root.sqlite"), dir.path());
    let other = entropy
        .durable_provider(&files.path().join("other.sqlite"))
        .expect("second durable provider");
    let identity = restore(&saved).expect("restore identity");
    code(
        ClientEndpoint::load(GROUP, ROOT, identity, other, &apf_public, None, None),
        "uninitialized",
    );
}

#[test]
fn restore_refuses_a_public_key_that_the_seed_does_not_derive() {
    let entropy = mock_entropy();
    let first = ClientIdentity::generate(&entropy.rand()).expect("first identity");
    let second = ClientIdentity::generate(&entropy.rand()).expect("second identity");
    let mut mixed = stored(&first);
    mixed["public"] = stored(&second)["public"].clone();
    code(restore(&mixed), "binding_mismatch");
}

#[test]
fn restore_refuses_a_non_ed25519_pair() {
    let entropy = mock_entropy();
    let identity = ClientIdentity::generate(&entropy.rand()).expect("identity");
    let mut saved = stored(&identity);
    let ed25519 = saved["signature_scheme"].clone();
    saved["signature_scheme"] =
        serde_json::to_value(openmls_traits::types::SignatureScheme::ECDSA_SECP256R1_SHA256)
            .unwrap();
    assert_ne!(saved["signature_scheme"], ed25519);
    code(restore(&saved), "binding_mismatch");
}

#[test]
fn restore_round_trips_an_identity() {
    let entropy = mock_entropy();
    let identity = ClientIdentity::generate(&entropy.rand()).expect("identity");
    let saved = stored(&identity);
    let restored = restore(&saved).expect("restore");
    assert_eq!(restored.public_key(), identity.public_key());
    assert_eq!(stored(&restored), saved);
}

#[test]
fn a_durable_provider_on_an_unusable_path_is_an_error() {
    let entropy = mock_entropy();
    let files = adapter_dir();
    let missing_parent = files.path().join("missing").join("client.sqlite");
    assert!(entropy.durable_provider(&missing_parent).is_err());
}
