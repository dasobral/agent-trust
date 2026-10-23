//! OpenMLS compatibility gate for the APF<->MLS adapter (`docs/adapter-contract.md`).
//!
//! These tests exercise the pinned OpenMLS fork directly, with only its normal
//! feature surface, to prove that every API the adapter relies on exists and
//! behaves as the contract assumes.  They test the dependency, not project
//! code.  All signature keys come from fixed test seeds through
//! `SignatureKeyPair::from_raw`; SQLite files live only in temporary
//! directories.

use std::path::Path;

use openmls::prelude::*;
use openmls::treesync::errors::LeafNodeValidationError;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto, RustCrypto};
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{Ciphersuite, SignatureScheme},
    OpenMlsProvider,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const ACC_CONTEXT: u16 = 0xf043;
const AUTHZ_INCARNATION: u16 = 0xf044;

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

/// serde_json codec for the SQLite storage provider.
#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// RustCrypto with SQLite-backed OpenMLS storage.
struct SqliteProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl SqliteProvider {
    fn open(path: &Path) -> Self {
        let connection = Connection::open(path).expect("open sqlite file");
        let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
        storage.run_migrations().expect("sqlite migrations");
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl OpenMlsProvider for SqliteProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ---------------------------------------------------------------------------
// Members and observer
// ---------------------------------------------------------------------------

struct Member<P: OpenMlsProvider> {
    provider: P,
    signer: SignatureKeyPair,
    group: MlsGroup,
}

impl<P: OpenMlsProvider> Member<P> {
    fn context(&self) -> &GroupContext {
        self.group.public_group().group_context()
    }

    fn index(&self) -> LeafNodeIndex {
        self.group.own_leaf_index()
    }
}

/// A member that has not joined yet: it owns a provider, a signer and a KeyPackage.
struct Candidate<P: OpenMlsProvider> {
    provider: P,
    signer: SignatureKeyPair,
    key_package: KeyPackage,
}

/// A sequencer-style observer built from exported GroupInfo and ratchet tree.
struct Observer {
    crypto: RustCrypto,
    storage: MemoryStorage,
    group: PublicGroup,
}

impl Observer {
    fn from_member<P: OpenMlsProvider>(member: &Member<P>) -> Self {
        let group_info = member
            .group
            .export_group_info(member.provider.crypto(), &member.signer, false)
            .expect("export group info");
        let verifiable = match MlsMessageIn::tls_deserialize_exact(wire(&group_info))
            .expect("group info decodes")
            .extract()
        {
            MlsMessageBodyIn::GroupInfo(group_info) => group_info,
            _ => panic!("exported message is not a GroupInfo"),
        };
        let ratchet_tree = member.group.export_ratchet_tree();
        let crypto = RustCrypto::default();
        let storage = MemoryStorage::default();
        let (group, _) = PublicGroup::from_external(
            &crypto,
            &storage,
            ratchet_tree.into(),
            verifiable,
            ProposalStore::new(),
        )
        .expect("PublicGroup::from_external");
        Self {
            crypto,
            storage,
            group,
        }
    }

    fn stage(&self, bytes: &[u8]) -> StagedCommit {
        let processed = self
            .group
            .process_message(&self.crypto, protocol_message(bytes))
            .expect("observer processes commit");
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
            _ => panic!("observer did not stage a commit"),
        }
    }

    fn merge(&mut self, staged: StagedCommit) {
        self.group
            .merge_commit(&self.storage, staged)
            .expect("observer merges commit");
    }

    fn context(&self) -> &GroupContext {
        self.group.group_context()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic Ed25519 test key derived from a fixed label and the member name.
fn test_signer(name: &str) -> SignatureKeyPair {
    let seed: [u8; 32] =
        Sha256::digest(format!("agent-trust/adapter-compat/test-seed/{name}")).into();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        seed.to_vec(),
        signing_key.verifying_key().to_bytes().to_vec(),
    )
}

fn credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

/// Leaf capabilities declaring the adapter's unknown extension types.
fn acc_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![
            ExtensionType::Unknown(ACC_CONTEXT),
            ExtensionType::Unknown(AUTHZ_INCARNATION),
        ])
        .build()
}

fn required_capabilities(types: &[u16]) -> Extension {
    let types: Vec<ExtensionType> = types.iter().map(|t| ExtensionType::Unknown(*t)).collect();
    Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&types, &[], &[]))
}

fn unknown(extension_type: u16, bytes: &[u8]) -> Extension {
    Extension::Unknown(extension_type, UnknownExtension(bytes.to_vec()))
}

fn join_config(policy: WireFormatPolicy) -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(policy)
        .use_ratchet_tree_extension(true)
        .build()
}

fn found_group<P: OpenMlsProvider>(
    provider: P,
    name: &str,
    policy: WireFormatPolicy,
    capabilities: Capabilities,
    group_context_extensions: Vec<Extension>,
) -> Member<P> {
    let signer = test_signer(name);
    signer.store(provider.storage()).expect("store signer");
    let group = MlsGroup::builder()
        .ciphersuite(CIPHERSUITE)
        .with_group_id(GroupId::from_slice(b"agent-trust-adapter-compat"))
        .with_wire_format_policy(policy)
        .use_ratchet_tree_extension(true)
        .with_capabilities(capabilities)
        .with_group_context_extensions(
            Extensions::from_vec(group_context_extensions).expect("valid GC extensions"),
        )
        .build(&provider, &signer, credential(name, &signer))
        .expect("create group");
    Member {
        provider,
        signer,
        group,
    }
}

fn plain_group(name: &str) -> Member<OpenMlsRustCrypto> {
    found_group(
        OpenMlsRustCrypto::default(),
        name,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        Capabilities::default(),
        vec![],
    )
}

fn candidate<P: OpenMlsProvider>(
    provider: P,
    name: &str,
    capabilities: Capabilities,
    leaf_extensions: Option<Extensions<LeafNode>>,
) -> Candidate<P> {
    let signer = test_signer(name);
    signer.store(provider.storage()).expect("store signer");
    let mut builder = KeyPackage::builder().leaf_node_capabilities(capabilities);
    if let Some(extensions) = leaf_extensions {
        builder = builder.leaf_node_extensions(extensions);
    }
    let bundle = builder
        .build(CIPHERSUITE, &provider, &signer, credential(name, &signer))
        .expect("build key package");
    Candidate {
        provider,
        signer,
        key_package: bundle.key_package().clone(),
    }
}

fn plain_candidate(name: &str) -> Candidate<OpenMlsRustCrypto> {
    candidate(
        OpenMlsRustCrypto::default(),
        name,
        Capabilities::default(),
        None,
    )
}

fn wire(message: &MlsMessageOut) -> Vec<u8> {
    message.tls_serialize_detached().expect("serialize message")
}

fn protocol_message(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("decode MLS message")
        .try_into_protocol_message()
        .expect("protocol message")
}

fn wire_format(bytes: &[u8]) -> WireFormat {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("decode MLS message")
        .wire_format()
}

/// Stages a commit (forced path) adding `key_packages`; does not merge.
fn stage_add<P: OpenMlsProvider>(
    committer: &mut Member<P>,
    key_packages: Vec<KeyPackage>,
) -> (Vec<u8>, Welcome) {
    let bundle = committer
        .group
        .commit_builder()
        .propose_adds(key_packages)
        .force_self_update(true)
        .load_psks(committer.provider.storage())
        .expect("load psks")
        .build(
            committer.provider.rand(),
            committer.provider.crypto(),
            &committer.signer,
            |_| true,
        )
        .expect("build add commit")
        .stage_commit(&committer.provider)
        .expect("stage add commit");
    let welcome = bundle.welcome().expect("add commit has welcome").clone();
    (wire(bundle.commit()), welcome)
}

fn join<P: OpenMlsProvider>(
    candidate: Candidate<P>,
    welcome: Welcome,
    policy: WireFormatPolicy,
) -> Member<P> {
    let group =
        StagedWelcome::new_from_welcome(&candidate.provider, &join_config(policy), welcome, None)
            .expect("stage welcome")
            .into_group(&candidate.provider)
            .expect("join from welcome");
    Member {
        provider: candidate.provider,
        signer: candidate.signer,
        group,
    }
}

/// Processes and merges a commit at a receiving member.
fn receive_commit<P: OpenMlsProvider>(member: &mut Member<P>, bytes: &[u8]) {
    let processed = member
        .group
        .process_message(&member.provider, protocol_message(bytes))
        .expect("member processes commit");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => member
            .group
            .merge_staged_commit(&member.provider, *staged)
            .expect("member merges commit"),
        _ => panic!("member did not stage a commit"),
    }
}

fn merge_own<P: OpenMlsProvider>(member: &mut Member<P>) {
    member
        .group
        .merge_pending_commit(&member.provider)
        .expect("merge pending commit");
}

/// Adds a candidate, merges at the committer and at `others`, and joins the candidate.
fn admit<P: OpenMlsProvider, Q: OpenMlsProvider>(
    committer: &mut Member<P>,
    others: &mut [&mut Member<OpenMlsRustCrypto>],
    candidate: Candidate<Q>,
    policy: WireFormatPolicy,
) -> Member<Q> {
    let (commit, welcome) = stage_add(committer, vec![candidate.key_package.clone()]);
    merge_own(committer);
    for other in others.iter_mut() {
        receive_commit(other, &commit);
    }
    join(candidate, welcome, policy)
}

fn send<P: OpenMlsProvider>(member: &mut Member<P>, payload: &[u8]) -> Vec<u8> {
    let message = member
        .group
        .create_message(&member.provider, &member.signer, payload)
        .expect("create application message");
    wire(&message)
}

fn receive<P: OpenMlsProvider>(member: &mut Member<P>, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|e| format!("{e:?}"))?
        .try_into_protocol_message()
        .map_err(|e| format!("{e:?}"))?;
    let processed = member
        .group
        .process_message(&member.provider, message)
        .map_err(|e| format!("{e:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
        _ => Err("not an application message".into()),
    }
}

fn leaf_index_of<P: OpenMlsProvider>(
    member: &Member<P>,
    signer: &SignatureKeyPair,
) -> LeafNodeIndex {
    member
        .group
        .members()
        .find(|m| m.signature_key == signer.to_public_vec())
        .map(|m| m.index)
        .expect("member is in the tree")
}

fn assert_frontier_eq(actual: &GroupContext, expected: &GroupContext, who: &str) {
    assert_eq!(actual.epoch(), expected.epoch(), "epoch for {who}");
    assert_eq!(
        actual.tree_hash(),
        expected.tree_hash(),
        "tree hash for {who}"
    );
    assert_eq!(
        actual.confirmed_transcript_hash(),
        expected.confirmed_transcript_hash(),
        "confirmed transcript hash for {who}"
    );
    assert_eq!(actual, expected, "full group context for {who}");
}

fn assert_unsupported_extensions<E: std::fmt::Debug>(
    error: Option<AddMembersError<E>>,
    case: &str,
) {
    assert!(
        matches!(
            error,
            Some(AddMembersError::CreateCommitError(
                CreateCommitError::ProposalValidationError(
                    ProposalValidationError::LeafNodeValidation(
                        LeafNodeValidationError::UnsupportedExtensions
                    )
                )
            ))
        ),
        "{case} must be rejected for unsupported required extensions, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn public_group_from_external_tracks_member_frontier() {
    // Catches a sequencer that cannot be bootstrapped from GroupInfo + tree, or
    // that derives a frontier different from the members' GroupContext.
    let mut alice = plain_group("alice");
    let mut bob_member = admit(
        &mut alice,
        &mut [],
        plain_candidate("bob"),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    assert_eq!(alice.group.members().count(), 2);
    assert_eq!(alice.group.epoch().as_u64(), 1);

    let observer = Observer::from_member(&alice);

    assert_frontier_eq(observer.context(), alice.context(), "observer vs alice");
    assert_frontier_eq(observer.context(), bob_member.context(), "observer vs bob");
    assert_eq!(observer.group.members().count(), 2);
    assert!(!observer.context().tree_hash().is_empty());
    assert!(!observer.context().confirmed_transcript_hash().is_empty());

    // An observer built later, from bob, tracks the advanced frontier as well.
    let (commit, _) = stage_add(&mut bob_member, vec![plain_candidate("carol").key_package]);
    merge_own(&mut bob_member);
    receive_commit(&mut alice, &commit);
    let later = Observer::from_member(&bob_member);
    assert_eq!(later.context().epoch().as_u64(), 2);
    assert_frontier_eq(later.context(), alice.context(), "later observer vs alice");
    assert_ne!(
        later.context().tree_hash(),
        observer.context().tree_hash(),
        "adding a member must change the tree hash"
    );
}

#[test]
fn staged_commit_group_context_equals_merged_member_context() {
    // Catches a successor frontier computed before merge that differs from the
    // state members actually reach, or an observer merge that diverges.
    let mut alice = plain_group("alice");
    let mut bob = admit(
        &mut alice,
        &mut [],
        plain_candidate("bob"),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    let mut observer = Observer::from_member(&alice);
    let parent = observer.context().clone();

    let carol_candidate = plain_candidate("carol");
    let (commit, welcome) = stage_add(&mut alice, vec![carol_candidate.key_package.clone()]);

    let staged = observer.stage(&commit);
    let successor = staged.group_context().clone();
    assert_eq!(successor.epoch().as_u64(), parent.epoch().as_u64() + 1);
    assert_ne!(successor.tree_hash(), parent.tree_hash());
    assert_ne!(
        successor.confirmed_transcript_hash(),
        parent.confirmed_transcript_hash()
    );
    // Not merged yet: the observer still reports the parent frontier.
    assert_frontier_eq(observer.context(), &parent, "observer before merge");

    merge_own(&mut alice);
    receive_commit(&mut bob, &commit);
    let carol = join(carol_candidate, welcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY);

    assert_frontier_eq(alice.context(), &successor, "committer alice");
    assert_frontier_eq(bob.context(), &successor, "receiver bob");
    assert_frontier_eq(carol.context(), &successor, "joiner carol");

    observer.merge(staged);
    assert_frontier_eq(observer.context(), &successor, "observer after merge");
    assert_frontier_eq(observer.context(), alice.context(), "observer vs alice");
}

#[test]
fn plaintext_handshake_is_processable_by_public_group() {
    // Catches a wire format policy that still encrypts handshakes, which would
    // make the sequencer blind to Add and Remove commits.
    let mut alice = plain_group("alice");
    let mut observer = Observer::from_member(&alice);

    // Add commit.
    let bob_candidate = plain_candidate("bob");
    let bob_key = bob_candidate.signer.to_public_vec();
    let (add_commit, welcome) = stage_add(&mut alice, vec![bob_candidate.key_package.clone()]);
    assert_eq!(wire_format(&add_commit), WireFormat::PublicMessage);
    let staged_add = observer.stage(&add_commit);
    let adds: Vec<_> = staged_add.add_proposals().collect();
    assert_eq!(adds.len(), 1, "observer sees exactly one Add");
    assert_eq!(
        adds[0]
            .add_proposal()
            .key_package()
            .leaf_node()
            .signature_key()
            .as_slice(),
        bob_key.as_slice()
    );
    observer.merge(staged_add);
    merge_own(&mut alice);
    let mut bob = join(bob_candidate, welcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY);
    let carol_candidate = plain_candidate("carol");
    let (carol_commit, carol_welcome) =
        stage_add(&mut alice, vec![carol_candidate.key_package.clone()]);
    let staged_carol = observer.stage(&carol_commit);
    observer.merge(staged_carol);
    merge_own(&mut alice);
    receive_commit(&mut bob, &carol_commit);
    let mut carol = join(
        carol_candidate,
        carol_welcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    assert_frontier_eq(observer.context(), alice.context(), "after adds");

    // Remove commit.
    let bob_index = bob.index();
    let (remove_commit, _, _) = alice
        .group
        .remove_members(&alice.provider, &alice.signer, &[bob_index])
        .expect("remove bob");
    let remove_commit = wire(&remove_commit);
    assert_eq!(wire_format(&remove_commit), WireFormat::PublicMessage);
    let staged_remove = observer.stage(&remove_commit);
    let removed: Vec<_> = staged_remove
        .remove_proposals()
        .map(|p| p.remove_proposal().removed())
        .collect();
    assert_eq!(removed, vec![bob_index], "observer sees the Remove of bob");
    observer.merge(staged_remove);
    merge_own(&mut alice);
    receive_commit(&mut carol, &remove_commit);

    assert_frontier_eq(observer.context(), alice.context(), "observer after remove");
    assert_frontier_eq(carol.context(), alice.context(), "carol after remove");
    assert_eq!(observer.group.members().count(), 2);
}

#[test]
fn application_messages_stay_private_under_pure_plaintext_policy() {
    // Catches a plaintext handshake policy that also downgrades application
    // data, which would expose payloads to the sequencer.
    let mut alice = plain_group("alice");
    let mut bob = admit(
        &mut alice,
        &mut [],
        plain_candidate("bob"),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    let observer = Observer::from_member(&alice);

    let payload = b"confidential payload 9f3c";
    let message = alice
        .group
        .create_message(&alice.provider, &alice.signer, payload)
        .expect("create message");
    assert!(
        matches!(message.body(), MlsMessageBodyOut::PrivateMessage(_)),
        "application message body must be a PrivateMessage"
    );
    let bytes = wire(&message);
    assert_eq!(wire_format(&bytes), WireFormat::PrivateMessage);
    assert!(
        !bytes.windows(payload.len()).any(|w| w == payload),
        "plaintext must not appear in the wire bytes"
    );

    let result = observer
        .group
        .process_message(&observer.crypto, protocol_message(&bytes));
    assert!(
        matches!(
            result,
            Err(PublicProcessMessageError::IncompatibleWireFormat)
        ),
        "observer must not process a PrivateMessage, got {result:?}"
    );

    // Positive control: a member decrypts it.
    assert_eq!(receive(&mut bob, &bytes).expect("bob decrypts"), payload);
}

#[test]
fn leaf_node_extensions_survive_key_package_into_ratchet_tree() {
    // Catches loss or rewriting of the authz_incarnation leaf extension between
    // the KeyPackage and the ratchet tree seen by members and the sequencer.
    let mut alice = found_group(
        OpenMlsRustCrypto::default(),
        "alice",
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        acc_capabilities(),
        vec![],
    );
    let mut observer = Observer::from_member(&alice);

    let incarnation = b"\x01\x00\x03bob\x00\x00\x00\x00\x00\x00\x00\x07incarnation-bytes".to_vec();
    let bob_candidate = candidate(
        OpenMlsRustCrypto::default(),
        "bob",
        acc_capabilities(),
        Some(
            Extensions::single(unknown(AUTHZ_INCARNATION, &incarnation))
                .expect("leaf extension valid"),
        ),
    );
    let kp_leaf = bob_candidate.key_package.leaf_node().clone();
    assert_eq!(
        kp_leaf.extensions().unknown(AUTHZ_INCARNATION),
        Some(&UnknownExtension(incarnation.clone())),
        "KeyPackage leaf carries the extension"
    );
    let bob_signer_public = bob_candidate.signer.to_public_vec();

    let (commit, welcome) = stage_add(&mut alice, vec![bob_candidate.key_package.clone()]);
    let staged = observer.stage(&commit);
    observer.merge(staged);
    merge_own(&mut alice);
    let bob = join(bob_candidate, welcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY);

    let bob_index = bob.index();
    assert_eq!(
        leaf_index_of(&alice, &bob.signer),
        bob_index,
        "alice and bob agree on bob's leaf"
    );
    let kp_leaf_bytes = kp_leaf.tls_serialize_detached().expect("serialize leaf");
    for (who, leaf) in [
        ("alice", alice.group.public_group().leaf(bob_index)),
        ("observer", observer.group.leaf(bob_index)),
        ("bob", bob.group.public_group().leaf(bob_index)),
    ] {
        let leaf = leaf.unwrap_or_else(|| panic!("{who} has bob's leaf"));
        assert_eq!(
            leaf.signature_key().as_slice(),
            bob_signer_public.as_slice()
        );
        assert_eq!(
            leaf.extensions().unknown(AUTHZ_INCARNATION),
            Some(&UnknownExtension(incarnation.clone())),
            "{who} sees the authz_incarnation bytes"
        );
        assert_eq!(
            leaf.tls_serialize_detached().expect("serialize leaf"),
            kp_leaf_bytes,
            "{who} sees a byte-identical leaf node"
        );
    }
}

#[test]
fn one_commit_carries_removals_gce_and_forced_path() {
    // Catches an inability to express the repair commit (Remove + new
    // acc_context + UpdatePath) as one commit visible to the sequencer.
    let acc_v0 = b"acc_context policy_revision=0".to_vec();
    let acc_v1 = b"acc_context policy_revision=1".to_vec();
    let mut alice = found_group(
        OpenMlsRustCrypto::default(),
        "alice",
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        acc_capabilities(),
        vec![
            required_capabilities(&[ACC_CONTEXT]),
            unknown(ACC_CONTEXT, &acc_v0),
        ],
    );
    let bob = admit(
        &mut alice,
        &mut [],
        candidate(
            OpenMlsRustCrypto::default(),
            "bob",
            acc_capabilities(),
            None,
        ),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    let mut bob = bob;
    let carol_candidate = candidate(
        OpenMlsRustCrypto::default(),
        "carol",
        acc_capabilities(),
        None,
    );
    let (commit, welcome) = stage_add(&mut alice, vec![carol_candidate.key_package.clone()]);
    merge_own(&mut alice);
    receive_commit(&mut bob, &commit);
    let mut carol = join(carol_candidate, welcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY);
    let mut observer = Observer::from_member(&alice);
    assert_eq!(
        observer.context().extensions().unknown(ACC_CONTEXT),
        Some(&UnknownExtension(acc_v0.clone()))
    );

    let bob_index = bob.index();
    let new_extensions = Extensions::from_vec(vec![
        required_capabilities(&[ACC_CONTEXT]),
        unknown(ACC_CONTEXT, &acc_v1),
    ])
    .expect("valid GC extensions");
    let bundle = alice
        .group
        .commit_builder()
        .propose_removals([bob_index])
        .propose_group_context_extensions(new_extensions)
        .expect("propose GCE")
        .force_self_update(true)
        .load_psks(alice.provider.storage())
        .expect("load psks")
        .build(
            alice.provider.rand(),
            alice.provider.crypto(),
            &alice.signer,
            |_| true,
        )
        .expect("build repair commit")
        .stage_commit(&alice.provider)
        .expect("stage repair commit");
    let repair = wire(bundle.commit());
    assert_eq!(wire_format(&repair), WireFormat::PublicMessage);

    let staged = observer.stage(&repair);
    let removed: Vec<_> = staged
        .remove_proposals()
        .map(|p| p.remove_proposal().removed())
        .collect();
    assert_eq!(removed, vec![bob_index], "exactly bob is removed");
    let gce_count = staged
        .queued_proposals()
        .filter(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_)))
        .count();
    assert_eq!(gce_count, 1, "one GroupContextExtensions proposal");
    assert_eq!(staged.queued_proposals().count(), 2, "no other proposals");
    let path_leaf = staged
        .update_path_leaf_node()
        .expect("forced UpdatePath is present");
    assert_eq!(
        path_leaf.signature_key().as_slice(),
        alice.signer.to_public_vec().as_slice(),
        "the path leaf is the committer's"
    );
    let successor = staged.group_context().clone();
    assert_eq!(
        successor.extensions().unknown(ACC_CONTEXT),
        Some(&UnknownExtension(acc_v1.clone())),
        "successor context carries the new acc_context"
    );
    assert_eq!(
        successor
            .extensions()
            .iter()
            .filter(|e| e.extension_type() == ExtensionType::Unknown(ACC_CONTEXT))
            .count(),
        1,
        "exactly one acc_context"
    );

    observer.merge(staged);
    merge_own(&mut alice);
    receive_commit(&mut carol, &repair);
    assert_frontier_eq(observer.context(), &successor, "observer");
    assert_frontier_eq(alice.context(), &successor, "alice");
    assert_frontier_eq(carol.context(), &successor, "carol");
    assert_eq!(observer.group.members().count(), 2);
}

#[test]
fn required_capabilities_reject_key_package_without_acc_extensions() {
    // Catches required_capabilities that are not enforced on Add, which would
    // let a client that ignores acc_context / authz_incarnation join.
    let mut alice = found_group(
        OpenMlsRustCrypto::default(),
        "alice",
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        acc_capabilities(),
        vec![required_capabilities(&[ACC_CONTEXT, AUTHZ_INCARNATION])],
    );
    assert_eq!(
        alice
            .context()
            .required_capabilities()
            .expect("required capabilities set")
            .extension_types(),
        &[
            ExtensionType::Unknown(ACC_CONTEXT),
            ExtensionType::Unknown(AUTHZ_INCARNATION)
        ]
    );

    // Positive path: a KeyPackage that declares both types is accepted.
    let bob = admit(
        &mut alice,
        &mut [],
        candidate(
            OpenMlsRustCrypto::default(),
            "bob",
            acc_capabilities(),
            None,
        ),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    assert_eq!(alice.group.members().count(), 2);
    assert_frontier_eq(bob.context(), alice.context(), "bob joined");
    let epoch = alice.group.epoch();

    // Negative path: a KeyPackage that does not declare them is rejected.
    let mallory = plain_candidate("mallory");
    let result = alice
        .group
        .add_members(&alice.provider, &alice.signer, &[mallory.key_package]);
    assert_unsupported_extensions(result.err(), "KeyPackage declaring neither type");
    let partial = candidate(
        OpenMlsRustCrypto::default(),
        "trent",
        Capabilities::builder()
            .extensions(vec![ExtensionType::Unknown(ACC_CONTEXT)])
            .build(),
        None,
    );
    let result = alice
        .group
        .add_members(&alice.provider, &alice.signer, &[partial.key_package]);
    assert_unsupported_extensions(result.err(), "KeyPackage declaring only 0xf043");
    assert_eq!(alice.group.epoch(), epoch, "rejected adds do not advance");
    assert_eq!(alice.group.members().count(), 2);
}

#[test]
fn sqlite_storage_round_trips_mls_group_load() {
    // Catches SQLite persistence that does not restore a usable MlsGroup, and
    // retained storage copies that keep access after the member's removal.
    let dir = tempfile::tempdir().expect("temp dir");
    let bob_path = dir.path().join("bob.sqlite");
    let copy_path = dir.path().join("bob-retained.sqlite");

    let mut alice = plain_group("alice");
    let bob_candidate = candidate(
        SqliteProvider::open(&bob_path),
        "bob",
        Capabilities::default(),
        None,
    );
    let bob = admit(
        &mut alice,
        &mut [],
        bob_candidate,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    let mut bob = bob;
    let carol_candidate = plain_candidate("carol");
    let (commit, welcome) = stage_add(&mut alice, vec![carol_candidate.key_package.clone()]);
    merge_own(&mut alice);
    receive_commit(&mut bob, &commit);
    let mut carol = join(carol_candidate, welcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY);

    let group_id = bob.group.group_id().clone();
    let epoch = bob.group.epoch();
    let bob_public = bob.signer.to_public_vec();
    assert_eq!(epoch.as_u64(), 2);

    // Close bob's storage, take a byte copy, then reopen the original file.
    drop(bob);
    std::fs::copy(&bob_path, &copy_path).expect("copy sqlite file");

    let reopened = SqliteProvider::open(&bob_path);
    let group = MlsGroup::load(reopened.storage(), &group_id)
        .expect("load from sqlite")
        .expect("group present in sqlite");
    let signer = SignatureKeyPair::read(reopened.storage(), &bob_public, SignatureScheme::ED25519)
        .expect("signer present in sqlite");
    let mut bob = Member {
        provider: reopened,
        signer,
        group,
    };
    assert_eq!(bob.group.epoch(), epoch, "reloaded epoch");
    assert_frontier_eq(bob.context(), alice.context(), "reloaded bob");
    assert_eq!(
        bob.group.epoch_authenticator().as_slice(),
        alice.group.epoch_authenticator().as_slice()
    );

    let before = b"message before removal";
    let before_wire = send(&mut alice, before);
    assert_eq!(
        receive(&mut bob, &before_wire).expect("reloaded bob decrypts"),
        before
    );

    // Retained copy: positive control on pre-removal traffic.
    let copy_provider = SqliteProvider::open(&copy_path);
    let copy_group = MlsGroup::load(copy_provider.storage(), &group_id)
        .expect("load copy")
        .expect("group present in copy");
    let copy_signer = test_signer("bob");
    let mut copy = Member {
        provider: copy_provider,
        signer: copy_signer,
        group: copy_group,
    };
    assert_eq!(copy.group.epoch(), epoch);
    assert_eq!(
        receive(&mut copy, &before_wire).expect("copy decrypts pre-removal message"),
        before
    );

    // Remove bob; successor traffic must be unreadable by the copy.
    let bob_index = bob.index();
    let (remove_commit, _, _) = alice
        .group
        .remove_members(&alice.provider, &alice.signer, &[bob_index])
        .expect("remove bob");
    let remove_commit = wire(&remove_commit);
    merge_own(&mut alice);
    receive_commit(&mut carol, &remove_commit);

    let after = b"message after removal";
    let after_wire = send(&mut alice, after);
    assert_eq!(
        receive(&mut carol, &after_wire).expect("carol decrypts"),
        after
    );
    let copy_result = receive(&mut copy, &after_wire);
    assert!(
        copy_result.is_err(),
        "retained pre-removal copy must not decrypt successor traffic"
    );
    assert!(
        receive(&mut bob, &after_wire).is_err(),
        "removed bob must not decrypt successor traffic"
    );
}

#[test]
fn epoch_authenticator_matches_across_members() {
    // Catches an epoch authenticator that is not shared group state or that
    // does not change across epochs (repair confirmation relies on both).
    let mut alice = plain_group("alice");
    let mut bob = admit(
        &mut alice,
        &mut [],
        plain_candidate("bob"),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    let carol = admit(
        &mut alice,
        &mut [&mut bob],
        plain_candidate("carol"),
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    let mut carol = carol;

    let previous = alice.group.epoch_authenticator().as_slice().to_vec();
    assert!(!previous.is_empty());
    assert_eq!(bob.group.epoch_authenticator().as_slice(), previous);
    assert_eq!(carol.group.epoch_authenticator().as_slice(), previous);

    let bundle = bob
        .group
        .commit_builder()
        .force_self_update(true)
        .load_psks(bob.provider.storage())
        .expect("load psks")
        .build(
            bob.provider.rand(),
            bob.provider.crypto(),
            &bob.signer,
            |_| true,
        )
        .expect("build update commit")
        .stage_commit(&bob.provider)
        .expect("stage update commit");
    let commit = wire(bundle.commit());
    merge_own(&mut bob);
    receive_commit(&mut alice, &commit);
    receive_commit(&mut carol, &commit);

    let current = alice.group.epoch_authenticator().as_slice().to_vec();
    assert_eq!(bob.group.epoch_authenticator().as_slice(), current);
    assert_eq!(carol.group.epoch_authenticator().as_slice(), current);
    assert_ne!(
        current, previous,
        "a commit must change the epoch authenticator"
    );
}

#[test]
fn signature_key_pair_from_raw_signs_and_verifies() {
    // Catches a from_raw key that the OpenMLS Signer or RustCrypto verifier
    // interpret differently from Ed25519 over the given seed.
    use ed25519_dalek::Signer as DalekSigner;

    let seed = [0x42u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key().to_bytes();
    let key_pair =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    assert_eq!(key_pair.to_public_vec(), public.to_vec());
    assert_eq!(
        Signer::signature_scheme(&key_pair),
        SignatureScheme::ED25519
    );

    let payload = b"agent-trust/adapter-compat/signing-check";
    let signature = Signer::sign(&key_pair, payload).expect("sign through OpenMLS Signer");
    assert_eq!(
        signature,
        signing_key.sign(payload).to_bytes().to_vec(),
        "Ed25519 is deterministic: same seed, same signature"
    );
    let crypto = RustCrypto::default();
    crypto
        .verify_signature(SignatureScheme::ED25519, payload, &public, &signature)
        .expect("RustCrypto verifies");
    assert!(
        crypto
            .verify_signature(SignatureScheme::ED25519, b"tampered", &public, &signature)
            .is_err(),
        "a signature over different data must not verify"
    );

    // Group creation and admission with from_raw keys.
    let alice_provider = OpenMlsRustCrypto::default();
    key_pair
        .store(alice_provider.storage())
        .expect("store signer");
    let mut alice = Member {
        group: MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build(&alice_provider, &key_pair, credential("alice", &key_pair))
            .expect("create group with from_raw key"),
        provider: alice_provider,
        signer: key_pair,
    };
    let bob_candidate = plain_candidate("bob");
    let bob_public = bob_candidate.signer.to_public_vec();
    let mut bob = admit(
        &mut alice,
        &mut [],
        bob_candidate,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    );
    assert_eq!(alice.group.members().count(), 2);
    let alice_leaf = alice
        .group
        .public_group()
        .leaf(alice.index())
        .expect("alice leaf");
    assert_eq!(alice_leaf.signature_key().as_slice(), public.as_slice());
    assert_eq!(leaf_index_of(&alice, &bob.signer), bob.index());
    assert_eq!(bob.signer.to_public_vec(), bob_public);

    let wire_bytes = send(&mut alice, b"from raw key");
    assert_eq!(
        receive(&mut bob, &wire_bytes).expect("bob decrypts"),
        b"from raw key"
    );
}
