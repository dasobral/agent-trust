//! A small in-memory MLS laboratory backed by OpenMLS.
//!
//! Each endpoint owns a real MLS group and an independent crypto provider.  The
//! `roster` is the set of endpoints allowed to originate application traffic;
//! stale copies are retained only for adversarial decryption experiments.

use std::{collections::BTreeMap, sync::RwLock};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto, RustCrypto};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{Ciphersuite, SignatureScheme},
    OpenMlsProvider,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const GROUP_ID: &[u8] = b"agent-trust-mls-lab";
const APF_BINDING_EXTENSION_TYPE: u16 = 0xf042;
const APF_CERTIFICATE_MAGIC: &[u8] = b"AT-APF-KP";
const APF_CERTIFICATE_VERSION: u8 = 1;

/// The stock provider uses a private `MemoryStorage` field and only enables its
/// `Clone` implementation under OpenMLS test features.  This wrapper keeps the
/// stock RustCrypto implementation while making each endpoint's storage
/// explicit, so a snapshot can take an exact copy without enabling test-only
/// OpenMLS features.
#[derive(Debug, Default)]
struct LabProvider {
    crypto: OpenMlsRustCrypto,
    storage: MemoryStorage,
}

impl LabProvider {
    fn snapshot(&self) -> Self {
        let values = self
            .storage
            .values
            .read()
            .expect("memory storage lock")
            .clone();
        Self {
            crypto: OpenMlsRustCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(values),
            },
        }
    }
}

impl OpenMlsProvider for LabProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto.crypto()
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto.rand()
    }
}

struct Endpoint {
    provider: LabProvider,
    group: MlsGroup,
    signer: Option<SignatureKeyPair>,
    admission_key_package: Option<Vec<u8>>,
    prepared_canonical: Option<Vec<u8>>,
}

struct PendingMember {
    provider: LabProvider,
    signer: SignatureKeyPair,
    key_package: KeyPackageBundle,
    key_package_wire: Vec<u8>,
    prepared_canonical: Vec<u8>,
}

impl PendingMember {
    fn new(name: &str, generation: u64, apf_signer: &SignatureKeyPair) -> Result<Self, String> {
        let provider = LabProvider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(error)?;
        signer.store(provider.storage()).map_err(error)?;
        let capabilities = Capabilities::builder()
            .extensions(vec![ExtensionType::Unknown(APF_BINDING_EXTENSION_TYPE)])
            .build();
        let prepared = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .prepare(
                CIPHERSUITE,
                &provider,
                &signer,
                credential(name, &signer),
                APF_BINDING_EXTENSION_TYPE,
            )
            .map_err(error)?;
        let prepared_canonical = prepared.canonical_binding_bytes().to_vec();
        let certificate = issue_admission_certificate(
            GROUP_ID,
            name,
            generation,
            &prepared_canonical,
            apf_signer,
        )?;
        let key_package = prepared
            .with_external_binding(certificate)
            .map_err(error)?
            .finalize(&provider, &signer)
            .map_err(error)?;
        let key_package_wire = key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(error)?;
        Ok(Self {
            provider,
            signer,
            key_package,
            key_package_wire,
            prepared_canonical,
        })
    }
}

impl Endpoint {
    fn process_commit(&mut self, wire: &[u8]) -> Result<(), String> {
        let message = protocol_message(wire)?;
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(error)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => self
                .group
                .merge_staged_commit(&self.provider, *commit)
                .map_err(error),
            _ => Err("MLS commit did not stage".into()),
        }
    }
}

/// A real OpenMLS group endpoint laboratory.
pub struct MlsLab {
    roster: BTreeMap<String, Endpoint>,
    stale: BTreeMap<String, Endpoint>,
    apf_signer: SignatureKeyPair,
}

/// Evidence returned after independently validating an embedded admission binding.
#[derive(Debug)]
pub struct AdmissionBindingEvidence {
    pub subject: String,
    pub generation: u64,
    pub prepared_canonical: Vec<u8>,
    pub recomputed_canonical: Vec<u8>,
    pub certificate_preimage_hash: Vec<u8>,
    pub final_key_package: Vec<u8>,
}

impl MlsLab {
    /// Verifies retained admission evidence against an expected APF incarnation.
    pub fn verify_member_admission_for(
        &self,
        name: &str,
        expected_subject: &str,
        expected_generation: u64,
    ) -> Result<AdmissionBindingEvidence, String> {
        let endpoint = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        let final_key_package = endpoint
            .admission_key_package
            .as_ref()
            .ok_or_else(|| "member has no staged admission evidence".to_owned())?;
        let prepared_canonical = endpoint
            .prepared_canonical
            .as_ref()
            .ok_or_else(|| "member has no prepared canonical bytes".to_owned())?;
        let verified = verify_admission_key_package(
            &endpoint.provider,
            final_key_package,
            expected_subject,
            expected_generation,
            &self.apf_signer.to_public_vec(),
        )?;
        if verified.recomputed_canonical != *prepared_canonical {
            return Err("prepared and recomputed KeyPackage bytes differ".into());
        }
        Ok(AdmissionBindingEvidence {
            subject: verified.subject,
            generation: verified.generation,
            prepared_canonical: prepared_canonical.clone(),
            recomputed_canonical: verified.recomputed_canonical,
            certificate_preimage_hash: verified.preimage_hash,
            final_key_package: final_key_package.clone(),
        })
    }

    /// Verifies the staged KeyPackage admission evidence retained for a member.
    pub fn verify_member_admission(&self, name: &str) -> Result<AdmissionBindingEvidence, String> {
        self.verify_member_admission_for(name, name, 0)
    }

    /// Creates the group with Alice as its founding member.
    pub fn new() -> Result<Self, String> {
        let provider = LabProvider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(error)?;
        let apf_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(error)?;
        signer.store(provider.storage()).map_err(error)?;
        let group = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(GROUP_ID))
            .use_ratchet_tree_extension(true)
            .build(&provider, &signer, credential("alice", &signer))
            .map_err(error)?;
        Ok(Self {
            roster: BTreeMap::from([(
                "alice".to_owned(),
                Endpoint {
                    provider,
                    group,
                    signer: Some(signer),
                    admission_key_package: None,
                    prepared_canonical: None,
                },
            )]),
            stale: BTreeMap::new(),
            apf_signer,
        })
    }

    /// Adds a member using a KeyPackage and makes every continuing member merge
    /// the authenticated commit; the new member joins from its Welcome.
    pub fn add_member(&mut self, name: &str) -> Result<(), String> {
        ensure_name(name)?;
        if self.roster.contains_key(name) || self.stale.contains_key(name) {
            return Err("member name already used".into());
        }
        let joiner = PendingMember::new(name, 0, &self.apf_signer)?;
        let verified = verify_admission_key_package(
            &joiner.provider,
            &joiner.key_package_wire,
            name,
            0,
            &self.apf_signer.to_public_vec(),
        )?;
        if verified.recomputed_canonical != joiner.prepared_canonical {
            return Err("prepared and recomputed KeyPackage bytes differ".into());
        }
        let key_package = joiner.key_package.key_package().clone();
        let (commit_wire, welcome, committer_index) = {
            let committer = self
                .roster
                .get_mut("alice")
                .ok_or_else(|| "alice endpoint unavailable".to_owned())?;
            let signer = committer
                .signer
                .as_ref()
                .ok_or_else(|| "committer has no signing key".to_owned())?;
            let (commit, welcome, _) = committer
                .group
                .add_members(&committer.provider, signer, &[key_package])
                .map_err(error)?;
            let commit_wire = commit.tls_serialize_detached().map_err(error)?;
            let committer_index = committer.group.own_leaf_index();
            committer
                .group
                .merge_pending_commit(&committer.provider)
                .map_err(error)?;
            (commit_wire, welcome, committer_index)
        };

        for endpoint in self
            .roster
            .values_mut()
            .filter(|endpoint| endpoint.group.own_leaf_index() != committer_index)
        {
            endpoint.process_commit(&commit_wire)?;
        }

        let welcome = welcome_from_out(welcome)?;
        let staged = StagedWelcome::new_from_welcome(
            &joiner.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )
        .map_err(error)?;
        let group = staged.into_group(&joiner.provider).map_err(error)?;
        self.roster.insert(
            name.to_owned(),
            Endpoint {
                provider: joiner.provider,
                group,
                signer: Some(joiner.signer),
                admission_key_package: Some(joiner.key_package_wire),
                prepared_canonical: Some(joiner.prepared_canonical),
            },
        );
        Ok(())
    }

    /// Encrypts an application message with authenticated data using a current
    /// MLS member's sender ratchet.
    pub fn protect(&mut self, sender: &str, payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let endpoint = self
            .roster
            .get_mut(sender)
            .ok_or_else(|| "sender is not a current member".to_owned())?;
        let signer = endpoint
            .signer
            .as_ref()
            .ok_or_else(|| "sender has no signing key".to_owned())?;
        endpoint.group.set_aad(aad.to_vec());
        endpoint
            .group
            .create_message(&endpoint.provider, signer, payload)
            .map_err(error)?
            .tls_serialize_detached()
            .map_err(error)
    }

    /// Processes an MLS wire message with the requested endpoint's retained
    /// state.  Stale endpoints deliberately take this same real MLS path.
    pub fn decrypt(&mut self, recipient: &str, wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let endpoint = self
            .roster
            .get_mut(recipient)
            .or_else(|| self.stale.get_mut(recipient))
            .ok_or_else(|| "unknown recipient".to_owned())?;
        let message = protocol_message(wire)?;
        let processed = endpoint
            .group
            .process_message(&endpoint.provider, message)
            .map_err(error)?;
        let aad = processed.aad().to_vec();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok((message.into_bytes(), aad)),
            _ => Err("MLS message was not application data".into()),
        }
    }

    /// Removes a current member with a real MLS Remove commit.  Every continuing
    /// endpoint processes and merges the resulting confirmed commit.  The
    /// removed endpoint is retained as stale state only for decryption attacks.
    pub fn remove_member(&mut self, name: &str) -> Result<(), String> {
        if !self.roster.contains_key(name) {
            return Err("member is not current".into());
        }
        if self.roster.len() < 2 {
            return Err("cannot remove the only member".into());
        }
        let committer_name = self
            .roster
            .keys()
            .find(|candidate| candidate.as_str() != name)
            .cloned()
            .ok_or_else(|| "no continuing committer".to_owned())?;
        let removed_index = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?
            .group
            .own_leaf_index();

        let (commit_wire, committer_index) = {
            let committer = self
                .roster
                .get_mut(&committer_name)
                .expect("selected committer");
            let signer = committer
                .signer
                .as_ref()
                .ok_or_else(|| "committer has no signing key".to_owned())?;
            let (commit, _, _) = committer
                .group
                .remove_members(&committer.provider, signer, &[removed_index])
                .map_err(error)?;
            let commit_wire = commit.tls_serialize_detached().map_err(error)?;
            let committer_index = committer.group.own_leaf_index();
            committer
                .group
                .merge_pending_commit(&committer.provider)
                .map_err(error)?;
            (commit_wire, committer_index)
        };

        for (member, endpoint) in &mut self.roster {
            if member != name && endpoint.group.own_leaf_index() != committer_index {
                endpoint.process_commit(&commit_wire)?;
            }
        }

        let removed = self.roster.remove(name).expect("checked current member");
        self.stale.insert(name.to_owned(), removed);
        Ok(())
    }

    /// Copies a member's stored group state and secret storage to a distinct
    /// stale endpoint.  This is intentionally outside the active roster.
    pub fn snapshot_member(&mut self, name: &str, snapshot_name: &str) -> Result<(), String> {
        ensure_name(snapshot_name)?;
        if self.roster.contains_key(snapshot_name) || self.stale.contains_key(snapshot_name) {
            return Err("snapshot name already used".into());
        }
        let original = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        let provider = original.provider.snapshot();
        let group_id = original.group.group_id().clone();
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(error)?
            .ok_or_else(|| "snapshot group missing from copied storage".to_owned())?;
        self.stale.insert(
            snapshot_name.to_owned(),
            Endpoint {
                provider,
                group,
                signer: None,
                admission_key_package: original.admission_key_package.clone(),
                prepared_canonical: original.prepared_canonical.clone(),
            },
        );
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.roster
            .values()
            .next()
            .map(|endpoint| endpoint.group.epoch().as_u64())
            .unwrap_or(0)
    }

    pub fn members(&self) -> Vec<String> {
        self.roster.keys().cloned().collect()
    }
}

struct VerifiedAdmission {
    subject: String,
    generation: u64,
    preimage_hash: Vec<u8>,
    recomputed_canonical: Vec<u8>,
}

fn issue_admission_certificate(
    group: &[u8],
    subject: &str,
    generation: u64,
    canonical: &[u8],
    signer: &impl Signer,
) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(APF_CERTIFICATE_MAGIC);
    payload.push(APF_CERTIFICATE_VERSION);
    append_sized(&mut payload, group)?;
    append_sized(&mut payload, subject.as_bytes())?;
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&Sha256::digest(canonical));
    let signature = signer.sign(&payload).map_err(error)?;
    append_sized(&mut payload, &signature)?;
    Ok(payload)
}

fn verify_admission_key_package(
    provider: &LabProvider,
    wire: &[u8],
    expected_subject: &str,
    expected_generation: u64,
    apf_public_key: &[u8],
) -> Result<VerifiedAdmission, String> {
    let key_package = KeyPackageIn::tls_deserialize_exact(wire)
        .map_err(error)?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(error)?;
    let recomputed_canonical = key_package
        .canonical_binding_bytes(APF_BINDING_EXTENSION_TYPE)
        .map_err(error)?;
    let certificate = key_package
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            Extension::Unknown(extension_type, UnknownExtension(bytes))
                if *extension_type == APF_BINDING_EXTENSION_TYPE =>
            {
                Some(bytes.as_slice())
            }
            _ => None,
        })
        .ok_or_else(|| "APF binding extension missing".to_owned())?;

    let mut input = certificate;
    if take(&mut input, APF_CERTIFICATE_MAGIC.len())? != APF_CERTIFICATE_MAGIC {
        return Err("invalid APF certificate magic".into());
    }
    if take(&mut input, 1)?[0] != APF_CERTIFICATE_VERSION {
        return Err("unsupported APF certificate version".into());
    }
    let group = take_sized(&mut input)?;
    let subject = take_sized(&mut input)?;
    let generation = u64::from_be_bytes(
        take(&mut input, 8)?
            .try_into()
            .map_err(|_| "invalid APF generation".to_owned())?,
    );
    let preimage_hash = take(&mut input, 32)?.to_vec();
    let signed_len = certificate.len() - input.len();
    let signature = take_sized(&mut input)?;
    if !input.is_empty() {
        return Err("trailing APF certificate bytes".into());
    }
    if group != GROUP_ID {
        return Err("APF certificate group mismatch".into());
    }
    if subject != expected_subject.as_bytes() {
        return Err("APF certificate subject mismatch".into());
    }
    if generation != expected_generation {
        return Err("APF certificate generation mismatch".into());
    }
    if preimage_hash != Sha256::digest(&recomputed_canonical).as_slice() {
        return Err("APF certificate KeyPackage binding mismatch".into());
    }
    provider
        .crypto()
        .verify_signature(
            SignatureScheme::ED25519,
            &certificate[..signed_len],
            apf_public_key,
            signature,
        )
        .map_err(|_| "invalid APF certificate signature".to_owned())?;

    Ok(VerifiedAdmission {
        subject: String::from_utf8(subject.to_vec())
            .map_err(|_| "APF certificate subject is not UTF-8".to_owned())?,
        generation,
        preimage_hash,
        recomputed_canonical,
    })
}

fn append_sized(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u16::try_from(value.len()).map_err(|_| "APF certificate field too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn take_sized<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let length = u16::from_be_bytes(
        take(input, 2)?
            .try_into()
            .map_err(|_| "invalid APF certificate length".to_owned())?,
    ) as usize;
    take(input, length)
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], String> {
    if input.len() < length {
        return Err("truncated APF certificate".into());
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn protocol_message(wire: &[u8]) -> Result<ProtocolMessage, String> {
    MlsMessageIn::tls_deserialize_exact(wire)
        .map_err(error)?
        .try_into_protocol_message()
        .map_err(error)
}

fn welcome_from_out(welcome: MlsMessageOut) -> Result<Welcome, String> {
    match MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().map_err(error)?)
        .map_err(error)?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err("MLS add operation did not produce a Welcome".into()),
    }
}

fn ensure_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        Err("member name must not be empty".into())
    } else {
        Ok(())
    }
}

fn error<E: std::fmt::Debug>(error: E) -> String {
    format!("OpenMLS error: {error:?}")
}
