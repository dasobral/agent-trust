//! Client endpoint: one OpenMLS group member with its own keys and storage
//! (`docs/adapter-contract.md` §5.1, §5.2, §5.3, C-12, C-18). Generic over the OpenMLS provider.

use openmls::extensions::ExtensionValidator;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::adapter::ClientIdentity;
use crate::wire::{
    operation_digest, verify_ed25519, AccContext, AckKind, AuthzIncarnation, CanonicalAck,
    ConsumeReceipt, Envelope, FounderCertificate, Frontier, FrozenContent, ReleaseCertificate,
    Right, SignedStructure, ACC_CONTEXT_EXTENSION_TYPE, ADMISSION_EXTENSION_TYPE,
    AUTHZ_INCARNATION_EXTENSION_TYPE,
};

/// The laboratory ciphersuite; its signature scheme is the Ed25519 of every identity.
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// The three adapter extension types every leaf declares and the group requires.
pub(crate) const ADAPTER_EXTENSIONS: [u16; 3] = [
    ADMISSION_EXTENSION_TYPE,
    ACC_CONTEXT_EXTENSION_TYPE,
    AUTHZ_INCARNATION_EXTENSION_TYPE,
];
/// Length of the joiner's zero `admission_cert_hash` placeholder (§4.3).
pub(crate) const ZERO_HASH: [u8; 32] = [0; 32];

/// A current group member.
pub struct ClientEndpoint<P: OpenMlsProvider> {
    provider: P,
    identity: ClientIdentity,
    group: MlsGroup,
    subject: String,
    apf_public_key: Vec<u8>,
    /// Exact bytes of this member's own staged, unmerged commit.
    pending: Option<Vec<u8>>,
}

/// A commit staged by this member and not yet merged.
#[derive(Clone, Debug)]
pub struct StagedAdd {
    /// Exact commit `MlsMessage` bytes to submit.
    pub commit: Vec<u8>,
    /// Welcome `MlsMessage` bytes for the joiner.
    pub welcome: Vec<u8>,
    pub parent: Frontier,
}

/// A candidate that has prepared, but not finalized, its KeyPackage.
pub struct PreparedJoin<P: OpenMlsProvider> {
    provider: P,
    identity: ClientIdentity,
    prepared: PreparedKeyPackage,
    group: String,
    subject: String,
    apf_public_key: Vec<u8>,
}

/// A candidate with a finalized KeyPackage, waiting for a Welcome.
pub struct JoinCandidate<P: OpenMlsProvider> {
    provider: P,
    identity: ClientIdentity,
    key_package: Vec<u8>,
    group: String,
    subject: String,
    apf_public_key: Vec<u8>,
}

impl<P: OpenMlsProvider> ClientEndpoint<P> {
    /// Creates the group as founder (§5.1 step 3): group id = `group`, `acc_context`
    /// payload, required capabilities `0xf042`–`0xf044`, leaf `authz_incarnation`
    /// carrying `SHA-256(founder_certificate)` and the root's `rights`, and the
    /// pure-plaintext handshake wire format.
    #[allow(clippy::too_many_arguments)]
    pub fn found(
        group: &str,
        subject: &str,
        rights: &[(Right, u64)],
        identity: ClientIdentity,
        provider: P,
        founder_certificate: &[u8],
        acc_context: &[u8],
        apf_public_key: &[u8],
    ) -> Result<Self, String> {
        let rights = sorted_rights(rights)?;
        let apf_key_id = Sha256::digest(apf_public_key).to_vec();

        // The founder checks its own evidence before it creates anything.
        let founder =
            FounderCertificate::verify(founder_certificate, apf_public_key, provider.crypto())?;
        if founder.apf_key_id != apf_key_id
            || founder.group != group
            || founder.subject != subject
            || founder.rights != rights
            || founder.signature_key != identity.public_key()
        {
            return Err("binding_mismatch: founder certificate".into());
        }
        let acc = AccContext::decode(acc_context)?;
        if acc.apf_key_id != apf_key_id || acc.group != group {
            return Err("binding_mismatch: acc_context".into());
        }

        let incarnation = AuthzIncarnation {
            version: 1,
            subject: subject.to_owned(),
            rights,
            admission_cert_hash: Sha256::digest(founder_certificate).to_vec(),
        }
        .encode()?;
        let context_extensions = Extensions::from_vec(vec![
            required_capabilities(),
            Extension::Unknown(
                ACC_CONTEXT_EXTENSION_TYPE,
                UnknownExtension(acc_context.to_vec()),
            ),
        ])
        .map_err(mls)?;
        let leaf_extensions = Extensions::single(Extension::Unknown(
            AUTHZ_INCARNATION_EXTENSION_TYPE,
            UnknownExtension(incarnation),
        ))
        .map_err(mls)?;

        let group_state = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(group.as_bytes()))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_capabilities(leaf_capabilities())
            .with_group_context_extensions(context_extensions)
            .with_leaf_node_extensions(leaf_extensions)
            .map_err(mls)?
            .build(&provider, identity.signer(), credential(subject, &identity))
            .map_err(mls)?;

        Ok(Self {
            provider,
            identity,
            group: group_state,
            subject: subject.to_owned(),
            apf_public_key: apf_public_key.to_vec(),
            pending: None,
        })
    }

    /// GroupInfo `MlsMessage` bytes for the sequencer.
    pub fn export_group_info(&self) -> Result<Vec<u8>, String> {
        self.group
            .export_group_info(self.provider.crypto(), self.identity.signer(), false)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// TLS-encoded ratchet tree for the sequencer.
    pub fn export_ratchet_tree(&self) -> Result<Vec<u8>, String> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// The member's current canonical frontier.
    pub fn frontier(&self) -> Result<Frontier, String> {
        context_frontier(self.group.public_group().group_context())
    }

    /// The subject name carried in this member's credential.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Stages one Add with a forced UpdatePath, without merging (C-12).
    pub fn stage_add(&mut self, key_package: &[u8]) -> Result<StagedAdd, String> {
        let key_package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(mls)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls)?;
        let parent = self.frontier()?;
        let bundle = self
            .group
            .commit_builder()
            .propose_adds([key_package])
            .force_self_update(true)
            .load_psks(self.provider.storage())
            .map_err(mls)?
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                self.identity.signer(),
                |_| true,
            )
            .map_err(mls)?
            .stage_commit(&self.provider)
            .map_err(mls)?;
        let commit = bundle.commit().tls_serialize_detached().map_err(mls)?;
        let welcome = bundle
            .into_welcome_msg()
            .ok_or("malformed: add commit without Welcome")?
            .tls_serialize_detached()
            .map_err(mls)?;
        self.pending = Some(commit.clone());
        Ok(StagedAdd {
            commit,
            welcome,
            parent,
        })
    }

    /// Discards this member's pending commit, if any.
    pub fn discard_pending(&mut self) -> Result<(), String> {
        self.group
            .clear_pending_commit(self.provider.storage())
            .map_err(mls)?;
        self.pending = None;
        Ok(())
    }

    /// Merges `commit` only under a valid matching canonical ack (§4.6, C-12).
    pub fn apply_ack(&mut self, commit: &[u8], ack: &[u8]) -> Result<Frontier, String> {
        // The signature comes first: an unauthenticated ack says nothing about bindings.
        let ack = CanonicalAck::verify(ack, &self.apf_public_key, self.provider.crypto())?;
        if ack.apf_key_id != Sha256::digest(&self.apf_public_key).as_slice()
            || ack.group.as_bytes() != self.group.group_id().as_slice()
        {
            return Err("binding_mismatch: ack issuer".into());
        }
        if ack.commit_hash != Sha256::digest(commit).as_slice() {
            return Err("binding_mismatch: commit hash".into());
        }
        if ack.parent != self.frontier()? {
            return Err("binding_mismatch: parent frontier".into());
        }

        let own = self.pending.as_deref() == Some(commit) && self.group.pending_commit().is_some();
        if own {
            let staged = self
                .group
                .pending_commit()
                .ok_or("binding_mismatch: no pending commit")?;
            if context_frontier(staged.group_context())? != ack.successor {
                return Err("binding_mismatch: successor frontier".into());
            }
            self.group
                .merge_pending_commit(&self.provider)
                .map_err(mls)?;
        } else {
            let message = MlsMessageIn::tls_deserialize_exact(commit)
                .map_err(|_| "binding_mismatch: commit encoding")?
                .try_into_protocol_message()
                .map_err(|_| "binding_mismatch: commit encoding")?;
            let processed = self
                .group
                .process_message(&self.provider, message)
                .map_err(|err| format!("binding_mismatch: commit does not process: {err:?}"))?;
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                return Err("binding_mismatch: not a commit".into());
            };
            if context_frontier(staged.group_context())? != ack.successor {
                return Err("binding_mismatch: successor frontier".into());
            }
            self.group
                .merge_staged_commit(&self.provider, *staged)
                .map_err(mls)?;
        }
        self.pending = None;
        self.frontier()
    }

    /// Raw OpenMLS access for adversarial tests only; honest code never uses it.
    pub fn mls_parts_mut(&mut self) -> (&mut MlsGroup, &P, &SignatureKeyPair) {
        (&mut self.group, &self.provider, self.identity.signer())
    }
}

impl<P: OpenMlsProvider> PreparedJoin<P> {
    /// Prepares a KeyPackage whose leaf carries `authz_incarnation { subject, rights,
    /// 32 zero bytes }` and declares `0xf042`–`0xf044`.
    pub fn prepare(
        group: &str,
        subject: &str,
        rights: &[(Right, u64)],
        identity: ClientIdentity,
        provider: P,
        apf_public_key: &[u8],
    ) -> Result<Self, String> {
        let incarnation = AuthzIncarnation {
            version: 1,
            subject: subject.to_owned(),
            rights: sorted_rights(rights)?,
            admission_cert_hash: ZERO_HASH.to_vec(),
        }
        .encode()?;
        let prepared = KeyPackage::builder()
            .leaf_node_capabilities(leaf_capabilities())
            .leaf_node_extensions(
                Extensions::single(Extension::Unknown(
                    AUTHZ_INCARNATION_EXTENSION_TYPE,
                    UnknownExtension(incarnation),
                ))
                .map_err(mls)?,
            )
            .prepare(
                CIPHERSUITE,
                &provider,
                identity.signer(),
                credential(subject, &identity),
                ADMISSION_EXTENSION_TYPE,
            )
            .map_err(mls)?;
        Ok(Self {
            provider,
            identity,
            prepared,
            group: group.to_owned(),
            subject: subject.to_owned(),
            apf_public_key: apf_public_key.to_vec(),
        })
    }

    /// Canonical stripped KeyPackage preimage bytes to certify.
    pub fn preimage(&self) -> &[u8] {
        self.prepared.canonical_binding_bytes()
    }

    /// Embeds `certificate` (any bytes; the sequencer validates) and signs the KeyPackage.
    pub fn finalize(self, certificate: &[u8]) -> Result<JoinCandidate<P>, String> {
        let bundle = self
            .prepared
            .with_external_binding(certificate.to_vec())
            .map_err(mls)?
            .finalize(&self.provider, self.identity.signer())
            .map_err(mls)?;
        let key_package = bundle.key_package().tls_serialize_detached().map_err(mls)?;
        Ok(JoinCandidate {
            provider: self.provider,
            identity: self.identity,
            key_package,
            group: self.group,
            subject: self.subject,
            apf_public_key: self.apf_public_key,
        })
    }
}

impl<P: OpenMlsProvider> JoinCandidate<P> {
    /// Final KeyPackage TLS bytes.
    pub fn key_package(&self) -> &[u8] {
        &self.key_package
    }

    /// Joins from `welcome` only under a valid matching admit ack (C-12).
    pub fn join(self, welcome: &[u8], ack: &[u8]) -> Result<ClientEndpoint<P>, String> {
        let ack = CanonicalAck::verify(ack, &self.apf_public_key, self.provider.crypto())?;
        let apf_key_id = Sha256::digest(&self.apf_public_key).to_vec();
        if ack.kind != AckKind::Admit || ack.apf_key_id != apf_key_id || ack.group != self.group {
            return Err("binding_mismatch: ack".into());
        }

        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|_| "binding_mismatch: welcome encoding")?
            .extract()
        else {
            return Err("binding_mismatch: not a Welcome".into());
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|err| format!("binding_mismatch: welcome does not process: {err:?}"))?;

        // Bind the joined state to the ack before the group is created in storage.
        let context = staged.group_context();
        if context.group_id().as_slice() != self.group.as_bytes()
            || context_frontier(context)? != ack.successor
        {
            return Err("binding_mismatch: joined frontier".into());
        }
        let accs = unknown_payloads(context.extensions(), ACC_CONTEXT_EXTENSION_TYPE);
        let [acc] = accs.as_slice() else {
            return Err("binding_mismatch: acc_context count".into());
        };
        let acc = AccContext::decode(acc).map_err(|_| "binding_mismatch: acc_context")?;
        if acc.apf_key_id != apf_key_id || acc.group != self.group {
            return Err("binding_mismatch: acc_context".into());
        }

        let group = staged.into_group(&self.provider).map_err(mls)?;
        Ok(ClientEndpoint {
            provider: self.provider,
            identity: self.identity,
            group,
            subject: self.subject,
            apf_public_key: self.apf_public_key,
            pending: None,
        })
    }
}

/// The frontier of a GroupContext (§4.1).
pub(crate) fn context_frontier(context: &GroupContext) -> Result<Frontier, String> {
    Frontier::compute(
        context.group_id().as_slice(),
        context.epoch().as_u64(),
        context.tree_hash(),
        context.confirmed_transcript_hash(),
    )
}

/// The payloads of every `Unknown(extension_type)` extension, in order.
pub(crate) fn unknown_payloads<T: ExtensionValidator>(
    extensions: &Extensions<T>,
    extension_type: u16,
) -> Vec<Vec<u8>> {
    extensions
        .iter()
        .filter_map(|extension| match extension {
            Extension::Unknown(t, UnknownExtension(bytes)) if *t == extension_type => {
                Some(bytes.clone())
            }
            _ => None,
        })
        .collect()
}

fn leaf_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(
            ADAPTER_EXTENSIONS
                .iter()
                .map(|t| ExtensionType::Unknown(*t))
                .collect(),
        )
        .build()
}

fn required_capabilities() -> Extension {
    let types: Vec<ExtensionType> = ADAPTER_EXTENSIONS
        .iter()
        .map(|t| ExtensionType::Unknown(*t))
        .collect();
    Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&types, &[], &[]))
}

fn credential(subject: &str, identity: &ClientIdentity) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(subject.as_bytes().to_vec()).into(),
        signature_key: identity.public_key().to_vec().into(),
    }
}

/// Rights sorted by code; duplicates are refused.
fn sorted_rights(rights: &[(Right, u64)]) -> Result<Vec<(Right, u64)>, String> {
    let mut sorted = rights.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("malformed: duplicate right".into());
    }
    Ok(sorted)
}

fn mls<E: std::fmt::Debug>(err: E) -> String {
    format!("malformed: OpenMLS {err:?}")
}

// ---------------------------------------------------------------------------
// Phase 4.3: protection, receive and delivery (C-18)
// ---------------------------------------------------------------------------

/// A decrypted application message held until its consume receipt is verified (C-18).
/// The plaintext is private: only [`PendingDelivery::deliver`] releases it, and dropping
/// the value drops it.
pub struct PendingDelivery {
    op: String,
    actor: String,
    group: String,
    recipient: String,
    apf_public_key: Vec<u8>,
    certificate_hash: Vec<u8>,
    content: FrozenContent,
}

impl PendingDelivery {
    /// Operation identifier from the release certificate.
    pub fn op(&self) -> &str {
        &self.op
    }

    /// Sender named by the release certificate.
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Verifies the consume receipt (C-15), then returns `(content_type, payload)`.
    /// A receipt that does not verify under the pinned APF key is `unauthenticated`; a
    /// valid receipt for another issuer, group, operation, recipient or certificate is
    /// `binding_mismatch`. On any error the plaintext is dropped.
    pub fn deliver(self, receipt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let receipt = verify_ed25519::<ConsumeReceipt>(receipt, &self.apf_public_key)
            .map_err(|_| "unauthenticated".to_string())?;
        if receipt.apf_key_id != Sha256::digest(&self.apf_public_key).as_slice()
            || receipt.group != self.group
        {
            return Err("binding_mismatch: receipt issuer".into());
        }
        if receipt.op != self.op
            || receipt.recipient != self.recipient
            || receipt.release_certificate_hash != self.certificate_hash
        {
            return Err("binding_mismatch: receipt".into());
        }
        Ok((self.content.content_type, self.content.payload))
    }
}

impl<P: OpenMlsProvider> ClientEndpoint<P> {
    /// Protects frozen content once under `certificate` and returns the envelope (C-18).
    ///
    /// The certificate must verify under the pinned APF key (`unauthenticated`), and be
    /// issued for this group to this member at its current frontier for exactly this
    /// content (`binding_mismatch`). Then `set_aad(SHA-256(certificate))` comes
    /// immediately before exactly one `create_message(FrozenContent)`.
    pub fn protect(
        &mut self,
        certificate: &[u8],
        content_type: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let released =
            ReleaseCertificate::verify(certificate, &self.apf_public_key, self.provider.crypto())
                .map_err(|err| {
                if err.starts_with("unauthenticated") {
                    err
                } else {
                    "binding_mismatch: certificate encoding".to_string()
                }
            })?;
        self.check_issuer(&released)?;
        if released.actor != self.subject {
            return Err("binding_mismatch: certificate actor".into());
        }
        if released.frontier != self.frontier()? {
            return Err("binding_mismatch: certificate frontier".into());
        }
        let digest = operation_digest(
            &released.op,
            &released.resource,
            content_type,
            payload,
            &released.frontier,
            released.policy_revision,
        )?;
        if digest != released.digest {
            return Err("binding_mismatch: digest".into());
        }

        let plaintext = FrozenContent {
            content_type: content_type.to_vec(),
            payload: payload.to_vec(),
        }
        .encode()?;
        self.group.set_aad(Sha256::digest(certificate).to_vec());
        let created = self
            .group
            .create_message(&self.provider, self.identity.signer(), &plaintext);
        // OpenMLS clears the AAD only on success; never leave it set for a later message.
        self.group.set_aad(Vec::new());
        let mls_message = created
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)?;
        Envelope {
            certificate: certificate.to_vec(),
            mls_message,
        }
        .encode()
    }

    /// Decrypts and checks an envelope without delivering it (C-18).
    ///
    /// A certificate that does not verify is `unauthenticated`; an MLS message that does
    /// not process as an application message is `undecryptable`; an AAD, sender leaf,
    /// reader, frontier or digest mismatch is `binding_mismatch`.
    pub fn receive(&mut self, envelope: &[u8]) -> Result<PendingDelivery, String> {
        let envelope = Envelope::decode(envelope).map_err(|_| "malformed: envelope")?;
        let released = ReleaseCertificate::verify(
            &envelope.certificate,
            &self.apf_public_key,
            self.provider.crypto(),
        )
        .map_err(|_| "unauthenticated".to_string())?;
        self.check_issuer(&released)?;

        // MLS processing; any failure here (old epoch, deleted key, not a private
        // application message for this group) yields no plaintext.
        let message = MlsMessageIn::tls_deserialize_exact(&envelope.mls_message)
            .map_err(|_| "undecryptable: MLS message encoding")?;
        if message.wire_format() != WireFormat::PrivateMessage {
            return Err("undecryptable: not a PrivateMessage".into());
        }
        let message = message
            .try_into_protocol_message()
            .map_err(|_| "undecryptable: not a protocol message")?;
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(|_| "undecryptable: MLS processing")?;
        let aad = processed.aad().to_vec();
        let sender = processed.sender().clone();
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err("undecryptable: not an application message".into());
        };
        let plaintext = application.into_bytes();

        // The AAD binds the ciphertext to exactly this certificate.
        if aad != Sha256::digest(&envelope.certificate).as_slice() {
            return Err("binding_mismatch: AAD".into());
        }
        // The sender leaf is the certified actor at the certified write generation.
        let Sender::Member(index) = sender else {
            return Err("binding_mismatch: sender is not a member".into());
        };
        let sender_leaf = self
            .group
            .public_group()
            .leaf(index)
            .ok_or("binding_mismatch: sender leaf")?;
        if BasicCredential::try_from(sender_leaf.credential().clone())
            .ok()
            .map(|basic| basic.identity().to_vec())
            .as_deref()
            != Some(released.actor.as_bytes())
        {
            return Err("binding_mismatch: sender credential".into());
        }
        if leaf_generation(sender_leaf, &released.actor, Right::Write)
            != Some(released.writer_generation)
        {
            return Err("binding_mismatch: sender write generation".into());
        }
        // This member is a certified reader at its own incarnation read generation.
        let own_leaf = self
            .group
            .own_leaf_node()
            .ok_or("binding_mismatch: own leaf")?;
        let own_read = leaf_generation(own_leaf, &self.subject, Right::Read)
            .ok_or("binding_mismatch: own read generation")?;
        if !released
            .readers
            .iter()
            .any(|(subject, generation)| *subject == self.subject && *generation == own_read)
        {
            return Err("binding_mismatch: not a certified reader".into());
        }
        if released.frontier != self.frontier()? {
            return Err("binding_mismatch: certificate frontier".into());
        }
        // The decrypted content is exactly the frozen content the kernel released.
        let content =
            FrozenContent::decode(&plaintext).map_err(|_| "binding_mismatch: not FrozenContent")?;
        let digest = operation_digest(
            &released.op,
            &released.resource,
            &content.content_type,
            &content.payload,
            &released.frontier,
            released.policy_revision,
        )?;
        if digest != released.digest {
            return Err("binding_mismatch: digest".into());
        }

        Ok(PendingDelivery {
            op: released.op,
            actor: released.actor,
            group: released.group,
            recipient: self.subject.clone(),
            apf_public_key: self.apf_public_key.clone(),
            certificate_hash: Sha256::digest(&envelope.certificate).to_vec(),
            content,
        })
    }

    /// The certificate names the pinned APF key and this group.
    fn check_issuer(&self, released: &ReleaseCertificate) -> Result<(), String> {
        if released.apf_key_id != Sha256::digest(&self.apf_public_key).as_slice()
            || released.group.as_bytes() != self.group.group_id().as_slice()
        {
            return Err("binding_mismatch: certificate issuer".into());
        }
        Ok(())
    }
}

/// The generation of `right` in a leaf's single well-formed `authz_incarnation` for
/// `subject`, if any.
fn leaf_generation(leaf: &LeafNode, subject: &str, right: Right) -> Option<u64> {
    let incarnations = unknown_payloads(leaf.extensions(), AUTHZ_INCARNATION_EXTENSION_TYPE);
    let [incarnation] = incarnations.as_slice() else {
        return None;
    };
    let incarnation = AuthzIncarnation::decode(incarnation).ok()?;
    if incarnation.subject != subject {
        return None;
    }
    incarnation
        .rights
        .iter()
        .find(|(r, _)| *r == right)
        .map(|(_, generation)| *generation)
}
