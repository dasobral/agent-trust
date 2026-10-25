//! Client endpoint: one OpenMLS group member with its own keys and storage
//! (`docs/adapter-contract.md` §5.1, §5.2, §5.3, §5.4, C-12, C-18, C-20 to C-24, C-28). Generic over the OpenMLS provider.

use openmls::extensions::ExtensionValidator;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::CryptoError;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::suite::Suite;

use crate::adapter::ClientIdentity;
use crate::wire::{
    epoch_authenticator_hash, operation_digest, verify_without_provider, AccContext, AckKind,
    AuthzIncarnation, CanonicalAck, ConsumeReceipt, Envelope, FounderCertificate, Frontier,
    FrozenContent, ReleaseCertificate, RepairConfirmation, Right, SignedStructure,
    ACC_CONTEXT_EXTENSION_TYPE, ADMISSION_EXTENSION_TYPE, AUTHZ_INCARNATION_EXTENSION_TYPE,
};

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
    /// The new identity of a staged, unmerged rekey (C-28); it replaces `identity` only
    /// when the matching update ack is applied.
    pending_identity: Option<ClientIdentity>,
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

/// A refused [`PreparedJoin::try_prepare`]: the error, and the identity and provider it
/// was given, unused. Preparation writes nothing to the provider's storage.
pub struct Unprepared<P: OpenMlsProvider> {
    pub error: String,
    pub identity: ClientIdentity,
    pub provider: P,
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
            .ciphersuite(identity.suite().ciphersuite())
            .with_group_id(GroupId::from_slice(group.as_bytes()))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_capabilities(leaf_capabilities(identity.suite()))
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
            pending_identity: None,
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
        self.pending_identity = None;
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
            // C-28: an own rekey merges only under an update ack.
            if self.pending_identity.is_some() && ack.kind != AckKind::Update {
                return Err("binding_mismatch: rekey outside an update".into());
            }
            self.group
                .merge_pending_commit(&self.provider)
                .map_err(mls)?;
            // The merged leaf carries the new signature key: from now on this member
            // signs with the new identity, and the old one is dropped.
            if let Some(new_identity) = self.pending_identity.take() {
                self.identity = new_identity;
            }
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
            let successor = if staged.self_removed() {
                // C-24: a removed member's OpenMLS processing stops before the confirmed
                // transcript hash, because it cannot check the confirmation tag. Its
                // public group recomputes the public successor context, as the sequencer
                // does, so the merge into the inactive state is still bound to the ack.
                if ack.kind != AckKind::Repair {
                    return Err("binding_mismatch: removal outside a repair".into());
                }
                let message = MlsMessageIn::tls_deserialize_exact(commit)
                    .map_err(|_| "binding_mismatch: commit encoding")?
                    .try_into_protocol_message()
                    .map_err(|_| "binding_mismatch: commit encoding")?;
                let public = self
                    .group
                    .public_group()
                    .process_message(self.provider.crypto(), message)
                    .map_err(|err| format!("binding_mismatch: commit does not process: {err:?}"))?;
                let ProcessedMessageContent::StagedCommitMessage(public) = public.into_content()
                else {
                    return Err("binding_mismatch: not a commit".into());
                };
                context_frontier(public.group_context())?
            } else {
                context_frontier(staged.group_context())?
            };
            if successor != ack.successor {
                return Err("binding_mismatch: successor frontier".into());
            }
            self.group
                .merge_staged_commit(&self.provider, *staged)
                .map_err(mls)?;
        }
        // Merging any other canonical commit discards an own staged rekey.
        self.pending = None;
        self.pending_identity = None;
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
        Self::try_prepare(group, subject, rights, identity, provider, apf_public_key)
            .map_err(|unprepared| unprepared.error)
    }

    /// [`PreparedJoin::prepare`], but a refusal (a refused draw included) gives the
    /// identity and provider back, so the same candidate can try again.
    pub fn try_prepare(
        group: &str,
        subject: &str,
        rights: &[(Right, u64)],
        identity: ClientIdentity,
        provider: P,
        apf_public_key: &[u8],
    ) -> Result<Self, Unprepared<P>> {
        match prepare_key_package(subject, rights, &identity, &provider) {
            Ok(prepared) => Ok(Self {
                provider,
                identity,
                prepared,
                group: group.to_owned(),
                subject: subject.to_owned(),
                apf_public_key: apf_public_key.to_vec(),
            }),
            Err(error) => Err(Unprepared {
                error,
                identity,
                provider,
            }),
        }
    }

    /// Drops the prepared KeyPackage and gives the identity and provider back, e.g. when
    /// no admission certificate is issued.
    pub fn abandon(self) -> (ClientIdentity, P) {
        (self.identity, self.provider)
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

    /// Drops the KeyPackage and gives the identity and provider back, e.g. when its Add
    /// is not acked. The provider's storage still holds the dropped KeyPackage's private
    /// keys.
    pub fn abandon(self) -> (ClientIdentity, P) {
        (self.identity, self.provider)
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
            pending_identity: None,
        })
    }
}

/// The candidate's KeyPackage, prepared and not yet bound to a certificate.
fn prepare_key_package<P: OpenMlsProvider>(
    subject: &str,
    rights: &[(Right, u64)],
    identity: &ClientIdentity,
    provider: &P,
) -> Result<PreparedKeyPackage, String> {
    let incarnation = AuthzIncarnation {
        version: 1,
        subject: subject.to_owned(),
        rights: sorted_rights(rights)?,
        admission_cert_hash: ZERO_HASH.to_vec(),
    }
    .encode()?;
    KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities(identity.suite()))
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                AUTHZ_INCARNATION_EXTENSION_TYPE,
                UnknownExtension(incarnation),
            ))
            .map_err(mls)?,
        )
        .prepare(
            identity.suite().ciphersuite(),
            provider,
            identity.signer(),
            credential(subject, identity),
            ADMISSION_EXTENSION_TYPE,
        )
        .map_err(mls)
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

/// The leaf capabilities: the ciphersuite of the identity's suite (C-42) and the adapter
/// extensions.
fn leaf_capabilities(suite: Suite) -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![suite.ciphersuite()])
        .credentials(vec![CredentialType::Basic])
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

/// An OpenMLS error as a lab code. A refused draw is the §12 `entropy_unavailable`, with
/// no provider text. OpenMLS keeps the `CryptoError` in `LibraryError`'s private field,
/// so the refusal is recognized by that variant's name in the error's debug form.
fn mls<E: std::fmt::Debug>(err: E) -> String {
    let text = format!("{err:?}");
    if text.contains(&format!("{:?}", CryptoError::InsufficientRandomness)) {
        return "entropy_unavailable".into();
    }
    format!("malformed: OpenMLS {text}")
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
        let receipt = verify_without_provider::<ConsumeReceipt>(receipt, &self.apf_public_key)
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

// ---------------------------------------------------------------------------
// Phase 4.4a: repair commit and confirmation (C-20 to C-24)
// ---------------------------------------------------------------------------

/// A repair commit staged by this member and not yet merged.
#[derive(Clone, Debug)]
pub struct StagedRepair {
    /// Exact commit `MlsMessage` bytes to submit.
    pub commit: Vec<u8>,
    pub parent: Frontier,
}

impl<P: OpenMlsProvider> ClientEndpoint<P> {
    /// Stages, without merging, one commit that removes exactly the leaves of `removed`,
    /// replaces `acc_context` with the planned payload and forces an UpdatePath (C-22).
    ///
    /// The plan comes from the APF (C-20), so the committer has no discretion (C-21). The
    /// client checks only that the planned `acc_context` names its pinned APF key and
    /// group; the sequencer is the gate for everything else.
    pub fn stage_repair(
        &mut self,
        removed: &[String],
        acc_context: &[u8],
    ) -> Result<StagedRepair, String> {
        let acc = AccContext::decode(acc_context).map_err(|_| "binding_mismatch: acc_context")?;
        if acc.apf_key_id != Sha256::digest(&self.apf_public_key).as_slice()
            || acc.group.as_bytes() != self.group.group_id().as_slice()
        {
            return Err("binding_mismatch: acc_context".into());
        }
        if removed.contains(&self.subject) {
            return Err("invalid_repair: the committer is removed".into());
        }

        // Every leaf whose credential names a removed subject.
        let mut indices = Vec::new();
        for subject in removed {
            let before = indices.len();
            indices.extend(
                self.group
                    .members()
                    .filter(|member| {
                        credential_identity(&member.credential).as_deref()
                            == Some(subject.as_bytes())
                    })
                    .map(|member| member.index),
            );
            if indices.len() == before {
                return Err(format!("invalid_repair: {subject} has no leaf"));
            }
        }

        // The current GroupContext extensions with exactly the acc_context replaced.
        let mut replaced = 0;
        let mut extensions = Vec::new();
        for extension in self
            .group
            .public_group()
            .group_context()
            .extensions()
            .iter()
        {
            match extension {
                Extension::Unknown(t, _) if *t == ACC_CONTEXT_EXTENSION_TYPE => {
                    replaced += 1;
                    extensions.push(Extension::Unknown(
                        ACC_CONTEXT_EXTENSION_TYPE,
                        UnknownExtension(acc_context.to_vec()),
                    ));
                }
                other => extensions.push(other.clone()),
            }
        }
        if replaced != 1 {
            return Err("binding_mismatch: acc_context count".into());
        }
        let extensions = Extensions::from_vec(extensions).map_err(mls)?;

        let parent = self.frontier()?;
        let bundle = self
            .group
            .commit_builder()
            .propose_removals(indices)
            .propose_group_context_extensions(extensions)
            .map_err(mls)?
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
        self.pending = Some(commit.clone());
        Ok(StagedRepair { commit, parent })
    }

    /// Signed repair confirmation for the member's current frontier (C-23). The member
    /// reaches a frontier only by merging an acked commit, which verified the confirmation
    /// tag; only a hash of the epoch authenticator leaves the client.
    pub fn confirmation(&self) -> Result<Vec<u8>, String> {
        if !self.group.is_active() {
            return Err("binding_mismatch: group inactive".into());
        }
        let frontier = self.frontier()?;
        let group = String::from_utf8(self.group.group_id().as_slice().to_vec())
            .map_err(|_| "malformed: group id")?;
        let hash = epoch_authenticator_hash(
            &frontier.branch,
            self.group.epoch_authenticator().as_slice(),
        );
        RepairConfirmation {
            group,
            frontier,
            epoch_authenticator_hash: hash,
        }
        .sign(self.identity.signer())
    }
}

/// A basic credential's identity bytes.
fn credential_identity(credential: &Credential) -> Option<Vec<u8>> {
    BasicCredential::try_from(credential.clone())
        .ok()
        .map(|basic| basic.identity().to_vec())
}

// ---------------------------------------------------------------------------
// Phase 4.4b: rekey of a current member (C-28, R-10)
// ---------------------------------------------------------------------------

/// An update commit with a new signer, staged by this member and not yet merged.
#[derive(Clone, Debug)]
pub struct StagedRekey {
    /// Exact commit `MlsMessage` bytes to submit.
    pub commit: Vec<u8>,
    pub parent: Frontier,
}

impl<P: OpenMlsProvider> ClientEndpoint<P> {
    /// Stages, without merging, a `self_update_with_new_signer` commit whose new leaf keeps
    /// this member's credential identity, carries `new_identity`'s signature key and an
    /// `authz_incarnation` with `rights` and the existing `admission_cert_hash` (C-28).
    /// After the matching ack is applied, `identity()` is `new_identity`.
    ///
    /// The commit has no proposals and carries an UpdatePath; it is signed by the current
    /// key, and its new leaf by the new key. The client does not check the rights against
    /// any policy: the sequencer is the gate (C-28 step 5).
    pub fn stage_rekey(
        &mut self,
        new_identity: ClientIdentity,
        rights: &[(Right, u64)],
    ) -> Result<StagedRekey, String> {
        let rights = sorted_rights(rights)?;
        let own = self
            .group
            .own_leaf_node()
            .ok_or("binding_mismatch: own leaf")?
            .clone();
        let incarnations = unknown_payloads(own.extensions(), AUTHZ_INCARNATION_EXTENSION_TYPE);
        let [previous] = incarnations.as_slice() else {
            return Err("binding_mismatch: authz_incarnation count".into());
        };
        let previous = AuthzIncarnation::decode(previous)
            .map_err(|_| "binding_mismatch: authz_incarnation encoding")?;
        let incarnation = AuthzIncarnation {
            version: 1,
            subject: self.subject.clone(),
            rights,
            admission_cert_hash: previous.admission_cert_hash,
        }
        .encode()?;

        // Every other leaf extension and the capabilities stay as they are.
        let extensions: Vec<Extension> = own
            .extensions()
            .iter()
            .map(|extension| match extension {
                Extension::Unknown(t, _) if *t == AUTHZ_INCARNATION_EXTENSION_TYPE => {
                    Extension::Unknown(
                        AUTHZ_INCARNATION_EXTENSION_TYPE,
                        UnknownExtension(incarnation.clone()),
                    )
                }
                other => other.clone(),
            })
            .collect();
        let parameters = LeafNodeParameters::builder()
            .with_capabilities(own.capabilities().clone())
            .with_extensions(Extensions::from_vec(extensions).map_err(mls)?)
            .build();

        let parent = self.frontier()?;
        let bundle = self
            .group
            .self_update_with_new_signer(
                &self.provider,
                self.identity.signer(),
                NewSignerBundle {
                    signer: new_identity.signer(),
                    credential_with_key: credential(&self.subject, &new_identity),
                },
                parameters,
            )
            .map_err(mls)?;
        let commit = bundle.commit().tls_serialize_detached().map_err(mls)?;
        self.pending = Some(commit.clone());
        self.pending_identity = Some(new_identity);
        Ok(StagedRekey { commit, parent })
    }
}

// ---------------------------------------------------------------------------
// Phase 4.5: client restart (C-33, §6 B4 to B8)
// ---------------------------------------------------------------------------

impl<P: OpenMlsProvider> ClientEndpoint<P> {
    /// Reloads a member from its provider's storage (C-33). `pending_commit` is the exact
    /// commit this member staged and submitted before restarting; `pending_identity` is the
    /// new identity of a staged rekey whose ack was not yet applied.
    ///
    /// OpenMLS keeps the group, its secrets, the decryption state and a staged commit in
    /// storage; the client keeps only the commit bytes and a rekey's new identity in
    /// memory, so the application supplies them. The reloaded member is at its stored
    /// frontier: it reaches an acked successor only through `apply_ack`, and a rolled-back
    /// storage stays unready until the missing acks are applied in order (C-24).
    ///
    /// The stored leaf must carry `subject` and `identity`'s key, and the group must carry
    /// exactly one `acc_context` for the pinned APF key. A supplied pending commit requires
    /// a staged commit in storage whose path leaf carries the key it will merge with:
    /// `pending_identity`'s for a rekey, otherwise `identity`'s. Mismatches are
    /// `binding_mismatch`.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        group: &str,
        subject: &str,
        identity: ClientIdentity,
        provider: P,
        apf_public_key: &[u8],
        pending_commit: Option<&[u8]>,
        pending_identity: Option<ClientIdentity>,
    ) -> Result<Self, String> {
        if pending_identity.is_some() && pending_commit.is_none() {
            return Err("malformed: pending identity without a pending commit".into());
        }
        let state = MlsGroup::load(provider.storage(), &GroupId::from_slice(group.as_bytes()))
            .map_err(mls)?
            .ok_or("uninitialized: group missing from storage")?;

        let apf_key_id = Sha256::digest(apf_public_key).to_vec();
        let accs = unknown_payloads(
            state.public_group().group_context().extensions(),
            ACC_CONTEXT_EXTENSION_TYPE,
        );
        let [acc] = accs.as_slice() else {
            return Err("binding_mismatch: acc_context count".into());
        };
        let acc = AccContext::decode(acc).map_err(|_| "binding_mismatch: acc_context")?;
        if acc.apf_key_id != apf_key_id || acc.group != group {
            return Err("binding_mismatch: acc_context".into());
        }

        // A removed member's inactive state has no own leaf; it stays inactive.
        if let Some(own) = state.own_leaf_node() {
            if credential_identity(own.credential()).as_deref() != Some(subject.as_bytes())
                || own.signature_key().as_slice() != identity.public_key()
            {
                return Err("binding_mismatch: stored leaf".into());
            }
        }

        if pending_commit.is_some() {
            let staged = state
                .pending_commit()
                .ok_or("binding_mismatch: no staged commit in storage")?;
            let merged_key = pending_identity
                .as_ref()
                .map_or(identity.public_key(), ClientIdentity::public_key);
            let path_key = staged
                .update_path_leaf_node()
                .map(|leaf| leaf.signature_key().as_slice());
            if path_key != Some(merged_key) {
                return Err("binding_mismatch: pending identity".into());
            }
        }

        Ok(Self {
            provider,
            identity,
            group: state,
            subject: subject.to_owned(),
            apf_public_key: apf_public_key.to_vec(),
            pending: pending_commit.map(<[u8]>::to_vec),
            pending_identity,
        })
    }
}
