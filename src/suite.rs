//! The two cryptographic suites of a group (`docs/adapter-contract.md` §8.3, C-42).
//!
//! A suite fixes the MLS ciphersuite and the one signature scheme that the group's
//! client identities, request keys and APF key all use. `pq` is the post quantum suite;
//! its code point comes from `draft-ietf-mls-pq-ciphersuites` and can change before the
//! draft becomes an RFC.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::{Ciphersuite, SignatureScheme};

/// Environment variable that selects the lab suite (C-42): `pq` or `classical`.
pub const SUITE_ENV: &str = "AGENT_TRUST_SUITE";

/// Ed25519 public key and seed length.
const ED25519_KEY_LEN: usize = 32;
/// Ed25519 signature length.
const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-44 public key length (FIPS 204).
const ML_DSA_44_KEY_LEN: usize = 1312;
/// ML-DSA-44 signature length (FIPS 204).
const ML_DSA_44_SIGNATURE_LEN: usize = 2420;
/// Length of the seed every identity and APF key is derived from (C-6).
pub const SEED_LEN: usize = 32;

/// A group's suite (C-42).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Suite {
    /// MLS `0x0001`: DHKEM X25519, AES-128-GCM, SHA-256, Ed25519.
    Classical,
    /// MLS `0x0052`: X-Wing (ML-KEM-768 with X25519), ChaCha20-Poly1305, SHA-384,
    /// ML-DSA-44.
    PostQuantum,
}

impl Suite {
    /// The suite name used by the lab and stored in `adapter.sqlite`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Classical => "classical",
            Self::PostQuantum => "pq",
        }
    }

    /// Parses a suite name; anything else is `malformed: suite`.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "classical" => Ok(Self::Classical),
            "pq" => Ok(Self::PostQuantum),
            _ => Err("malformed: suite (expected pq or classical)".into()),
        }
    }

    /// The lab suite from [`SUITE_ENV`]; `pq` when the variable is not set.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        match get(SUITE_ENV) {
            None => Ok(Self::PostQuantum),
            Some(name) => Self::parse(&name),
        }
    }

    /// The MLS ciphersuite.
    pub fn ciphersuite(self) -> Ciphersuite {
        match self {
            Self::Classical => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Self::PostQuantum => {
                Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44
            }
        }
    }

    /// The one signature scheme of the group.
    pub fn signature_scheme(self) -> SignatureScheme {
        self.ciphersuite().signature_algorithm()
    }

    pub fn public_key_len(self) -> usize {
        match self {
            Self::Classical => ED25519_KEY_LEN,
            Self::PostQuantum => ML_DSA_44_KEY_LEN,
        }
    }

    pub fn signature_len(self) -> usize {
        match self {
            Self::Classical => ED25519_SIGNATURE_LEN,
            Self::PostQuantum => ML_DSA_44_SIGNATURE_LEN,
        }
    }

    /// The suite whose valid public key `bytes` is: an Ed25519 point or an ML-DSA-44
    /// key that decodes. `None` for anything else.
    pub fn from_public_key(bytes: &[u8]) -> Option<Self> {
        [Self::Classical, Self::PostQuantum]
            .into_iter()
            .find(|suite| suite.is_public_key(bytes))
    }

    /// Whether `bytes` is a valid public key of this suite.
    pub fn is_public_key(self, bytes: &[u8]) -> bool {
        match self {
            Self::Classical => <[u8; ED25519_KEY_LEN]>::try_from(bytes)
                .ok()
                .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok())
                .is_some(),
            Self::PostQuantum => ml_dsa_44_key(bytes).is_some(),
        }
    }

    /// The key pair derived from a 32-byte seed (C-6 as amended by C-42). For Ed25519
    /// the seed is the private key; for ML-DSA-44 it is the FIPS 204 seed ξ.
    pub fn key_pair_from_seed(self, seed: &[u8; SEED_LEN]) -> SignatureKeyPair {
        let public = self.public_key_from_seed(seed);
        SignatureKeyPair::from_raw(self.signature_scheme(), seed.to_vec(), public)
    }

    /// The public key that a 32-byte seed derives in this suite.
    pub fn public_key_from_seed(self, seed: &[u8; SEED_LEN]) -> Vec<u8> {
        match self {
            Self::Classical => ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            Self::PostQuantum => {
                use ml_dsa::Keypair;
                ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&(*seed).into())
                    .verifying_key()
                    .encode()
                    .to_vec()
            }
        }
    }

    /// The suite of a signature scheme, if any.
    pub fn of_scheme(scheme: SignatureScheme) -> Option<Self> {
        match scheme {
            SignatureScheme::ED25519 => Some(Self::Classical),
            SignatureScheme::MLDSA44 => Some(Self::PostQuantum),
            _ => None,
        }
    }

    /// Verifies a signature without an OpenMLS provider (C-18, C-42): Ed25519 with
    /// `verify_strict`, ML-DSA-44 with the `ml-dsa` crate and an empty context.
    pub fn verify_without_provider(self, data: &[u8], public_key: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Classical => {
                let Ok(key) = ed25519_dalek::VerifyingKey::try_from(public_key) else {
                    return false;
                };
                let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
                    return false;
                };
                key.verify_strict(data, &signature).is_ok()
            }
            Self::PostQuantum => {
                use ml_dsa::signature::Verifier;
                let Some(key) = ml_dsa_44_key(public_key) else {
                    return false;
                };
                let Ok(encoded) = ml_dsa::EncodedSignature::<ml_dsa::MlDsa44>::try_from(signature)
                else {
                    return false;
                };
                let Some(signature) = ml_dsa::Signature::<ml_dsa::MlDsa44>::decode(&encoded) else {
                    return false;
                };
                key.verify(data, &signature).is_ok()
            }
        }
    }
}

/// An ML-DSA-44 verifying key decoded from exactly 1312 bytes.
fn ml_dsa_44_key(bytes: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>> {
    let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(bytes).ok()?;
    Some(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded))
}
