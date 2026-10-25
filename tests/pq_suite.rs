//! C-42 contract tests: the post quantum suite (`docs/adapter-contract.md` §8.3).
//!
//! The `pq` suite is MLS `0x0052` (X-Wing key exchange, ChaCha20-Poly1305, SHA-384,
//! ML-DSA-44). One signature scheme serves the whole group: client identities, request
//! keys and the APF key. Every positive path runs before its negative case.

mod common;

use agent_trust::adapter::{Adapter, ClientIdentity, SignedRequest, APF_KEY_FILE};
use agent_trust::entropy::{EntropyConfig, QrngKeyExchange};
use agent_trust::lab::run_lab_with_suite;
use agent_trust::suite::{Suite, SUITE_ENV};
use common::{adapter_dir, code, lower_hex, scripted_provider, FixedClock, ScriptedRand};
use ml_dsa::{Keypair, MlDsa44};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use serde_json::{json, Value};

const GROUP: &str = "group-pq";
const ROOT: &str = "root";

/// The ML-DSA-44 public key that FIPS 204 KeyGen_internal derives from `seed`.
fn ml_dsa_public(seed: &[u8; 32]) -> Vec<u8> {
    ml_dsa::SigningKey::<MlDsa44>::from_seed(&(*seed).into())
        .verifying_key()
        .encode()
        .to_vec()
}

fn pq_identity(label: &str) -> ClientIdentity {
    ClientIdentity::generate_for(Suite::PostQuantum, &ScriptedRand::new(label.as_bytes()))
        .expect("pq identity")
}

// ---------------------------------------------------------------------------
// Suite table and selection
// ---------------------------------------------------------------------------

#[test]
fn suites_name_their_ciphersuite_scheme_and_sizes() {
    assert_eq!(Suite::parse("pq"), Ok(Suite::PostQuantum));
    assert_eq!(Suite::parse("classical"), Ok(Suite::Classical));
    assert_eq!(Suite::PostQuantum.name(), "pq");
    assert_eq!(Suite::Classical.name(), "classical");

    let pq = Suite::PostQuantum.ciphersuite();
    assert_eq!(
        pq,
        Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44
    );
    assert_eq!(u16::from(pq), 0x0052);
    assert_eq!(
        Suite::PostQuantum.signature_scheme(),
        SignatureScheme::MLDSA44
    );
    assert_eq!(Suite::PostQuantum.public_key_len(), 1312);
    assert_eq!(Suite::PostQuantum.signature_len(), 2420);

    let classical = Suite::Classical.ciphersuite();
    assert_eq!(
        classical,
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    );
    assert_eq!(u16::from(classical), 0x0001);
    assert_eq!(
        Suite::Classical.signature_scheme(),
        SignatureScheme::ED25519
    );
    assert_eq!(Suite::Classical.public_key_len(), 32);
    assert_eq!(Suite::Classical.signature_len(), 64);

    // Both providers of the lab support both suites.
    for suite in [Suite::PostQuantum, Suite::Classical] {
        RustCrypto::default()
            .supports(suite.ciphersuite())
            .expect("RustCrypto supports the suite");
        CryptoProvider::new()
            .expect("libcrux provider")
            .supports(suite.ciphersuite())
            .expect("libcrux supports the suite");
    }

    // Negative: unknown names are malformed.
    for bad in ["", "PQ", "ml-kem", "post-quantum", "classic"] {
        let error = Suite::parse(bad).expect_err("unknown suite name");
        assert!(error.starts_with("malformed: suite"), "{bad}: {error}");
    }
}

#[test]
fn environment_selects_the_suite_and_defaults_to_pq() {
    assert_eq!(SUITE_ENV, "AGENT_TRUST_SUITE");
    assert_eq!(Suite::from_env(|_| None), Ok(Suite::PostQuantum));
    let classical = |name: &str| (name == SUITE_ENV).then(|| "classical".to_string());
    assert_eq!(Suite::from_env(classical), Ok(Suite::Classical));
    let pq = |name: &str| (name == SUITE_ENV).then(|| "pq".to_string());
    assert_eq!(Suite::from_env(pq), Ok(Suite::PostQuantum));

    // Negative: a set but unknown value is an error, never a fallback.
    let bad = |name: &str| (name == SUITE_ENV).then(|| "kyber".to_string());
    let error = Suite::from_env(bad).expect_err("unknown suite");
    assert!(error.starts_with("malformed: suite"), "{error}");
}

#[test]
fn suite_is_recognized_from_a_public_key() {
    let pq = pq_identity("recognize/pq");
    let classical =
        ClientIdentity::generate(&ScriptedRand::new(b"recognize/classical")).expect("identity");
    assert_eq!(
        Suite::from_public_key(pq.public_key()),
        Some(Suite::PostQuantum)
    );
    assert_eq!(
        Suite::from_public_key(classical.public_key()),
        Some(Suite::Classical)
    );

    // Negative: wrong lengths and undecodable keys are recognized as nothing.
    assert_eq!(Suite::from_public_key(&pq.public_key()[..1311]), None);
    assert_eq!(
        Suite::from_public_key(&[pq.public_key(), &[0]].concat()),
        None
    );
    assert_eq!(Suite::from_public_key(&classical.public_key()[..31]), None);
    assert_eq!(Suite::from_public_key(&[]), None);
    // 32 bytes that are not an Ed25519 point (the y coordinate is not on the curve).
    let mut not_a_point = [0u8; 32];
    not_a_point[0] = 2;
    assert_eq!(Suite::from_public_key(&not_a_point), None);
}

// ---------------------------------------------------------------------------
// ML-DSA-44 keys and signatures (C-6, C-9 and C-41 as amended)
// ---------------------------------------------------------------------------

#[test]
fn ml_dsa_signatures_interoperate_and_are_deterministic() {
    let seed = [7u8; 32];
    let public = ml_dsa_public(&seed);
    assert_eq!(public.len(), 1312);
    let pair = SignatureKeyPair::from_raw(SignatureScheme::MLDSA44, seed.to_vec(), public.clone());

    // openmls_basic_credential signs; both providers verify.
    let first = pair.sign(b"payload").expect("sign");
    let second = pair.sign(b"payload").expect("sign again");
    assert_eq!(first.len(), 2420);
    assert_eq!(
        first, second,
        "ML-DSA signing is deterministic (C-32 byte identity)"
    );
    let libcrux = CryptoProvider::new().expect("libcrux provider");
    libcrux
        .verify_signature(SignatureScheme::MLDSA44, b"payload", &public, &first)
        .expect("libcrux verifies");
    RustCrypto::default()
        .verify_signature(SignatureScheme::MLDSA44, b"payload", &public, &first)
        .expect("RustCrypto verifies");

    // The libcrux provider's private key is the same 32-byte seed.
    let libcrux_signature = libcrux
        .sign(SignatureScheme::MLDSA44, b"payload", &seed)
        .expect("libcrux signs with the seed");
    libcrux
        .verify_signature(
            SignatureScheme::MLDSA44,
            b"payload",
            &public,
            &libcrux_signature,
        )
        .expect("the same seed gives the same public key");

    // Negative: another message, a flipped bit, another key.
    assert!(libcrux
        .verify_signature(SignatureScheme::MLDSA44, b"other", &public, &first)
        .is_err());
    let mut flipped = first.clone();
    flipped[100] ^= 1;
    assert!(libcrux
        .verify_signature(SignatureScheme::MLDSA44, b"payload", &public, &flipped)
        .is_err());
    let other = ml_dsa_public(&[8u8; 32]);
    assert!(libcrux
        .verify_signature(SignatureScheme::MLDSA44, b"payload", &other, &first)
        .is_err());
}

#[test]
fn pq_identity_takes_one_32_byte_draw_and_is_ml_dsa_44() {
    let rand = ScriptedRand::new(b"pq/identity");
    let identity = ClientIdentity::generate_for(Suite::PostQuantum, &rand).expect("identity");
    let draws = rand.draws();
    assert_eq!(draws.len(), 1, "one draw (C-6)");
    assert_eq!(draws[0].len, 32, "a 32-byte seed (C-6)");
    let seed: [u8; 32] = draws[0].bytes.clone().try_into().expect("32 bytes");

    assert_eq!(identity.suite(), Suite::PostQuantum);
    assert_eq!(
        identity.signer().signature_scheme(),
        SignatureScheme::MLDSA44
    );
    assert_eq!(
        identity.public_key(),
        ml_dsa_public(&seed).as_slice(),
        "the key pair is KeyGen_internal of the drawn seed ξ"
    );

    // The same seed gives the same identity; another seed another.
    assert_eq!(
        pq_identity("pq/identity").public_key(),
        identity.public_key()
    );
    assert_ne!(pq_identity("pq/other").public_key(), identity.public_key());

    // `generate` stays classical; `generate_for(Classical)` is the same thing.
    let classical = ClientIdentity::generate(&ScriptedRand::new(b"pq/identity")).expect("id");
    assert_eq!(classical.suite(), Suite::Classical);
    assert_eq!(classical.public_key().len(), 32);
    let same = ClientIdentity::generate_for(Suite::Classical, &ScriptedRand::new(b"pq/identity"))
        .expect("classical identity");
    assert_eq!(same.public_key(), classical.public_key());

    // Negative: no entropy, no identity.
    let error = ClientIdentity::generate_for(Suite::PostQuantum, &common::FailingRand)
        .err()
        .expect("a refused draw creates nothing");
    assert_eq!(error, "entropy_unavailable");
}

#[test]
fn restore_accepts_either_suite_only_when_the_public_key_derives_from_the_seed() {
    let rand = ScriptedRand::new(b"restore/pq");
    let pq = ClientIdentity::generate_for(Suite::PostQuantum, &rand).expect("pq identity");
    let pq_seed = rand.draws()[0].bytes.clone();
    let restored = ClientIdentity::restore(pq.signer().clone()).expect("pq restore");
    assert_eq!(restored.suite(), Suite::PostQuantum);
    assert_eq!(restored.public_key(), pq.public_key());

    let classical = ClientIdentity::generate(&ScriptedRand::new(b"restore/c")).expect("id");
    let restored = ClientIdentity::restore(classical.signer().clone()).expect("classical restore");
    assert_eq!(restored.suite(), Suite::Classical);

    // Negative: a pq seed paired with a foreign pq public key.
    let other = pq_identity("restore/other");
    let forged = SignatureKeyPair::from_raw(
        SignatureScheme::MLDSA44,
        pq_seed.clone(),
        other.public_key().to_vec(),
    );
    let error = ClientIdentity::restore(forged)
        .err()
        .expect("foreign public key");
    assert!(error.starts_with("binding_mismatch"), "{error}");
    // Positive control for the forged pair: the right public key restores.
    let honest =
        SignatureKeyPair::from_raw(SignatureScheme::MLDSA44, pq_seed, pq.public_key().to_vec());
    ClientIdentity::restore(honest).expect("seed with its own public key");

    // Negative: a wrong seed length and an unsupported scheme.
    let short = SignatureKeyPair::from_raw(
        SignatureScheme::MLDSA44,
        vec![1; 31],
        pq.public_key().to_vec(),
    );
    let error = ClientIdentity::restore(short).err().expect("short seed");
    assert!(error.starts_with("binding_mismatch"), "{error}");
    let ecdsa = SignatureKeyPair::from_raw(
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        vec![1; 32],
        vec![4; 65],
    );
    let error = ClientIdentity::restore(ecdsa)
        .err()
        .expect("unsupported scheme");
    assert!(error.starts_with("binding_mismatch"), "{error}");
}

// ---------------------------------------------------------------------------
// The adapter in the pq suite (C-1, C-5, C-9 as amended)
// ---------------------------------------------------------------------------

fn delegate_body(subject: &str, key: &[u8]) -> Value {
    json!({
        "command":"delegate", "subject":subject, "rights":["read"], "resources":[GROUP],
        "expires_at":10_000, "not_before":0, "depth":1, "subject_key":lower_hex(key)
    })
}

#[test]
fn pq_adapter_uses_ml_dsa_everywhere_and_keeps_its_suite_across_open() {
    let dir = adapter_dir();
    let (provider, apf_rand) = scripted_provider(b"pq/apf");
    let clock = FixedClock::new(1_000);
    let root = pq_identity("pq/root");
    let mut adapter = Adapter::create(
        dir.path(),
        GROUP,
        ROOT,
        root.public_key(),
        provider,
        clock.clone(),
    )
    .expect("pq adapter");
    assert_eq!(adapter.suite(), Suite::PostQuantum);

    // C-5 and C-6: one 32-byte draw, stored as the seed; the APF key is ML-DSA-44.
    let draws = apf_rand.draws();
    assert_eq!(draws.len(), 1);
    assert_eq!(draws[0].len, 32);
    let seed: [u8; 32] = draws[0].bytes.clone().try_into().expect("32 bytes");
    assert_eq!(
        std::fs::read(dir.path().join(APF_KEY_FILE)).expect("key file"),
        seed
    );
    assert_eq!(adapter.apf_public_key(), ml_dsa_public(&seed).as_slice());

    // C-1: a pq subject key is accepted, signed by the pq root.
    let bob = pq_identity("pq/bob");
    let request = SignedRequest::sign(
        GROUP,
        ROOT,
        1,
        &delegate_body("bob", bob.public_key()),
        root.signer(),
    )
    .expect("signed request");
    assert_eq!(request.signature.len(), 2420);
    adapter.handle(&request).expect("pq delegate accepted");

    // Negative (C-1): a classical key in a pq group is malformed, and so is a cut key.
    let carol = ClientIdentity::generate(&ScriptedRand::new(b"pq/carol")).expect("id");
    let request = SignedRequest::sign(
        GROUP,
        ROOT,
        2,
        &delegate_body("carol", carol.public_key()),
        root.signer(),
    )
    .expect("signed request");
    code(adapter.handle(&request), "malformed");
    let dave = pq_identity("pq/dave");
    let request = SignedRequest::sign(
        GROUP,
        ROOT,
        3,
        &delegate_body("dave", &dave.public_key()[..1300]),
        root.signer(),
    )
    .expect("signed request");
    code(adapter.handle(&request), "malformed");

    // Negative (C-4): a request signed with a classical key under the root's name.
    let impostor = ClientIdentity::generate(&ScriptedRand::new(b"pq/impostor")).expect("id");
    let request = SignedRequest::sign(
        GROUP,
        ROOT,
        4,
        &delegate_body("erin", pq_identity("pq/erin").public_key()),
        impostor.signer(),
    )
    .expect("signed request");
    code(adapter.handle(&request), "unauthenticated");
    drop(adapter);

    // `open` keeps the suite and keeps verifying ML-DSA requests.
    let (provider, _) = scripted_provider(b"pq/apf/reopen");
    let mut reopened = Adapter::open(dir.path(), provider, clock).expect("reopen");
    assert_eq!(reopened.suite(), Suite::PostQuantum);
    assert_eq!(reopened.apf_public_key(), ml_dsa_public(&seed).as_slice());
    let request = SignedRequest::sign(
        GROUP,
        ROOT,
        5,
        &delegate_body("dave", dave.public_key()),
        root.signer(),
    )
    .expect("signed request");
    reopened.handle(&request).expect("pq delegate after reopen");
}

#[test]
fn classical_root_key_still_gives_a_classical_adapter() {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(b"classical/apf");
    let root = ClientIdentity::generate(&ScriptedRand::new(b"classical/root")).expect("id");
    let adapter = Adapter::create(
        dir.path(),
        GROUP,
        ROOT,
        root.public_key(),
        provider,
        FixedClock::new(1),
    )
    .expect("classical adapter");
    assert_eq!(adapter.suite(), Suite::Classical);
    assert_eq!(adapter.apf_public_key().len(), 32);

    // Negative: a root key of neither suite is refused before anything is written.
    let dir = adapter_dir();
    let (provider, rand) = scripted_provider(b"bad/apf");
    let error = Adapter::create(
        dir.path(),
        GROUP,
        ROOT,
        &[9u8; 100],
        provider,
        FixedClock::new(1),
    )
    .err()
    .expect("bad root key");
    assert!(error.starts_with("malformed: root_public_key"), "{error}");
    assert!(
        rand.draws().is_empty(),
        "nothing is drawn before the key is checked"
    );
}

#[test]
fn the_apf_re_signs_identically_from_its_stored_seed() {
    // C-32 relies on deterministic signatures: an APF key rebuilt from the same seed
    // signs the same structure to the same bytes. Two geneses from the same scripted
    // seed produce byte-identical founder certificates under pq.
    let root = pq_identity("determinism/root");
    let mut certificates = Vec::new();
    for _ in 0..2 {
        let dir = adapter_dir();
        let (provider, _) = scripted_provider(b"determinism/apf");
        let pending = Adapter::begin_genesis(
            dir.path(),
            GROUP,
            ROOT,
            root.public_key(),
            provider,
            FixedClock::new(5),
        )
        .expect("pq genesis");
        assert_eq!(pending.apf_public_key().len(), 1312);
        certificates.push(pending.founder_certificate().to_vec());
    }
    assert_eq!(certificates[0], certificates[1]);
    // The certificate ends with a 2420-byte ML-DSA-44 signature behind its prefix.
    let certificate = &certificates[0];
    let tail = &certificate[certificate.len() - 2422..];
    assert_eq!(&tail[..2], &[0x49, 0x74]);
}

// ---------------------------------------------------------------------------
// A complete lab session in each suite (C-36 and C-40 as amended)
// ---------------------------------------------------------------------------

fn request(op: &str, args: Value) -> String {
    json!({ "op": op, "args": args }).to_string()
}

/// Runs `lines` through a lab of `suite` with the mock source; returns every response.
fn run_session(suite: Suite, lines: &[String]) -> Vec<Value> {
    let dir = adapter_dir();
    let entropy = EntropyConfig::Mock { seed: 3 }
        .connect_with(|_| None)
        .expect("mock source");
    let input = lines.join("\n");
    let mut output = Vec::new();
    run_lab_with_suite(
        dir.path(),
        11,
        entropy,
        suite,
        input.as_bytes(),
        &mut output,
    )
    .expect("lab session");
    String::from_utf8(output)
        .expect("utf-8 output")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON response"))
        .collect()
}

fn session_script() -> Vec<String> {
    let full = json!(["read", "write", "admit"]);
    let mut lines = vec![
        request("genesis", json!({"group": "lab-pq", "root": "alice"})),
        request("suite", json!({})),
        request("delegate", json!({"subject": "bob", "rights": full})),
        request("delegate", json!({"subject": "carol", "rights": full})),
        request("admit", json!({"subject": "bob", "by": "alice"})),
        request("admit", json!({"subject": "carol", "by": "alice"})),
        request(
            "send",
            json!({"from": "alice", "op": "op-1", "payload": "a1a1"}),
        ),
    ];
    lines.extend((0..8).map(|_| request("deliver", json!({}))));
    lines.extend([
        request("revoke", json!({"subject": "bob", "right": "read"})),
        request(
            "send",
            json!({"from": "alice", "op": "op-2", "payload": "a2a2"}),
        ),
        request("repair", json!({"by": "alice"})),
        request(
            "send",
            json!({"from": "alice", "op": "op-3", "payload": "a3a3"}),
        ),
    ]);
    // Delivery settles before the next epoch change (finding F-7 of the testbed).
    lines.extend((0..8).map(|_| request("deliver", json!({}))));
    lines.extend([
        request("revoke", json!({"subject": "carol", "right": "write"})),
        request(
            "rekey",
            json!({"subject": "carol", "right": "write", "generation": 1}),
        ),
        request(
            "send",
            json!({"from": "carol", "op": "op-4", "payload": "c4c4"}),
        ),
    ]);
    lines.extend((0..8).map(|_| request("deliver", json!({}))));
    lines.push(request("summary", json!({})));
    lines
}

fn check_session(suite: Suite, expected_ciphersuite: &str) {
    let responses = run_session(suite, &session_script());
    let script = session_script();
    assert_eq!(responses.len(), script.len());
    for (line, response) in script.iter().zip(&responses) {
        if line.contains("\"op-2\"") {
            assert_eq!(response["error"], json!("read_fenced"), "{line}");
        } else {
            assert!(response.get("ok").is_some(), "{line} -> {response}");
        }
    }
    assert_eq!(
        responses[1]["ok"],
        json!({"suite": suite.name(), "ciphersuite": expected_ciphersuite})
    );
    // op-1 reaches bob and carol, op-3 reaches carol, op-4 reaches alice.
    let summary = &responses.last().expect("summary")["ok"];
    assert_eq!(summary["delivered"], json!(4), "{summary}");
    assert_eq!(summary["duplicate_deliveries"], json!(0));
    assert_eq!(summary["deliveries_without_consume"], json!(0));
}

#[test]
fn a_full_lab_session_runs_under_pq() {
    check_session(Suite::PostQuantum, "0x0052");
}

#[test]
fn the_same_session_runs_under_classical() {
    check_session(Suite::Classical, "0x0001");
}

// ---------------------------------------------------------------------------
// The QRNG link: post quantum TLS key exchange (C-42, openmls-qrand `KeyExchange`)
// ---------------------------------------------------------------------------

fn qrng_key_exchange(config: Result<EntropyConfig, String>) -> Result<QrngKeyExchange, String> {
    match config? {
        EntropyConfig::Qrng(settings) => Ok(settings.key_exchange),
        other => panic!("expected a qrng source, got {other:?}"),
    }
}

#[test]
fn the_qrng_key_exchange_is_post_quantum_preferred_unless_configured() {
    // D-14: the `qrng` source is the Entropy Core link. It prefers `X25519MLKEM768` and
    // accepts a classical group from a server without it; the entropy report shows the
    // group (see `lab_entropy.rs`). `pq-only` stays available.
    let file = |extra: &str| {
        EntropyConfig::parse(
            &format!(
                "source = \"qrng\"\n[qrng]\nbase_url = \"https://127.0.0.1:8002\"\ntransport = \"tls\"\n{extra}"
            ),
            std::path::Path::new("base"),
        )
    };
    assert_eq!(
        qrng_key_exchange(file("")),
        Ok(QrngKeyExchange::PostQuantumPreferred)
    );
    assert_eq!(
        qrng_key_exchange(file("key_exchange = \"pq-only\"")),
        Ok(QrngKeyExchange::PostQuantumOnly)
    );
    assert_eq!(
        qrng_key_exchange(file("key_exchange = \"pq-preferred\"")),
        Ok(QrngKeyExchange::PostQuantumPreferred)
    );

    let env = |pairs: &'static [(&'static str, &'static str)]| {
        EntropyConfig::from_env_with(move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        })
    };
    const BASE: [(&str, &str); 2] = [
        ("AGENT_TRUST_ENTROPY_SOURCE", "qrng"),
        ("AGENT_TRUST_QRNG_BASE_URL", "https://127.0.0.1:8002"),
    ];
    assert_eq!(
        qrng_key_exchange(env(&BASE)),
        Ok(QrngKeyExchange::PostQuantumPreferred)
    );
    const ONLY: [(&str, &str); 3] = [
        BASE[0],
        BASE[1],
        ("AGENT_TRUST_QRNG_KEY_EXCHANGE", "pq-only"),
    ];
    assert_eq!(
        qrng_key_exchange(env(&ONLY)),
        Ok(QrngKeyExchange::PostQuantumOnly)
    );
    const PREFERRED: [(&str, &str); 3] = [
        BASE[0],
        BASE[1],
        ("AGENT_TRUST_QRNG_KEY_EXCHANGE", "pq-preferred"),
    ];
    assert_eq!(
        qrng_key_exchange(env(&PREFERRED)),
        Ok(QrngKeyExchange::PostQuantumPreferred)
    );

    // Negative: an unknown value is an error, never a classical fallback.
    let error = qrng_key_exchange(file("key_exchange = \"classical\"")).expect_err("unknown");
    assert!(error.contains("key_exchange"), "{error}");
    const BAD: [(&str, &str); 3] = [
        BASE[0],
        BASE[1],
        ("AGENT_TRUST_QRNG_KEY_EXCHANGE", "x25519"),
    ];
    let error = qrng_key_exchange(env(&BAD)).expect_err("unknown");
    assert!(error.contains("AGENT_TRUST_QRNG_KEY_EXCHANGE"), "{error}");
}

#[test]
fn genesis_reports_its_suite_before_completion() {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(b"pending/apf");
    let pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        pq_identity("pending/root").public_key(),
        provider,
        FixedClock::new(5),
    )
    .expect("pq genesis");
    assert_eq!(pending.suite(), Suite::PostQuantum);
}
