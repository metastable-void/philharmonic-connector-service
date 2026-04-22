use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use philharmonic_connector_common::ConnectorTokenClaims;
use philharmonic_connector_service::{
    MAX_PAYLOAD_BYTES, MintingKeyEntry, MintingKeyRegistry, TokenVerifyError, UnixMillis,
    verify_token,
};
use philharmonic_types::{Sha256, Uuid};

const SEED_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_seed.hex");
const PUBLIC_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_public.hex");
const PAYLOAD_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-a/wave_a_payload_plaintext.hex");
const COSE_SIGN1_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_cose_sign1.hex");

fn decode_hex_file(input: &str) -> Vec<u8> {
    hex::decode(input.trim()).expect("vector hex must decode")
}

fn seed_bytes() -> [u8; 32] {
    decode_hex_file(SEED_HEX)
        .try_into()
        .expect("seed vector must be 32 bytes")
}

fn public_bytes() -> [u8; 32] {
    decode_hex_file(PUBLIC_HEX)
        .try_into()
        .expect("public key vector must be 32 bytes")
}

fn wave_a_payload() -> Vec<u8> {
    decode_hex_file(PAYLOAD_HEX)
}

fn wave_a_claims() -> ConnectorTokenClaims {
    ConnectorTokenClaims {
        iss: "lowerer.main".to_owned(),
        exp: UnixMillis(1_924_992_000_000),
        kid: "lowerer.main-2026-04-22-3c8a91d0".to_owned(),
        realm: "llm".to_owned(),
        tenant: Uuid::parse_str("11111111-2222-4333-8444-555555555555")
            .expect("test UUID must be valid"),
        inst: Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa")
            .expect("test UUID must be valid"),
        step: 7,
        config_uuid: Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")
            .expect("test UUID must be valid"),
        payload_hash: Sha256::of(&wave_a_payload()),
    }
}

fn now() -> UnixMillis {
    UnixMillis(1_800_000_000_000)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&seed_bytes())
}

fn verifying_key() -> VerifyingKey {
    VerifyingKey::from_bytes(&public_bytes()).expect("public key vector must decode")
}

fn registry_for(kid: &str, not_before: UnixMillis, not_after: UnixMillis) -> MintingKeyRegistry {
    let mut registry = MintingKeyRegistry::new();
    registry.insert(
        kid.to_owned(),
        MintingKeyEntry {
            vk: verifying_key(),
            not_before,
            not_after,
        },
    );
    registry
}

fn valid_registry() -> MintingKeyRegistry {
    registry_for(
        "lowerer.main-2026-04-22-3c8a91d0",
        UnixMillis(1_700_000_000_000),
        UnixMillis(1_950_000_000_000),
    )
}

fn serialize_claims(claims: &ConnectorTokenClaims) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(claims, &mut out).expect("claims must serialize in test fixture");
    out
}

fn sign_token(claims: &ConnectorTokenClaims, protected_kid: &str, alg: iana::Algorithm) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(alg)
                .key_id(protected_kid.as_bytes().to_vec())
                .build(),
        )
        .payload(serialize_claims(claims))
        .create_signature(b"", |sig_structure| {
            signing_key().sign(sig_structure).to_bytes().to_vec()
        })
        .build()
        .to_vec()
        .expect("COSE_Sign1 should encode in test fixture")
}

fn positive_cose_bytes() -> Vec<u8> {
    decode_hex_file(COSE_SIGN1_HEX)
}

#[test]
fn positive_vector_verifies_and_returns_expected_context() {
    let payload = wave_a_payload();
    let now = now();

    let context = verify_token(
        &positive_cose_bytes(),
        &payload,
        "llm",
        &valid_registry(),
        now,
    )
    .expect("positive vector should verify");

    assert_eq!(
        context.tenant_id,
        Uuid::parse_str("11111111-2222-4333-8444-555555555555").expect("test UUID must be valid")
    );
    assert_eq!(
        context.instance_id,
        Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa").expect("test UUID must be valid")
    );
    assert_eq!(context.step_seq, 7);
    assert_eq!(
        context.config_uuid,
        Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff").expect("test UUID must be valid")
    );
    assert_eq!(context.issued_at, now);
    assert_eq!(context.expires_at, UnixMillis(1_924_992_000_000));
}

#[test]
fn negative_01_algorithm_not_allowed() {
    let claims = wave_a_claims();
    let token = sign_token(&claims, &claims.kid, iana::Algorithm::ES256);

    let err = verify_token(&token, &wave_a_payload(), "llm", &valid_registry(), now())
        .expect_err("alg -7 must be rejected before signature verification");

    assert_eq!(err, TokenVerifyError::AlgorithmNotAllowed);
}

#[test]
fn negative_02_unknown_kid() {
    let mut claims = wave_a_claims();
    claims.kid = "kid.not.registered".to_owned();
    let token = sign_token(&claims, &claims.kid, iana::Algorithm::EdDSA);

    let err = verify_token(&token, &wave_a_payload(), "llm", &valid_registry(), now())
        .expect_err("unknown kid must fail at lookup step");

    assert_eq!(
        err,
        TokenVerifyError::UnknownKid {
            kid: "kid.not.registered".to_owned(),
        }
    );
}

#[test]
fn negative_03_key_out_of_window() {
    let now = now();
    let registry = registry_for(
        "lowerer.main-2026-04-22-3c8a91d0",
        UnixMillis(1_700_000_000_000),
        UnixMillis(1_750_000_000_000),
    );

    let err = verify_token(
        &positive_cose_bytes(),
        &wave_a_payload(),
        "llm",
        &registry,
        now,
    )
    .expect_err("expired registry key must fail window check");

    assert_eq!(
        err,
        TokenVerifyError::KeyOutOfWindow {
            now,
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_750_000_000_000),
        }
    );
}

#[test]
fn negative_04_payload_too_large() {
    let oversized_len = MAX_PAYLOAD_BYTES
        .checked_add(1)
        .expect("MAX_PAYLOAD_BYTES must be far from usize::MAX in tests");
    let oversized_payload = vec![0_u8; oversized_len];

    let err = verify_token(
        &positive_cose_bytes(),
        &oversized_payload,
        "llm",
        &valid_registry(),
        now(),
    )
    .expect_err("oversized payload must fail before hash");

    assert_eq!(
        err,
        TokenVerifyError::PayloadTooLarge {
            limit: MAX_PAYLOAD_BYTES,
            actual: oversized_len,
        }
    );
}

#[test]
fn negative_05_bad_signature_by_signature_tamper() {
    let mut sign1 =
        CoseSign1::from_slice(&positive_cose_bytes()).expect("positive token should parse");
    if let Some(last) = sign1.signature.last_mut() {
        *last ^= 0x01;
    }
    let token = sign1.to_vec().expect("tampered sign1 should encode");

    let err = verify_token(&token, &wave_a_payload(), "llm", &valid_registry(), now())
        .expect_err("signature tamper must fail at signature step");

    assert_eq!(err, TokenVerifyError::BadSignature);
}

#[test]
fn negative_06_bad_signature_by_payload_tamper() {
    let mut sign1 =
        CoseSign1::from_slice(&positive_cose_bytes()).expect("positive token should parse");
    let payload = sign1
        .payload
        .as_mut()
        .expect("positive token must contain embedded payload");
    if let Some(first) = payload.first_mut() {
        *first ^= 0x01;
    }
    let token = sign1.to_vec().expect("tampered sign1 should encode");

    let err = verify_token(&token, &wave_a_payload(), "llm", &valid_registry(), now())
        .expect_err("payload tamper must fail signature verification");

    assert_eq!(err, TokenVerifyError::BadSignature);
}

#[test]
fn negative_07_kid_inconsistent() {
    let mut claims = wave_a_claims();
    claims.kid = "kid.claims.b".to_owned();
    let token = sign_token(&claims, "kid.protected.a", iana::Algorithm::EdDSA);
    let registry = registry_for(
        "kid.protected.a",
        UnixMillis(1_700_000_000_000),
        UnixMillis(1_950_000_000_000),
    );

    let err = verify_token(&token, &wave_a_payload(), "llm", &registry, now())
        .expect_err("kid mismatch must fail after signature and claim decode");

    assert_eq!(
        err,
        TokenVerifyError::KidInconsistent {
            protected: "kid.protected.a".to_owned(),
            claims: "kid.claims.b".to_owned(),
        }
    );
}

#[test]
fn negative_08_expired() {
    let mut claims = wave_a_claims();
    claims.exp = UnixMillis(1);
    let token = sign_token(&claims, &claims.kid, iana::Algorithm::EdDSA);

    let err = verify_token(&token, &wave_a_payload(), "llm", &valid_registry(), now())
        .expect_err("expired token must fail expiry check");

    assert_eq!(
        err,
        TokenVerifyError::Expired {
            exp: UnixMillis(1),
            now: now(),
        }
    );
}

#[test]
fn negative_09_payload_hash_mismatch() {
    let mut other_payload = wave_a_payload();
    if let Some(last) = other_payload.last_mut() {
        *last ^= 0x01;
    }

    let err = verify_token(
        &positive_cose_bytes(),
        &other_payload,
        "llm",
        &valid_registry(),
        now(),
    )
    .expect_err("payload hash mismatch must fail after expiry check");

    assert_eq!(err, TokenVerifyError::PayloadHashMismatch);
}

#[test]
fn negative_10_realm_mismatch() {
    let err = verify_token(
        &positive_cose_bytes(),
        &wave_a_payload(),
        "sql",
        &valid_registry(),
        now(),
    )
    .expect_err("realm mismatch must fail at final check");

    assert_eq!(
        err,
        TokenVerifyError::RealmMismatch {
            expected: "sql".to_owned(),
            found: "llm".to_owned(),
        }
    );
}
