use coset::{Algorithm, CborSerializable, CoseEncrypt0, Header, Label, cbor::value::Value, iana};
use philharmonic_connector_client::{
    AeadAadInputs, EncryptTestInputs, UnixMillis as ClientUnixMillis,
    encrypt_payload_with_test_inputs,
};
use philharmonic_connector_common::{ConnectorTokenClaims, RealmId, RealmPublicKey};
use philharmonic_connector_service::{
    RealmPrivateKeyEntry, RealmPrivateKeyRegistry, TokenVerifyError, UnixMillis, Uuid,
    decrypt_payload,
};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

const WAVE_B_MLKEM_SECRET_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_mlkem_secret.hex");
const WAVE_B_MLKEM_PUBLIC_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_mlkem_public.hex");
const WAVE_B_X25519_REALM_SK_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_x25519_realm_sk.hex");
const WAVE_B_X25519_REALM_PK_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_x25519_realm_pk.hex");
const WAVE_B_X25519_EPH_SK_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_x25519_eph_sk.hex");
const WAVE_B_MLKEM_ENCAPS_M_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_mlkem_encaps_m.hex");
const WAVE_B_NONCE_HEX: &str = include_str!("../../docs/crypto-vectors/wave-b/wave_b_nonce.hex");
const WAVE_B_PLAINTEXT_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_plaintext.hex");
const WAVE_B_COSE_ENCRYPT0_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-b/wave_b_cose_encrypt0.hex");
const WAVE_A_COMPOSITION_CLAIMS_CBOR_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-a/wave_a_composition_claims.cbor.hex");

const REALM_KID: &str = "llm.default-2026-04-22-realmkey0";

fn decode_hex_file(input: &str) -> Vec<u8> {
    hex::decode(input.trim()).expect("vector hex must decode")
}

fn bytes_32(input: &str) -> [u8; 32] {
    decode_hex_file(input)
        .try_into()
        .expect("vector must decode to 32 bytes")
}

fn bytes_2400(input: &str) -> [u8; 2400] {
    decode_hex_file(input)
        .try_into()
        .expect("vector must decode to 2400 bytes")
}

fn now() -> UnixMillis {
    UnixMillis(1_800_000_000_000)
}

fn composition_claims() -> ConnectorTokenClaims {
    let reader = decode_hex_file(WAVE_A_COMPOSITION_CLAIMS_CBOR_HEX);
    ciborium::de::from_reader(&mut reader.as_slice())
        .expect("composition claims vector must decode")
}

fn valid_realm_registry() -> RealmPrivateKeyRegistry {
    let mut registry = RealmPrivateKeyRegistry::new();
    registry.insert(
        REALM_KID.to_owned(),
        RealmPrivateKeyEntry {
            kem_sk: Zeroizing::new(bytes_2400(WAVE_B_MLKEM_SECRET_HEX)),
            ecdh_sk: StaticSecret::from(bytes_32(WAVE_B_X25519_REALM_SK_HEX)),
            realm: RealmId::new("llm"),
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_950_000_000_000),
        },
    );
    registry
}

fn positive_encrypt0_bytes() -> Vec<u8> {
    decode_hex_file(WAVE_B_COSE_ENCRYPT0_HEX)
}

fn positive_plaintext_bytes() -> Vec<u8> {
    decode_hex_file(WAVE_B_PLAINTEXT_HEX)
}

fn mutate_encrypt0(mutator: impl FnOnce(&mut CoseEncrypt0)) -> Vec<u8> {
    let mut encrypt0 = CoseEncrypt0::from_slice(&positive_encrypt0_bytes())
        .expect("positive vector must parse as COSE_Encrypt0");
    // Re-serialize from mutated header fields instead of parsed original bytes.
    encrypt0.protected.original_data = None;
    mutator(&mut encrypt0);
    encrypt0
        .to_vec()
        .expect("mutated COSE_Encrypt0 should serialize")
}

fn rest_bstr_mut<'a>(encrypt0: &'a mut CoseEncrypt0, label: &str) -> &'a mut Vec<u8> {
    for (entry_label, entry_value) in &mut encrypt0.protected.header.rest {
        if let (Label::Text(name), Value::Bytes(bytes)) = (entry_label, entry_value)
            && name == label
        {
            return bytes;
        }
    }
    panic!("expected protected-header label '{label}' not present");
}

#[test]
fn positive_vector_decrypts_to_expected_plaintext() {
    let plaintext = decrypt_payload(
        &positive_encrypt0_bytes(),
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect("positive vector should decrypt");

    assert_eq!(&*plaintext, &positive_plaintext_bytes());
}

#[test]
fn negative_01_truncated_encrypt0_is_malformed() {
    let mut bytes = positive_encrypt0_bytes();
    bytes.pop();

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("truncated envelope must fail parse");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_02_alg_not_a256gcm_is_malformed() {
    let bytes = mutate_encrypt0(|encrypt0| {
        encrypt0.protected.header.alg = Some(Algorithm::Assigned(iana::Algorithm::A128GCM));
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("non-A256GCM alg must be rejected");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_03_nonempty_unprotected_is_malformed() {
    let bytes = mutate_encrypt0(|encrypt0| {
        encrypt0.unprotected = Header {
            key_id: b"x".to_vec(),
            ..Header::default()
        };
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("non-empty unprotected header must be rejected");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_04_kem_ct_short_is_malformed() {
    let bytes = mutate_encrypt0(|encrypt0| {
        let kem_ct = rest_bstr_mut(encrypt0, "kem_ct");
        kem_ct.pop();
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("short kem_ct must be rejected");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_05_ecdh_pk_short_is_malformed() {
    let bytes = mutate_encrypt0(|encrypt0| {
        let ecdh_eph_pk = rest_bstr_mut(encrypt0, "ecdh_eph_pk");
        ecdh_eph_pk.pop();
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("short ecdh_eph_pk must be rejected");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_06_iv_short_is_malformed() {
    let bytes = mutate_encrypt0(|encrypt0| {
        encrypt0.protected.header.iv.pop();
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("short IV must be rejected");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_07_unknown_extra_label_is_malformed() {
    let bytes = mutate_encrypt0(|encrypt0| {
        encrypt0
            .protected
            .header
            .rest
            .push((Label::Text("unknown".to_owned()), Value::Bytes(vec![0x01])));
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("unknown protected-header label must be rejected");

    assert_eq!(err, TokenVerifyError::EncryptedPayloadMalformed);
}

#[test]
fn negative_08_unknown_realm_kid() {
    let bytes = mutate_encrypt0(|encrypt0| {
        encrypt0.protected.header.key_id = b"kid.not.registered".to_vec();
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("unknown realm kid must be rejected");

    assert_eq!(
        err,
        TokenVerifyError::UnknownRealmKid {
            kid: "kid.not.registered".to_owned(),
        }
    );
}

#[test]
fn negative_09_realm_key_out_of_window() {
    let mut registry = valid_realm_registry();
    registry.insert(
        REALM_KID.to_owned(),
        RealmPrivateKeyEntry {
            kem_sk: Zeroizing::new(bytes_2400(WAVE_B_MLKEM_SECRET_HEX)),
            ecdh_sk: StaticSecret::from(bytes_32(WAVE_B_X25519_REALM_SK_HEX)),
            realm: RealmId::new("llm"),
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_750_000_000_000),
        },
    );

    let err = decrypt_payload(
        &positive_encrypt0_bytes(),
        &registry,
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("expired realm key must be rejected");

    assert_eq!(
        err,
        TokenVerifyError::RealmKeyOutOfWindow {
            now: now(),
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_750_000_000_000),
        }
    );
}

#[test]
fn negative_10_realm_key_realm_mismatch() {
    let mut registry = valid_realm_registry();
    registry.insert(
        REALM_KID.to_owned(),
        RealmPrivateKeyEntry {
            kem_sk: Zeroizing::new(bytes_2400(WAVE_B_MLKEM_SECRET_HEX)),
            ecdh_sk: StaticSecret::from(bytes_32(WAVE_B_X25519_REALM_SK_HEX)),
            realm: RealmId::new("sql"),
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_950_000_000_000),
        },
    );

    let err = decrypt_payload(
        &positive_encrypt0_bytes(),
        &registry,
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("realm mismatch on key entry must be rejected");

    assert_eq!(
        err,
        TokenVerifyError::RealmKeyRealmMismatch {
            expected: "llm".to_owned(),
            found: "sql".to_owned(),
        }
    );
}

#[test]
fn negative_11_tag_tamper_fails_decryption() {
    let bytes = mutate_encrypt0(|encrypt0| {
        let ciphertext = encrypt0
            .ciphertext
            .as_mut()
            .expect("positive vector includes ciphertext");
        let last = ciphertext
            .last_mut()
            .expect("ciphertext+tag must contain at least one byte");
        *last ^= 0x01;
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("tampered tag must fail decryption");

    assert_eq!(err, TokenVerifyError::DecryptionFailed);
}

#[test]
fn negative_12_kem_ct_tamper_fails_decryption() {
    let bytes = mutate_encrypt0(|encrypt0| {
        let kem_ct = rest_bstr_mut(encrypt0, "kem_ct");
        kem_ct[0] ^= 0x01;
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("tampered kem_ct must fail decryption");

    assert_eq!(err, TokenVerifyError::DecryptionFailed);
}

#[test]
fn negative_13_ecdh_pk_tamper_fails_decryption() {
    let bytes = mutate_encrypt0(|encrypt0| {
        let ecdh_eph_pk = rest_bstr_mut(encrypt0, "ecdh_eph_pk");
        ecdh_eph_pk[0] ^= 0x01;
    });

    let err = decrypt_payload(
        &bytes,
        &valid_realm_registry(),
        "llm",
        &composition_claims(),
        now(),
    )
    .expect_err("tampered ecdh_eph_pk must fail decryption");

    assert_eq!(err, TokenVerifyError::DecryptionFailed);
}

#[test]
fn negative_14_aad_mismatch_fails_decryption() {
    let mut claims = composition_claims();
    claims.config_uuid =
        Uuid::parse_str("aaaaaaaa-0000-4000-8000-ffffffffffff").expect("test UUID must be valid");

    let err = decrypt_payload(
        &positive_encrypt0_bytes(),
        &valid_realm_registry(),
        "llm",
        &claims,
        now(),
    )
    .expect_err("AAD mismatch must fail decryption");

    assert_eq!(err, TokenVerifyError::DecryptionFailed);
}

#[test]
fn negative_15_inner_realm_mismatch() {
    let claims = composition_claims();
    let mut plaintext_json: serde_json::Value =
        serde_json::from_slice(&positive_plaintext_bytes()).expect("plaintext JSON must parse");
    plaintext_json["realm"] = serde_json::Value::String("sql".to_owned());
    let altered_plaintext = serde_json::to_vec(&plaintext_json).expect("JSON must serialize");

    let realm_public = RealmPublicKey::new(
        REALM_KID,
        RealmId::new("llm"),
        decode_hex_file(WAVE_B_MLKEM_PUBLIC_HEX),
        bytes_32(WAVE_B_X25519_REALM_PK_HEX),
        ClientUnixMillis(1_700_000_000_000),
        ClientUnixMillis(1_950_000_000_000),
    )
    .expect("realm public key vector must be valid");

    let encrypted = encrypt_payload_with_test_inputs(
        &altered_plaintext,
        &realm_public,
        AeadAadInputs {
            realm: &claims.realm,
            tenant: claims.tenant,
            inst: claims.inst,
            step: claims.step,
            config_uuid: claims.config_uuid,
            kid: &claims.kid,
        },
        EncryptTestInputs {
            mlkem_encapsulation_m: bytes_32(WAVE_B_MLKEM_ENCAPS_M_HEX),
            x25519_eph_private: bytes_32(WAVE_B_X25519_EPH_SK_HEX),
            nonce: decode_hex_file(WAVE_B_NONCE_HEX)
                .try_into()
                .expect("nonce vector must be 12 bytes"),
        },
    )
    .expect("deterministic vector encryption should succeed");

    let encrypted_bytes = encrypted
        .into_inner()
        .to_vec()
        .expect("COSE_Encrypt0 should serialize");

    let err = decrypt_payload(
        &encrypted_bytes,
        &valid_realm_registry(),
        "llm",
        &claims,
        now(),
    )
    .expect_err("inner realm mismatch must be rejected");

    assert_eq!(
        err,
        TokenVerifyError::InnerRealmMismatch {
            expected: "llm".to_owned(),
            found: "sql".to_owned(),
        }
    );
}
