use coset::CborSerializable;
use ed25519_dalek::VerifyingKey;
use philharmonic_connector_client::{
    AeadAadInputs, EncryptTestInputs, LowererSigningKey, Sha256, UnixMillis as ClientUnixMillis,
    Zeroizing as ClientZeroizing, encrypt_payload_with_test_inputs,
};
use philharmonic_connector_common::{ConnectorTokenClaims, RealmId, RealmPublicKey};
use philharmonic_connector_service::{
    MintingKeyEntry, MintingKeyRegistry, RealmPrivateKeyEntry, RealmPrivateKeyRegistry, UnixMillis,
    verify_and_decrypt, verify_token,
};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

const WAVE_A_SEED_HEX: &str = include_str!("vectors/wave-a/wave_a_seed.hex");
const WAVE_A_PUBLIC_HEX: &str = include_str!("vectors/wave-a/wave_a_public.hex");
const WAVE_A_COMPOSITION_CLAIMS_CBOR_HEX: &str =
    include_str!("vectors/wave-a/wave_a_composition_claims.cbor.hex");
const WAVE_A_COMPOSITION_PAYLOAD_HASH_HEX: &str =
    include_str!("vectors/wave-a/wave_a_composition_payload_hash.hex");
const WAVE_A_COMPOSITION_COSE_SIGN1_HEX: &str =
    include_str!("vectors/wave-a/wave_a_composition_cose_sign1.hex");

const WAVE_B_MLKEM_PUBLIC_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_public.hex");
const WAVE_B_MLKEM_SECRET_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_secret.hex");
const WAVE_B_MLKEM_ENCAPS_M_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_encaps_m.hex");
const WAVE_B_X25519_REALM_SK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_realm_sk.hex");
const WAVE_B_X25519_REALM_PK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_realm_pk.hex");
const WAVE_B_X25519_EPH_SK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_eph_sk.hex");
const WAVE_B_NONCE_HEX: &str = include_str!("vectors/wave-b/wave_b_nonce.hex");
const WAVE_B_PLAINTEXT_HEX: &str = include_str!("vectors/wave-b/wave_b_plaintext.hex");
const WAVE_B_COSE_ENCRYPT0_HEX: &str = include_str!("vectors/wave-b/wave_b_cose_encrypt0.hex");
const WAVE_B_PAYLOAD_HASH_HEX: &str = include_str!("vectors/wave-b/wave_b_payload_hash.hex");

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
    let bytes = decode_hex_file(WAVE_A_COMPOSITION_CLAIMS_CBOR_HEX);
    let mut reader = bytes.as_slice();
    ciborium::de::from_reader(&mut reader).expect("composition claims vector must decode")
}

fn minting_registry() -> MintingKeyRegistry {
    let mut registry = MintingKeyRegistry::new();
    registry.insert(
        "lowerer.main-2026-04-22-3c8a91d0",
        MintingKeyEntry {
            vk: VerifyingKey::from_bytes(&bytes_32(WAVE_A_PUBLIC_HEX))
                .expect("wave-a public key vector must decode"),
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_950_000_000_000),
        },
    );
    registry
}

fn realm_private_registry() -> RealmPrivateKeyRegistry {
    let mut registry = RealmPrivateKeyRegistry::new();
    registry.insert(
        REALM_KID.to_owned(),
        RealmPrivateKeyEntry {
            kem_sk: Zeroizing::new(bytes_2400(WAVE_B_MLKEM_SECRET_HEX)),
            ecdh_sk: Zeroizing::new(StaticSecret::from(bytes_32(WAVE_B_X25519_REALM_SK_HEX))),
            realm: RealmId::new("llm"),
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_950_000_000_000),
        },
    );
    registry
}

#[test]
fn wave_a_wave_b_composition_roundtrip_matches_vectors() {
    let claims = composition_claims();

    let realm_public = RealmPublicKey::new(
        REALM_KID,
        RealmId::new("llm"),
        decode_hex_file(WAVE_B_MLKEM_PUBLIC_HEX),
        bytes_32(WAVE_B_X25519_REALM_PK_HEX),
        ClientUnixMillis(1_700_000_000_000),
        ClientUnixMillis(1_950_000_000_000),
    )
    .expect("realm public key vector must be valid");

    let plaintext = decode_hex_file(WAVE_B_PLAINTEXT_HEX);
    let encrypted_payload = encrypt_payload_with_test_inputs(
        &plaintext,
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
    .expect("deterministic Wave B encrypt should succeed");

    let encrypted_payload_bytes = encrypted_payload
        .as_inner()
        .clone()
        .to_vec()
        .expect("COSE_Encrypt0 should serialize");
    assert_eq!(
        encrypted_payload_bytes,
        decode_hex_file(WAVE_B_COSE_ENCRYPT0_HEX),
        "Wave B envelope must match committed vector"
    );

    let payload_hash = Sha256::of(&encrypted_payload_bytes);
    assert_eq!(
        payload_hash.as_bytes(),
        &bytes_32(WAVE_A_COMPOSITION_PAYLOAD_HASH_HEX),
        "Wave A composition payload_hash must match"
    );
    assert_eq!(
        payload_hash.as_bytes(),
        &bytes_32(WAVE_B_PAYLOAD_HASH_HEX),
        "Wave B payload_hash vector must match"
    );

    assert_eq!(
        claims.payload_hash.as_bytes(),
        payload_hash.as_bytes(),
        "composition claims must commit to Wave B ciphertext"
    );

    let signing_key = LowererSigningKey::from_seed(
        ClientZeroizing::new(bytes_32(WAVE_A_SEED_HEX)),
        claims.kid.clone(),
    );
    let signed_token = signing_key
        .mint_token(&claims)
        .expect("Wave A mint should succeed for composition claims");
    let token_bytes = signed_token
        .as_inner()
        .clone()
        .to_vec()
        .expect("COSE_Sign1 should serialize");
    assert_eq!(
        token_bytes,
        decode_hex_file(WAVE_A_COMPOSITION_COSE_SIGN1_HEX),
        "Wave A composition token must match committed vector"
    );

    let context = verify_token(
        &token_bytes,
        &encrypted_payload_bytes,
        "llm",
        &minting_registry(),
        now(),
    )
    .expect("Wave A verification should succeed");
    assert_eq!(context.tenant_id, claims.tenant);
    assert_eq!(context.instance_id, claims.inst);
    assert_eq!(context.step_seq, claims.step);
    assert_eq!(context.config_uuid, claims.config_uuid);

    let verified_and_decrypted = verify_and_decrypt(
        &token_bytes,
        &encrypted_payload_bytes,
        "llm",
        &minting_registry(),
        &realm_private_registry(),
        now(),
    )
    .expect("Wave A verify + Wave B decrypt should succeed");

    assert_eq!(&*verified_and_decrypted.plaintext, &plaintext);
}
