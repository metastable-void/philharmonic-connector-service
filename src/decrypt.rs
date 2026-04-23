use std::boxed::Box;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use coset::{Algorithm, CborSerializable, CoseEncrypt0, Label, cbor::value::Value, iana};
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use philharmonic_connector_common::ConnectorTokenClaims;
use philharmonic_types::{Sha256, UnixMillis, Uuid};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, Zeroizing};

use crate::{RealmPrivateKeyRegistry, TokenVerifyError};

const EXTERNAL_AAD_DIGEST_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"philharmonic/wave-b/hybrid-kem/v1/aead-key";
const KEM_CT_LEN: usize = 1088;
const KEM_SS_LEN: usize = 32;
const ECDH_SS_LEN: usize = 32;
const HKDF_IKM_LEN: usize = KEM_SS_LEN + ECDH_SS_LEN;
const AEAD_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const ECDH_EPH_PK_LEN: usize = 32;

struct ParsedEncrypt0 {
    encrypt0: CoseEncrypt0,
    realm_kid: String,
    nonce: [u8; NONCE_LEN],
    kem_ct: [u8; KEM_CT_LEN],
    ecdh_eph_pk: [u8; ECDH_EPH_PK_LEN],
}

/// Decrypt a verified connector payload with the realm private-key registry.
pub fn decrypt_payload(
    cose_encrypt0_bytes: &[u8],
    registry: &RealmPrivateKeyRegistry,
    service_realm: &str,
    claims: &ConnectorTokenClaims,
    now: UnixMillis,
) -> Result<Zeroizing<Vec<u8>>, TokenVerifyError> {
    let parsed = parse_encrypt0(cose_encrypt0_bytes)?;

    let realm_key =
        registry
            .lookup(&parsed.realm_kid)
            .ok_or_else(|| TokenVerifyError::UnknownRealmKid {
                kid: parsed.realm_kid.clone(),
            })?;

    if now < realm_key.not_before || now >= realm_key.not_after {
        return Err(TokenVerifyError::RealmKeyOutOfWindow {
            now,
            not_before: realm_key.not_before,
            not_after: realm_key.not_after,
        });
    }

    if realm_key.realm.as_str() != service_realm {
        return Err(TokenVerifyError::RealmKeyRealmMismatch {
            expected: service_realm.to_owned(),
            found: realm_key.realm.as_str().to_owned(),
        });
    }

    let kem_ss = decapsulate_kem_ss(&realm_key.kem_sk, parsed.kem_ct)?;
    let ecdh_eph_pk = PublicKey::from(parsed.ecdh_eph_pk);
    let ecdh_ss = Zeroizing::new(realm_key.ecdh_sk.diffie_hellman(&ecdh_eph_pk).to_bytes());

    let mut ikm = Zeroizing::new([0_u8; HKDF_IKM_LEN]);
    ikm[..KEM_SS_LEN].copy_from_slice(&kem_ss[..]);
    ikm[KEM_SS_LEN..].copy_from_slice(&ecdh_ss[..]);

    let (_, hkdf) = Hkdf::<sha2::Sha256>::extract(Some(b""), &ikm[..]);

    let mut aead_key_bytes = [0_u8; AEAD_KEY_LEN];
    hkdf.expand(HKDF_INFO, &mut aead_key_bytes)
        .map_err(|_| TokenVerifyError::DecryptionFailed)?;

    let aead_key = SecretBox::new(Box::new(aead_key_bytes));
    aead_key_bytes.zeroize();
    let external_aad = compute_external_aad_digest(claims)?;

    let plaintext = parsed
        .encrypt0
        .decrypt_ciphertext(
            &external_aad,
            || TokenVerifyError::DecryptionFailed,
            |ciphertext, aad| decrypt_aes_gcm(ciphertext, aad, parsed.nonce, &aead_key),
        )
        .map_err(|_| TokenVerifyError::DecryptionFailed)?;

    let plaintext = Zeroizing::new(plaintext);
    let inner_realm = parse_inner_realm(&plaintext).ok_or(TokenVerifyError::DecryptionFailed)?;
    if inner_realm != claims.realm {
        return Err(TokenVerifyError::InnerRealmMismatch {
            expected: claims.realm.clone(),
            found: inner_realm,
        });
    }

    Ok(plaintext)
}

fn parse_encrypt0(cose_encrypt0_bytes: &[u8]) -> Result<ParsedEncrypt0, TokenVerifyError> {
    let encrypt0 = CoseEncrypt0::from_slice(cose_encrypt0_bytes)
        .map_err(|_| TokenVerifyError::EncryptedPayloadMalformed)?;

    let ciphertext = encrypt0
        .ciphertext
        .as_ref()
        .ok_or(TokenVerifyError::EncryptedPayloadMalformed)?;
    if ciphertext.is_empty() {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    if !encrypt0.unprotected.is_empty() {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    let header = &encrypt0.protected.header;

    if !matches!(
        header.alg,
        Some(Algorithm::Assigned(iana::Algorithm::A256GCM))
    ) {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    if !header.crit.is_empty()
        || header.content_type.is_some()
        || !header.partial_iv.is_empty()
        || !header.counter_signatures.is_empty()
    {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    if header.key_id.is_empty() || header.key_id.len() > u8::MAX as usize {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    if header.iv.len() != NONCE_LEN {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    let realm_kid = std::str::from_utf8(&header.key_id)
        .map_err(|_| TokenVerifyError::EncryptedPayloadMalformed)?
        .to_owned();

    let nonce: [u8; NONCE_LEN] = header
        .iv
        .as_slice()
        .try_into()
        .map_err(|_| TokenVerifyError::EncryptedPayloadMalformed)?;

    let mut kem_ct = None;
    let mut ecdh_eph_pk = None;

    for (label, value) in &header.rest {
        match label {
            Label::Text(name) if name == "kem_ct" => {
                if kem_ct.is_some() {
                    return Err(TokenVerifyError::EncryptedPayloadMalformed);
                }
                let bytes = match value {
                    Value::Bytes(bytes) => bytes,
                    _ => return Err(TokenVerifyError::EncryptedPayloadMalformed),
                };
                if bytes.len() != KEM_CT_LEN {
                    return Err(TokenVerifyError::EncryptedPayloadMalformed);
                }
                kem_ct = Some(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| TokenVerifyError::EncryptedPayloadMalformed)?,
                );
            }
            Label::Text(name) if name == "ecdh_eph_pk" => {
                if ecdh_eph_pk.is_some() {
                    return Err(TokenVerifyError::EncryptedPayloadMalformed);
                }
                let bytes = match value {
                    Value::Bytes(bytes) => bytes,
                    _ => return Err(TokenVerifyError::EncryptedPayloadMalformed),
                };
                if bytes.len() != ECDH_EPH_PK_LEN {
                    return Err(TokenVerifyError::EncryptedPayloadMalformed);
                }
                ecdh_eph_pk = Some(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| TokenVerifyError::EncryptedPayloadMalformed)?,
                );
            }
            _ => return Err(TokenVerifyError::EncryptedPayloadMalformed),
        }
    }

    let kem_ct = kem_ct.ok_or(TokenVerifyError::EncryptedPayloadMalformed)?;
    let ecdh_eph_pk = ecdh_eph_pk.ok_or(TokenVerifyError::EncryptedPayloadMalformed)?;

    if header.rest.len() != 2 {
        return Err(TokenVerifyError::EncryptedPayloadMalformed);
    }

    Ok(ParsedEncrypt0 {
        encrypt0,
        realm_kid,
        nonce,
        kem_ct,
        ecdh_eph_pk,
    })
}

fn decapsulate_kem_ss(
    kem_sk_bytes: &Zeroizing<[u8; 2400]>,
    kem_ct: [u8; KEM_CT_LEN],
) -> Result<Zeroizing<[u8; KEM_SS_LEN]>, TokenVerifyError> {
    type MlKemDecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

    let dk_encoded: Encoded<MlKemDecapsulationKey> = kem_sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TokenVerifyError::DecryptionFailed)?;
    let dk = MlKemDecapsulationKey::from_bytes(&dk_encoded);

    let kem_ct = ml_kem::Ciphertext::<MlKem768>::from(kem_ct);
    let kem_ss = dk
        .decapsulate(&kem_ct)
        .map_err(|_| TokenVerifyError::DecryptionFailed)?;

    Ok(Zeroizing::new(kem_ss.into()))
}

fn decrypt_aes_gcm(
    ciphertext_and_tag: &[u8],
    aad: &[u8],
    nonce: [u8; NONCE_LEN],
    aead_key: &SecretBox<[u8; AEAD_KEY_LEN]>,
) -> Result<Vec<u8>, TokenVerifyError> {
    // The AEAD API requires an unwrapped key reference at call time.
    let cipher = Aes256Gcm::new_from_slice(aead_key.expose_secret())
        .map_err(|_| TokenVerifyError::DecryptionFailed)?;

    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| TokenVerifyError::DecryptionFailed)
}

#[derive(Serialize)]
struct ExternalAadCbor<'a> {
    realm: &'a str,
    tenant: Uuid,
    inst: Uuid,
    step: u64,
    config_uuid: Uuid,
    kid: &'a str,
}

fn compute_external_aad_digest(
    claims: &ConnectorTokenClaims,
) -> Result<[u8; EXTERNAL_AAD_DIGEST_LEN], TokenVerifyError> {
    let mut encoded = Vec::new();
    let cbor = ExternalAadCbor {
        realm: &claims.realm,
        tenant: claims.tenant,
        inst: claims.inst,
        step: claims.step,
        config_uuid: claims.config_uuid,
        kid: &claims.kid,
    };

    ciborium::ser::into_writer(&cbor, &mut encoded)
        .map_err(|_| TokenVerifyError::DecryptionFailed)?;
    Ok(*Sha256::of(&encoded).as_bytes())
}

#[derive(Deserialize)]
struct InnerRealmEnvelope {
    realm: String,
}

fn parse_inner_realm(plaintext: &[u8]) -> Option<String> {
    serde_json::from_slice::<InnerRealmEnvelope>(plaintext)
        .ok()
        .map(|value| value.realm)
}
