use coset::{Algorithm, CborSerializable, CoseSign1, iana};
use ed25519_dalek::{Signature, Verifier};
use philharmonic_connector_common::{ConnectorCallContext, ConnectorTokenClaims};
use philharmonic_types::UnixMillis;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    MintingKeyRegistry, RealmPrivateKeyRegistry, TokenVerifyError, context::build_call_context,
    decrypt::decrypt_payload,
};

/// Default maximum accepted payload size in bytes (1 MiB).
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;

#[derive(Debug)]
struct VerifiedToken {
    claims: ConnectorTokenClaims,
    context: ConnectorCallContext,
}

/// Verified connector call metadata plus decrypted payload bytes.
#[derive(Debug)]
pub struct VerifiedDecryptedPayload {
    /// Verified connector call context derived from token claims.
    pub context: ConnectorCallContext,
    /// Decrypted payload plaintext bytes.
    pub plaintext: Zeroizing<Vec<u8>>,
}

/// Verify a connector authorization token using the default payload-size limit.
pub fn verify_token(
    cose_bytes: &[u8],
    payload_bytes: &[u8],
    service_realm: &str,
    registry: &MintingKeyRegistry,
    now: UnixMillis,
) -> Result<ConnectorCallContext, TokenVerifyError> {
    verify_token_with_limit(
        cose_bytes,
        payload_bytes,
        service_realm,
        registry,
        now,
        MAX_PAYLOAD_BYTES,
    )
}

/// Verify a connector authorization token with a caller-specified payload-size limit.
pub fn verify_token_with_limit(
    cose_bytes: &[u8],
    payload_bytes: &[u8],
    service_realm: &str,
    registry: &MintingKeyRegistry,
    now: UnixMillis,
    max_payload_bytes: usize,
) -> Result<ConnectorCallContext, TokenVerifyError> {
    verify_token_internal(
        cose_bytes,
        payload_bytes,
        service_realm,
        registry,
        now,
        max_payload_bytes,
    )
    .map(|verified| verified.context)
}

/// Verify Wave A token checks and decrypt Wave B payload checks in one call.
pub fn verify_and_decrypt(
    token_cose_bytes: &[u8],
    encrypted_payload_bytes: &[u8],
    service_realm: &str,
    minting_registry: &MintingKeyRegistry,
    realm_registry: &RealmPrivateKeyRegistry,
    now: UnixMillis,
) -> Result<VerifiedDecryptedPayload, TokenVerifyError> {
    verify_and_decrypt_with_limit(
        token_cose_bytes,
        encrypted_payload_bytes,
        service_realm,
        minting_registry,
        realm_registry,
        now,
        MAX_PAYLOAD_BYTES,
    )
}

/// Verify + decrypt with caller-specified payload-size limit.
pub fn verify_and_decrypt_with_limit(
    token_cose_bytes: &[u8],
    encrypted_payload_bytes: &[u8],
    service_realm: &str,
    minting_registry: &MintingKeyRegistry,
    realm_registry: &RealmPrivateKeyRegistry,
    now: UnixMillis,
    max_payload_bytes: usize,
) -> Result<VerifiedDecryptedPayload, TokenVerifyError> {
    let verified = verify_token_internal(
        token_cose_bytes,
        encrypted_payload_bytes,
        service_realm,
        minting_registry,
        now,
        max_payload_bytes,
    )?;

    let plaintext = decrypt_payload(
        encrypted_payload_bytes,
        realm_registry,
        service_realm,
        &verified.claims,
        now,
    )?;

    Ok(VerifiedDecryptedPayload {
        context: verified.context,
        plaintext,
    })
}

fn verify_token_internal(
    cose_bytes: &[u8],
    payload_bytes: &[u8],
    service_realm: &str,
    registry: &MintingKeyRegistry,
    now: UnixMillis,
    max_payload_bytes: usize,
) -> Result<VerifiedToken, TokenVerifyError> {
    // 1. Parse COSE_Sign1.
    let sign1 = CoseSign1::from_slice(cose_bytes).map_err(|_| TokenVerifyError::Malformed)?;

    // 2. Pin algorithm to EdDSA (-8).
    if !matches!(
        sign1.protected.header.alg,
        Some(Algorithm::Assigned(iana::Algorithm::EdDSA))
    ) {
        return Err(TokenVerifyError::AlgorithmNotAllowed);
    }

    // 3. Lookup key by protected-header kid.
    let protected_kid = std::str::from_utf8(sign1.protected.header.key_id.as_slice())
        .map_err(|_| TokenVerifyError::Malformed)?;
    let key_entry = registry
        .lookup(protected_kid)
        .ok_or_else(|| TokenVerifyError::UnknownKid {
            kid: protected_kid.to_owned(),
        })?;

    // 4. Enforce key validity window.
    if now < key_entry.not_before || now >= key_entry.not_after {
        return Err(TokenVerifyError::KeyOutOfWindow {
            now,
            not_before: key_entry.not_before,
            not_after: key_entry.not_after,
        });
    }

    // 5. Enforce payload-size ceiling before hashing.
    if payload_bytes.len() > max_payload_bytes {
        return Err(TokenVerifyError::PayloadTooLarge {
            limit: max_payload_bytes,
            actual: payload_bytes.len(),
        });
    }

    // 6. Verify Ed25519 signature.
    sign1.verify_signature(b"", |signature_bytes, signed_bytes| {
        let signature =
            Signature::try_from(signature_bytes).map_err(|_| TokenVerifyError::BadSignature)?;
        key_entry
            .vk
            .verify(signed_bytes, &signature)
            .map_err(|_| TokenVerifyError::BadSignature)
    })?;

    // 7. Decode claims payload.
    let claims_payload = sign1
        .payload
        .as_deref()
        .ok_or(TokenVerifyError::Malformed)?;
    let mut claims_reader = claims_payload;
    let claims: ConnectorTokenClaims =
        ciborium::de::from_reader(&mut claims_reader).map_err(|_| TokenVerifyError::Malformed)?;

    // 8. Protected-header kid must match claims kid.
    if claims.kid != protected_kid {
        return Err(TokenVerifyError::KidInconsistent {
            protected: protected_kid.to_owned(),
            claims: claims.kid,
        });
    }

    // 9. Expiry check.
    if claims.exp <= now {
        return Err(TokenVerifyError::Expired {
            exp: claims.exp,
            now,
        });
    }

    // 10. Constant-time payload hash comparison.
    let mut hasher = Sha256::new();
    hasher.update(payload_bytes);
    let digest_bytes: [u8; 32] = hasher.finalize().into();
    if !bool::from(claims.payload_hash.as_bytes().ct_eq(&digest_bytes)) {
        return Err(TokenVerifyError::PayloadHashMismatch);
    }

    // 11. Realm binding.
    if claims.realm != service_realm {
        return Err(TokenVerifyError::RealmMismatch {
            expected: service_realm.to_owned(),
            found: claims.realm,
        });
    }

    let context = build_call_context(&claims);

    Ok(VerifiedToken { claims, context })
}
