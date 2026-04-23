use philharmonic_types::UnixMillis;

/// Token verification failures in step-order.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TokenVerifyError {
    /// COSE structure or CBOR claim payload was malformed.
    #[error("malformed token")]
    Malformed,

    /// Protected header algorithm was not EdDSA (`-8`).
    #[error("token algorithm is not allowed")]
    AlgorithmNotAllowed,

    /// No verifier key was registered for the protected-header kid.
    #[error("unknown minting key id '{kid}'")]
    UnknownKid { kid: String },

    /// The verifier key exists but is not valid at `now`.
    #[error("key is outside validity window at {now:?}: [{not_before:?}, {not_after:?})")]
    KeyOutOfWindow {
        now: UnixMillis,
        not_before: UnixMillis,
        not_after: UnixMillis,
    },

    /// Caller-supplied payload exceeded the configured verification limit.
    #[error("payload exceeds maximum size: limit {limit} bytes, actual {actual} bytes")]
    PayloadTooLarge { limit: usize, actual: usize },

    /// Ed25519 signature validation failed.
    #[error("invalid token signature")]
    BadSignature,

    /// Protected-header kid and claim kid diverged.
    #[error("kid mismatch between protected header '{protected}' and claims '{claims}'")]
    KidInconsistent { protected: String, claims: String },

    /// Token expiry was in the past (or equal to `now`).
    #[error("token expired at {exp:?}, now is {now:?}")]
    Expired { exp: UnixMillis, now: UnixMillis },

    /// Caller-supplied payload hash did not match claims.
    #[error("payload hash mismatch")]
    PayloadHashMismatch,

    /// Token realm did not match this service realm.
    #[error("realm mismatch: expected '{expected}', found '{found}'")]
    RealmMismatch { expected: String, found: String },

    /// Encrypted payload COSE/CBOR framing or protected headers were malformed.
    #[error("malformed encrypted payload")]
    EncryptedPayloadMalformed,

    /// No realm private key was registered for the protected-header kid.
    #[error("unknown realm key id '{kid}'")]
    UnknownRealmKid { kid: String },

    /// Realm private key exists but is not valid at `now`.
    #[error("realm key is outside validity window at {now:?}: [{not_before:?}, {not_after:?})")]
    RealmKeyOutOfWindow {
        now: UnixMillis,
        not_before: UnixMillis,
        not_after: UnixMillis,
    },

    /// Realm private key entry is registered under a different realm.
    #[error("realm key realm mismatch: expected '{expected}', found '{found}'")]
    RealmKeyRealmMismatch { expected: String, found: String },

    /// Hybrid-KEM decapsulation, AAD binding, or AEAD tag verification failed.
    #[error("encrypted payload decryption failed")]
    DecryptionFailed,

    /// Inner decrypted payload `realm` field did not match token realm.
    #[error("inner payload realm mismatch: expected '{expected}', found '{found}'")]
    InnerRealmMismatch { expected: String, found: String },
}
