//! Verification primitives for Philharmonic connector authorization tokens.

mod context;
mod decrypt;
mod error;
mod realm_keys;
mod registry;
mod verify;

pub use decrypt::decrypt_payload;
pub use ed25519_dalek::VerifyingKey;
pub use error::TokenVerifyError;
pub use philharmonic_connector_common::{ConnectorCallContext, ConnectorTokenClaims};
pub use philharmonic_types::{Sha256, UnixMillis, Uuid};
pub use realm_keys::{RealmPrivateKeyEntry, RealmPrivateKeyRegistry};
pub use registry::{MintingKeyEntry, MintingKeyRegistry};
pub use verify::{
    MAX_PAYLOAD_BYTES, VerifiedDecryptedPayload, verify_and_decrypt, verify_and_decrypt_with_limit,
    verify_token, verify_token_with_limit,
};
