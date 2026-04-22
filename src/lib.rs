//! Verification primitives for Philharmonic connector authorization tokens.

mod context;
mod error;
mod registry;
mod verify;

pub use ed25519_dalek::VerifyingKey;
pub use error::TokenVerifyError;
pub use philharmonic_connector_common::{ConnectorCallContext, ConnectorTokenClaims};
pub use philharmonic_types::{Sha256, UnixMillis, Uuid};
pub use registry::{MintingKeyEntry, MintingKeyRegistry};
pub use verify::{MAX_PAYLOAD_BYTES, verify_token, verify_token_with_limit};
