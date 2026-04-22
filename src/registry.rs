use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use philharmonic_types::UnixMillis;

/// One minting key plus its validity window.
#[derive(Clone, Debug)]
pub struct MintingKeyEntry {
    /// Ed25519 verifying key.
    pub vk: VerifyingKey,
    /// Lower bound (inclusive) of this key's acceptance window.
    pub not_before: UnixMillis,
    /// Upper bound (exclusive) of this key's acceptance window.
    pub not_after: UnixMillis,
}

/// In-memory lookup table of minting keys by key identifier.
#[derive(Clone, Debug, Default)]
pub struct MintingKeyRegistry {
    by_kid: HashMap<String, MintingKeyEntry>,
}

impl MintingKeyRegistry {
    /// Construct an empty minting-key registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace one minting key entry.
    pub fn insert(
        &mut self,
        kid: impl Into<String>,
        entry: MintingKeyEntry,
    ) -> Option<MintingKeyEntry> {
        self.by_kid.insert(kid.into(), entry)
    }

    /// Look up one minting key by key identifier.
    pub fn lookup(&self, kid: &str) -> Option<&MintingKeyEntry> {
        self.by_kid.get(kid)
    }
}
