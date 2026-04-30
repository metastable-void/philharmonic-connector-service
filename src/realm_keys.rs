use std::collections::HashMap;

use philharmonic_connector_common::RealmId;
use philharmonic_types::UnixMillis;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

/// One realm-private hybrid KEM key entry plus validity metadata.
#[derive(Clone)]
pub struct RealmPrivateKeyEntry {
    /// ML-KEM-768 decapsulation key bytes (2400 bytes, zeroized on drop).
    pub kem_sk: Zeroizing<[u8; 2400]>,
    /// X25519 static private key (zeroized on drop).
    pub ecdh_sk: Zeroizing<StaticSecret>,
    /// Realm that owns this key entry.
    pub realm: RealmId,
    /// Lower bound (inclusive) of this key's acceptance window.
    pub not_before: UnixMillis,
    /// Upper bound (exclusive) of this key's acceptance window.
    pub not_after: UnixMillis,
}

/// In-memory lookup table of realm private keys by key identifier.
#[derive(Clone, Default)]
pub struct RealmPrivateKeyRegistry {
    by_kid: HashMap<String, RealmPrivateKeyEntry>,
}

impl RealmPrivateKeyRegistry {
    /// Construct an empty realm private-key registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace one realm private-key entry.
    pub fn insert(&mut self, kid: String, entry: RealmPrivateKeyEntry) {
        self.by_kid.insert(kid, entry);
    }

    /// Look up one realm private key by key identifier.
    pub fn lookup(&self, kid: &str) -> Option<&RealmPrivateKeyEntry> {
        self.by_kid.get(kid)
    }
}
