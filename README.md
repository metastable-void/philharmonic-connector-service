# philharmonic-connector-service

Verification library for Phase 5 connector authorization tokens in the
Philharmonic workspace. This crate verifies Ed25519 `COSE_Sign1`
authorization tokens, enforces claim checks in the approved order, and
returns a narrowed `ConnectorCallContext`.

Part of the Philharmonic workspace:
https://github.com/metastable-void/philharmonic-workspace

## Quick start

```rust
use philharmonic_connector_service::{
    MintingKeyEntry, MintingKeyRegistry, UnixMillis, VerifyingKey, verify_token,
};

fn verify_example(
    token_bytes: &[u8],
    payload_bytes: &[u8],
    vk: VerifyingKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = MintingKeyRegistry::new();
    registry.insert(
        "lowerer.main-2026-04-22-3c8a91d0",
        MintingKeyEntry {
            vk,
            not_before: UnixMillis(1_700_000_000_000),
            not_after: UnixMillis(1_950_000_000_000),
        },
    );

    let _context = verify_token(
        token_bytes,
        payload_bytes,
        "llm",
        &registry,
        UnixMillis(1_800_000_000_000),
    )?;

    Ok(())
}
```

Real services should parse config in their bin crate, then populate
`MintingKeyRegistry` with already-parsed key entries.

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`.

SPDX-License-Identifier: Apache-2.0 OR MPL-2.0
