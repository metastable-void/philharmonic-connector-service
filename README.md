# philharmonic-connector-service

Service-side verification library for the Philharmonic connector
layer.

This crate runs inside a per-realm connector service binary. Given
an opaque token byte slice (a `COSE_Sign1` structure in the HTTP
`Authorization` header) and an opaque payload byte slice (a
`COSE_Encrypt0` structure in the `X-Encrypted-Payload` header), it
walks the approved verification order, rejects with a typed error
for every distinct failure mode, and returns a narrowed
`ConnectorCallContext` for the dispatch layer to hand to a connector
implementation.

Part of the Philharmonic workspace:
https://github.com/metastable-void/philharmonic-workspace

## What's in this crate

- `verify_token` / `verify_token_with_limit` — the verification
  entry points. `verify_token` uses the default `MAX_PAYLOAD_BYTES`
  (1 MiB) cap on the payload bytes before hashing; the `_with_limit`
  variant lets a bin override that cap when deployment policy
  requires.
- `MintingKeyRegistry` + `MintingKeyEntry` — a `kid`-indexed lookup
  of Ed25519 verifying keys, each tagged with a
  `not_before` / `not_after` validity window for key rotation.
- `TokenVerifyError` — the rejection taxonomy. One variant per
  distinct failure mode (malformed COSE, unknown `kid`, expired,
  not-yet-valid, signature mismatch, payload-size-over-limit,
  payload-hash mismatch, realm mismatch, etc.). Deliberately granular
  so observability pipelines can count each class separately.
- Re-exports of the common vocabulary + the raw
  `ed25519_dalek::VerifyingKey` so bin crates can assemble a registry
  without pulling `ed25519-dalek` into their own dep list.

The verification sequence enforces an explicit 11-step order; the
exact ordering is pinned in
[`docs/design/crypto-proposals/2026-04-22-phase-5-wave-a-cose-sign1-tokens.md`](../docs/design/crypto-proposals/2026-04-22-phase-5-wave-a-cose-sign1-tokens.md).
Rejection happens as early as possible so obviously-malformed input
doesn't consume CPU.

## What's out of scope

- HTTP framing and response serialization. The bin crate wraps this
  library (its own binary entry point, its own router, its own TLS
  termination).
- Key loading from filesystem / environment / KMS. This library
  takes already-parsed keys; the bin is responsible for sourcing
  them.

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

    let context = verify_token(
        token_bytes,
        payload_bytes,
        "llm",
        &registry,
        UnixMillis(1_800_000_000_000),
    )?;

    // `context.issued_at` comes from the `iat` claim (mint time),
    // not from the verification timestamp — so logs and audit
    // entries see the authoritative mint time.
    let _ = context.issued_at;
    Ok(())
}
```

## Verification + security notes

- Primitives: `ed25519-dalek 2` for signature verification,
  `sha2 0.11` for payload hashing, `subtle 2` for constant-time
  comparisons, `coset 0.4` for COSE framing. No custom crypto.
- Side-channel discipline: payload-hash comparison uses
  `subtle::ConstantTimeEq`; unknown-`kid` rejection happens before
  any signature work; the 1 MiB payload cap bounds the cost of a
  malicious large-payload replay.
- Known-answer test vectors (positive + 10 negative) live under
  [`docs/crypto-vectors/wave-a/`](../docs/crypto-vectors/wave-a/)
  and are verified byte-for-byte by the test suite.
- Design background:
  [`docs/design/11-security-and-cryptography.md`](../docs/design/11-security-and-cryptography.md),
  [`docs/design/08-connector-architecture.md`](../docs/design/08-connector-architecture.md).

## Versioning notes

- `0.1.0` — first publish (with Wave B); bundles the Wave A verify
  path with the Wave B decrypt path so `0.1.0` is a cohesive
  release of the service-side library.

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MPL](LICENSE-MPL).

SPDX-License-Identifier: `Apache-2.0 OR MPL-2.0`

## Contributing

This crate is developed as a submodule of the Philharmonic
workspace. Workspace-wide development conventions — git workflow,
script wrappers, Rust code rules, versioning, terminology — live
in the workspace meta-repo at
[metastable-void/philharmonic-workspace](https://github.com/metastable-void/philharmonic-workspace),
authoritatively in its
[`CONTRIBUTING.md`](https://github.com/metastable-void/philharmonic-workspace/blob/main/CONTRIBUTING.md).
