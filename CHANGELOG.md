# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-23

### Added

- Added `MintingKeyEntry` and `MintingKeyRegistry` for key-id lookup with
  key validity windows.
- Added `verify_token` / `verify_token_with_limit` implementing the
  approved 11-step verification order for COSE_Sign1 connector tokens.
- Added `MAX_PAYLOAD_BYTES` default ceiling (1 MiB) and explicit
  payload-size rejection before hashing.
- Added `TokenVerifyError` taxonomy for all rejection modes in the
  verification path.
- Added known-answer tests for Wave A positive vector plus 10 negative
  vectors asserting exact error variants.
- Added README usage documentation.
- Bump `philharmonic-connector-common` pin `"0.1"` → `"0.2"`. Picks up the
  new `iat` claim on `ConnectorTokenClaims`; `ConnectorCallContext.issued_at`
  is now populated from `claims.iat` (mint time) instead of `now` (verify
  time), closing the Wave A Gate-2 follow-up. `build_call_context` drops
  the `now` parameter and is now pure in the claim set.
- Added Wave B `RealmPrivateKeyEntry` and `RealmPrivateKeyRegistry` for
  realm-scoped hybrid-KEM private key lookup with validity-window checks.
- Added Wave B `decrypt_payload` implementing approved steps 12/12a/13/14/15
  (strict COSE_Encrypt0/header validation, registry checks, hybrid decapsulation,
  AAD-bound AES-256-GCM decrypt, inner-realm assertion).
- Added `verify_and_decrypt` / `verify_and_decrypt_with_limit` APIs while
  preserving existing token-only `verify_token` surfaces.
- Extended `TokenVerifyError` with Wave B-specific rejection variants:
  malformed encrypted payload, realm key lookup/window/realm mismatch,
  decryption failure folding, and inner realm mismatch.
- Added Wave B positive vectors, 15 negative-path vector tests with exact
  variant assertions, and an end-to-end Wave A × Wave B composition roundtrip
  test asserting byte-for-byte vector equality.

### Changed

- Tightened Wave B AEAD key handling by zeroizing stack `aead_key_bytes` immediately after copying into `SecretBox`.
- Removed dead HKDF `prk_bytes` scratch handling and unused PRK tuple binding; HKDF expansion continues through the existing `hkdf` context unchanged.
