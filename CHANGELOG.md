# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.0.0]

Name reservation on crates.io. No functional content yet.
