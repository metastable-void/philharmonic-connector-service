# Phase 5 Wave A reference vectors

Reference byte values for Phase 5 Wave A (COSE_Sign1 connector
authorization tokens). The Rust implementations in
[`philharmonic-connector-client`](../../../philharmonic-connector-client/)
(signing) and
[`philharmonic-connector-service`](../../../philharmonic-connector-service/)
(verification) must reproduce these bytes exactly.

## How these were generated

`gen_wave_a_vectors.py` uses the RFC 8032 §7.1 TEST 1 Ed25519
keypair (a public external reference), deterministic claim-set
constants, and `cbor2` + `cryptography` to produce each artifact.
Ed25519 signing is deterministic per RFC 8032, so the output is
reproducible byte-for-byte from the committed seed + claims.

The script is committed alongside the hex outputs so anyone can
re-run it to verify the vectors.

### Reproducing

```sh
python3 -m venv /tmp/wave-a-vendor
/tmp/wave-a-vendor/bin/pip install cbor2 cose cryptography
/tmp/wave-a-vendor/bin/python \
    tests/crypto-vectors/wave-a/gen_wave_a_vectors.py
```

The script overwrites the `wave_a_*.hex` files in its own
directory and prints a summary to stdout.

## Why these vectors exist

The crypto-review protocol in this workspace (see
[ROADMAP.md §5](../ROADMAP.md) and the
`crypto-review-protocol` skill) requires **known-answer test
vectors**, not round-trip tests. Round-trip alone (encrypt-then-
decrypt or sign-then-verify) can pass while both sides are wrong
in matching ways; committing expected bytes from an external
reference catches that class of bug. Codex is explicitly
prohibited from generating the reference values it is being
verified against.

## Files

| File | Content | Source |
|------|---------|--------|
| `wave_a_seed.hex` | 32-byte Ed25519 seed | RFC 8032 §7.1 TEST 1 |
| `wave_a_public.hex` | 32-byte Ed25519 public key | RFC 8032 §7.1 TEST 1 |
| `wave_a_payload_plaintext.hex` | 27-byte plaintext `"phase-5-wave-a-test-payload"` | fixed |
| `wave_a_payload_hash.hex` | SHA-256 of the plaintext | computed |
| `wave_a_claims.cbor.hex` | Canonical CBOR of the claim payload (220 bytes) | computed |
| `wave_a_protected.hex` | COSE_Sign1 protected header bytes (38 bytes) | computed |
| `wave_a_sig_structure1.hex` | RFC 9052 §4.4 `Sig_structure1` (275 bytes) | computed |
| `wave_a_signature.hex` | Ed25519 signature over `Sig_structure1` (64 bytes) | computed |
| `wave_a_cose_sign1.hex` | Final COSE_Sign1 structure (330 bytes) | computed |

**Byte sizes updated 2026-04-22** after the
`philharmonic-connector-common 0.2.0` bump added an `iat` claim
(9 → 10 claim-map entries; all downstream byte sizes grew).
Prior-`0.1.0`-shaped vectors (claims 207, Sig_structure1 262,
COSE_Sign1 317 bytes) are no longer valid; re-run the generator
to match the current shape.

## Claim-set constants

Mirrored in the Rust tests. The field order below MUST match the
declaration order of `philharmonic_connector_common::ConnectorTokenClaims`
because `ciborium` + `serde` emit CBOR map entries in struct-field
declaration order.

| Field | Value |
|-------|-------|
| `iss` | `"lowerer.main"` |
| `exp` | `1924992000000` (2031-01-01T00:00:00Z) |
| `iat` | `1924991880000` (exp − 120 000 ms, the Wave A default validity window) |
| `kid` | `"lowerer.main-2026-04-22-3c8a91d0"` |
| `realm` | `"llm"` |
| `tenant` | `11111111-2222-4333-8444-555555555555` |
| `inst` | `66666666-7777-4888-8999-aaaaaaaaaaaa` |
| `step` | `7` |
| `config_uuid` | `bbbbbbbb-cccc-4ddd-8eee-ffffffffffff` |
| `payload_hash` | `sha256("phase-5-wave-a-test-payload")` |

## Dependencies

- `philharmonic-connector-common >= 0.2.0` for the `iat` claim.
  Earlier `0.1.x` versions don't have `iat` and will NOT match
  `wave_a_claims.cbor.hex`.
- `philharmonic-types >= 0.3.5` for the CBOR-bstr-shaped `Sha256`
  serde impl. Earlier versions emit a hex text string instead
  and will NOT match `wave_a_claims.cbor.hex`.
- `uuid = "1.23"` with the `serde` feature on the consuming crate
  for `Uuid` → 16-byte bstr in `!is_human_readable()` serializers.

## Negative-path vectors

Negative-path vectors (alg-confusion, unknown-kid, tampered sig,
expired, realm mismatch, payload-hash mismatch, kid-inconsistent,
key-out-of-window, payload-too-large) are built at test time in
the Rust test files from these positive vectors — they aren't
pre-committed here. See the proposal's §Negative-path vectors for
the exact synthesis recipes.
