# Phase 5 Wave B reference vectors

Reference byte values for Phase 5 Wave B (hybrid ML-KEM-768 +
X25519 KEM, HKDF-SHA256, AES-256-GCM, COSE_Encrypt0). The Rust
implementations in
[`philharmonic-connector-client`](../../../philharmonic-connector-client/)
(encryption) and
[`philharmonic-connector-service`](../../../philharmonic-connector-service/)
(decryption) must reproduce these bytes exactly.

## How these were generated

`gen_wave_b_vectors.py` uses:

- `kyber-py` for ML-KEM-768, specifically its `_keygen_internal(d,
  z)` and `_encaps_internal(ek, m)` methods, which are the
  deterministic FIPS 203 Algorithm 16 and Algorithm 17 primitives
  with explicit internal randomness (the same surface `ml-kem
  0.2.x` in Rust exposes for reproducible test vectors).
- `cryptography` for X25519 (`X25519PrivateKey.from_private_bytes`
  + `.exchange()`), HKDF-SHA256, AES-256-GCM.
- `cbor2` for canonical CBOR encoding of the COSE_Encrypt0
  protected header, the `Enc_structure` (RFC 9052 §5.3), and the
  outer envelope.

Every input is a fixed byte pattern committed at the top of the
generator (ML-KEM d/z/m, X25519 realm + ephemeral private keys,
AEAD nonce, plaintext). The generator is byte-deterministic.

### Reproducing

```sh
python3 -m venv /tmp/wave-b-vendor
/tmp/wave-b-vendor/bin/pip install kyber-py cbor2 cryptography
/tmp/wave-b-vendor/bin/python \
    tests/crypto-vectors/wave-b/gen_wave_b_vectors.py
```

The script overwrites the `wave_b_*.hex` files in its own
directory and prints a multi-section summary to stdout.

### CBOR ordering — deliberate (not RFC 8949 §4.2.1)

The COSE_Encrypt0 protected header is a CBOR map with a mix of
integer and text labels: `1` (alg), `4` (kid), `5` (IV),
`"kem_ct"`, `"ecdh_eph_pk"`. `coset 0.4.2` emits them in a fixed
order derived from the struct shape of `coset::Header`: integer
labels in the order alg → crit → content_type → kid → iv →
partial_iv → counter_sigs, followed by custom `rest` labels in
insertion order. This generator mirrors that emission order in
`cbor2` (Python dict insertion order), so the Rust and Python
outputs match byte-for-byte.

RFC 8949 §4.2.1's deterministic-encoding rule would sort keys by
`(encoded_length, bytewise_lex)`, which is a DIFFERENT ordering.
We're not using canonical deterministic encoding here; we're
using coset's fixed ordering. This is fine as long as both
implementations agree — and they do, because coset is the only
COSE encoder either side uses.

## Why these vectors exist

The crypto-review protocol in this workspace (see
[ROADMAP.md §5](../ROADMAP.md) and the
`crypto-review-protocol` skill) requires **known-answer test
vectors**, not round-trip tests. Round-trip alone (encrypt-then-
decrypt) can pass while both sides are wrong in matching ways;
committing expected bytes from an external reference catches
that class of bug. Codex is explicitly prohibited from
generating the reference values it is being verified against.

## Files

| File | Content | Source |
|------|---------|--------|
| `wave_b_mlkem_keygen_d.hex` | 32-byte FIPS 203 Alg. 16 `d` seed | fixed |
| `wave_b_mlkem_keygen_z.hex` | 32-byte FIPS 203 Alg. 16 `z` seed | fixed |
| `wave_b_mlkem_encaps_m.hex` | 32-byte FIPS 203 Alg. 17 `m` randomness | fixed |
| `wave_b_mlkem_public.hex` | ML-KEM-768 encapsulation key (ek), 1184 bytes | computed from d, z |
| `wave_b_mlkem_secret.hex` | ML-KEM-768 decapsulation key (dk), 2400 bytes | computed from d, z |
| `wave_b_mlkem_ct.hex` | ML-KEM-768 ciphertext, 1088 bytes | computed from ek, m |
| `wave_b_mlkem_ss.hex` | ML-KEM-768 shared secret, 32 bytes | computed from ek, m |
| `wave_b_x25519_realm_sk.hex` | X25519 realm private, 32 bytes | fixed |
| `wave_b_x25519_realm_pk.hex` | X25519 realm public, 32 bytes | computed |
| `wave_b_x25519_eph_sk.hex` | X25519 lowerer-ephemeral private, 32 bytes | fixed |
| `wave_b_x25519_eph_pk.hex` | X25519 lowerer-ephemeral public, 32 bytes | computed |
| `wave_b_ecdh_ss.hex` | ECDH shared secret, 32 bytes | computed |
| `wave_b_hkdf_ikm.hex` | HKDF input keying material (kem_ss ‖ ecdh_ss), 64 bytes | concatenation |
| `wave_b_aead_key.hex` | AES-256-GCM key, 32 bytes | HKDF-Extract-then-Expand |
| `wave_b_external_aad.hex` | SHA-256 of the call-context CBOR map, 32 bytes | computed |
| `wave_b_nonce.hex` | AES-256-GCM nonce, 12 bytes | fixed |
| `wave_b_plaintext.hex` | Representative TenantEndpointConfig JSON plaintext, 119 bytes | fixed |
| `wave_b_plaintext.json` | Same plaintext as a readable JSON file | fixed |
| `wave_b_protected.hex` | COSE_Encrypt0 protected header bytes, 1196 bytes | computed |
| `wave_b_enc_structure.hex` | RFC 9052 §5.3 `Enc_structure` (AEAD AAD input), 1243 bytes | computed |
| `wave_b_ciphertext_and_tag.hex` | AES-256-GCM output (ciphertext ‖ tag), 135 bytes | computed |
| `wave_b_cose_encrypt0.hex` | Final COSE_Encrypt0 envelope bytes, 1338 bytes | computed |
| `wave_b_payload_hash.hex` | SHA-256 of the COSE_Encrypt0 bytes, 32 bytes | computed |

`wave_b_payload_hash.hex` is the value a composed Wave A token
would place in its `payload_hash` claim to commit to this
ciphertext. The composition vector (Wave A token over this
`payload_hash` + the new `iat` claim) is a follow-up artifact —
not yet generated here because the Wave A generator at
`tests/crypto-vectors/wave-a/gen_wave_a_vectors.py` still commits
to `SHA-256("phase-5-wave-a-test-payload")`. When Wave B's
end-to-end test lands, the Wave A generator will be extended to
accept a `--payload-hash-from` argument (or equivalent) so the
two sets of vectors interlock.

## Construction parameters

All pinned at the top of `gen_wave_b_vectors.py`:

| Parameter | Value |
|-----------|-------|
| ML-KEM algorithm | ML-KEM-768 (FIPS 203) |
| X25519 curve | RFC 7748 §6.1 |
| HKDF hash | SHA-256 |
| HKDF salt | `b""` (empty) |
| HKDF info | `b"philharmonic/wave-b/hybrid-kem/v1/aead-key"` |
| HKDF IKM order | `kem_ss ‖ ecdh_ss` (ML-KEM first, per Gate-1 Q#1) |
| AEAD | AES-256-GCM (COSE `alg = 3`) |
| AEAD nonce size | 12 bytes, random in production / fixed here |
| AEAD tag size | 16 bytes |
| AEAD AAD input | RFC 9052 `Enc_structure = ["Encrypt0", protected, external_aad]` |
| `external_aad` | SHA-256 of canonical CBOR of `(realm, tenant, inst, step, config_uuid, kid)` in that declaration order |
| Realm KEM kid | `"llm.default-2026-04-22-realmkey0"` (distinct from the Wave A lowerer signing kid) |

## Dependencies

- `philharmonic-connector-common >= 0.2.0` for `iat` on the
  companion Wave A claim set.
- `philharmonic-types >= 0.3.5` for the CBOR-bstr-shaped `Sha256`
  serde.
- `ml-kem = "0.2"` — Rust consumer of these vectors must use
  FIPS 203 internal randomness surface.
- `x25519-dalek = "2"`, `hkdf = "0.12"` or `"0.13"`, `aes-gcm =
  "0.10"`, `sha2 = "0.11"`, `coset = "0.4"`, `ciborium = "0.2"`,
  `zeroize = "1"`, `secrecy = "0.10"`.

## Negative-path vectors

Negative-path vectors (malformed envelope, wrong alg, unprotected
non-empty, wrong kem_ct/ecdh_eph_pk/IV lengths, unknown labels,
unknown realm-kid, realm-key window / realm mismatch, tag tamper,
kem_ct tamper, ecdh_eph_pk tamper, AAD tamper, inner-realm
mismatch) are synthesized at test time in the Rust test file from
these positive vectors — they aren't pre-committed here. See the
proposal's §Negative-path vectors for the exact synthesis recipes.

## Outstanding (for the next session)

- **Wave A × Wave B composition vectors.** Regenerate the Wave A
  COSE_Sign1 with `claims.payload_hash` set to
  `wave_b_payload_hash.hex` (the digest above). This replaces the
  self-contained Wave A test payload and makes the Wave A positive
  vector point at a real Wave B-encrypted payload. Blocked only on
  a small extension to `gen_wave_a_vectors.py` to accept an
  overrideable payload-hash input.
- **pycose cross-check.** The proposal lists pycose as an external
  reference; this generator used `cbor2` + `cryptography` +
  `kyber-py` directly. A pycose cross-run would be defense in
  depth against `cbor2`-or-coset shared-bug scenarios. Defer to
  Gate-2 review time.
- **Codex-prompt archive + dispatch.** Wave B implementation
  prompt uses these vectors as committed pass targets (per the
  crypto-review skill, Codex does not generate reference values).
