#!/usr/bin/env python3
"""Reference vector generator for Phase 5 Wave B hybrid KEM + COSE_Encrypt0.

Produces byte-identical reference values for:

- ML-KEM-768 keypair from FIPS 203 Algorithm 16 internal randomness
  (d, z) — the canonical deterministic keygen path.
- ML-KEM-768 encapsulation from FIPS 203 Algorithm 17 internal
  randomness (m) — canonical deterministic encap.
- X25519 realm long-lived keypair + lowerer ephemeral keypair from
  fixed 32-byte private-key seeds.
- HKDF-SHA256 over `kem_ss || ecdh_ss` with
  `info = "philharmonic/wave-b/hybrid-kem/v1/aead-key"` and empty
  salt, deriving a 32-byte AES-256-GCM key.
- External-AAD digest: SHA-256 of canonical CBOR of
  `{realm, tenant, inst, step, config_uuid, kid}` (insertion order
  matches a Rust struct's declaration order).
- Protected header: CBOR map in the order coset emits
  (int labels first: alg, kid, IV; then custom text labels in
  insertion order: `kem_ct`, `ecdh_eph_pk`). This is NOT RFC 8949
  §4.2.1 canonical encoding but IS deterministic across coset +
  cbor2.
- `Enc_structure = ["Encrypt0", protected, external_aad]` per
  RFC 9052 §5.3 — the AEAD's associated-data input.
- AES-256-GCM encryption of a representative TenantEndpointConfig
  plaintext under the hybrid-derived key + committed nonce +
  Enc_structure AAD.
- Final COSE_Encrypt0 envelope bytes.
- `payload_hash = SHA-256(cose_encrypt0)` — the value a Wave A
  COSE_Sign1 token would commit to in its `payload_hash` claim.

Run inside a venv with `kyber-py`, `cbor2`, and `cryptography`:

    python3 -m venv /tmp/wave-b-vendor
    /tmp/wave-b-vendor/bin/pip install kyber-py cbor2 cryptography
    /tmp/wave-b-vendor/bin/python \\
        docs/crypto-vectors/wave-b/gen_wave_b_vectors.py

The script overwrites the `wave_b_*.hex` files in its own
directory and prints a summary to stdout.

Every output is keyed to fixed inputs committed at the top of
this file. A Rust implementation using the `ml-kem 0.2`,
`x25519-dalek 2`, `hkdf 0.12+`, and `aes-gcm 0.10` crates — fed
the same deterministic inputs — must reproduce every byte
below. That's the whole point of known-answer vectors: Codex
is explicitly not permitted to generate these; they exist to
catch drift in its implementation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768


# ---------------------------------------------------------------------------
# Inputs (pin at the top; keep in lockstep with the proposal's test-vector
# plan and with the Rust implementation's test fixtures).

# FIPS 203 ML-KEM-768 keygen randomness (Algorithm 16).
# 32 bytes each. Patterned byte values for easy hex-dump identification.
MLKEM_KEYGEN_D_HEX = "1011121314151617" "18191a1b1c1d1e1f" \
                    "2021222324252627" "28292a2b2c2d2e2f"
MLKEM_KEYGEN_Z_HEX = "3031323334353637" "38393a3b3c3d3e3f" \
                    "4041424344454647" "48494a4b4c4d4e4f"

# FIPS 203 ML-KEM-768 encapsulation randomness (Algorithm 17). 32 bytes.
MLKEM_ENCAPS_M_HEX = "5051525354555657" "58595a5b5c5d5e5f" \
                    "6061626364656667" "68696a6b6c6d6e6f"

# X25519 realm long-lived private key. 32 bytes.
X25519_REALM_SK_HEX = "7071727374757677" "78797a7b7c7d7e7f" \
                     "8081828384858687" "88898a8b8c8d8e8f"

# X25519 lowerer-side ephemeral private key. 32 bytes.
X25519_EPH_SK_HEX   = "9091929394959697" "98999a9b9c9d9e9f" \
                     "a0a1a2a3a4a5a6a7" "a8a9aaabacadaeaf"

# AES-GCM nonce. 12 bytes. Random in production; fixed here for the
# known-answer vector.
AEAD_NONCE_HEX = "b0b1b2b3b4b5b6b7" "b8b9babb"

# Representative TenantEndpointConfig plaintext. Byte-identical to
# what the lowerer would receive from SCK decryption of an admin-
# submitted config. The inner `realm` field matches the token's
# `realm` claim for the happy-path test; mismatch is the step-15
# negative vector.
PLAINTEXT_JSON = (
    b'{"realm":"llm","impl":"llm_openai_compat",'
    b'"config":{"base_url":"https://example.com/v1",'
    b'"api_key":"sk-wave-b-fixture"}}'
)

# Realm KEM kid (distinct from the lowerer signing kid used in
# Wave A). Different-purpose kids per the proposal.
REALM_KID = "llm.default-2026-04-22-realmkey0"

# Wave-A claim-context fields that bind into the AEAD AAD. Must
# match the values the regenerated Wave A generator emits so that
# the composition vectors line up end-to-end.
CALL_CONTEXT = {
    "realm":       "llm",
    "tenant":      bytes.fromhex("11111111222243338444555555555555"),
    "inst":        bytes.fromhex("66666666777748888999aaaaaaaaaaaa"),
    "step":        7,
    "config_uuid": bytes.fromhex("bbbbbbbbcccc4ddd8eeeffffffffffff"),
    "kid":         "lowerer.main-2026-04-22-3c8a91d0",
}

# HKDF-SHA256 parameters.
HKDF_SALT = b""
HKDF_INFO = b"philharmonic/wave-b/hybrid-kem/v1/aead-key"


# ---------------------------------------------------------------------------
# Helpers.


def hexclean(s: str) -> str:
    """Strip whitespace from a hex string."""
    return s.replace(" ", "").replace("\n", "")


def x25519_public_bytes(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def encode_external_aad(call_context: dict) -> bytes:
    """Serialize the AAD call-context map in the fixed field order
    and return its SHA-256 digest."""
    # Insertion order is load-bearing: matches the Rust struct's
    # declaration order so ciborium emits identical bytes.
    aad_map = {
        "realm":       call_context["realm"],
        "tenant":      call_context["tenant"],
        "inst":        call_context["inst"],
        "step":        call_context["step"],
        "config_uuid": call_context["config_uuid"],
        "kid":         call_context["kid"],
    }
    return hashlib.sha256(cbor2.dumps(aad_map)).digest()


def encode_protected_header(
    kid_bytes: bytes,
    nonce: bytes,
    kem_ct: bytes,
    ecdh_eph_pk: bytes,
) -> bytes:
    """Emit the COSE_Encrypt0 protected header in the exact order
    `coset 0.4.2` produces: int labels alg, kid, iv first, then
    custom text labels `kem_ct`, `ecdh_eph_pk` in insertion order.

    See `coset-0.4.2/src/header/mod.rs` `impl AsCborValue for Header`.
    """
    return cbor2.dumps({
        1: 3,                       # alg = A256GCM (RFC 9053 §4.2.1)
        4: kid_bytes,               # kid
        5: nonce,                   # IV
        "kem_ct":      kem_ct,      # 1088 bytes, ML-KEM-768 ciphertext
        "ecdh_eph_pk": ecdh_eph_pk, # 32 bytes, X25519 ephemeral public
    })


def encode_enc_structure(protected_bytes: bytes, external_aad: bytes) -> bytes:
    """RFC 9052 §5.3 `Enc_structure` — the AEAD's AAD input."""
    return cbor2.dumps(["Encrypt0", protected_bytes, external_aad])


# ---------------------------------------------------------------------------
# Main.


def main(outdir: Path) -> None:
    # --- ML-KEM-768 keypair from FIPS 203 internal randomness ---
    d = bytes.fromhex(hexclean(MLKEM_KEYGEN_D_HEX))
    z = bytes.fromhex(hexclean(MLKEM_KEYGEN_Z_HEX))
    assert len(d) == 32 and len(z) == 32
    (kem_pk, kem_sk) = ML_KEM_768._keygen_internal(d, z)
    assert len(kem_pk) == 1184, f"ML-KEM-768 pk should be 1184 bytes, got {len(kem_pk)}"
    assert len(kem_sk) == 2400, f"ML-KEM-768 sk should be 2400 bytes, got {len(kem_sk)}"

    # --- ML-KEM-768 encapsulate ---
    m = bytes.fromhex(hexclean(MLKEM_ENCAPS_M_HEX))
    assert len(m) == 32
    (kem_ss, kem_ct) = ML_KEM_768._encaps_internal(kem_pk, m)
    assert len(kem_ss) == 32
    assert len(kem_ct) == 1088, f"ML-KEM-768 ciphertext should be 1088 bytes, got {len(kem_ct)}"

    # --- Round-trip check: decapsulate must recover kem_ss ---
    kem_ss_check = ML_KEM_768.decaps(kem_sk, kem_ct)
    assert kem_ss == kem_ss_check, "ML-KEM encap/decap round-trip failed"

    # --- X25519 realm keypair ---
    realm_sk = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(hexclean(X25519_REALM_SK_HEX))
    )
    realm_pk_bytes = x25519_public_bytes(realm_sk)

    # --- X25519 ephemeral keypair (lowerer side) ---
    eph_sk = X25519PrivateKey.from_private_bytes(
        bytes.fromhex(hexclean(X25519_EPH_SK_HEX))
    )
    eph_pk_bytes = x25519_public_bytes(eph_sk)

    # --- X25519 ECDH: ephemeral_sk × realm_pk (lowerer side) ---
    ecdh_ss = eph_sk.exchange(realm_sk.public_key())
    # Service side would compute realm_sk × eph_pk; must match.
    ecdh_ss_service_side = realm_sk.exchange(eph_sk.public_key())
    assert ecdh_ss == ecdh_ss_service_side
    assert len(ecdh_ss) == 32

    # --- HKDF-SHA256 → AES-256-GCM key ---
    # IKM = kem_ss || ecdh_ss (ML-KEM first per Gate-1 Q#1).
    ikm = kem_ss + ecdh_ss
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    aead_key = hkdf.derive(ikm)
    assert len(aead_key) == 32

    # --- External AAD digest (call-context binding) ---
    external_aad = encode_external_aad(CALL_CONTEXT)
    assert len(external_aad) == 32

    # --- Protected header bytes ---
    nonce = bytes.fromhex(hexclean(AEAD_NONCE_HEX))
    assert len(nonce) == 12
    kid_bytes = REALM_KID.encode("utf-8")
    protected_bytes = encode_protected_header(
        kid_bytes=kid_bytes,
        nonce=nonce,
        kem_ct=kem_ct,
        ecdh_eph_pk=eph_pk_bytes,
    )

    # --- Enc_structure (AEAD AAD) ---
    enc_structure = encode_enc_structure(protected_bytes, external_aad)

    # --- AES-256-GCM encrypt ---
    aesgcm = AESGCM(aead_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, PLAINTEXT_JSON, enc_structure)
    # cryptography returns ciphertext || 16-byte tag concatenated.
    assert len(ciphertext_and_tag) == len(PLAINTEXT_JSON) + 16

    # --- Final COSE_Encrypt0 envelope ---
    cose_encrypt0 = cbor2.dumps([
        protected_bytes,
        {},  # empty unprotected
        ciphertext_and_tag,
    ])

    # --- Payload hash a Wave A token would commit to ---
    payload_hash = hashlib.sha256(cose_encrypt0).digest()

    # --- Write all artifacts ---
    outdir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        # FIPS 203 deterministic inputs
        "wave_b_mlkem_keygen_d.hex": d.hex(),
        "wave_b_mlkem_keygen_z.hex": z.hex(),
        "wave_b_mlkem_encaps_m.hex": m.hex(),
        # ML-KEM-768 outputs
        "wave_b_mlkem_public.hex": kem_pk.hex(),
        "wave_b_mlkem_secret.hex": kem_sk.hex(),
        "wave_b_mlkem_ct.hex": kem_ct.hex(),
        "wave_b_mlkem_ss.hex": kem_ss.hex(),
        # X25519
        "wave_b_x25519_realm_sk.hex": bytes.fromhex(hexclean(X25519_REALM_SK_HEX)).hex(),
        "wave_b_x25519_realm_pk.hex": realm_pk_bytes.hex(),
        "wave_b_x25519_eph_sk.hex": bytes.fromhex(hexclean(X25519_EPH_SK_HEX)).hex(),
        "wave_b_x25519_eph_pk.hex": eph_pk_bytes.hex(),
        "wave_b_ecdh_ss.hex": ecdh_ss.hex(),
        # HKDF
        "wave_b_hkdf_ikm.hex": ikm.hex(),
        "wave_b_aead_key.hex": aead_key.hex(),
        # AAD / Enc_structure
        "wave_b_external_aad.hex": external_aad.hex(),
        "wave_b_enc_structure.hex": enc_structure.hex(),
        # AEAD
        "wave_b_nonce.hex": nonce.hex(),
        "wave_b_plaintext.hex": PLAINTEXT_JSON.hex(),
        "wave_b_ciphertext_and_tag.hex": ciphertext_and_tag.hex(),
        # COSE_Encrypt0
        "wave_b_protected.hex": protected_bytes.hex(),
        "wave_b_cose_encrypt0.hex": cose_encrypt0.hex(),
        "wave_b_payload_hash.hex": payload_hash.hex(),
    }
    for name, hx in artifacts.items():
        (outdir / name).write_text(hx + "\n")

    # Also write the plaintext as a readable JSON file for debugging.
    (outdir / "wave_b_plaintext.json").write_bytes(PLAINTEXT_JSON + b"\n")

    # Stdout summary.
    def sz(b: bytes) -> str:
        return f"{len(b):>4d} B"

    print("# Wave B reference vectors")
    print()
    print("## ML-KEM-768 (FIPS 203)")
    print(f"  d                    = {d.hex()}")
    print(f"  z                    = {z.hex()}")
    print(f"  m (encaps)           = {m.hex()}")
    print(f"  public      ({sz(kem_pk)}) = {kem_pk.hex()[:48]}…")
    print(f"  secret      ({sz(kem_sk)}) = {kem_sk.hex()[:48]}…")
    print(f"  ciphertext  ({sz(kem_ct)}) = {kem_ct.hex()[:48]}…")
    print(f"  shared secret ({sz(kem_ss)}) = {kem_ss.hex()}")
    print()
    print("## X25519")
    print(f"  realm pk    ({sz(realm_pk_bytes)}) = {realm_pk_bytes.hex()}")
    print(f"  eph pk      ({sz(eph_pk_bytes)}) = {eph_pk_bytes.hex()}")
    print(f"  ecdh ss     ({sz(ecdh_ss)}) = {ecdh_ss.hex()}")
    print()
    print("## HKDF-SHA256")
    print(f"  ikm ({sz(ikm)}) = kem_ss || ecdh_ss")
    print(f"  aead_key ({sz(aead_key)}) = {aead_key.hex()}")
    print()
    print("## COSE_Encrypt0")
    print(f"  protected     ({sz(protected_bytes)}) = {protected_bytes.hex()[:80]}…")
    print(f"  external_aad  ({sz(external_aad)}) = {external_aad.hex()}")
    print(f"  enc_structure ({sz(enc_structure)}) = {enc_structure.hex()[:80]}…")
    print(f"  nonce         ({sz(nonce)}) = {nonce.hex()}")
    print(f"  plaintext     ({sz(PLAINTEXT_JSON)}) = {PLAINTEXT_JSON!r}")
    print(f"  ct + tag      ({sz(ciphertext_and_tag)}) = {ciphertext_and_tag.hex()[:80]}…")
    print(f"  COSE_Encrypt0 ({sz(cose_encrypt0)}) = {cose_encrypt0.hex()[:80]}…")
    print()
    print(f"  payload_hash  ({sz(payload_hash)}) = {payload_hash.hex()}")


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    main(here)
