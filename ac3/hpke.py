"""RFC 9180 HPKE — the subset AC3-X session mode uses.

Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD
(kem_id 0x0020, kdf_id 0x0001, aead_id 0xFFFF) — the RFC's registered
suite for applications that derive their own keys from the HPKE context
instead of using its built-in AEAD (RFC 9180, Appendix A.7).

Conformance: tests/test_hpke.py verifies this implementation byte-for-byte
against the RFC 9180 A.7.1 Base Setup vectors, including the exported
values for the three published exporter contexts.

Scope (deliberate): only base mode (mode_base) and the exporter interface
are implemented — session mode performs one-shot encryption to a published
recipient key and derives its session master through ctx.export().
"""

import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.exceptions import InvalidTag  # noqa: F401  (parity with other modules)

from .keys import _expand

KEM_ID = 0x0020          # DHKEM(X25519, HKDF-SHA256)
KDF_ID = 0x0001          # HKDF-SHA256
AEAD_ID_EXPORT_ONLY = 0xFFFF

_HPKE_V1 = b"HPKE-v1"
_SUITE_KEM = b"KEM" + struct.pack(">H", KEM_ID)
_SUITE = b"HPKE" + struct.pack(">H", KEM_ID) + struct.pack(">H", KDF_ID) \
    + struct.pack(">H", AEAD_ID_EXPORT_ONLY)

_N_SECRET = 32
_N_EXPORTER = 32

_MODE_BASE = 0x00


def _i2osp(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite: bytes) -> bytes:
    """RFC 9180 §4: Extract(salt, Labeled("HPKE-v1", suite, label, ikm))."""
    return _hmac_sha256(salt, _HPKE_V1 + suite + label + ikm)


def labeled_expand(prk: bytes, label: bytes, info: bytes, length: int,
                   suite: bytes) -> bytes:
    """RFC 9180 §4: Expand(prk, Labeled("HPKE-v1", suite, label, info), L).

    Labeled(...) = I2OSP(L, 2) || "HPKE-v1" || suite || label || info.
    """
    return _expand(prk, _i2osp(length, 2) + _HPKE_V1 + suite + label + info, length)


# --------------------------------------------------------------------------
# KEM: DHKEM(X25519, HKDF-SHA256)  (RFC 9180 §7.1)
# --------------------------------------------------------------------------

def derive_key_pair(ikm: bytes) -> tuple:
    """RFC 9180 §7.1.4 DeriveKeyPair for X25519 -> (secret_key, public_key)."""
    dkp_prk = labeled_extract(b"", b"dkp_prk", ikm, _SUITE_KEM)
    sk = labeled_expand(dkp_prk, b"sk", b"", 32, _SUITE_KEM)
    pk = X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()
    return sk, pk


def _encap(recipient_pk: bytes, ephemeral_ikm: bytes | None):
    """RFC 9180 §7.1.1 Encap -> (shared_secret, enc, ephemeral_sk)."""
    if ephemeral_ikm is not None:
        sk_em, pk_em = derive_key_pair(ephemeral_ikm)
        sk_obj = X25519PrivateKey.from_private_bytes(sk_em)
    else:
        sk_obj = X25519PrivateKey.generate()
        pk_em = sk_obj.public_key().public_bytes_raw()
    dh = sk_obj.exchange(X25519PublicKey.from_public_bytes(recipient_pk))
    kem_context = pk_em + recipient_pk
    shared_secret = labeled_expand(
        labeled_extract(b"", b"eae_prk", dh, _SUITE_KEM),
        b"shared_secret", kem_context, _N_SECRET, _SUITE_KEM,
    )
    return shared_secret, pk_em, sk_obj


def _decap(enc: bytes, recipient_sk: bytes):
    """RFC 9180 §7.1.2 Decap -> (shared_secret, own_public_key)."""
    sk_obj = X25519PrivateKey.from_private_bytes(recipient_sk)
    pk_rm = sk_obj.public_key().public_bytes_raw()
    dh = sk_obj.exchange(X25519PublicKey.from_public_bytes(enc))
    kem_context = enc + pk_rm
    shared_secret = labeled_expand(
        labeled_extract(b"", b"eae_prk", dh, _SUITE_KEM),
        b"shared_secret", kem_context, _N_SECRET, _SUITE_KEM,
    )
    return shared_secret, pk_rm


# --------------------------------------------------------------------------
# Key schedule (RFC 9180 §5.1, mode_base) and exporter (§5.3)
# --------------------------------------------------------------------------

def key_schedule(shared_secret: bytes, info: bytes) -> dict:
    """RFC 9180 §5.1 mode_base key schedule.

    Returns the context dict with key_schedule_context, secret, key,
    base_nonce (both empty for the Export-Only suite) and exporter_secret.
    """
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"", _SUITE)
    info_hash = labeled_extract(b"", b"info_hash", info, _SUITE)
    ks_context = _i2osp(_MODE_BASE, 1) + psk_id_hash + info_hash
    secret = labeled_extract(shared_secret, b"secret", b"", _SUITE)
    return {
        "key_schedule_context": ks_context,
        "secret": secret,
        "key": labeled_expand(secret, b"key", ks_context, 0, _SUITE),
        "base_nonce": labeled_expand(secret, b"base_nonce", ks_context, 0, _SUITE),
        "exporter_secret": labeled_expand(secret, b"exp", ks_context,
                                          _N_EXPORTER, _SUITE),
    }


def export(exporter_secret: bytes, exporter_context: bytes, length: int) -> bytes:
    """RFC 9180 §5.3 Export -> LabeledExpand(exporter_secret, "sec", ctx, L)."""
    return labeled_expand(exporter_secret, b"sec", exporter_context, length, _SUITE)


# --------------------------------------------------------------------------
# Context object
# --------------------------------------------------------------------------

class HpkeContext:
    """The sender/receiver side of a base-mode HPKE context (export only)."""

    def __init__(self, shared_secret: bytes, info: bytes, enc: bytes):
        self.enc = enc
        schedule = key_schedule(shared_secret, info)
        self.key_schedule_context = schedule["key_schedule_context"]
        self.secret = schedule["secret"]
        self.key = schedule["key"]
        self.base_nonce = schedule["base_nonce"]
        self.exporter_secret = schedule["exporter_secret"]

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return export(self.exporter_secret, exporter_context, length)


def setup_base_s(recipient_pk: bytes, info: bytes,
                 ephemeral_ikm: bytes | None = None) -> tuple:
    """RFC 9180 §5.1.1 SetupBaseS -> (enc, HpkeContext).

    `ephemeral_ikm` exists ONLY for RFC test-vector conformance; production
    callers omit it and the ephemeral key is generated internally.
    """
    shared_secret, enc, sk_obj = _encap(recipient_pk, ephemeral_ikm)
    return enc, HpkeContext(shared_secret, info, enc), sk_obj


def setup_base_r(enc: bytes, recipient_sk: bytes, info: bytes) -> HpkeContext:
    """RFC 9180 §5.1.2 SetupBaseR."""
    shared_secret, pk_rm = _decap(enc, recipient_sk)
    return HpkeContext(shared_secret, info, enc)


__all__ = [
    "HpkeContext",
    "setup_base_s",
    "setup_base_r",
    "derive_key_pair",
    "KEM_ID",
    "KDF_ID",
    "AEAD_ID_EXPORT_ONLY",
]
