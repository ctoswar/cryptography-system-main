"""Ciphertext envelope formats for AC3-X (v4).

Text envelope families (unpadded base64url, `.`-separated):

    classic   AC3X.<nonce>.<body>.<tag>[.<keyid>]
    siv       AC3S.<nonce12>.<siv_output>[.<keyid>]
    session   AC3E.<eph_pk>.<salt>.<nonce>.<body>.<mac>[.<keyid>]

The trailing ``keyid`` field (4 bytes) is key-management metadata added in
v4: it names the long-term key that protected the envelope so rotation never
orphans data. Legacy 3-part ``AC3X`` tokens (and the SPEC conformance
vectors) remain valid — they resolve to the active key, then the archive.

Binary data (files, arbitrary size) uses the chunked stream format defined
in :mod:`ac3.core` (magics ``AC3X3\\x01`` legacy / ``AC3X4\\x01`` with key ID).

Legacy v2 envelopes (``AC3v2.``) and the interim AES envelopes (``AC3A.``)
are NOT accepted: v3 was a clean break.
"""

import base64
import re

from .exceptions import EnvelopeError

TEXT_PREFIX = "AC3X."
SIV_PREFIX = "AC3S."
SESSION_PREFIX = "AC3E."
NONCE_SIZE = 16
TAG_SIZE = 32
KEY_ID_SIZE = 4

# Unpadded base64url alphabet only. Python's decoder discards unknown
# characters by default, which would make token strings malleable
# (AC3X.n.BO.JUNK!US... == AC3X.n.BONUS...); reject anything off-alphabet.
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")

# Prefixes this implementation must refuse (clean break from v2 / interim AES).
_LEGACY_PREFIXES = ("AC3v2.", "AC3A.")


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str, what: str) -> bytes:
    if not _B64URL.match(text):
        raise EnvelopeError(f"{what} contains characters outside base64url.")
    try:
        padding = "=" * (-len(text) % 4)
        raw = base64.urlsafe_b64decode(text + padding)
    except Exception as exc:
        raise EnvelopeError(f"{what} is not valid base64url.") from exc
    if _b64e(raw) != text:
        # Non-canonical encoding (wrong padding bits) — decodes but must not
        # be accepted, otherwise two strings map to one ciphertext.
        raise EnvelopeError(f"{what} is not canonical base64url.")
    return raw


def encode_text(parts: list, *, prefix: str = TEXT_PREFIX) -> str:
    """Join b64url-encoded parts (last optional part may be a key ID)."""
    return prefix + ".".join(_b64e(p) for p in parts)


def _reject_legacy(token) -> None:
    for legacy in _LEGACY_PREFIXES:
        if isinstance(token, str) and token.startswith(legacy):
            raise EnvelopeError(
                f"Legacy envelope '{legacy}' is not supported by AC3-X (v3+); "
                "re-encrypt the data with the current version."
            )


def _split(token: str, prefix: str, what: str) -> list:
    """Shared prefix/body parse: b64url-decode every dot-separated field."""
    if not isinstance(token, str) or not token.startswith(prefix):
        _reject_legacy(token)
        raise EnvelopeError(f"Ciphertext must start with '{prefix}'.")
    raw_fields = token[len(prefix):].split(".")
    decoded = [
        _b64d(part, f"{what} field {i + 1}")
        for i, part in enumerate(raw_fields)
    ]
    return raw_fields, decoded


def decode_classic(token: str):
    """Parse ``AC3X.<nonce>.<body>.<tag>[.<keyid>]``.

    Returns (nonce, body, tag, key_id_or_None). The 3-part form is the
    legacy/spec shape and resolves to the active key.
    """
    raw_fields, decoded = _split(token, TEXT_PREFIX, "Ciphertext")
    if len(raw_fields) not in (3, 4):
        raise EnvelopeError(
            f"Ciphertext must have the form {TEXT_PREFIX}nonce.body.tag[.keyid]."
        )
    nonce, body, tag = decoded[0], decoded[1], decoded[2]
    if len(nonce) != NONCE_SIZE:
        raise EnvelopeError(f"Nonce must be {NONCE_SIZE} bytes.")
    if len(tag) != TAG_SIZE:
        raise EnvelopeError(f"Tag must be {TAG_SIZE} bytes.")
    key_id_value = None
    if len(raw_fields) == 4:
        key_id_value = decoded[3]
        if len(key_id_value) != KEY_ID_SIZE:
            raise EnvelopeError(f"Key ID must be {KEY_ID_SIZE} bytes.")
    return nonce, body, tag, key_id_value


def decode_siv(token: str):
    """Parse ``AC3S.<nonce12>.<siv_output>[.<keyid>]``.

    Returns (nonce, siv_output, key_id_or_None). The synthetic IV (16 bytes)
    and ciphertext travel together in ``siv_output``.
    """
    raw_fields, decoded = _split(token, SIV_PREFIX, "SIV ciphertext")
    if len(raw_fields) not in (2, 3):
        raise EnvelopeError(
            f"Ciphertext must have the form {SIV_PREFIX}nonce.output[.keyid]."
        )
    nonce, output = decoded[0], decoded[1]
    if len(nonce) != 12:
        raise EnvelopeError("SIV nonce must be 12 bytes.")
    if len(output) < 16:
        raise EnvelopeError("SIV output is truncated (missing synthetic IV).")
    key_id_value = None
    if len(raw_fields) == 3:
        key_id_value = decoded[2]
        if len(key_id_value) != KEY_ID_SIZE:
            raise EnvelopeError(f"Key ID must be {KEY_ID_SIZE} bytes.")
    return nonce, output, key_id_value


def decode_session(token: str):
    """Parse ``AC3E.<eph_pk>.<salt>.<nonce>.<body>.<mac>[.<keyid>]``.

    ``mac`` = 32-byte HMAC tag || 16-byte handshake bind tag (48 bytes).
    Returns (eph_pk, salt, nonce, body, mac, key_id_or_None).
    """
    raw_fields, decoded = _split(token, SESSION_PREFIX, "Session ciphertext")
    if len(raw_fields) not in (5, 6):
        raise EnvelopeError(
            f"Ciphertext must have the form "
            f"{SESSION_PREFIX}eph_pk.salt.nonce.body.mac[.keyid]."
        )
    eph_pk, salt, nonce, body, mac = decoded[:5]
    if len(eph_pk) != 32:
        raise EnvelopeError("Ephemeral X25519 public key must be 32 bytes.")
    if len(salt) < 16:
        raise EnvelopeError("Session salt must be at least 16 bytes.")
    if len(nonce) != NONCE_SIZE:
        raise EnvelopeError(f"Nonce must be {NONCE_SIZE} bytes.")
    if len(mac) != TAG_SIZE + 16:
        raise EnvelopeError("Session MAC field must be 48 bytes (tag + bind).")
    key_id_value = None
    if len(raw_fields) == 6:
        key_id_value = decoded[5]
        if len(key_id_value) != KEY_ID_SIZE:
            raise EnvelopeError(f"Key ID must be {KEY_ID_SIZE} bytes.")
    return eph_pk, salt, nonce, body, mac, key_id_value


def decode_text(token: str):
    """Backward-compatible classic decode (used by the core pipeline)."""
    return decode_classic(token)
