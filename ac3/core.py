"""AC3 v2 core — the five-layer encryption pipeline.

Layer map (thesis lineage noted in parentheses):

    1  Framing        version byte + uint32 length   (replaces v1 prefix/suffix wrap)
    2  Byte Caesar    keyed additive shift mod 256   (v1 Caesar, was ASCII-only)
    3  XOR stream     XOR with message-unique keys   (v1 XOR pass)
    4  Transposition  keyed column shuffle           (new in v2)
    5  XOR + HMAC     final XOR pass + integrity tag (v1 XOR pass + new MAC)

Every layer key is derived with HKDF-SHA256 from (master key, random nonce)
under a distinct info label, so no two messages ever share keystream material.
The v1 construction — five XOR passes over static per-process keys — collapsed
mathematically into a single XOR (k1 ⊕ k2 ⊕ ... ⊕ k5); that design is
deliberately not carried forward.

All layers operate on bytes, so any Unicode text round-trips safely.
"""

import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

from .envelope import (
    NONCE_SIZE,
    decode_binary,
    decode_text,
    encode_binary,
    encode_text,
)
from .exceptions import AC3Error, EnvelopeError, IntegrityError, InvalidKeyError
from .keys import MASTER_KEY_BYTES, KeyManager, derive_stream

VERSION = 2

_FRAME_VERSION = 2
_LENGTH_SIZE = 4
_MAX_PLAINTEXT = (1 << 32) - 1
_COLUMNS = 8
_MAC_KEY_SIZE = 32

_INFO_SHIFT = b"ac3v2/level2-caesar-shift"
_INFO_XOR_EARLY = b"ac3v2/level3-xor-stream"
_INFO_COLUMNS = b"ac3v2/level4-column-order"
_INFO_XOR_LATE = b"ac3v2/level5-xor-stream"
_INFO_MAC = b"ac3v2/integrity-mac"


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def _xor(data: bytes, stream: bytes) -> bytes:
    """Positional XOR of equal-length byte strings, executed as one big-int op."""
    if not data:
        return b""
    return (
        int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")
    ).to_bytes(len(data), "big")


def _shift_table(shift: int) -> bytes:
    """256-byte translate table implementing (b + shift) mod 256 at C speed."""
    shift &= 0xFF
    return bytes((b + shift) & 0xFF for b in range(256))


def _column_order(master_key: bytes, nonce: bytes) -> list:
    """Deterministic Fisher-Yates shuffle of column indices 0..7."""
    rnd = derive_stream(master_key, nonce, _INFO_COLUMNS, _COLUMNS)
    order = list(range(_COLUMNS))
    for i in range(_COLUMNS - 1, 0, -1):
        j = rnd[_COLUMNS - 1 - i] % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def _transpose(data: bytes, order: list) -> bytes:
    """Gather columns by slice, emit them in keyed order (all C-speed slices)."""
    k = len(order)
    if len(data) < 2:
        return data
    columns = [data[j::k] for j in range(k)]
    return b"".join(columns[j] for j in order)


def _untranspose(data: bytes, order: list) -> bytes:
    """Inverse of _transpose: split by known column lengths, scatter back."""
    k = len(order)
    if len(data) < 2:
        return data
    n = len(data)
    lengths = [(n - j + k - 1) // k for j in range(k)]
    columns: list = [None] * k
    pos = 0
    for idx in order:
        columns[idx] = data[pos:pos + lengths[idx]]
        pos += lengths[idx]
    result = bytearray(n)
    for j, col in enumerate(columns):
        result[j::k] = col
    return bytes(result)


def _compute_tag(master_key: bytes, nonce: bytes, body: bytes) -> bytes:
    mac = hmac.HMAC(
        derive_stream(master_key, nonce, _INFO_MAC, _MAC_KEY_SIZE),
        hashes.SHA256(),
    )
    mac.update(bytes([_FRAME_VERSION]) + nonce + body)
    return mac.finalize()


def _verify_tag(master_key: bytes, nonce: bytes, body: bytes, tag: bytes) -> None:
    mac = hmac.HMAC(
        derive_stream(master_key, nonce, _INFO_MAC, _MAC_KEY_SIZE),
        hashes.SHA256(),
    )
    mac.update(bytes([_FRAME_VERSION]) + nonce + body)
    try:
        mac.verify(tag)
    except InvalidSignature as exc:
        raise IntegrityError(
            "Integrity check failed: ciphertext was modified or the key is wrong."
        ) from exc


# --------------------------------------------------------------------------
# cipher
# --------------------------------------------------------------------------

class AC3Cipher:
    """Encrypts/decrypts with the AC3 v2 pipeline.

    Accepts a :class:`KeyManager`, a raw 32-byte master key, or nothing
    (auto-provisions from the project ``.env`` on first use).
    """

    def __init__(self, key_source=None):
        if isinstance(key_source, KeyManager):
            master = key_source.master_key
        elif isinstance(key_source, (bytes, bytearray)):
            master = bytes(key_source)
            if len(master) != MASTER_KEY_BYTES:
                raise InvalidKeyError(
                    f"Master key must be {MASTER_KEY_BYTES} bytes, got {len(master)}."
                )
        elif key_source is None:
            master = KeyManager().master_key
        else:
            raise TypeError(
                "key_source must be a KeyManager, bytes, or None; "
                f"got {type(key_source).__name__}."
            )
        self._master = master

    # -- str API (text envelope) ------------------------------------------

    def encrypt(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError(f"encrypt() expects str, got {type(text).__name__}.")
        nonce, body, tag = self._seal(text.encode("utf-8"))
        return encode_text(nonce, body, tag)

    def decrypt(self, token: str) -> str:
        nonce, body, tag = decode_text(token)
        return self._open(nonce, body, tag).decode("utf-8")

    # -- bytes API (binary envelope, for files) ---------------------------

    def encrypt_bytes(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"encrypt_bytes() expects bytes, got {type(data).__name__}."
            )
        nonce, body, tag = self._seal(bytes(data))
        return encode_binary(nonce, body, tag)

    def decrypt_bytes(self, blob: bytes) -> bytes:
        nonce, body, tag = decode_binary(blob)
        return self._open(nonce, body, tag)

    # -- pipeline ----------------------------------------------------------

    def _seal(self, data: bytes):
        if len(data) > _MAX_PLAINTEXT:
            raise AC3Error(f"Plaintext exceeds {_MAX_PLAINTEXT} bytes.")
        nonce = secrets.token_bytes(NONCE_SIZE)

        # Level 1 — framing: version byte + declared length + payload.
        framed = bytes([_FRAME_VERSION]) + len(data).to_bytes(_LENGTH_SIZE, "big") + data

        # Level 2 — keyed byte Caesar (binary-safe, shift is never 0).
        shift = (derive_stream(self._master, nonce, _INFO_SHIFT, 1)[0] % 255) + 1
        level2 = framed.translate(_shift_table(shift))

        # Level 3 — XOR with a message-unique keystream.
        level3 = _xor(
            level2, derive_stream(self._master, nonce, _INFO_XOR_EARLY, len(level2))
        )

        # Level 4 — keyed column transposition.
        level4 = _transpose(level3, _column_order(self._master, nonce))

        # Level 5 — second XOR pass, then integrity tag over everything.
        level5 = _xor(
            level4, derive_stream(self._master, nonce, _INFO_XOR_LATE, len(level4))
        )
        tag = _compute_tag(self._master, nonce, level5)
        return nonce, level5, tag

    def _open(self, nonce: bytes, body: bytes, tag: bytes) -> bytes:
        _verify_tag(self._master, nonce, body, tag)

        # Level 5 reversed.
        level4 = _xor(
            body, derive_stream(self._master, nonce, _INFO_XOR_LATE, len(body))
        )

        # Level 4 reversed.
        level3 = _untranspose(level4, _column_order(self._master, nonce))

        # Level 3 reversed.
        level2 = _xor(
            level3, derive_stream(self._master, nonce, _INFO_XOR_EARLY, len(level3))
        )

        # Level 2 reversed.
        shift = (derive_stream(self._master, nonce, _INFO_SHIFT, 1)[0] % 255) + 1
        framed = level2.translate(_shift_table(-shift))

        # Level 1 reversed.
        if len(framed) < 1 + _LENGTH_SIZE:
            raise EnvelopeError("Ciphertext decrypted to a truncated frame.")
        version = framed[0]
        if version != _FRAME_VERSION:
            raise EnvelopeError(
                f"Unsupported frame version {version} (expected {_FRAME_VERSION})."
            )
        declared = int.from_bytes(framed[1:1 + _LENGTH_SIZE], "big")
        payload = framed[1 + _LENGTH_SIZE:]
        if len(payload) != declared:
            raise EnvelopeError("Decrypted frame length does not match its header.")
        return payload
