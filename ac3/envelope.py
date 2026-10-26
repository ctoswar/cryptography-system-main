"""Ciphertext envelope formats for AC3 v2.

Text form (API/CLI strings):
    AC3v2.<nonce_b64url>.<body_b64url>.<tag_b64url>

Binary form (file encryption) — avoids inflating files with base64:
    b"AC3V2\x01" || nonce(16) || body || tag(32)
"""

import base64
import re

from .exceptions import EnvelopeError

TEXT_PREFIX = "AC3v2."
BINARY_MAGIC = b"AC3V2\x01"
NONCE_SIZE = 16
TAG_SIZE = 32

# Unpadded base64url alphabet only. Python's decoder discards unknown
# characters by default, which would make token strings malleable
# (AC3v2.n.BO.JUNK!US... == AC3v2.n.BONUS...); reject anything off-alphabet.
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


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


def encode_text(nonce: bytes, body: bytes, tag: bytes, *, prefix: str = TEXT_PREFIX) -> str:
    return f"{prefix}{_b64e(nonce)}.{_b64e(body)}.{_b64e(tag)}"


def decode_text(
    token: str,
    *,
    prefix: str = TEXT_PREFIX,
    nonce_size: int = NONCE_SIZE,
    tag_size: int = TAG_SIZE,
):
    if not isinstance(token, str) or not token.startswith(prefix):
        raise EnvelopeError(f"Ciphertext must start with '{prefix}'.")
    parts = token[len(prefix):].split(".")
    if len(parts) != 3:
        raise EnvelopeError(f"Ciphertext must have the form {prefix}nonce.body.tag.")
    nonce, body, tag = (_b64d(part, name) for part, name in zip(parts, ("Nonce", "Body", "Tag")))
    if len(nonce) != nonce_size:
        raise EnvelopeError(f"Nonce must be {nonce_size} bytes.")
    if len(tag) != tag_size:
        raise EnvelopeError(f"Tag must be {tag_size} bytes.")
    return nonce, body, tag


def encode_binary(nonce: bytes, body: bytes, tag: bytes) -> bytes:
    return BINARY_MAGIC + nonce + body + tag


def decode_binary(blob: bytes):
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise EnvelopeError("Binary ciphertext must be bytes.")
    blob = bytes(blob)
    header = len(BINARY_MAGIC) + NONCE_SIZE
    if len(blob) < header + TAG_SIZE:
        raise EnvelopeError("Binary ciphertext is truncated.")
    if not blob.startswith(BINARY_MAGIC):
        raise EnvelopeError("Binary ciphertext is missing the AC3 v2 header.")
    nonce = blob[len(BINARY_MAGIC):header]
    body = blob[header:-TAG_SIZE]
    tag = blob[-TAG_SIZE:]
    return nonce, body, tag
