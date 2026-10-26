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


def encode_text(nonce: bytes, body: bytes, tag: bytes) -> str:
    return f"{TEXT_PREFIX}{_b64e(nonce)}.{_b64e(body)}.{_b64e(tag)}"


def decode_text(token: str):
    if not isinstance(token, str) or not token.startswith(TEXT_PREFIX):
        raise EnvelopeError("Ciphertext must start with 'AC3v2.'.")
    parts = token[len(TEXT_PREFIX):].split(".")
    if len(parts) != 3:
        raise EnvelopeError("Ciphertext must have the form AC3v2.nonce.body.tag.")
    nonce, body, tag = (_b64d(part, name) for part, name in zip(parts, ("Nonce", "Body", "Tag")))
    if len(nonce) != NONCE_SIZE:
        raise EnvelopeError(f"Nonce must be {NONCE_SIZE} bytes.")
    if len(tag) != TAG_SIZE:
        raise EnvelopeError(f"Tag must be {TAG_SIZE} bytes.")
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
