"""Ciphertext envelope formats for AC3-X (v3).

Text form (API/CLI strings):
    AC3X.<nonce_b64url>.<body_b64url>.<tag_b64url>

Binary data (files, arbitrary size) uses the chunked stream format defined in
:mod:`ac3.core` (magic ``AC3X3\\x01``); there is no separate one-shot binary
envelope in v3.

Legacy v2 envelopes (``AC3v2.`` text, ``AC3V2`` binary) and the interim AES
envelopes (``AC3A.``) are NOT accepted: v3 is a clean break.
"""

import base64
import re

from .exceptions import EnvelopeError

TEXT_PREFIX = "AC3X."
NONCE_SIZE = 16
TAG_SIZE = 32

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
        for legacy in _LEGACY_PREFIXES:
            if isinstance(token, str) and token.startswith(legacy):
                raise EnvelopeError(
                    f"Legacy envelope '{legacy}' is not supported by AC3-X (v3); "
                    "re-encrypt the data with the current version."
                )
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
