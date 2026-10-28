"""SIV mode — nonce-misuse-resistant authenticated encryption (RFC 5297).

Why this mode exists (v4 weakness W-2): the classic AC3X envelope is
counter-mode based, so reusing a nonce reuses the keystream — catastrophic
and silent. SIV (Synthetic Initialization Vector) is *misuse-resistant*:
the synthetic IV is derived FROM the plaintext, so reusing a nonce degrades
to deterministic encryption — an attacker learns only that two messages are
equal — instead of recovering keystream relationships.

Envelope:

    AC3S.<nonce12_b64url>.<siv_output_b64url>[.<keyid>]

    key   = HKDF-SHA256(master, salt = nonce, info = "ac3x/v4/siv/key", 64)
            (512-bit: S2V key || CTR key per RFC 5297 AES-SIV-CMAC-512)
    ads   = [b"ac3x/v4/siv", nonce]
    output= AESSIV.encrypt(ads, plaintext)  ->  SIV(16) || ciphertext

Behaviour under nonce reuse:

    same message, same nonce   -> identical ciphertext (equality leaks only)
    different message, same nonce -> still confidential, still authenticated
    any tampering              -> IntegrityError

The 12-byte random nonce keeps distinct messages unlinkable in normal
operation; its reuse is simply no longer catastrophic.
"""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from .core import AC3Cipher
from .envelope import SIV_PREFIX, decode_siv, encode_text
from .exceptions import AC3Error, EnvelopeError, IntegrityError
from .keys import derive_stream, key_id

_NONCE_SIZE = 12
_SIV_KEY_BYTES = 64   # AES-SIV-CMAC-512
_SIV_TAG_SIZE = 16
_INFO = b"ac3x/v4/siv/key"


class SIVTextCipher:
    """Nonce-misuse-resistant text encryption (RFC 5297 AES-SIV-CMAC-512).

    Same constructor contract as :class:`AC3Cipher`: a
    :class:`~ac3.keys.KeyManager`, raw 32-byte master key, or ``None``.
    """

    def __init__(self, key_source=None):
        if hasattr(key_source, "_master") and hasattr(key_source, "_keys"):
            # any sibling cipher sharing the same master — duck-typed
            self._master = key_source._master
            self._keys = key_source._keys
        elif isinstance(key_source, AC3Cipher):
            self._master = key_source._master
            self._keys = key_source._keys
        else:
            from .keys import KeyManager, MASTER_KEY_BYTES

            if isinstance(key_source, KeyManager):
                self._keys = key_source
                self._master = key_source.master_key
            elif isinstance(key_source, (bytes, bytearray)):
                self._keys = None
                self._master = bytes(key_source)
                if len(self._master) != MASTER_KEY_BYTES:
                    raise AC3Error(
                        f"Master key must be {MASTER_KEY_BYTES} bytes, "
                        f"got {len(self._master)}."
                    )
            elif key_source is None:
                self._keys = KeyManager()
                self._master = self._keys.master_key
            else:
                raise TypeError(
                    "key_source must be a KeyManager, bytes, or None; "
                    f"got {type(key_source).__name__}."
                )

    def _siv_key(self, nonce: bytes, master: bytes) -> bytes:
        return derive_stream(master, nonce, _INFO, _SIV_KEY_BYTES)

    def _resolve(self, key_id_value):
        if key_id_value is None:
            return [self._master] + (
                [k for k in self._keys.all_keys().values() if k != self._master]
                if self._keys is not None and self._keys.manages_archive else []
            )
        if key_id_value == key_id(self._master):
            return [self._master]
        if self._keys is not None:
            found = self._keys.lookup_by_key_id(key_id_value)
            if found is not None:
                return [found]
        raise EnvelopeError(
            "Encrypted with an unknown key version: the key that produced "
            "this ciphertext is neither the active key nor in the archive."
        )

    def encrypt(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError(f"encrypt() expects str, got {type(text).__name__}.")
        nonce = secrets.token_bytes(_NONCE_SIZE)
        key = self._siv_key(nonce, self._master)
        output = AESSIV(key).encrypt(text.encode("utf-8"), [_INFO, nonce])
        return encode_text([nonce, output, key_id(self._master)], prefix=SIV_PREFIX)

    def decrypt(self, token: str) -> str:
        nonce, output, key_id_value = decode_siv(token)
        ads = [_INFO, nonce]
        last_error = None
        plain = None
        for master in self._resolve(key_id_value):
            try:
                plain = AESSIV(self._siv_key(nonce, master)).decrypt(output, ads)
                break
            except InvalidTag as exc:
                last_error = exc
        if plain is None:
            raise IntegrityError(
                "Integrity check failed: ciphertext was modified or the key is wrong."
            ) from last_error
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EnvelopeError(
                "Decrypted plaintext is not valid UTF-8."
            ) from exc


__all__ = ["SIVTextCipher", "SIV_PREFIX"]
