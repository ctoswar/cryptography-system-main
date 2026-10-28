"""FIPS mode — AES-256-GCM core with zero custom cryptographic construction.

Why this mode exists (the engineering tier): every cryptographic operation
here is a **FIPS-approved algorithm in a NIST-specified mode**, applied per
its specification, with no custom construction layered into the security
argument:

    * AES-256-GCM   — AES per FIPS 197; GCM per NIST SP 800-38D
    * HKDF-SHA256   — key derivation per NIST SP 800-56C Rev 2
    * HMAC-SHA256   — key IDs per FIPS 198-1

The envelope framing is non-cryptographic metadata (the same status as the
framing in age or Fernet).

**Approved =/ validated (stated explicitly).** FIPS 140-3 validation is a CMVP
certification of a specific implementation — no Python library qualifies. The
precise claim this module supports: *uses FIPS-approved algorithms in
NIST-specified modes, structured so a future module validation of the
primitive layer would cover all cryptographic operations.*

**Documented trade-off — key commitment.** GCM is not key-committing
(Bellare & Hoang 2022, ePrint 2022/268; NDSS 2022 partitioning-oracle
literature). The classic (``AC3X``) and SIV (``AC3S``) modes retain
commitment; this mode trades it for maximal algorithmic standardness.

**Nonce discipline.** SP 800-38D bounds a GCM key to 2^32 encryptions with
random 96-bit nonces. Both envelopes here derive the GCM key per message /
per stream from (master, fresh random salt) via HKDF, so each key encrypts
exactly one message (text) or one stream with a 96-bit nonce space
(8-byte prefix || 32-bit counter — up to 2^32 chunks per stream).

Envelopes:

    text    AC3F.<nonce12_b64url>.<ct+tag_b64url>[.<keyid>]
    stream  b"AC3F1" || keyid(4) || salt(16) || nonce_prefix(8)
            || chunk_size(4) || frames(flag|len|ct+tag)...

The AAD binds the envelope metadata: text AAD = b"AC3F" || keyid; per-chunk
stream AAD = header || chunk_index(8) || flag — keyid substitution and
chunk reordering/truncation/trailing data all fail authentication. The key
ID names the long-term key for rotation (active -> archive resolution,
never orphaning data).
"""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .core import AC3Cipher
from .envelope import decode_fips, encode_text
from .exceptions import AC3Error, EnvelopeError, IntegrityError
from .keys import derive_stream, key_id

TEXT_PREFIX = "AC3F."
STREAM_MAGIC = b"AC3F1\x01"
FRAME_HEADER_SIZE = 1 + 4                 # flag + length
TAG_SIZE = 16                             # GCM tag
NONCE_SIZE = 12                           # 96-bit GCM nonce
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
KEY_BYTES = 32
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024      # 4 MiB
MAX_CHUNK_SIZE = 64 * 1024 * 1024
HEADER_SIZE = len(STREAM_MAGIC) + 4 + SALT_SIZE + NONCE_PREFIX_SIZE + 4

_INFO_TEXT = b"ac3x/fips/v1/key"
_INFO_STREAM = b"ac3x/fips/v1/stream"
_AAD_PREFIX = b"AC3F"


def _aad(key_id_value):
    """Envelope metadata bound into the GCM authentication."""
    if key_id_value is None:
        return _AAD_PREFIX
    return _AAD_PREFIX + key_id_value


def _read_exact(src, size: int, what: str) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        piece = src.read(remaining)
        if not piece:
            raise EnvelopeError(f"FIPS stream truncated while reading {what}.")
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


class FIPSCipher:
    """AES-256-GCM cipher with the standard key-management contract.

    Accepts a :class:`~ac3.keys.KeyManager`, raw 32-byte master key, or
    ``None`` — mirroring :class:`AC3Cipher` and :class:`SIVTextCipher`.
    Envelopes carry the 4-byte key ID; decryption resolves it against the
    active key and the rotation archive.
    """

    def __init__(self, key_source=None):
        if isinstance(key_source, AC3Cipher):
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

    # -- key resolution (same contract as the classic cipher) ---------------

    def _resolve(self, key_id_value):
        if key_id_value == key_id(self._master):
            return self._master
        if self._keys is not None:
            found = self._keys.lookup_by_key_id(key_id_value)
            if found is not None:
                return found
        raise EnvelopeError(
            "Encrypted with an unknown key version: the key that produced "
            "this ciphertext is neither the active key nor in the archive."
        )

    def _legacy_candidates(self):
        candidates = [self._master]
        if self._keys is not None and self._keys.manages_archive:
            candidates += [
                k for k in self._keys.all_keys().values() if k != self._master
            ]
        return candidates

    # -- text envelope --------------------------------------------------------

    def encrypt(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError(f"encrypt() expects str, got {type(text).__name__}.")
        nonce = secrets.token_bytes(NONCE_SIZE)
        key = derive_stream(self._master, nonce, _INFO_TEXT, KEY_BYTES)
        kid = key_id(self._master)
        output = AESGCM(key).encrypt(nonce, text.encode("utf-8"), _aad(kid))
        return encode_text([nonce, output, kid], prefix=TEXT_PREFIX)

    def decrypt(self, token: str) -> str:
        nonce, output, key_id_value = decode_fips(token)
        aad = _aad(key_id_value)
        candidates = (
            [self._resolve(key_id_value)]
            if key_id_value is not None
            else self._legacy_candidates()
        )
        last_error = None
        plain = None
        for master in candidates:
            key = derive_stream(master, nonce, _INFO_TEXT, KEY_BYTES)
            try:
                plain = AESGCM(key).decrypt(nonce, output, aad)
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

    # -- bytes API (stream envelope, in memory) -------------------------------

    def encrypt_bytes(self, data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"encrypt_bytes() expects bytes, got {type(data).__name__}."
            )
        import io

        src, dst = io.BytesIO(bytes(data)), io.BytesIO()
        self.encrypt_stream(src, dst, chunk_size=chunk_size)
        return dst.getvalue()

    def decrypt_bytes(self, blob: bytes) -> bytes:
        import io

        src, dst = io.BytesIO(bytes(blob)), io.BytesIO()
        self.decrypt_stream(src, dst)
        return dst.getvalue()

    # -- streaming API (files, constant memory) --------------------------------

    def encrypt_stream(self, src, dst, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
        """Encrypt a binary stream into `dst`. Returns bytes written.

        One GCM key per stream (HKDF from master + fresh 16-byte salt);
        per-chunk 96-bit nonce = fresh 8-byte prefix || 32-bit counter, so
        the SP 800-38D uniqueness condition holds within the stream and the
        per-stream key is never reused across streams.
        """
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise AC3Error(f"chunk_size must be 1..{MAX_CHUNK_SIZE} bytes.")
        kid = key_id(self._master)
        salt = secrets.token_bytes(SALT_SIZE)
        nonce_prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
        key = derive_stream(self._master, salt, _INFO_STREAM, KEY_BYTES)
        header = (
            STREAM_MAGIC + kid + salt + nonce_prefix
            + chunk_size.to_bytes(4, "big")
        )
        aead = AESGCM(key)

        dst.write(header)
        written = len(header)
        index = 0
        carry = b""
        while True:
            chunk = carry + src.read(chunk_size - len(carry))
            carry = b""
            if len(chunk) == chunk_size:
                nxt = src.read(1)
                if nxt:
                    flag, carry = 0, nxt
                else:
                    flag = 1
            else:
                flag = 1
            nonce = nonce_prefix + index.to_bytes(4, "big")
            aad = header + index.to_bytes(8, "big") + bytes([flag])
            sealed = aead.encrypt(nonce, chunk, aad)
            frame = bytes([flag]) + len(sealed).to_bytes(4, "big") + sealed
            dst.write(frame)
            written += len(frame)
            index += 1
            if flag == 1:
                break
        return written

    def decrypt_stream(self, src, dst) -> int:
        """Decrypt an AC3F stream from `src` into `dst`. Returns bytes written.

        Every frame's AAD binds the full header and its chunk index/flag, so
        reordering, truncation, splicing, flag flips, and trailing data all
        fail GCM authentication. The controller stages output and commits
        only after the final chunk authenticates.
        """
        header = _read_exact(src, HEADER_SIZE, "header")
        if not header.startswith(STREAM_MAGIC):
            raise EnvelopeError("Stream is missing the AC3F header.")
        offset = len(STREAM_MAGIC)
        key_id_value = header[offset:offset + 4]
        offset += 4
        salt = header[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce_prefix = header[offset:offset + NONCE_PREFIX_SIZE]
        offset += NONCE_PREFIX_SIZE
        chunk_size = int.from_bytes(header[offset:offset + 4], "big")
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise EnvelopeError(f"Stream declares invalid chunk size {chunk_size}.")

        master = self._resolve(key_id_value)
        key = derive_stream(master, salt, _INFO_STREAM, KEY_BYTES)
        aead = AESGCM(key)

        index = 0
        written = 0
        while True:
            frame_header = src.read(FRAME_HEADER_SIZE)
            if not frame_header:
                raise EnvelopeError("FIPS stream ended without a final chunk (truncated).")
            if len(frame_header) < FRAME_HEADER_SIZE:
                raise EnvelopeError("FIPS stream frame header truncated.")
            flag = frame_header[0]
            if flag not in (0, 1):
                raise EnvelopeError(f"Invalid frame flag {flag}.")
            length = int.from_bytes(frame_header[1:5], "big")
            if flag == 0 and length != chunk_size + TAG_SIZE:
                raise EnvelopeError(
                    "Non-final frame length does not match the declared chunk size."
                )
            if flag == 1 and not TAG_SIZE <= length <= chunk_size + TAG_SIZE:
                raise EnvelopeError(f"Final frame length {length} exceeds chunk size.")
            sealed = _read_exact(src, length, f"frame {index}")
            nonce = nonce_prefix + index.to_bytes(4, "big")
            aad = header + index.to_bytes(8, "big") + bytes([flag])
            try:
                chunk = aead.decrypt(nonce, sealed, aad)
            except InvalidTag as exc:
                raise IntegrityError(
                    "Integrity check failed: stream was modified, reordered, "
                    "truncated, spliced, or the key is wrong."
                ) from exc
            dst.write(chunk)
            written += len(chunk)
            if flag == 1:
                if src.read(1):
                    raise EnvelopeError("Data found after the final chunk.")
                return written
            index += 1

    # -- file API ----------------------------------------------------------------

    def encrypt_file(self, source, target, chunk_size: int = DEFAULT_CHUNK_SIZE):
        from pathlib import Path

        src_path, dst_path = Path(source), Path(target)
        if not src_path.is_file():
            raise AC3Error(f"Input file not found: {src_path}")
        with src_path.open("rb") as fin, dst_path.open("wb") as fout:
            self.encrypt_stream(fin, fout, chunk_size=chunk_size)
        return dst_path

    def decrypt_file(self, source, target):
        from pathlib import Path

        src_path, dst_path = Path(source), Path(target)
        if not src_path.is_file():
            raise AC3Error(f"Input file not found: {src_path}")
        with src_path.open("rb") as fin, dst_path.open("wb") as fout:
            self.decrypt_stream(fin, fout)
        return dst_path


__all__ = ["FIPSCipher", "TEXT_PREFIX", "STREAM_MAGIC"]
