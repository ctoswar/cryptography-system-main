"""AES-256-GCM — the standard AEAD mode, with chunked streaming for bulk data.

Why this module exists next to :mod:`ac3.core`:
  * ``ac3.core`` is the thesis's five-layer identity — educational, homegrown.
  * AES-256-GCM (NIST SP 800-38D) is the vetted industry standard. Use it for
    real data. It is hardware-accelerated (AES-NI) — roughly GB/s, versus the
    layered pipeline's ~3 MB/s.

Two envelopes:

Text (``AC3A.<nonce>.<body>.<tag>``) — one-shot:
    key      = HKDF-SHA256(master, salt = 16-byte message nonce, info = "ac3/aes-256-gcm/text")
    nonce    = 12 random bytes (GCM standard), tag = 16 bytes

Streaming (files) — chunked construction with per-chunk authentication:

    header   = b"AC3AES\\x01" || nonce_prefix(4) || salt(16) || chunk_size(4)
    frame    = flag(1) || length(4) || ciphertext+tag
    key      = HKDF-SHA256(master, salt = header salt, info = "ac3/aes-256-gcm/stream")
    nonce_i  = nonce_prefix(4) || counter(8)        # unique per chunk
    aad_i    = header || counter(8) || flag(1)

  * **Reordering** fails: the counter is in both the nonce and the AAD.
  * **Truncation** fails: every frame except the last carries flag=0; a stream
    that ends on flag=0 has no final chunk -> rejected. Flipping a flag to 1
    breaks that frame's tag (the flag is authenticated).
  * **Splicing** across files fails: the whole header (salt) is in every AAD,
    so frames from another stream never verify.
  * **Trailing data** after the final frame is rejected.

Memory is constant regardless of file size: only one chunk (default 4 MiB)
is held at a time, so multi-GB files stream through at full disk speed.
"""

import io
import secrets
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .envelope import decode_text, encode_text
from .exceptions import AC3Error, EnvelopeError, IntegrityError, InvalidKeyError
from .keys import resolve_master_key

TEXT_PREFIX = "AC3A."
STREAM_MAGIC = b"AC3AES\x01"
NONCE_SIZE = 12          # GCM standard nonce
TAG_SIZE = 16            # 128-bit GCM tag
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 4
HEADER_SIZE = len(STREAM_MAGIC) + NONCE_PREFIX_SIZE + SALT_SIZE + 4
FRAME_HEADER_SIZE = 1 + 4  # flag + length
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024       # 4 MiB
MAX_CHUNK_SIZE = 64 * 1024 * 1024

_INFO_TEXT = b"ac3/aes-256-gcm/text"
_INFO_STREAM = b"ac3/aes-256-gcm/stream"

_ALGORITHMS = {"ac3", "aes"}


def validate_algorithm(algorithm: str) -> str:
    if algorithm not in _ALGORITHMS:
        from .exceptions import InvalidAlgorithmError

        raise InvalidAlgorithmError(
            f"Unknown algorithm {algorithm!r}; expected one of {sorted(_ALGORITHMS)}."
        )
    return algorithm


def _read_exact(src, size: int, what: str) -> bytes:
    """Read exactly `size` bytes or raise (partial reads are truncation)."""
    chunks = []
    remaining = size
    while remaining > 0:
        piece = src.read(remaining)
        if not piece:
            raise EnvelopeError(f"AES stream truncated while reading {what}.")
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


class AESGCMCipher:
    """AES-256-GCM cipher with one-shot and streaming APIs.

    Accepts a :class:`KeyManager`, raw 32-byte master key, or nothing
    (auto-provisions from the project ``.env``) — same contract as AC3Cipher.
    The same master key is reused; HKDF domain separation keeps the AES
    subkeys independent of the five-layer pipeline's subkeys.
    """

    def __init__(self, key_source=None):
        self._master = resolve_master_key(key_source)

    # -- str API (text envelope) ------------------------------------------

    def encrypt(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError(f"encrypt() expects str, got {type(text).__name__}.")
        nonce = secrets.token_bytes(NONCE_SIZE)
        # Per-message key from a random salt: no cross-message key reuse even
        # if the nonce generator were ever to fail open.
        key = self._derive(nonce, _INFO_TEXT)
        sealed = AESGCM(key).encrypt(nonce, text.encode("utf-8"), TEXT_PREFIX.encode())
        body, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]
        return encode_text(nonce, body, tag, prefix=TEXT_PREFIX)

    def decrypt(self, token: str) -> str:
        nonce, body, tag = decode_text(
            token, prefix=TEXT_PREFIX, nonce_size=NONCE_SIZE, tag_size=TAG_SIZE
        )
        key = self._derive(nonce, _INFO_TEXT)
        try:
            plain = AESGCM(key).decrypt(nonce, body + tag, TEXT_PREFIX.encode())
        except InvalidTag as exc:
            raise IntegrityError(
                "Integrity check failed: ciphertext was modified or the key is wrong."
            ) from exc
        return plain.decode("utf-8")

    # -- bytes API (streaming envelope) -----------------------------------

    def encrypt_bytes(self, data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"encrypt_bytes() expects bytes, got {type(data).__name__}."
            )
        src, dst = io.BytesIO(bytes(data)), io.BytesIO()
        self.encrypt_stream(src, dst, chunk_size=chunk_size)
        return dst.getvalue()

    def decrypt_bytes(self, blob: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        src, dst = io.BytesIO(bytes(blob)), io.BytesIO()
        self.decrypt_stream(src, dst)
        return dst.getvalue()

    # -- streaming API (high volume) --------------------------------------

    def encrypt_stream(self, src, dst, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
        """Encrypt a binary stream into `dst`. Returns bytes written.

        Constant memory: at most `chunk_size` + framing overhead is held.
        """
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise AC3Error(f"chunk_size must be 1..{MAX_CHUNK_SIZE} bytes.")
        nonce_prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
        salt = secrets.token_bytes(SALT_SIZE)
        header = STREAM_MAGIC + nonce_prefix + salt + struct.pack(">I", chunk_size)
        key = self._derive(salt, _INFO_STREAM)
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
                    flag, carry = 0, nxt   # more data follows
                else:
                    flag = 1               # exact-multiple boundary: this is last
            else:
                flag = 1                   # short read (or empty input) = final
            aad = header + struct.pack(">Q", index) + bytes([flag])
            nonce = nonce_prefix + struct.pack(">Q", index)
            sealed = aead.encrypt(nonce, chunk, aad)
            frame = bytes([flag]) + struct.pack(">I", len(sealed)) + sealed
            dst.write(frame)
            written += len(frame)
            index += 1
            if flag == 1:
                break
        return written

    def decrypt_stream(self, src, dst) -> int:
        """Decrypt an AES stream from `dst`'s counterpart. Returns bytes written.

        Rejects truncation, reordering, splicing, and trailing data — see the
        module docstring for the construction.
        """
        header = _read_exact(src, HEADER_SIZE, "header")
        if not header.startswith(STREAM_MAGIC):
            raise EnvelopeError("Stream is missing the AC3 AES header.")
        salt_at = len(STREAM_MAGIC) + NONCE_PREFIX_SIZE
        nonce_prefix = header[len(STREAM_MAGIC):salt_at]
        salt = header[salt_at:salt_at + SALT_SIZE]
        chunk_size = struct.unpack(">I", header[salt_at + SALT_SIZE:])[0]
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise EnvelopeError(f"Stream declares invalid chunk size {chunk_size}.")

        key = self._derive(salt, _INFO_STREAM)
        aead = AESGCM(key)
        index = 0
        written = 0
        while True:
            frame_header = src.read(FRAME_HEADER_SIZE)
            if not frame_header:
                raise EnvelopeError("AES stream ended without a final chunk (truncated).")
            if len(frame_header) < FRAME_HEADER_SIZE:
                raise EnvelopeError("AES stream frame header truncated.")
            flag = frame_header[0]
            if flag not in (0, 1):
                raise EnvelopeError(f"Invalid frame flag {flag}.")
            length = struct.unpack(">I", frame_header[1:5])[0]
            if not TAG_SIZE <= length <= chunk_size + TAG_SIZE:
                raise EnvelopeError(f"Frame length {length} out of range.")
            sealed = _read_exact(src, length, f"frame {index}")
            aad = header + struct.pack(">Q", index) + bytes([flag])
            nonce = nonce_prefix + struct.pack(">Q", index)
            try:
                plain = aead.decrypt(nonce, sealed, aad)
            except InvalidTag as exc:
                raise IntegrityError(
                    "AES integrity check failed: stream was modified, reordered, "
                    "truncated, spliced, or the key is wrong."
                ) from exc
            dst.write(plain)
            written += len(plain)
            if flag == 1:
                if src.read(1):
                    raise EnvelopeError("Data found after the final chunk.")
                return written
            index += 1

    # -- file API ----------------------------------------------------------

    def encrypt_file(self, source, target, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Path:
        src_path, dst_path = Path(source), Path(target)
        if not src_path.is_file():
            raise AC3Error(f"Input file not found: {src_path}")
        with src_path.open("rb") as fin, dst_path.open("wb") as fout:
            self.encrypt_stream(fin, fout, chunk_size=chunk_size)
        return dst_path

    def decrypt_file(self, source, target) -> Path:
        src_path, dst_path = Path(source), Path(target)
        if not src_path.is_file():
            raise AC3Error(f"Input file not found: {src_path}")
        with src_path.open("rb") as fin, dst_path.open("wb") as fout:
            self.decrypt_stream(fin, fout)
        return dst_path

    # -- derivation ---------------------------------------------------------

    def _derive(self, salt: bytes, info: bytes) -> bytes:
        from .keys import derive_stream

        return derive_stream(self._master, salt, info, 32)


def looks_like_aes_text(token: str) -> bool:
    return isinstance(token, str) and token.startswith(TEXT_PREFIX)


def looks_like_aes_stream(blob) -> bool:
    return bytes(blob[: len(STREAM_MAGIC)]) == STREAM_MAGIC
