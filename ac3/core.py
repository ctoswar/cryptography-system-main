"""AC3-X (v3) — the thesis five-layer pipeline with an AES-256-CTR engine.

AC3-X is the hybrid of the AC3 thesis identity and NIST-standard primitives.
The five layers keep their structure and their order; what changed from v2 is
the keystream generator inside both XOR passes: raw HKDF-Expand output is
replaced by **AES-256-CTR** keystreams under independently derived subkeys.

Layer map (thesis lineage):

    L1  Framing        version byte + uint32 length   (v2 framing, unchanged)
    L2  Byte Caesar    keyed additive shift mod 256   (v2 Caesar, unchanged)
    L3  XOR stream     XOR with AES-256-CTR keystream (v2 XOR, AES-CTR engine)
    L4  Transposition  keyed column shuffle           (v2 transposition, unchanged)
    L5  XOR + HMAC     AES-CTR XOR pass + HMAC-SHA256 (v2 layer, AES-CTR engine)

Standard primitives and the claims that rest on them:

    * AES-256-CTR        (NIST SP 800-38A)  — confidentiality of both XOR passes
    * HMAC-SHA256        (FIPS 198-1)       — integrity, encrypt-then-MAC order
    * HKDF-SHA256        (RFC 5869)         — all subkeys from (master, nonce)
    * Encrypt-then-MAC   (Bellare–Namprempre) — provably secure composition

Honest scope (see SPEC.md): the *layering* adds no provable strength over the
AES-CTR + HMAC composition — its purpose is architectural continuity with the
thesis. The security case rests entirely on the standard primitives above and
on per-message nonce uniqueness.

Envelopes:

    Text    AC3X.<nonce_b64url>.<body_b64url>.<tag_b64url>     (one-shot)
    Stream  b"AC3X3\\x01" || nonce(16) || chunk_size(4) || frames… || tag(32)

The stream format is chunked: constant memory regardless of file size. Every
frame (flag, length, payload) and the whole header are covered by one running
HMAC, so truncation, reordering, splicing across files, and trailing data all
fail authentication. Decryptors stage output and commit only after the final
stream tag verifies (the controller enforces this with an atomic rename).

Legacy envelopes (``AC3v2.``/``AC3V2``, ``AC3A.``/``AC3AES``) are rejected:
v3 is a clean break with no backward compatibility, same policy as v1 -> v2.
"""

import io
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .envelope import decode_text, encode_text
from .exceptions import AC3Error, EnvelopeError, IntegrityError, InvalidKeyError
from .keys import MASTER_KEY_BYTES, KeyManager, _expand, _extract

VERSION = 3

_FRAME_VERSION = 3
_LENGTH_SIZE = 4
_MAX_PLAINTEXT = (1 << 32) - 1
_COLUMNS = 8
_MAC_SIZE = 32
_NONCE_SIZE = 16

TEXT_PREFIX = "AC3X."
STREAM_MAGIC = b"AC3X3\x01"
HEADER_SIZE = len(STREAM_MAGIC) + _NONCE_SIZE + 4   # magic + nonce + chunk_size
FRAME_HEADER_SIZE = 1 + 4                           # flag + length
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024                # 4 MiB
MAX_CHUNK_SIZE = 64 * 1024 * 1024

_INFO = b"ac3x/v3/"


# --------------------------------------------------------------------------
# subkey schedule — HKDF-SHA256, salt = message nonce (RFC 5869)
# --------------------------------------------------------------------------

class _KeySchedule:
    """All per-message key material, derived once from (master, nonce)."""

    def __init__(self, master_key: bytes, nonce: bytes):
        self.prk = _extract(master_key, nonce)  # HKDF-Extract, salt = nonce
        shift_byte = _expand(self.prk, _INFO + b"l2-shift", 1)[0]
        self.shift = (shift_byte % 255) + 1     # never 0: Caesar must move bytes
        self.k3 = _expand(self.prk, _INFO + b"l3-ctr-key", 32)
        self.k5 = _expand(self.prk, _INFO + b"l5-ctr-key", 32)
        self.columns = self._column_order()
        self.mac_key = _expand(self.prk, _INFO + b"mac", 32)

    def iv(self, layer: int, index: int) -> bytes:
        """16-byte CTR counter block, unique per (layer, chunk index)."""
        idx = index.to_bytes(8, "big")
        return _expand(self.prk, _INFO + f"l{layer}-ctr-iv/".encode() + idx, 16)

    def _column_order(self) -> list:
        """Deterministic Fisher-Yates shuffle of column indices 0..7."""
        rnd = _expand(self.prk, _INFO + b"l4-columns", _COLUMNS)
        order = list(range(_COLUMNS))
        for i in range(_COLUMNS - 1, 0, -1):
            j = rnd[_COLUMNS - 1 - i] % (i + 1)
            order[i], order[j] = order[j], order[i]
        return order


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def _ctr_apply(key: bytes, iv: bytes, data: bytes) -> bytes:
    """The XOR-with-keystream pass, computed by AES-256-CTR in optimized C.

    CTR mode ciphertext = plaintext XOR AES(counter block), so applying CTR
    to `data` IS the keyed XOR pass — byte-identical to
    ``_xor(data, _ctr_keystream(key, iv, len(data)))`` but without the
    intermediate Python-side buffers. CTR is symmetric, so one function
    serves both directions.
    """
    if not data:
        return b""
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(data)


def _shift_table(shift: int) -> bytes:
    """256-byte translate table implementing (b + shift) mod 256 at C speed."""
    shift &= 0xFF
    return bytes((b + shift) & 0xFF for b in range(256))


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


def _read_exact(src, size: int, what: str) -> bytes:
    """Read exactly `size` bytes or raise (partial reads are truncation)."""
    chunks = []
    remaining = size
    while remaining > 0:
        piece = src.read(remaining)
        if not piece:
            raise EnvelopeError(f"AC3-X stream truncated while reading {what}.")
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


# --------------------------------------------------------------------------
# cipher
# --------------------------------------------------------------------------

class AC3Cipher:
    """AC3-X (v3) cipher — five thesis layers over AES-CTR + HMAC-SHA256.

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
        nonce = secrets.token_bytes(_NONCE_SIZE)
        body, tag = self._seal(text.encode("utf-8"), nonce)
        return encode_text(nonce, body, tag, prefix=TEXT_PREFIX)

    def decrypt(self, token: str) -> str:
        nonce, body, tag = decode_text(token, prefix=TEXT_PREFIX)
        return self._open(nonce, body, tag).decode("utf-8")

    # -- bytes API (stream envelope, in memory) ----------------------------

    def encrypt_bytes(self, data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"encrypt_bytes() expects bytes, got {type(data).__name__}."
            )
        src, dst = io.BytesIO(bytes(data)), io.BytesIO()
        self.encrypt_stream(src, dst, chunk_size=chunk_size)
        return dst.getvalue()

    def decrypt_bytes(self, blob: bytes) -> bytes:
        src, dst = io.BytesIO(bytes(blob)), io.BytesIO()
        self.decrypt_stream(src, dst)
        return dst.getvalue()

    # -- streaming API (high volume) ---------------------------------------

    def encrypt_stream(self, src, dst, chunk_size: int = DEFAULT_CHUNK_SIZE,
                       nonce: bytes | None = None) -> int:
        """Encrypt a binary stream into `dst`. Returns bytes written.

        Constant memory: at most `chunk_size` + framing overhead is held.
        `nonce` exists ONLY for SPEC conformance vectors — it must be random
        per message in production (reuse catastrophically weakens CTR).
        """
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise AC3Error(f"chunk_size must be 1..{MAX_CHUNK_SIZE} bytes.")
        nonce = nonce or secrets.token_bytes(_NONCE_SIZE)
        if len(nonce) != _NONCE_SIZE:
            raise AC3Error(f"nonce must be {_NONCE_SIZE} bytes.")
        ks = _KeySchedule(self._master, nonce)
        header = STREAM_MAGIC + nonce + chunk_size.to_bytes(4, "big")

        mac = hmac.HMAC(ks.mac_key, hashes.SHA256())
        mac.update(header)

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
            processed = self._transform_chunk(chunk, ks, index)
            frame = bytes([flag]) + len(processed).to_bytes(4, "big") + processed
            mac.update(frame)
            dst.write(frame)
            written += len(frame)
            index += 1
            if flag == 1:
                break
        tag = mac.finalize()
        dst.write(tag)
        return written + _MAC_SIZE

    def decrypt_stream(self, src, dst) -> int:
        """Decrypt an AC3-X stream from `src` into `dst`. Returns bytes written.

        The running HMAC covers the header and every frame, so reordering,
        truncation, splicing, flag flips, and trailing data all fail. The
        final tag verifies before the caller should trust `dst` — the
        controller stages to a temp file and commits only on success.
        """
        header = _read_exact(src, HEADER_SIZE, "header")
        if not header.startswith(STREAM_MAGIC):
            raise EnvelopeError("Stream is missing the AC3-X header.")
        nonce = header[len(STREAM_MAGIC):len(STREAM_MAGIC) + _NONCE_SIZE]
        chunk_size = int.from_bytes(header[len(STREAM_MAGIC) + _NONCE_SIZE:], "big")
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise EnvelopeError(f"Stream declares invalid chunk size {chunk_size}.")

        ks = _KeySchedule(self._master, nonce)
        mac = hmac.HMAC(ks.mac_key, hashes.SHA256())
        mac.update(header)

        index = 0
        written = 0
        while True:
            frame_header = src.read(FRAME_HEADER_SIZE)
            if not frame_header:
                raise EnvelopeError("AC3-X stream ended without a final chunk (truncated).")
            if len(frame_header) < FRAME_HEADER_SIZE:
                raise EnvelopeError("AC3-X stream frame header truncated.")
            flag = frame_header[0]
            if flag not in (0, 1):
                raise EnvelopeError(f"Invalid frame flag {flag}.")
            length = int.from_bytes(frame_header[1:5], "big")
            if flag == 0 and length != chunk_size:
                raise EnvelopeError("Non-final frame length does not match the declared chunk size.")
            if flag == 1 and length > chunk_size:
                raise EnvelopeError(f"Final frame length {length} exceeds chunk size.")
            processed = _read_exact(src, length, f"frame {index}")
            mac.update(frame_header + processed)
            chunk = self._untransform_chunk(processed, ks, index)
            dst.write(chunk)
            written += len(chunk)
            if flag == 1:
                tag = _read_exact(src, _MAC_SIZE, "stream tag")
                try:
                    mac.verify(tag)
                except InvalidSignature as exc:
                    raise IntegrityError(
                        "Integrity check failed: stream was modified, reordered, "
                        "truncated, spliced, or the key is wrong."
                    ) from exc
                if src.read(1):
                    raise EnvelopeError("Data found after the final chunk.")
                return written
            index += 1

    # -- file API ------------------------------------------------------------

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

    # -- pipeline --------------------------------------------------------------

    def _transform_chunk(self, chunk: bytes, ks: _KeySchedule, index: int) -> bytes:
        """L2 Caesar -> L3 XOR (AES-CTR) -> L4 transpose -> L5 XOR (AES-CTR)."""
        level2 = chunk.translate(_shift_table(ks.shift))
        level3 = _ctr_apply(ks.k3, ks.iv(3, index), level2)
        level4 = _transpose(level3, ks.columns)
        return _ctr_apply(ks.k5, ks.iv(5, index), level4)

    def _untransform_chunk(self, processed: bytes, ks: _KeySchedule, index: int) -> bytes:
        """Exact inverse of _transform_chunk."""
        level4 = _ctr_apply(ks.k5, ks.iv(5, index), processed)
        level3 = _untranspose(level4, ks.columns)
        level2 = _ctr_apply(ks.k3, ks.iv(3, index), level3)
        return level2.translate(_shift_table(-ks.shift))

    def _seal(self, data: bytes, nonce: bytes):
        """One-shot text-envelope pipeline. Returns (body, tag)."""
        if len(data) > _MAX_PLAINTEXT:
            raise AC3Error(f"Plaintext exceeds {_MAX_PLAINTEXT} bytes.")
        ks = _KeySchedule(self._master, nonce)

        # L1 — framing: version byte + declared length + payload.
        framed = bytes([_FRAME_VERSION]) + len(data).to_bytes(_LENGTH_SIZE, "big") + data
        body = self._transform_chunk(framed, ks, index=0)

        # L5 tag — HMAC-SHA256 over version + nonce + ciphertext (encrypt-then-MAC).
        mac = hmac.HMAC(ks.mac_key, hashes.SHA256())
        mac.update(bytes([_FRAME_VERSION]) + nonce + body)
        return body, mac.finalize()

    def _open(self, nonce: bytes, body: bytes, tag: bytes) -> bytes:
        ks = _KeySchedule(self._master, nonce)

        # Verify BEFORE decrypting (constant-time via cryptography's hmac).
        mac = hmac.HMAC(ks.mac_key, hashes.SHA256())
        mac.update(bytes([_FRAME_VERSION]) + nonce + body)
        try:
            mac.verify(tag)
        except InvalidSignature as exc:
            raise IntegrityError(
                "Integrity check failed: ciphertext was modified or the key is wrong."
            ) from exc

        framed = self._untransform_chunk(body, ks, index=0)

        # L1 reversed.
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

    # -- deterministic sealing (SPEC conformance vectors ONLY) ------------------

    def seal_deterministic(self, data: bytes, nonce: bytes) -> str:
        """Produce the text envelope for a FIXED nonce.

        For SPEC.md conformance vectors and cross-implementation tests only.
        Never use in production: reusing a nonce across messages reuses CTR
        keystreams and is catastrophic.
        """
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != _NONCE_SIZE:
            raise AC3Error(f"nonce must be exactly {_NONCE_SIZE} bytes.")
        nonce = bytes(nonce)
        body, tag = self._seal(bytes(data), nonce)
        return encode_text(nonce, body, tag, prefix=TEXT_PREFIX)


__all__ = ["AC3Cipher", "VERSION", "TEXT_PREFIX", "STREAM_MAGIC"]
