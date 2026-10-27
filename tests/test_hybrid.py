"""AC3-X (v3) tests: text pipeline, chunked streaming, attacks, and spec vectors.

The hybrid keeps the five thesis layers and swaps the keystream generator to
AES-256-CTR. These tests cover:
  * text round-trips and tamper rejection for every envelope region
  * chunk-boundary streaming (0 / 1 / exact / +1 / multi-chunk)
  * structural stream attacks: bit-flip, truncate, reorder, splice, trailing
  * the legacy-envelope clean break
  * deterministic SPEC conformance vectors (byte-exact)
  * constant-memory streaming proof
"""

import io
import secrets
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import AC3Cipher, CMainController, IntegrityError
from ac3.core import (
    DEFAULT_CHUNK_SIZE,
    HEADER_SIZE,
    MAX_CHUNK_SIZE,
    STREAM_MAGIC,
    STREAM_MAGIC_V4,
    TEXT_PREFIX,
    VERSION,
)
from ac3.exceptions import EnvelopeError

# Fixed material for deterministic vectors (mirrors SPEC.md).
VECTOR_MASTER = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
VECTOR_NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")


@pytest.fixture()
def same_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture()
def cipher(same_key) -> AC3Cipher:
    return AC3Cipher(same_key)


# --------------------------------------------------------------------------
# text pipeline
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["", "hello", "ünïcode 🔐", "x" * 10_000])
def test_text_roundtrip(cipher, text):
    token = cipher.encrypt(text)
    assert token.startswith(TEXT_PREFIX)
    assert cipher.decrypt(token) == text


def test_text_tokens_are_unique(cipher):
    tokens = {cipher.encrypt("same message") for _ in range(20)}
    assert len(tokens) == 20, "random nonce not producing unique tokens"


def test_text_tamper_body_rejected(cipher):
    token = cipher.encrypt("attack at dawn")
    prefix, nonce, body, tag = token.split(".", 3)
    bad_body = ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(IntegrityError):
        cipher.decrypt(f"{prefix}.{nonce}.{bad_body}.{tag}")


def test_text_tamper_tag_rejected(cipher):
    token = cipher.encrypt("attack at dawn")
    prefix, nonce, body, tag = token.split(".", 3)
    bad_tag = ("A" if tag[0] != "A" else "B") + tag[1:]
    with pytest.raises(IntegrityError):
        cipher.decrypt(f"{prefix}.{nonce}.{body}.{bad_tag}")


def test_text_wrong_key_rejected(cipher):
    from ac3.exceptions import EnvelopeError

    token = cipher.encrypt("secret")
    other = AC3Cipher(secrets.token_bytes(32))
    # A token from a different deployment carries a key ID this cipher does
    # not recognize — that is an envelope/key-management error, distinct
    # from same-key tampering (which raises IntegrityError).
    with pytest.raises(EnvelopeError, match="unknown key version"):
        other.decrypt(token)


def test_deterministic_seal_is_reproducible(cipher):
    a = cipher.seal_deterministic(b"determinism check", VECTOR_NONCE)
    b = cipher.seal_deterministic(b"determinism check", VECTOR_NONCE)
    assert a == b, "fixed (key, nonce, plaintext) must yield identical output"


def test_deterministic_seal_rejects_bad_nonce(cipher):
    with pytest.raises(Exception):
        cipher.seal_deterministic(b"x", b"short")


def test_different_nonces_give_different_ciphertexts(cipher):
    data = b"same plaintext"
    a = cipher.seal_deterministic(data, b"\x00" * 16)
    b = cipher.seal_deterministic(data, b"\x01" * 16)
    assert a != b


# --------------------------------------------------------------------------
# streaming — chunk boundaries
# --------------------------------------------------------------------------

@pytest.mark.parametrize("size,chunk", [
    (0, 64),
    (1, 64),
    (63, 64),
    (64, 64),      # exact boundary
    (65, 64),      # boundary + 1
    (5000, 256),   # many chunks
    (10_000, DEFAULT_CHUNK_SIZE),  # single-chunk with default size
])
def test_stream_roundtrip(cipher, size, chunk):
    data = secrets.token_bytes(size)
    blob = cipher.encrypt_bytes(data, chunk_size=chunk)
    assert blob[: len(STREAM_MAGIC_V4)] == STREAM_MAGIC_V4
    assert cipher.decrypt_bytes(blob) == data


def test_stream_header_layout(cipher):
    blob = cipher.encrypt_bytes(b"data", chunk_size=1024)
    assert blob[:6] == STREAM_MAGIC_V4
    key_id_field = blob[6:10]
    nonce = blob[10:26]
    declared = struct.unpack(">I", blob[26:30])[0]
    assert len(key_id_field) == 4 and len(nonce) == 16 and declared == 1024
    assert HEADER_SIZE == 30


def test_legacy_stream_still_decrypts(cipher):
    """Pre-v4 AC3X3 streams (no key ID) decrypt via the legacy fallback.

    Built genuinely: v4 frames are byte-identical to what the legacy format
    would produce (same key schedule, same nonce) — only the header and its
    MAC differ, so the legacy stream is re-MACed over the legacy header.
    """
    from cryptography.hazmat.primitives import hashes, hmac as _hmac

    from ac3.core import (
        LEGACY_HEADER_SIZE,
        STREAM_MAGIC,
        _KeySchedule,
        DEFAULT_CHUNK_SIZE,
    )

    data = b"pre-v4 stream content" * 20
    nonce = secrets.token_bytes(16)
    ks = _KeySchedule(cipher._master, nonce, domain=b"stream")
    chunk_size = 128
    header = STREAM_MAGIC + nonce + chunk_size.to_bytes(4, "big")
    mac = _hmac.HMAC(ks.mac_key, hashes.SHA256())
    mac.update(header)

    frames = io.BytesIO()
    src = io.BytesIO(data)
    chunks = []
    while True:
        piece = src.read(chunk_size)
        if not piece:
            break
        chunks.append(piece)
    for index, chunk in enumerate(chunks):
        flag = 1 if index == len(chunks) - 1 else 0
        processed = cipher._transform_chunk(chunk, ks, index)
        frame = bytes([flag]) + len(processed).to_bytes(4, "big") + processed
        mac.update(frame)
        frames.write(frame)
    legacy_stream = header + frames.getvalue() + mac.finalize()
    assert len(header) == LEGACY_HEADER_SIZE

    back = io.BytesIO()
    cipher.decrypt_stream(io.BytesIO(legacy_stream), back)
    assert back.getvalue() == data


def test_stream_header_downgrade_is_tamper_evident(cipher):
    """The header is inside the MAC: flipping a v4 stream to the legacy
    magic (even stripping the key ID consistently) must fail authentication."""
    data = b"downgrade attempt" * 10
    blob = bytearray(cipher.encrypt_bytes(data, chunk_size=128))
    blob[3] = ord("3")  # AC3X4 -> AC3X3
    legacy_attempt = bytes(blob[:6]) + bytes(blob[10:])
    with pytest.raises((IntegrityError, EnvelopeError)):
        cipher.decrypt_bytes(legacy_attempt)


def test_stream_chunk_size_bounds(cipher):
    with pytest.raises(Exception):
        cipher.encrypt_bytes(b"data", chunk_size=0)
    with pytest.raises(Exception):
        cipher.encrypt_bytes(b"data", chunk_size=MAX_CHUNK_SIZE + 1)


def test_stream_object_api(cipher):
    data = secrets.token_bytes(1000)
    out = io.BytesIO()
    written = cipher.encrypt_stream(io.BytesIO(data), out, chunk_size=128)
    assert written == len(out.getvalue())
    back = io.BytesIO()
    read = cipher.decrypt_stream(io.BytesIO(out.getvalue()), back)
    assert back.getvalue() == data and read == len(data)


# --------------------------------------------------------------------------
# streaming — structural attacks
# --------------------------------------------------------------------------

def test_stream_rejects_bitflip_anywhere(cipher):
    data = secrets.token_bytes(2000)
    for position in (5, 30, 45, 100, 1500, -1):  # header, frame meta, bodies, tag
        blob = bytearray(cipher.encrypt_bytes(data, chunk_size=128))
        idx = position if position >= 0 else len(blob) + position
        blob[idx] ^= 0x01
        with pytest.raises((IntegrityError, EnvelopeError)):
            cipher.decrypt_bytes(bytes(blob))


def test_stream_rejects_truncation(cipher):
    data = secrets.token_bytes(3000)
    blob = cipher.encrypt_bytes(data, chunk_size=256)
    for cut in (10, HEADER_SIZE, len(blob) - 1):
        with pytest.raises((IntegrityError, EnvelopeError)):
            cipher.decrypt_bytes(blob[:cut])


def test_stream_rejects_trailing_data(cipher):
    blob = cipher.encrypt_bytes(b"payload", chunk_size=64)
    with pytest.raises(EnvelopeError):
        cipher.decrypt_bytes(blob + b"junk")


def test_stream_rejects_swapped_frames(cipher):
    """Two chunks swapped must fail: the MAC covers the ordered frame sequence."""
    data = secrets.token_bytes(300)
    blob = cipher.encrypt_bytes(data, chunk_size=100)
    frame_len = 5 + 100  # flag + length + processed (length-preserving transforms)
    header = blob[:HEADER_SIZE]
    f0 = blob[HEADER_SIZE:HEADER_SIZE + frame_len]
    f1 = blob[HEADER_SIZE + frame_len:HEADER_SIZE + 2 * frame_len]
    reordered = header + f1 + f0 + blob[HEADER_SIZE + 2 * frame_len:]
    with pytest.raises((IntegrityError, EnvelopeError)):
        cipher.decrypt_bytes(reordered)


def test_stream_rejects_splice_from_other_stream(cipher):
    """Frames from stream B inside stream A must fail: the header (nonce) is MACed."""
    a = cipher.encrypt_bytes(secrets.token_bytes(200), chunk_size=100)
    b = cipher.encrypt_bytes(secrets.token_bytes(200), chunk_size=100)
    frame_len = lambda blob: 5 + struct.unpack(">I", blob[HEADER_SIZE + 1:HEADER_SIZE + 5])[0]
    a_frame0 = frame_len(a)
    b_frame0 = frame_len(b)
    spliced = a[:HEADER_SIZE] + b[HEADER_SIZE:HEADER_SIZE + b_frame0] + a[HEADER_SIZE + a_frame0:]
    with pytest.raises((IntegrityError, EnvelopeError)):
        cipher.decrypt_bytes(spliced)


def test_stream_rejects_missing_final_flag(cipher):
    """A stream that ends on a flag=0 frame is truncated."""
    data = secrets.token_bytes(300)
    blob = bytearray(cipher.encrypt_bytes(data, chunk_size=100))
    pos = HEADER_SIZE
    last_flag_pos = None
    while pos < len(blob):
        last_flag_pos = pos
        length = struct.unpack(">I", blob[pos + 1:pos + 5])[0]
        pos += 5 + length
    blob[last_flag_pos] = 0
    with pytest.raises((IntegrityError, EnvelopeError)):
        cipher.decrypt_bytes(bytes(blob))


def test_stream_rejects_length_mismatch_on_nonfinal_frame(cipher):
    """flag=0 frames must be exactly chunk_size: catch early, fail loudly."""
    data = secrets.token_bytes(300)
    blob = bytearray(cipher.encrypt_bytes(data, chunk_size=100))
    # claim the first (non-final) frame is short
    struct.pack_into(">I", blob, HEADER_SIZE + 1, 10)
    with pytest.raises((IntegrityError, EnvelopeError)):
        cipher.decrypt_bytes(bytes(blob))


def test_stream_rejects_garbage_header(cipher):
    with pytest.raises(EnvelopeError):
        cipher.decrypt_bytes(b"NOTAC3" + secrets.token_bytes(50))


def test_stream_rejects_oversized_declared_chunk(cipher):
    blob = bytearray(cipher.encrypt_bytes(b"data"))
    struct.pack_into(">I", blob, HEADER_SIZE - 4, MAX_CHUNK_SIZE + 1)
    with pytest.raises(EnvelopeError):
        cipher.decrypt_bytes(bytes(blob))


# --------------------------------------------------------------------------
# controller integration
# --------------------------------------------------------------------------

def test_controller_file_roundtrip(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "doc.bin"
    payload = secrets.token_bytes(100_000)
    src.write_bytes(payload)
    enc = c.encrypt_file(src, tmp_path / "doc.ac3")
    dec = c.decrypt_file(enc, tmp_path / "doc.out")
    assert dec.read_bytes() == payload


def test_controller_default_target_no_clobber(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "report.txt"
    src.write_bytes(b"data")
    target = c.encrypt_file(src)
    assert target.name == "report.txt.ac3"
    with pytest.raises(Exception):
        c.encrypt_file(src)  # second time must not overwrite
    out = c.decrypt_file(target)
    assert out.read_bytes() == b"data" and out.name == "report.txt"


def test_controller_rejects_overwrite_with_different_content(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "a.bin"
    src.write_bytes(b"first")
    enc = c.encrypt_file(src)
    (tmp_path / "a.bin").write_bytes(b"DIFFERENT EXISTING")
    with pytest.raises(Exception):
        c.decrypt_file(enc)
    assert (tmp_path / "a.bin").read_bytes() == b"DIFFERENT EXISTING"


def test_failed_decrypt_leaves_no_partial_output(tmp_path, same_key):
    """V-1 regression: a mid-stream failure must never leave plaintext behind."""
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"payload " * 500)
    enc = c.encrypt_file(src, tmp_path / "doc.txt.ac3", chunk_size=64)
    blob = bytearray(enc.read_bytes())
    blob[-2] ^= 0xFF  # corrupt the final stream tag
    enc.write_bytes(bytes(blob))

    target = tmp_path / "out.txt"
    with pytest.raises(IntegrityError):
        c.decrypt_file(enc, target)
    assert not target.exists(), "partial plaintext left on disk after failed decrypt"
    assert not list(tmp_path.glob(".ac3stg-*")), "staging temp left behind"


def test_controller_aes_stream_constant_memory(tmp_path, same_key):
    """Peak memory stays far below file size: only ~one chunk is held at a time."""
    import tracemalloc

    c = CMainController(cipher=AC3Cipher(same_key))
    data = secrets.token_bytes(32 * 1024 * 1024)
    src = tmp_path / "big.bin"
    src.write_bytes(data)

    tracemalloc.start()
    enc = c.encrypt_file(src, tmp_path / "big.enc", chunk_size=256 * 1024)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 8 * 1024 * 1024, (
        f"peak memory {peak / 1e6:.1f} MB — not streaming (file is {len(data) / 1e6:.0f} MB)"
    )
    assert c.decrypt_file(enc, tmp_path / "big.out").read_bytes() == data


# --------------------------------------------------------------------------
# SPEC conformance vectors (byte-exact; mirrored in SPEC.md)
# --------------------------------------------------------------------------

def _vector_cipher() -> AC3Cipher:
    return AC3Cipher(VECTOR_MASTER)


def test_spec_vector_text_short():
    token = _vector_cipher().seal_deterministic(b"AC3-X", VECTOR_NONCE)
    assert token == (
        "AC3X.ABEiM0RVZneImaq7zN3u_w."
        "9TPrCObvpumVeQ."
        "Q7U1gtd5xx6HggcZEWy69k4ubwj-AY1EkFEFl9_Je9Q"
    )


def test_spec_vector_text_empty():
    token = _vector_cipher().seal_deterministic(b"", VECTOR_NONCE)
    assert token == (
        "AC3X.ABEiM0RVZneImaq7zN3u_w."
        "HPKtceE."
        "KjTQlfFhYF9ldHFdAM9hFBBuI3Rhd3jkNMaOEr8r3Ws"
    )


def test_spec_vector_stream_multichunk():
    out = io.BytesIO()
    _vector_cipher().encrypt_stream(
        io.BytesIO(b"AC3-X hybrid vector payload"),
        out,
        chunk_size=8,
        nonce=VECTOR_NONCE,
    )
    assert out.getvalue().hex() == (
        "414333583401651c403700112233445566778899aabbccddeeff00000008000000000884479d6de69f121f"
        "0000000008f6d2032b063f38b000000000081ce4f663705f7b380100000003c9687ca0f40245534db8bf10"
        "a4246a79233c3b6e6fc478d41080c456ea11ff4cf1533a"
    )


def test_spec_vectors_roundtrip_through_public_api():
    c = _vector_cipher()
    assert c.decrypt(c.seal_deterministic(b"AC3-X", VECTOR_NONCE)) == "AC3-X"
    blob = c.encrypt_bytes(b"AC3-X", chunk_size=8)
    assert c.decrypt_bytes(blob) == b"AC3-X"


# --------------------------------------------------------------------------
# Audit-round-3 regressions (F-1, F-2, F-3)
# --------------------------------------------------------------------------

def test_valid_tag_non_utf8_rejected_as_envelope_error(cipher):
    """F-1: a validly-tagged non-UTF-8 plaintext must raise AC3Error,
    never a bare UnicodeDecodeError (which would escape the API as a 500).
    Reachable only with the key — this locks the failure *type*."""
    from cryptography.hazmat.primitives import hmac as _hmac, hashes

    raw = bytes([0xFF, 0xFE, 0x00])  # invalid UTF-8
    nonce = secrets.token_bytes(16)
    body, tag = cipher._seal(raw, nonce)
    token = TEXT_PREFIX + ".".join([
        __import__("base64").urlsafe_b64encode(nonce).decode().rstrip("="),
        __import__("base64").urlsafe_b64encode(body).decode().rstrip("="),
        __import__("base64").urlsafe_b64encode(tag).decode().rstrip("="),
    ])
    with pytest.raises(EnvelopeError, match="UTF-8"):
        cipher.decrypt(token)


def test_text_and_stream_subkeys_are_domain_separated(same_key):
    """F-2: the text and stream protocols must never share subkey material,
    even for the same (master, nonce)."""
    from ac3.core import _KeySchedule

    ks_text = _KeySchedule(same_key, VECTOR_NONCE, domain=b"text")
    ks_stream = _KeySchedule(same_key, VECTOR_NONCE, domain=b"stream")
    assert ks_text.k3 != ks_stream.k3
    assert ks_text.k5 != ks_stream.k5
    assert ks_text.mac_key != ks_stream.mac_key
    assert ks_text.shift != ks_stream.shift or ks_text.columns != ks_stream.columns
    assert ks_text.iv(3, 0) != ks_stream.iv(3, 0)


def test_controller_chunk_size_zero_raises(tmp_path, same_key):
    """F-3: chunk_size=0 must be rejected, not silently treated as the default."""
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "a.bin"
    src.write_bytes(b"data" * 100)
    with pytest.raises(Exception):
        c.encrypt_file(src, tmp_path / "a.ac3", chunk_size=0)
    with pytest.raises(Exception):
        c.encrypt_bytes(b"data", chunk_size=0)
