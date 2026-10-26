"""Tests for the AES-256-GCM module: text, streaming, tamper, and controller glue."""

import io
import secrets
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import AESGCMCipher, CMainController, IntegrityError
from ac3.aesgcm import (
    DEFAULT_CHUNK_SIZE,
    HEADER_SIZE,
    STREAM_MAGIC,
    TEXT_PREFIX,
    looks_like_aes_stream,
    looks_like_aes_text,
    validate_algorithm,
)
from ac3.core import AC3Cipher
from ac3.exceptions import EnvelopeError, InvalidAlgorithmError
from ac3.keys import derive_stream


@pytest.fixture()
def aes() -> AESGCMCipher:
    return AESGCMCipher(secrets.token_bytes(32))


@pytest.fixture()
def same_key(request) -> bytes:
    key = secrets.token_bytes(32)
    return key


# --------------------------------------------------------------------------
# Text envelope
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["", "hello", "ünïcode 🔐", "x" * 10_000])
def test_text_roundtrip(aes, text):
    token = aes.encrypt(text)
    assert token.startswith(TEXT_PREFIX)
    assert aes.decrypt(token) == text


def test_text_tokens_are_unique(aes):
    tokens = {aes.encrypt("same message") for _ in range(20)}
    assert len(tokens) == 20, "random nonce not producing unique tokens"


def test_text_tamper_body_rejected(aes):
    token = aes.encrypt("attack at dawn")
    prefix, nonce, body, tag = token.split(".", 3)
    bad_body = ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(IntegrityError):
        aes.decrypt(f"{prefix}.{nonce}.{bad_body}.{tag}")


def test_text_tamper_tag_rejected(aes):
    token = aes.encrypt("attack at dawn")
    prefix, nonce, body, tag = token.split(".", 3)
    bad_tag = ("A" if tag[0] != "A" else "B") + tag[1:]
    with pytest.raises(IntegrityError):
        aes.decrypt(f"{prefix}.{nonce}.{body}.{bad_tag}")


def test_text_wrong_key_rejected(aes):
    token = aes.encrypt("secret")
    other = AESGCMCipher(secrets.token_bytes(32))
    with pytest.raises(IntegrityError):
        other.decrypt(token)


def test_wrong_prefix_rejected(aes):
    token = aes.encrypt("secret")
    with pytest.raises(EnvelopeError):
        aes.decrypt(token.replace(TEXT_PREFIX, "AC3v2.", 1))


def test_non_string_input_rejected(aes):
    with pytest.raises(TypeError):
        aes.encrypt(b"bytes are not str")


# --------------------------------------------------------------------------
# Streaming envelope — boundaries, tampering, structure
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
def test_stream_roundtrip(aes, size, chunk):
    data = secrets.token_bytes(size)
    blob = aes.encrypt_bytes(data, chunk_size=chunk)
    assert blob[:len(STREAM_MAGIC)] == STREAM_MAGIC
    assert looks_like_aes_stream(blob)
    assert aes.decrypt_bytes(blob) == data


def test_stream_rejects_bitflip_anywhere(aes):
    data = secrets.token_bytes(2000)
    for position in (5, 30, 45, 100, 1500, -1):  # header, frame meta, bodies, tag
        blob = bytearray(aes.encrypt_bytes(data, chunk_size=128))
        idx = position if position >= 0 else len(blob) + position
        blob[idx] ^= 0x01
        with pytest.raises((IntegrityError, EnvelopeError)):
            aes.decrypt_bytes(bytes(blob))


def test_stream_rejects_truncation(aes):
    data = secrets.token_bytes(3000)
    blob = aes.encrypt_bytes(data, chunk_size=256)
    for cut in (10, HEADER_SIZE, len(blob) - 1):
        with pytest.raises((IntegrityError, EnvelopeError)):
            aes.decrypt_bytes(blob[:cut])


def test_stream_rejects_trailing_data(aes):
    blob = aes.encrypt_bytes(b"payload", chunk_size=64)
    with pytest.raises(EnvelopeError):
        aes.decrypt_bytes(blob + b"junk")


def test_stream_rejects_swapped_frames(aes):
    """Two chunks swapped must fail: counter is in nonce and AAD."""
    data = secrets.token_bytes(300)
    blob = aes.encrypt_bytes(data, chunk_size=100)
    # frame 0 starts at HEADER_SIZE: flag(1) + length(4) + sealed(100+16)
    f0_len = 5 + 100 + 16
    f1_len = 5 + 100 + 16
    header = blob[:HEADER_SIZE]
    f0 = blob[HEADER_SIZE:HEADER_SIZE + f0_len]
    f1 = blob[HEADER_SIZE + f0_len:HEADER_SIZE + f0_len + f1_len]
    reordered = header + f1 + f0 + blob[HEADER_SIZE + f0_len + f1_len:]
    with pytest.raises((IntegrityError, EnvelopeError)):
        aes.decrypt_bytes(reordered)


def test_stream_rejects_splice_from_other_stream(aes):
    """Frames from stream B inside stream A's header must fail (salt in AAD)."""
    a = aes.encrypt_bytes(secrets.token_bytes(200), chunk_size=100)
    b = aes.encrypt_bytes(secrets.token_bytes(200), chunk_size=100)
    # replace A's first frame (after header) with B's first frame
    frame_len = lambda blob: 5 + struct.unpack(">I", blob[HEADER_SIZE + 1:HEADER_SIZE + 5])[0]
    a_frame0 = frame_len(a)
    b_frame0 = frame_len(b)
    spliced = a[:HEADER_SIZE] + b[HEADER_SIZE:HEADER_SIZE + b_frame0] + a[HEADER_SIZE + a_frame0:]
    with pytest.raises((IntegrityError, EnvelopeError)):
        aes.decrypt_bytes(spliced)


def test_stream_rejects_missing_final_flag(aes):
    """A stream that ends on a flag=0 frame is truncated."""
    data = secrets.token_bytes(300)
    blob = bytearray(aes.encrypt_bytes(data, chunk_size=100))
    # walk frames; clear the final flag byte, making the stream look unterminated
    pos = HEADER_SIZE
    last_flag_pos = None
    while pos < len(blob):
        last_flag_pos = pos
        length = struct.unpack(">I", blob[pos + 1:pos + 5])[0]
        pos += 5 + length
    blob[last_flag_pos] = 0
    with pytest.raises((IntegrityError, EnvelopeError)):
        aes.decrypt_bytes(bytes(blob))


def test_stream_chunk_size_bounds(aes):
    from ac3.aesgcm import MAX_CHUNK_SIZE

    with pytest.raises(Exception):
        aes.encrypt_bytes(b"data", chunk_size=0)
    with pytest.raises(Exception):
        aes.encrypt_bytes(b"data", chunk_size=MAX_CHUNK_SIZE + 1)


def test_stream_object_stream_api(aes):
    data = secrets.token_bytes(1000)
    out = io.BytesIO()
    written = aes.encrypt_stream(io.BytesIO(data), out, chunk_size=128)
    assert written == len(out.getvalue())
    back = io.BytesIO()
    read = aes.decrypt_stream(io.BytesIO(out.getvalue()), back)
    assert back.getvalue() == data and read == len(data)


def test_stream_rejects_garbage_header(aes):
    with pytest.raises(EnvelopeError):
        aes.decrypt_bytes(b"NOTAES" + secrets.token_bytes(50))


# --------------------------------------------------------------------------
# Derivation domain separation
# --------------------------------------------------------------------------

def test_text_and_stream_keys_differ(same_key):
    aes = AESGCMCipher(same_key)
    salt = secrets.token_bytes(16)
    text_key = derive_stream(same_key, salt, b"ac3/aes-256-gcm/text", 32)
    stream_key = derive_stream(same_key, salt, b"ac3/aes-256-gcm/stream", 32)
    ac3_key = derive_stream(same_key, salt, b"ac3/v2/subkey/0", 32)
    assert len({text_key, stream_key, ac3_key}) == 3


# --------------------------------------------------------------------------
# Controller integration
# --------------------------------------------------------------------------

def test_controller_algorithm_select_and_autodetect(same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    ac3_token = c.encrypt("thesis mode")
    aes_token = c.encrypt("standard mode", algorithm="aes")
    assert ac3_token.startswith("AC3v2.") and aes_token.startswith(TEXT_PREFIX)
    assert c.decrypt(ac3_token) == "thesis mode"
    assert c.decrypt(aes_token) == "standard mode"


def test_controller_unknown_algorithm_rejected(same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    with pytest.raises(InvalidAlgorithmError):
        c.encrypt("x", algorithm="rot13")
    with pytest.raises(InvalidAlgorithmError):
        validate_algorithm("DES")


def test_controller_file_roundtrip_both_algs(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "doc.bin"
    payload = secrets.token_bytes(100_000)
    src.write_bytes(payload)
    for alg in ("ac3", "aes"):
        enc = c.encrypt_file(src, tmp_path / f"doc.{alg}.ac3", algorithm=alg)
        dec = c.decrypt_file(enc, tmp_path / f"doc.{alg}.out")
        assert dec.read_bytes() == payload, f"{alg} file roundtrip failed"


def test_controller_default_target_no_clobber(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "report.txt"
    src.write_bytes(b"data")
    target = c.encrypt_file(src, algorithm="aes")  # report.txt.ac3
    assert target.name == "report.txt.ac3"
    with pytest.raises(Exception):
        c.encrypt_file(src, algorithm="aes")  # second time must not overwrite
    # decrypt to default name (strips .ac3) then refuse differing overwrite
    out = c.decrypt_file(target)
    assert out.read_bytes() == b"data" and out.name == "report.txt"
    target.write_bytes(target.read_bytes())  # keep same content
    out2 = c.decrypt_file(target)  # identical content: idempotent, no error
    assert out2.read_bytes() == b"data"


def test_controller_rejects_overwrite_with_different_content(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "a.bin"
    src.write_bytes(b"first")
    enc = c.encrypt_file(src, algorithm="aes")
    (tmp_path / "a.bin").write_bytes(b"DIFFERENT EXISTING")  # simulate clobber risk
    with pytest.raises(Exception):
        c.decrypt_file(enc)  # default target 'a.bin' has different content
    assert (tmp_path / "a.bin").read_bytes() == b"DIFFERENT EXISTING"  # untouched


def test_controller_aes_file_streams_constant_memory(tmp_path, same_key):
    """Peak memory stays far below file size: only ~one chunk is held at a time."""
    import tracemalloc

    c = CMainController(cipher=AC3Cipher(same_key))
    # 32 MB payload streamed with 256 KiB chunks: peak must be << payload size,
    # proving we never materialize the whole file (the non-streaming path would
    # need >= 32 MB for the plaintext plus 32 MB for the ciphertext).
    data = secrets.token_bytes(32 * 1024 * 1024)
    src = tmp_path / "big.bin"
    src.write_bytes(data)

    tracemalloc.start()
    enc = c.encrypt_file(src, tmp_path / "big.enc", algorithm="aes",
                         chunk_size=256 * 1024)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 8 * 1024 * 1024, (
        f"peak memory {peak / 1e6:.1f} MB — not streaming (file is {len(data) / 1e6:.0f} MB)"
    )
    assert c.decrypt_file(enc, tmp_path / "big.out").read_bytes() == data


# --------------------------------------------------------------------------
# V-1 regression: failed decrypt/encrypt must not leave partial output on disk
#
# Found by red-team repro: the AES streaming path used to write straight to
# the destination file, so a mid-stream IntegrityError left partial PLAINTEXT
# at the target (leaking decrypted content after a reported failure), and an
# explicit target got truncated before failing. Atomic staging fixes it.
# --------------------------------------------------------------------------

def _corrupt_last_byte(path: Path) -> Path:
    data = bytearray(path.read_bytes())
    data[-2] ^= 0xFF  # flip a byte in the final chunk's tag
    path.write_bytes(bytes(data))
    return path


def test_failed_aes_decrypt_leaves_no_partial_plaintext(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"PLAINText-CONTENT-" * 400)  # many chunks
    enc = c.encrypt_file(src, tmp_path / "doc.txt.ac3", algorithm="aes", chunk_size=64)
    enc = _corrupt_last_byte(enc)

    target = tmp_path / "decrypted_out.txt"
    with pytest.raises(IntegrityError):
        c.decrypt_file(enc, target)
    assert not target.exists(), "partial plaintext left on disk after failed decrypt"
    assert not list(tmp_path.glob(".ac3stg-*")), "staging temp left behind"
    assert not list(tmp_path.glob(".ac3tmp-*")), "staging temp left behind"


def test_failed_aes_decrypt_does_not_truncate_explicit_target(tmp_path, same_key):
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "doc.txt"
    src.write_bytes(b"payload " * 500)
    enc = c.encrypt_file(src, tmp_path / "doc.txt.ac3", algorithm="aes", chunk_size=64)
    enc = _corrupt_last_byte(enc)

    victim = tmp_path / "important.txt"
    victim.write_bytes(b"PRECIOUS EXISTING DATA")
    with pytest.raises(IntegrityError):
        c.decrypt_file(enc, victim)
    assert victim.read_bytes() == b"PRECIOUS EXISTING DATA", (
        "explicit target was truncated/overwritten by a decrypt that failed"
    )


def test_failed_aes_decrypt_default_path_not_bricked(tmp_path, same_key):
    """A failed decrypt must not create the default target (which would brick a retry)."""
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "payload.bin"
    src.write_bytes(b"content " * 300)
    # Encrypt to a distinct name so the default decrypt target ("sealed",
    # after stripping .ac3) does NOT pre-exist — it's a fresh path.
    enc = c.encrypt_file(src, tmp_path / "sealed.ac3", algorithm="aes", chunk_size=64)
    enc = _corrupt_last_byte(enc)

    default_target = tmp_path / "sealed"  # _default_decrypt_target("sealed.ac3")
    assert not default_target.exists()
    with pytest.raises(IntegrityError):
        c.decrypt_file(enc)  # default target: "sealed"
    assert not default_target.exists(), (
        "failed decrypt created the default target, which would brick a retry"
    )
    # retry path is clean: no stray temps to confuse the no-clobber logic
    assert not list(tmp_path.glob(".ac3stg-*"))
    assert not list(tmp_path.glob(".ac3tmp-*"))


def test_failed_aes_encrypt_leaves_no_partial_ciphertext(tmp_path, same_key):
    """A mid-stream encrypt failure must not leave a half-written .ac3 behind."""
    c = CMainController(cipher=AC3Cipher(same_key))
    src = tmp_path / "src.bin"
    src.write_bytes(b"data " * 1000)

    # Force a failure by making the AES cipher raise mid-write.
    target = tmp_path / "out.ac3"
    original = c._aes.encrypt_file
    calls = {"n": 0}

    def exploding(stream_src, stream_dst, **kw):
        # write a few bytes then fail, mimicking an I/O or key error mid-stream
        Path(stream_dst).write_bytes(b"PARTIAL-GARBAGE")
        raise OSError("simulated disk failure mid-stream")

    c._aes.encrypt_file = exploding
    try:
        with pytest.raises(OSError):
            c.encrypt_file(src, target, algorithm="aes")
    finally:
        c._aes.encrypt_file = original

    assert not target.exists(), "half-written ciphertext left behind after failed encrypt"
    assert not list(tmp_path.glob(".ac3stg-*")), "staging temp left behind"
