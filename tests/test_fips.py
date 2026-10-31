"""FIPS mode tests - AES-256-GCM core (the production layer).

Covers the AC3F text envelope and AC3F1 chunked stream: round-trips, tamper
rejection (including key-ID substitution), chunk boundaries, stream attacks,
rotation survival, and the constant-memory guarantee.
"""

import base64
import secrets
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import FIPSCipher
from ac3.exceptions import EnvelopeError, IntegrityError

MASTER = secrets.token_bytes(32)


@pytest.fixture()
def fips():
    return FIPSCipher(MASTER)


@pytest.mark.parametrize("text", ["", "hello", "x" * 10_000])
def test_text_roundtrip(fips, text):
    token = fips.encrypt(text)
    assert token.startswith("AC3F.")
    assert fips.decrypt(token) == text


def test_envelope_shape(fips):
    token = fips.encrypt("shape check")
    parts = token.split(".")
    assert parts[0] == "AC3F"
    assert len(parts) == 4  # prefix + nonce(12B) + output(ct+tag) + keyid(4B)
    assert len(base64.urlsafe_b64decode(parts[1] + "==")) == 12
    assert len(base64.urlsafe_b64decode(parts[3] + "==")) == 4


def test_tokens_are_unique(fips):
    tokens = {fips.encrypt("same") for _ in range(20)}
    assert len(tokens) == 20


def test_tamper_output_rejected(fips):
    token = fips.encrypt("attack at dawn")
    parts = token.split(".")
    output = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
    output[0] ^= 0x01
    parts[2] = base64.urlsafe_b64encode(bytes(output)).decode().rstrip("=")
    with pytest.raises(IntegrityError):
        fips.decrypt(".".join(parts))


def test_tamper_nonce_rejected(fips):
    token = fips.encrypt("attack at dawn")
    parts = token.split(".")
    nonce = bytearray(base64.urlsafe_b64decode(parts[1] + "=="))
    nonce[0] ^= 0x01
    parts[1] = base64.urlsafe_b64encode(bytes(nonce)).decode().rstrip("=")
    with pytest.raises(IntegrityError):
        fips.decrypt(".".join(parts))


def test_key_id_substitution_rejected(tmp_path):
    """The key ID is bound into the GCM AAD - swapping it for another key the
    deployment KNOWS (post-rotation) must still fail authentication."""
    import os

    from ac3.keys import KeyManager, key_id

    os.environ.pop("AC3_MASTER_KEY", None)
    keys = KeyManager(env_path=tmp_path / ".env")
    cipher = FIPSCipher(keys)
    token_a = cipher.encrypt("bound to key a")  # minted under the active key
    keys.rotate()  # key a is archived; key b is now active and resolvable

    parts = token_a.split(".")
    parts[3] = base64.urlsafe_b64encode(key_id(keys.master_key)).decode().rstrip("=")
    # resolution succeeds (key b is active) but the AAD no longer matches
    with pytest.raises(IntegrityError):
        cipher.decrypt(".".join(parts))


def test_wrong_key_rejected():
    token = FIPSCipher(MASTER).encrypt("secret")
    with pytest.raises((IntegrityError, EnvelopeError)):
        FIPSCipher(secrets.token_bytes(32)).decrypt(token)


@pytest.mark.parametrize("size,chunk", [
    (0, 64),
    (1, 64),
    (63, 64),
    (64, 64),
    (65, 64),
    (5000, 256),
    (10_000, 4 * 1024 * 1024),
])
def test_stream_roundtrip(fips, size, chunk):
    data = secrets.token_bytes(size)
    blob = fips.encrypt_bytes(data, chunk_size=chunk)
    assert blob[:6] == b"AC3F1\x01"
    assert fips.decrypt_bytes(blob) == data


def test_stream_header_layout(fips):
    blob = fips.encrypt_bytes(b"data", chunk_size=1024)
    assert blob[:6] == b"AC3F1\x01"
    assert len(blob[6:10]) == 4    # key ID
    assert len(blob[10:26]) == 16  # salt
    assert len(blob[26:34]) == 8   # nonce prefix
    assert struct.unpack(">I", blob[34:38])[0] == 1024


def test_stream_chunk_size_bounds(fips):
    with pytest.raises(Exception):
        fips.encrypt_bytes(b"data", chunk_size=0)
    with pytest.raises(Exception):
        fips.encrypt_bytes(b"data", chunk_size=64 * 1024 * 1024 + 1)


def test_stream_tamper_rejected(fips):
    data = secrets.token_bytes(2000)
    for position in (5, 30, 45, 100, 1500, -1):
        blob = bytearray(fips.encrypt_bytes(data, chunk_size=128))
        idx = position if position >= 0 else len(blob) + position
        blob[idx] ^= 0x01
        with pytest.raises((IntegrityError, EnvelopeError)):
            fips.decrypt_bytes(bytes(blob))


def test_stream_truncate_rejected(fips):
    blob = fips.encrypt_bytes(secrets.token_bytes(3000), chunk_size=256)
    for cut in (10, 38, len(blob) - 1):
        with pytest.raises((IntegrityError, EnvelopeError)):
            fips.decrypt_bytes(blob[:cut])


def test_stream_trailing_data_rejected(fips):
    blob = fips.encrypt_bytes(b"payload", chunk_size=64)
    with pytest.raises(EnvelopeError):
        fips.decrypt_bytes(blob + b"junk")


def test_stream_reorder_rejected(fips):
    data = secrets.token_bytes(300)
    blob = fips.encrypt_bytes(data, chunk_size=100)
    frame_len = 5 + 100 + 16  # flag + len + sealed(chunk+tag)
    header = blob[:38]
    f0 = blob[38:38 + frame_len]
    f1 = blob[38 + frame_len:38 + 2 * frame_len]
    reordered = header + f1 + f0 + blob[38 + 2 * frame_len:]
    with pytest.raises((IntegrityError, EnvelopeError)):
        fips.decrypt_bytes(reordered)


def test_stream_splice_rejected(fips):
    a = fips.encrypt_bytes(secrets.token_bytes(200), chunk_size=100)
    b = fips.encrypt_bytes(secrets.token_bytes(200), chunk_size=100)
    flen = lambda blob: 5 + int.from_bytes(blob[39:43], "big")
    spliced = a[:38] + b[38:38 + flen(b)] + a[38 + flen(a):]
    with pytest.raises((IntegrityError, EnvelopeError)):
        fips.decrypt_bytes(spliced)


def test_rotation_survival(tmp_path):
    import os

    from ac3.keys import KeyManager

    os.environ.pop("AC3_MASTER_KEY", None)
    keys = KeyManager(env_path=tmp_path / ".env")
    cipher = FIPSCipher(keys)
    token = cipher.encrypt("pre-rotation fips data")
    src = tmp_path / "doc.bin"
    src.write_bytes(b"stream " * 500)
    enc = cipher.encrypt_file(src, tmp_path / "doc.ac3")

    keys.rotate()
    assert cipher.decrypt(token) == "pre-rotation fips data"
    cipher.decrypt_file(enc, tmp_path / "doc.out")
    assert (tmp_path / "doc.out").read_bytes() == src.read_bytes()


def test_unknown_key_version_rejected(tmp_path):
    import os

    from ac3.keys import KeyManager

    os.environ.pop("AC3_MASTER_KEY", None)
    a = FIPSCipher(KeyManager(env_path=tmp_path / "a.env"))
    token = a.encrypt("from deployment a")
    b = FIPSCipher(KeyManager(env_path=tmp_path / "b.env"))
    with pytest.raises(EnvelopeError, match="unknown key version"):
        b.decrypt(token)


def test_constant_memory_streaming(tmp_path):
    import tracemalloc

    cipher = FIPSCipher(MASTER)
    data = secrets.token_bytes(32 * 1024 * 1024)
    src = tmp_path / "big.bin"
    src.write_bytes(data)
    tracemalloc.start()
    enc = cipher.encrypt_file(src, tmp_path / "big.enc", chunk_size=256 * 1024)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 8 * 1024 * 1024, f"peak memory {peak / 1e6:.1f} MB - not streaming"
    assert cipher.decrypt_file(enc, tmp_path / "big.out").read_bytes() == data


def test_fips_nonce_is_fresh_per_message(fips):
    nonces = {
        base64.urlsafe_b64decode(fips.encrypt("same").split(".")[1] + "==")
        for _ in range(20)
    }
    assert len(nonces) == 20


# --------------------------------------------------------------------------
# key commitment (closes the GCM non-commitment trade-off)
# --------------------------------------------------------------------------

def test_output_includes_commitment_tag(fips):
    token = fips.encrypt("commitment check")
    output = base64.urlsafe_b64decode(token.split(".")[2] + "==")
    # plaintext(15) + GCM tag(16) + commitment(16)
    assert len(output) == len("commitment check") + 16 + 16


def test_commitment_tamper_is_distinct_from_tag_tamper(fips):
    """The commitment tag is separate from the GCM tag: flipping a commitment
    bit raises IntegrityError (key-partitioning defense), while stripping it
    raises EnvelopeError (downgrade attempt)."""
    token = fips.encrypt("two-layer integrity")
    parts = token.split(".")
    output = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
    assert len(output) == len("two-layer integrity") + 16 + 16
    output[-1] ^= 0x01  # commitment byte
    parts[2] = base64.urlsafe_b64encode(bytes(output)).decode().rstrip("=")
    with pytest.raises((IntegrityError, EnvelopeError)):
        fips.decrypt(".".join(parts))


def test_commitment_strips_are_rejected(fips):
    """Stripping the commitment field (downgrade to plain GCM) must fail."""
    token = fips.encrypt("downgrade probe")
    parts = token.split(".")
    output = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
    stripped = output[:-16]  # drop the commitment tag
    parts[2] = base64.urlsafe_b64encode(bytes(stripped)).decode().rstrip("=")
    with pytest.raises(EnvelopeError):
        fips.decrypt(".".join(parts))


def test_commitment_tamper_rejected(fips):
    token = fips.encrypt("commit tamper")
    parts = token.split(".")
    output = bytearray(base64.urlsafe_b64decode(parts[2] + "=="))
    output[-1] ^= 0x01  # flip a commitment bit
    parts[2] = base64.urlsafe_b64encode(bytes(output)).decode().rstrip("=")
    with pytest.raises((IntegrityError, EnvelopeError)):
        fips.decrypt(".".join(parts))
