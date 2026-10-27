"""Roundtrip and envelope tests for the AC3-X (v3) core."""

import base64

import pytest

from ac3 import AC3Cipher, EnvelopeError, IntegrityError
from ac3.core import STREAM_MAGIC, VERSION

ASCII_SAMPLES = [
    "a",
    "hello world",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 0123456789",
    "punctuation !@#$%^&*()_+-=[]{}|;:',.<>/?`~",
]

UNICODE_SAMPLES = [
    "ñ á é í ó ú ü",
    "Ünïcödé tëst",
    "中文 日本語 한국어",
    "العربية עברית",
    "emoji: 😀🎉🔐👨‍👩‍👧‍👦",
    "mixed 中文 and ñ and 🔐 together",
    "combining: é (e + ́)",
]


@pytest.mark.parametrize("text", ASCII_SAMPLES + UNICODE_SAMPLES)
def test_text_roundtrip(cipher, text):
    token = cipher.encrypt(text)
    assert cipher.decrypt(token) == text


def test_empty_string_roundtrip(cipher):
    token = cipher.encrypt("")
    assert cipher.decrypt(token) == ""


def test_large_text_roundtrip(cipher):
    text = "lorem ipsum dolor sit amet 😀 " * 5000
    assert cipher.decrypt(cipher.encrypt(text)) == text


def test_null_and_control_bytes_roundtrip(cipher):
    """Raw bytes API must handle every byte value 0-255."""
    data = bytes(range(256)) * 4
    assert cipher.decrypt_bytes(cipher.encrypt_bytes(data)) == data


def test_envelope_format(cipher):
    token = cipher.encrypt("secret")
    assert token.startswith("AC3X.")  # versioned prefix
    assert len(token.split(".")) == 4  # AC3X, nonce, body, tag
    # nonce: 16 bytes -> 22 unpadded b64url chars; tag: 32 -> 43
    nonce_b, body_b, tag_b = token.split(".")[1:]
    assert len(nonce_b) == 22
    assert len(tag_b) == 43


def test_token_is_json_safe_ascii(cipher):
    """Envelope must be URL/JSON-safe (no padding, no +// chars)."""
    token = cipher.encrypt("any text ünï")
    assert token == token.replace("=", "")  # no '=' padding
    assert set(token) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
    )


def test_same_plaintext_produces_unique_tokens(cipher):
    """Fresh random nonce per message — no deterministic ciphertexts."""
    tokens = {cipher.encrypt("same input") for _ in range(10)}
    assert len(tokens) == 10


def test_version_constant():
    assert VERSION == 3


# --------------------------------------------------------------------------
# tamper detection
# --------------------------------------------------------------------------

def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@pytest.fixture()
def dissected(cipher):
    token = cipher.encrypt("attack at dawn")
    prefix, nonce_b, body_b, tag_b = token.split(".", 3)
    assert prefix == "AC3X"
    return nonce_b, body_b, tag_b


def test_tampered_body_rejected(cipher, dissected):
    nonce_b, body_b, tag_b = dissected
    body = bytearray(_b64d(body_b))
    body[len(body) // 2] ^= 0x01
    tampered = "AC3X." + ".".join([nonce_b, _b64e(bytes(body)), tag_b])
    with pytest.raises(IntegrityError):
        cipher.decrypt(tampered)


def test_tampered_nonce_rejected(cipher, dissected):
    nonce_b, body_b, tag_b = dissected
    nonce = bytearray(_b64d(nonce_b))
    nonce[0] ^= 0x01
    tampered = "AC3X." + ".".join([_b64e(bytes(nonce)), body_b, tag_b])
    with pytest.raises(IntegrityError):
        cipher.decrypt(tampered)


def test_tampered_tag_rejected(cipher, dissected):
    nonce_b, body_b, tag_b = dissected
    tag = bytearray(_b64d(tag_b))
    tag[0] ^= 0x01
    tampered = "AC3X." + ".".join([nonce_b, body_b, _b64e(bytes(tag))])
    with pytest.raises(IntegrityError):
        cipher.decrypt(tampered)


def test_wrong_key_rejected_not_garbage(cipher, dissected):
    from ac3 import AC3Cipher as C
    import secrets as s

    other = C(s.token_bytes(32))
    nonce_b, body_b, tag_b = dissected
    token = "AC3X." + ".".join([nonce_b, body_b, tag_b])
    with pytest.raises(IntegrityError):
        other.decrypt(token)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-a-ciphertext",
        "AC3X",
        "AC3X.onlyonepart",
        "AC3X.a.b",
        "AC3X.a.b.c.d",
        "AC3X.!!!.body.tag",  # invalid base64
        "AC3v2.aaaa.bbbb.cccc",  # legacy v2 prefix: clean break
        "AC3A.aaaa.bbbb.cccc",  # interim AES prefix: clean break
        "AC3v1.aaaa.bbbb.cccc",  # wrong version prefix
    ],
)
def test_malformed_and_legacy_envelopes_rejected(cipher, bad):
    with pytest.raises(EnvelopeError):
        cipher.decrypt(bad)


def test_legacy_rejection_message_is_actionable(cipher):
    with pytest.raises(EnvelopeError, match="re-encrypt"):
        cipher.decrypt("AC3v2.aaaa.bbbb.cccc")


def test_truncated_stream_rejected(cipher):
    blob = cipher.encrypt_bytes(b"payload")
    assert blob[: len(STREAM_MAGIC)] == STREAM_MAGIC
    with pytest.raises(EnvelopeError):
        cipher.decrypt_bytes(blob[:10])
    with pytest.raises(EnvelopeError):
        cipher.decrypt_bytes(b"NOTAC3!" + blob[7:])
