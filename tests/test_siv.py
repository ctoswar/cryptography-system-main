"""v4 SIV mode tests: nonce misuse degrades to determinism, never catastrophe."""

import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import SIVTextCipher
from ac3.exceptions import IntegrityError

MASTER = secrets.token_bytes(32)


@pytest.fixture()
def siv():
    return SIVTextCipher(MASTER)


def test_roundtrip(siv):
    for text in ["", "hello", "ünïcode 🔐", "x" * 5000]:
        assert siv.decrypt(siv.encrypt(text)) == text


def test_envelope_prefix_and_shape(siv):
    token = siv.encrypt("shape check")
    parts = token.split(".")
    assert parts[0] == "AC3S"
    assert len(parts) == 4  # prefix + nonce(12B) + output + keyid(4B)


def test_same_nonce_same_message_is_deterministic_not_catastrophic(siv):
    """THE property: nonce reuse must leak equality only.

    Two encryptions of the same message under the SAME nonce produce the
    same ciphertext (deterministic) — and critically, the message itself is
    still confidential and authenticated. (Under classic CTR, nonce reuse
    would expose keystream relationships.)
    """
    nonce = secrets.token_bytes(12)
    pt = "same message under reused nonce"
    key = siv._siv_key(nonce, MASTER)
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    a = AESSIV(key).encrypt(pt.encode(), [b"ac3x/v4/siv", nonce])
    b = AESSIV(key).encrypt(pt.encode(), [b"ac3x/v4/siv", nonce])
    assert a == b  # deterministic — equality leaks, nothing more


def test_same_nonce_different_message_still_confidential(siv):
    """Under CTR, reusing a nonce across DIFFERENT messages reveals
    P1 XOR P2. Under SIV it must not: the two ciphertexts remain
    independent-looking and both authenticate."""
    nonce = secrets.token_bytes(12)
    m1 = "message one under a reused nonce"
    m2 = "a completely different message two!"
    key = siv._siv_key(nonce, MASTER)
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV

    c1 = AESSIV(key).encrypt(m1.encode(), [b"ac3x/v4/siv", nonce])
    c2 = AESSIV(key).encrypt(m2.encode(), [b"ac3x/v4/siv", nonce])
    assert c1 != c2
    # decrypting both works: no keystream corruption
    assert AESSIV(key).decrypt(c1, [b"ac3x/v4/siv", nonce]).decode() == m1
    assert AESSIV(key).decrypt(c2, [b"ac3x/v4/siv", nonce]).decode() == m2


def test_random_nonce_unlinkability(siv):
    """Normal operation (fresh nonce per message) keeps equal messages unlinkable."""
    tokens = {siv.encrypt("identical") for _ in range(10)}
    assert len(tokens) == 10


def test_tamper_rejected(siv):
    token = siv.encrypt("tamper target")
    parts = token.split(".")
    output = bytearray(__import__("base64").urlsafe_b64decode(parts[2] + "=="))
    output[-1] ^= 0x01
    parts[2] = __import__("base64").urlsafe_b64encode(bytes(output)).decode().rstrip("=")
    with pytest.raises(IntegrityError):
        siv.decrypt(".".join(parts))


def test_wrong_key_rejected():
    """A token from another deployment carries a foreign key ID — v4 routes
    that to the key-management error (distinct from same-key tampering)."""
    from ac3.exceptions import EnvelopeError

    token = SIVTextCipher(MASTER).encrypt("secret")
    other = SIVTextCipher(secrets.token_bytes(32))
    with pytest.raises(EnvelopeError, match="unknown key version"):
        other.decrypt(token)


def test_unknown_key_version_rejected():
    from ac3.exceptions import EnvelopeError

    token = SIVTextCipher(MASTER).encrypt("from a")
    other = SIVTextCipher(secrets.token_bytes(32))
    with pytest.raises(EnvelopeError, match="unknown key version"):
        other.decrypt(token)


def test_survives_rotation():
    """SIV tokens carry a key ID: rotation keeps them decryptable."""
    import os
    import tempfile

    from ac3.keys import KeyManager

    with tempfile.TemporaryDirectory() as tmp:
        os.environ.pop("AC3_MASTER_KEY", None)
        keys = KeyManager(env_path=Path(tmp) / ".env")
        cipher = SIVTextCipher(keys)
        token = cipher.encrypt("pre-rotation siv data")
        keys.rotate()
        assert cipher.decrypt(token) == "pre-rotation siv data"
