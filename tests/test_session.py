"""v4 session mode tests: X25519 key agreement + authenticated handshake."""

import base64
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import SessionCipher
from ac3.exceptions import AC3Error, IntegrityError, InvalidKeyError
from ac3.keys import KeyManager


@pytest.fixture()
def keys(env_dir, monkeypatch):
    monkeypatch.delenv("AC3_MASTER_KEY", raising=False)
    monkeypatch.delenv("AC3_X25519_SK", raising=False)
    return KeyManager(env_path=env_dir / ".env")


@pytest.fixture()
def session(keys):
    return SessionCipher(keys.master_key, keys)


def test_x25519_provisioned_once(keys):
    sk1 = keys.x25519_private_key()
    sk2 = keys.x25519_private_key()
    assert sk1 == sk2  # stable across calls (persisted)
    assert len(keys.x25519_public_key()) == 32


def test_roundtrip_self_session(session, keys):
    token = session.encrypt("session secret 🔐", keys.x25519_public_key())
    assert token.startswith("AC3E.")
    assert session.decrypt(token) == "session secret 🔐"


def test_envelope_shape(session, keys):
    token = session.encrypt("shape", keys.x25519_public_key())
    parts = token.split(".")
    assert parts[0] == "AC3E"
    assert len(parts) == 6  # prefix + enc + nonce + body + mac + keyid
    assert len(base64.urlsafe_b64decode(parts[1] + "==")) == 32  # HPKE enc
    assert len(base64.urlsafe_b64decode(parts[2] + "==")) == 16  # inner nonce


def test_ephemeral_randomness(session, keys):
    """Each encryption uses a fresh ephemeral key: same plaintext twice
    yields different envelopes (and different ephemeral public keys)."""
    pub = keys.x25519_public_key()
    t1 = session.encrypt("same plaintext", pub)
    t2 = session.encrypt("same plaintext", pub)
    assert t1 != t2
    assert t1.split(".")[1] != t2.split(".")[1]  # different ephemeral PKs


def test_handshake_bind_rejects_forgery(session, keys):
    """Replacing the bind tag (or encrypting to a foreign recipient key)
    must fail handshake authentication before any decryption."""
    pub = keys.x25519_public_key()
    token = session.encrypt("auth check", pub)
    parts = token.split(".")
    mac = bytearray(base64.urlsafe_b64decode(parts[4] + "=="))
    mac[-1] ^= 0x01  # flip a bind-tag bit (mac field = inner tag || bind)
    parts[4] = base64.urlsafe_b64encode(bytes(mac)).decode().rstrip("=")
    with pytest.raises(IntegrityError, match="handshake"):
        session.decrypt(".".join(parts))


def test_ephemeral_pk_tamper_rejected(session, keys):
    """Substituting the ephemeral public key breaks the bind (it is MACed)."""
    pub = keys.x25519_public_key()
    token = session.encrypt("mitm check", pub)
    parts = token.split(".")
    epk = bytearray(base64.urlsafe_b64decode(parts[1] + "=="))
    epk[0] ^= 0x01
    parts[1] = base64.urlsafe_b64encode(bytes(epk)).decode().rstrip("=")
    with pytest.raises((IntegrityError, AC3Error)):
        session.decrypt(".".join(parts))


def test_cross_key_session_rejected(session, keys):
    """A session envelope bound to a different deployment's master is rejected
    at the key-ID resolution layer (the foreign key is not in our archive)."""
    from ac3.exceptions import EnvelopeError

    other_env = keys._env_path.parent / "other.env"
    other_keys = KeyManager(env_path=other_env)
    other = SessionCipher(other_keys.master_key, other_keys)
    foreign = other.encrypt("bound to another master", other_keys.x25519_public_key())
    with pytest.raises(EnvelopeError, match="unknown key version"):
        session.decrypt(foreign)


def test_requires_env_backed_keys():
    with pytest.raises(InvalidKeyError):
        SessionCipher(secrets.token_bytes(32), None)


def test_session_keys_are_not_the_master(session, keys):
    """The confidentiality path uses the HPKE-derived session master —
    an attacker holding ONLY the master key cannot decrypt (the ephemeral
    secret is gone). Verified here by directly attempting the classic
    pipeline under the master key."""
    pub = keys.x25519_public_key()
    token = session.encrypt("not decryptable with master alone", pub)
    # carve the inner classic fields out of the session envelope
    parts = token.split(".")
    nonce = base64.urlsafe_b64decode(parts[2] + "==")
    body = base64.urlsafe_b64decode(parts[3] + "==")
    tag = base64.urlsafe_b64decode(parts[4] + "==")[:32]
    from ac3 import AC3Cipher

    with pytest.raises(IntegrityError):
        AC3Cipher(keys.master_key).decrypt(
            "AC3X." + ".".join([
                base64.urlsafe_b64encode(nonce).decode().rstrip("="),
                base64.urlsafe_b64encode(body).decode().rstrip("="),
                base64.urlsafe_b64encode(tag).decode().rstrip("="),
            ])
        )
