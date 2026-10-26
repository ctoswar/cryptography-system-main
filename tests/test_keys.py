"""Key management tests: stability, .env persistence, derivation properties.

The v1 critical bug was key rotation on every boot and after every decrypt;
these tests are the regression guard against that ever coming back.
"""

import pytest

from ac3.exceptions import InvalidKeyError
from ac3.keys import MASTER_KEY_ENV, MASTER_KEY_BYTES, KeyManager, derive_stream


def test_key_created_once_then_stable(env_dir):
    env_path = env_dir / ".env"
    first = KeyManager(env_path=env_path).master_key
    second = KeyManager(env_path=env_path).master_key
    third = KeyManager(env_path=env_path).master_key
    assert first == second == third, "master key must never rotate"
    assert len(first) == MASTER_KEY_BYTES


def test_key_persisted_to_env_file(env_dir):
    env_path = env_dir / ".env"
    KeyManager(env_path=env_path)
    assert env_path.exists()
    content = env_path.read_text()
    assert MASTER_KEY_ENV in content


def test_existing_env_key_is_loaded_not_regenerated(env_dir, monkeypatch):
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    env_path = env_dir / ".env"
    stored = "ab" * MASTER_KEY_BYTES
    env_path.write_text(f"{MASTER_KEY_ENV}={stored}\n")
    assert KeyManager(env_path=env_path).master_key == bytes.fromhex(stored)


def test_env_var_takes_precedence(env_dir, monkeypatch):
    key = "cd" * MASTER_KEY_BYTES
    monkeypatch.setenv(MASTER_KEY_ENV, key)
    env_path = env_dir / ".env"
    KeyManager(env_path=env_path)  # would otherwise create its own
    assert KeyManager(env_path=env_path).master_key == bytes.fromhex(key)


def test_other_env_entries_survive_key_creation(env_dir):
    env_path = env_dir / ".env"
    env_path.write_text("UNRELATED=keepme\nANOTHER=42\n")
    KeyManager(env_path=env_path)
    content = env_path.read_text()
    assert "UNRELATED=keepme" in content
    assert "ANOTHER=42" in content
    assert MASTER_KEY_ENV in content


def test_invalid_hex_rejected(env_dir):
    env_path = env_dir / ".env"
    env_path.write_text(f"{MASTER_KEY_ENV}=not-hex-at-all\n")
    with pytest.raises(InvalidKeyError):
        KeyManager(env_path=env_path)


def test_wrong_length_key_rejected(env_dir):
    env_path = env_dir / ".env"
    env_path.write_text(f"{MASTER_KEY_ENV}={'ab' * 16}\n")  # 16 bytes, need 32
    with pytest.raises(InvalidKeyError):
        KeyManager(env_path=env_path)


def test_decrypt_works_across_restart(env_dir, monkeypatch):
    """The v1 killer: data encrypted before a 'restart' must decrypt after."""
    from ac3 import AC3Cipher

    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    env_path = env_dir / ".env"

    # First process: encrypt.
    token = AC3Cipher(KeyManager(env_path=env_path)).encrypt("survives restart")

    # Second 'process': same .env, fresh objects.
    cipher = AC3Cipher(KeyManager(env_path=env_path))
    assert cipher.decrypt(token) == "survives restart"


# --------------------------------------------------------------------------
# derivation properties
# --------------------------------------------------------------------------

def test_derive_stream_deterministic():
    master, nonce = b"\x01" * 32, b"\x02" * 16
    a = derive_stream(master, nonce, b"info", 64)
    b = derive_stream(master, nonce, b"info", 64)
    assert a == b


def test_derive_stream_differs_by_nonce_info_and_master():
    a = derive_stream(b"\x01" * 32, b"\x02" * 16, b"x", 64)
    assert a != derive_stream(b"\x01" * 32, b"\x03" * 16, b"x", 64)  # nonce
    assert a != derive_stream(b"\x01" * 32, b"\x02" * 16, b"y", 64)  # info
    assert a != derive_stream(b"\xff" * 32, b"\x02" * 16, b"x", 64)  # master


def test_derive_stream_lengths():
    master, nonce = b"\x01" * 32, b"\x02" * 16
    assert derive_stream(master, nonce, b"i", 0) == b""
    assert len(derive_stream(master, nonce, b"i", 1)) == 1
    # long stream exercises chunked expansion (> 8160-byte HKDF-Expand ceiling)
    long_stream = derive_stream(master, nonce, b"i", 40000)
    assert len(long_stream) == 40000
    assert len(set(long_stream)) > 200  # no pathological repetition


def test_derive_stream_no_zero_length_crash():
    # length beyond one expansion must not raise or truncate
    out = derive_stream(b"\x09" * 32, b"\x09" * 16, b"chunked", 10000)
    assert len(out) == 10000
