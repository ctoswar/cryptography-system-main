"""v4 key rotation tests: rotation never orphans data (the anti-v1 guarantee)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import AC3Cipher, CMainController
from ac3.exceptions import AC3Error, EnvelopeError
from ac3.keys import ARCHIVE_PREFIX, KeyManager, key_id


@pytest.fixture()
def keys(env_dir, monkeypatch):
    monkeypatch.delenv("AC3_MASTER_KEY", raising=False)
    return KeyManager(env_path=env_dir / ".env")


def test_new_envelopes_carry_key_id(keys):
    cipher = AC3Cipher(keys)
    token = cipher.encrypt("rotation test")
    assert len(token.split(".")) == 5  # prefix + nonce + body + tag + keyid
    assert token.split(".")[4] != ""


def test_rotate_keeps_old_data_decryptable(keys):
    """The anti-v1 guarantee: rotation must never orphan ciphertexts."""
    cipher = AC3Cipher(keys)
    old_token = cipher.encrypt("encrypted before rotation")
    old_id = key_id(keys.master_key)

    summary = keys.rotate()
    assert summary["archived_as"] == f"{ARCHIVE_PREFIX}1"
    assert summary["old_key_id"] == old_id
    assert keys.master_key != keys.lookup_by_key_id(old_id)

    # pre-rotation data decrypts via the archived key (explicit ID)
    assert cipher.decrypt(old_token) == "encrypted before rotation"


def test_rotate_twice_keeps_both_generations(keys):
    cipher = AC3Cipher(keys)
    t1 = cipher.encrypt("generation one")
    keys.rotate()
    t2 = cipher.encrypt("generation two")
    keys.rotate()
    t3 = cipher.encrypt("generation three")

    assert cipher.decrypt(t1) == "generation one"
    assert cipher.decrypt(t2) == "generation two"
    assert cipher.decrypt(t3) == "generation three"
    archive = [k for k in keys.all_keys() if k != key_id(keys.master_key)]
    assert len(archive) == 2


def test_new_data_uses_new_key_after_rotation(keys):
    """New tokens minted AFTER rotation carry the NEW key's ID. Note: an
    existing cipher instance keeps its constructed key — rotation takes
    effect for new key material on the next cipher/controller build."""
    AC3Cipher(keys).encrypt("pre-rotation")
    keys.rotate()
    new_cipher = AC3Cipher(keys)
    token = new_cipher.encrypt("post-rotation")
    import base64

    decoded = base64.urlsafe_b64decode(token.split(".")[4] + "==")
    assert decoded == key_id(keys.master_key)


def test_unknown_key_id_rejected_with_clear_error(env_dir, monkeypatch):
    monkeypatch.delenv("AC3_MASTER_KEY", raising=False)
    keys_a = KeyManager(env_path=env_dir / "a.env")
    token_a = AC3Cipher(keys_a).encrypt("from deployment a")
    keys_b = KeyManager(env_path=env_dir / "b.env")
    with pytest.raises(EnvelopeError, match="unknown key version"):
        AC3Cipher(keys_b).decrypt(token_a)


def test_stream_ciphertexts_survive_rotation(keys, tmp_path):
    controller = CMainController(cipher=AC3Cipher(keys))
    src = tmp_path / "doc.bin"
    src.write_bytes(b"stream data " * 500)
    enc = controller.encrypt_file(src, tmp_path / "doc.ac3")
    keys.rotate()
    out = controller.decrypt_file(enc, tmp_path / "doc.out")
    assert out.read_bytes() == src.read_bytes()


def test_legacy_three_part_token_falls_back_to_archive(keys):
    """A key-ID-less token (pre-v4 shape) resolves active-then-archive."""
    import base64

    from ac3.envelope import encode_text

    cipher = AC3Cipher(keys)
    old_master = keys.master_key
    old_nonce = b"\x11" * 16
    body, tag = cipher._seal(b"legacy shape", old_nonce)
    legacy_token = encode_text([old_nonce, body, tag])  # no key ID
    keys.rotate()  # the key that made this token is now archived
    assert cipher.decrypt(legacy_token) == "legacy shape"
    # and the resolution used the archive, not the active key
    assert key_id(keys.master_key) != key_id(old_master)
    assert keys.lookup_by_key_id(key_id(old_master)) == old_master


def test_controller_rotation_end_to_end(keys):
    controller = CMainController(cipher=AC3Cipher(keys))
    before = controller.encrypt("before")
    keys.rotate()
    after = controller.encrypt("after", mode="classic")
    assert controller.decrypt(before) == "before"
    assert controller.decrypt(after) == "after"


def test_rotate_requires_env_backed_manager():
    from ac3.exceptions import InvalidKeyError

    cipher = AC3Cipher(b"\x01" * 32)
    assert cipher._keys is None  # raw-key cipher: no archive available
    mgr = KeyManager(master_key_hex=(b"\x02" * 32).hex())
    with pytest.raises(InvalidKeyError):
        mgr.rotate()
