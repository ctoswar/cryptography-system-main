"""Controller facade and file encryption tests."""

import pytest

from ac3 import CMainController
from ac3.exceptions import AC3Error, EnvelopeError, IntegrityError
from ac3.keys import KeyManager


@pytest.fixture()
def controller(env_dir, monkeypatch):
    # Isolate from the developer's real .env / process env.
    monkeypatch.delenv("AC3_MASTER_KEY", raising=False)
    return CMainController(env_path=env_dir / ".env")


def test_text_roundtrip(controller):
    assert controller.decrypt(controller.encrypt("muling muli")) == "muling muli"


def test_unicode_roundtrip(controller):
    text = "Pangungusap na may ñ at 🔐: 你好"
    assert controller.decrypt(controller.encrypt(text)) == text


def test_file_roundtrip(controller, tmp_path):
    src = tmp_path / "notes.txt"
    payload = b"confidential\x00\xff data \xf0\x9f\x94\x90"
    src.write_bytes(payload)

    enc = controller.encrypt_file(src)
    assert enc.name == "notes.txt.ac3"
    assert enc.read_bytes() != payload  # actually encrypted
    assert src.read_bytes() == payload  # original untouched

    dec = controller.decrypt_file(enc)
    assert dec.name == "notes.txt"
    assert dec.read_bytes() == payload


def test_file_roundtrip_explicit_targets(controller, tmp_path):
    src = tmp_path / "report.bin"
    src.write_bytes(bytes(range(256)) * 10)
    enc = controller.encrypt_file(src, tmp_path / "out.ac3")
    dec = controller.decrypt_file(enc, tmp_path / "restored.bin")
    assert dec.read_bytes() == src.read_bytes()


def test_encrypt_refuses_to_clobber(controller, tmp_path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"data")
    controller.encrypt_file(src)  # creates a.txt.ac3
    with pytest.raises(AC3Error, match="Refusing to overwrite"):
        controller.encrypt_file(src)  # second run must not overwrite


def test_decrypt_refuses_to_clobber_different_content(controller, tmp_path):
    """Decrypt may be idempotent, but must never silently destroy other data."""
    src = tmp_path / "b.txt"
    src.write_bytes(b"data")
    enc = controller.encrypt_file(src)
    # User later edits b.txt to something unrelated...
    src.write_bytes(b"totally different user work")
    with pytest.raises(AC3Error, match="Refusing to overwrite"):
        controller.decrypt_file(enc)  # ...decrypt must not destroy it


def test_decrypt_idempotent_when_content_already_present(controller, tmp_path):
    """Normal roundtrip: original still exists with identical bytes -> no error."""
    src = tmp_path / "same.txt"
    src.write_bytes(b"data")
    enc = controller.encrypt_file(src)
    out = controller.decrypt_file(enc)  # same.txt exists, identical content
    assert out == src
    assert out.read_bytes() == b"data"


def test_missing_input_file(controller, tmp_path):
    with pytest.raises(AC3Error, match="not found"):
        controller.encrypt_file(tmp_path / "ghost.txt")
    with pytest.raises(AC3Error, match="not found"):
        controller.decrypt_file(tmp_path / "ghost.ac3")


def test_decrypt_corrupted_file(controller, tmp_path):
    src = tmp_path / "c.txt"
    src.write_bytes(b"important")
    enc = controller.encrypt_file(src)
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0xFF  # flip last byte of tag
    enc.write_bytes(bytes(blob))
    with pytest.raises(IntegrityError):
        controller.decrypt_file(enc)


def test_decrypt_non_ac3_file(controller, tmp_path):
    plain = tmp_path / "d.txt"
    plain.write_bytes(b"this is not AC3 ciphertext at all")
    with pytest.raises(EnvelopeError):
        controller.decrypt_file(plain)


def test_controller_shares_keys_via_same_env(controller, env_dir):
    """A second controller reading the same .env can decrypt the first's output."""
    other = CMainController(env_path=env_dir / ".env")
    token = controller.encrypt("shared keys work")
    assert other.decrypt(token) == "shared keys work"


def test_newer_file_cipher_does_not_log_plaintext(controller, caplog):
    import logging

    with caplog.at_level(logging.DEBUG, logger="ac3"):
        controller.encrypt("super secret passphrase")
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "super secret passphrase" not in joined, "plaintext leaked into logs"
