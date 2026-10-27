"""Regression proof: the v1 collapse attack demonstration must keep working.

These tests convert the research's central finding into CI-verifiable
evidence: if anyone ever changes the v1 reconstruction or the attack logic
such that the demo stops reproducing, the suite fails.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "evaluation"))

from break_v1 import (  # noqa: E402
    attack_1_config_known,
    attack_2_no_config,
    decrypt_with_mask,
    strip_common_affixes,
)
from v1_reference import V1Cipher, V1Config  # noqa: E402

MESSAGES = [
    "Meet at the library at 5pm",
    "My password for the portal is hunter2!",
    "The exam reviewer is in the shared drive",
    "Happy birthday!!! See you later",
    "Calling you in 10 minutes",
    "Sent you the photos already",
    "Group study later at the canteen?",
    "Do not forget the project deadline",
]


@pytest.fixture()
def session():
    cfg = V1Config.generate()
    cipher = V1Cipher(cfg)
    ciphertexts = [cipher.encrypt(m) for m in MESSAGES]
    return cfg, list(zip(MESSAGES, ciphertexts))


def test_v1_reconstruction_roundtrips(session):
    """The faithful v1 reconstruction must encrypt/decrypt correctly first."""
    cfg, pairs = session
    cipher = V1Cipher(cfg)
    for pt, ct in pairs:
        assert cipher.decrypt(ct) == pt


def test_collapse_mask_equals_xor_of_all_five_keys(session):
    """The core claim: five XOR layers collapse to exactly one combined mask."""
    cfg, _ = session
    pairs = session[1]
    rec = attack_1_config_known(cfg, pairs)
    assert rec["mask"] == cfg.combined_mask()


def test_attack_1_one_pair_breaks_whole_session(session):
    cfg, pairs = session
    rec = attack_1_config_known(cfg, pairs)
    for pt, ct in pairs:
        out = decrypt_with_mask(ct, rec["mask"], rec["shift"])
        assert out.removeprefix(cfg.prefix).removesuffix(cfg.suffix) == pt


def test_attack_2_no_configuration_breaks_whole_session(session):
    """Only Firebase-leaked pairs; the Caesar shift, padding offset, and the
    full periodic mask are recovered by brute force + consistency voting."""
    cfg, pairs = session
    rec = attack_2_no_config(pairs)
    assert rec["shift"] == cfg.caesar_shift
    assert rec["mask"] == cfg.combined_mask()
    padded = [decrypt_with_mask(ct, rec["mask"], rec["shift"]) for _, ct in pairs]
    assert strip_common_affixes(padded) == MESSAGES


def test_boot_rotation_orphans_history(session):
    """v1's second design flaw: new boot -> new keys -> old data unreadable."""
    cfg, pairs = session
    old_cipher_text = pairs[0][1]
    new_cipher = V1Cipher(V1Config.generate())  # a fresh 'boot'
    recovered = new_cipher.decrypt(old_cipher_text)
    assert recovered != MESSAGES[0]
