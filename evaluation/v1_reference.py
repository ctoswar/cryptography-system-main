"""Faithful reconstruction of the original AC3 v1 algorithm.

Reconstructed from APPENDIX F (SOURCE CODE) of the thesis document
"AC3 level 5 Encryption Algorithm with Caesar Cipher and XOR Cipher using
Python" (STI College Bacoor, 2023) and the algorithm narrative in its
System Design Specification (encryption/decryption process sections).

This module exists so the research's central finding — that stacking five
XOR layers with static keys provides only ONE layer of security — can be
demonstrated empirically against the real v1 design, not a strawman.

v1 construction (per the thesis):

    boot:   the application "autonomously generates XOR keys, Caesar shift
            values, prefixes, and suffixes" and stores them in the .env file
    L1:     plain_text = prefix + input + suffix
            caesar     = chr((ord(c) - 32 + shift) % 96 + 32) for each char
            ct1        = caesar.encode('utf-8') XOR-repeat KEY_LEVEL1
    L2..L5: ct_n = ct_{n-1} XOR-repeat KEY_LEVELn
    output: base64url(ct5)

Documented v1 behaviours preserved here on purpose (they are the findings):

    * keys are STATIC per boot session -> every ciphertext in a session
      shares one effective mask (see break_v1.py),
    * keys rotate on regeneration -> ciphertexts from earlier sessions
      become permanently undecryptable,
    * Caesar operates on the 96 printable ASCII codes 32..127 only, and
      decryption rebuilds text with chr(byte) per byte, corrupting any
      non-ASCII UTF-8 sequence (the v2 README's "Unicode destroyed" finding).
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field

CAESAR_MODULUS = 96      # printable ASCII 32..127 per the thesis source
CAESAR_BASE = 32
LEVELS = 5
KEY_BYTES = 16           # v1 stored hex keys in the .env; 16 bytes assumed


@dataclass
class V1Config:
    """The boot-generated parameters v1 stored in its .env file."""

    xor_keys: list = field(default_factory=list)   # 5 x bytes
    caesar_shift: int = 0
    prefix: str = ""
    suffix: str = ""

    @staticmethod
    def generate() -> "V1Config":
        """Simulate v1's boot-time 'autonomous' parameter generation."""
        return V1Config(
            xor_keys=[secrets.token_bytes(KEY_BYTES) for _ in range(LEVELS)],
            caesar_shift=secrets.randbelow(CAESAR_MODULUS),
            prefix="".join(chr(CAESAR_BASE + secrets.randbelow(CAESAR_MODULUS)) for _ in range(8)),
            suffix="".join(chr(CAESAR_BASE + secrets.randbelow(CAESAR_MODULUS)) for _ in range(8)),
        )

    def combined_mask(self) -> bytes:
        """K1 XOR K2 XOR K3 XOR K4 XOR K5 — what all five layers collapse to.

        The repeating-key XOR of the five levels is mathematically identical
        to a single repeating-key XOR under this combined mask, because XOR
        is associative and commutative. break_v1.py proves this empirically
        by recovering the mask from ciphertext alone and comparing.
        """
        period = max(len(k) for k in self.xor_keys)
        combined = bytearray(period)
        for key in self.xor_keys:
            for i, byte in enumerate(key):
                combined[i % period] ^= byte
        return bytes(combined)


def _apply_caesar_shift(text: str, shift: int) -> str:
    """Verbatim reconstruction of the thesis appendix Caesar implementation."""
    return "".join(chr((ord(char) - CAESAR_BASE + shift) % CAESAR_MODULUS + CAESAR_BASE) for char in text)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """Verbatim reconstruction of the thesis appendix XOR (repeating key)."""
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


class V1Cipher:
    """The original AC3 v1 pipeline, as published in the thesis appendix."""

    def __init__(self, config: V1Config):
        self._cfg = config

    # -- encryption: L1 (affix + Caesar + XOR) then L2..L5 (XOR) ------------

    def encrypt(self, input_text: str) -> str:
        cfg = self._cfg
        plain_text = cfg.prefix + input_text + cfg.suffix          # appendix L2013
        caesar_text = _apply_caesar_shift(plain_text, cfg.caesar_shift)
        current = _xor_bytes(caesar_text.encode("utf-8"), cfg.xor_keys[0])
        for level in range(1, LEVELS):                             # L2..L5
            current = _xor_bytes(current, cfg.xor_keys[level])
        return base64.urlsafe_b64encode(current).decode("ascii")

    # -- decryption: exactly the appendix's per-byte chr() reconstruction ----

    def decrypt(self, encrypted_text: str) -> str:
        cfg = self._cfg
        raw = base64.urlsafe_b64decode(encrypted_text.encode("ascii"))
        current = raw
        for level in range(LEVELS - 1, -1, -1):                    # L5..L1
            current = _xor_bytes(current, cfg.xor_keys[level])
        # The appendix rebuilds text with chr(byte) per byte, then Caesar-
        # reverses. Preserved verbatim in behaviour (including its handling
        # of bytes >= 128, which is v1's documented Unicode corruption).
        caesar_text = "".join(chr(byte) for byte in current)
        original_text = _apply_caesar_shift(caesar_text, -cfg.caesar_shift)
        return original_text[len(cfg.prefix): len(original_text) - len(cfg.suffix)]
