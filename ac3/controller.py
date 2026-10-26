"""Application facade over the AC3 v2 cipher.

Keeps the thesis-era entry point (``CMainController`` with ``encrypt`` /
``decrypt``) while adding file support. Never logs message contents.
"""

import logging
from pathlib import Path

from .core import AC3Cipher
from .exceptions import AC3Error
from .keys import DEFAULT_ENV_PATH, KeyManager

logger = logging.getLogger("ac3")

ENCRYPTED_SUFFIX = ".ac3"


class CMainController:
    """Facade used by the Flask app, the CLI, and tests."""

    def __init__(self, env_path=DEFAULT_ENV_PATH, key_manager=None, cipher=None):
        if cipher is not None:
            self._cipher = cipher
        else:
            self._cipher = AC3Cipher(key_manager or KeyManager(env_path))

    # -- text ---------------------------------------------------------------

    def encrypt(self, text: str) -> str:
        token = self._cipher.encrypt(text)
        logger.debug("encrypted text: %d chars -> %d chars", len(text), len(token))
        return token

    def decrypt(self, token: str) -> str:
        text = self._cipher.decrypt(token)
        logger.debug("decrypted token: %d chars -> %d chars", len(token), len(text))
        return text

    # -- bytes ---------------------------------------------------------------

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self._cipher.encrypt_bytes(data)

    def decrypt_bytes(self, blob: bytes) -> bytes:
        return self._cipher.decrypt_bytes(blob)

    # -- files ----------------------------------------------------------------

    @staticmethod
    def _default_encrypt_target(source: Path) -> Path:
        target = source.with_name(source.name + ENCRYPTED_SUFFIX)
        if target.exists():
            raise AC3Error(
                f"Refusing to overwrite existing file: {target}. "
                "Pass an explicit output path instead."
            )
        return target

    @staticmethod
    def _default_decrypt_target(source: Path) -> Path:
        name = source.name
        base = (
            name[: -len(ENCRYPTED_SUFFIX)]
            if name.endswith(ENCRYPTED_SUFFIX)
            else name + ".decrypted"
        )
        if not base:
            base = name + ".decrypted"
        return source.with_name(base)

    def encrypt_file(self, source, target=None) -> Path:
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        ciphertext = self._cipher.encrypt_bytes(src.read_bytes())
        if target:
            dst = Path(target)
            dst.write_bytes(ciphertext)  # explicit path: user intent is clear
        else:
            dst = self._default_encrypt_target(src)
            dst.write_bytes(ciphertext)
        logger.info("encrypted file: %s -> %s (%d bytes)", src, dst, len(ciphertext))
        return dst

    def decrypt_file(self, source, target=None) -> Path:
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        plaintext = self._cipher.decrypt_bytes(src.read_bytes())
        if target:
            dst = Path(target)
            dst.write_bytes(plaintext)
            logger.info(
                "decrypted file: %s -> %s (%d bytes)", src, dst, len(plaintext)
            )
            return dst
        dst = self._default_decrypt_target(src)
        if dst.exists():
            if dst.read_bytes() == plaintext:
                # Idempotent: the file already holds exactly this content.
                logger.info("decrypted content already present: %s", dst)
                return dst
            raise AC3Error(
                f"Refusing to overwrite existing file with different content: "
                f"{dst}. Pass an explicit output path instead."
            )
        dst.write_bytes(plaintext)
        logger.info("decrypted file: %s -> %s (%d bytes)", src, dst, len(plaintext))
        return dst
