"""Application facade over the AC3 v2 and AES-GCM ciphers.

Keeps the thesis-era entry point (``CMainController`` with ``encrypt`` /
``decrypt``) while adding file support and algorithm selection.

Algorithm contract:
    * ``encrypt(..., algorithm=...)`` selects the mode — ``"ac3"`` (default,
      the five-layer thesis identity) or ``"aes"`` (AES-256-GCM standard).
    * ``decrypt`` / ``decrypt_file`` **auto-detect** from the envelope:
      ``AC3a.…`` text or ``AC3AES`` magic -> AES; ``AC3v2.…`` / ``AC3V2`` -> AC3.
      Callers never have to remember which mode produced a ciphertext.
    * File encryption with ``algorithm="aes"`` streams chunk-by-chunk:
      constant memory, AES-NI speed — the high-volume path.

Never logs message contents.
"""

import logging
import os
import tempfile
from pathlib import Path

from .aesgcm import (
    TEXT_PREFIX as AES_TEXT_PREFIX,
    AESGCMCipher,
    looks_like_aes_stream,
    looks_like_aes_text,
    validate_algorithm,
)
from .core import AC3Cipher
from .exceptions import AC3Error, EnvelopeError
from .keys import DEFAULT_ENV_PATH, KeyManager

logger = logging.getLogger("ac3")

ENCRYPTED_SUFFIX = ".ac3"


class CMainController:
    """Facade used by the Flask app, the CLI, and tests."""

    def __init__(self, env_path=DEFAULT_ENV_PATH, key_manager=None, cipher=None):
        if cipher is not None:
            self._cipher = cipher
            self._aes = AESGCMCipher(cipher._master)  # same master key
        else:
            keys = key_manager or KeyManager(env_path)
            self._cipher = AC3Cipher(keys)
            self._aes = AESGCMCipher(keys)

    @property
    def algorithms(self):
        return ("ac3", "aes")

    # -- text ---------------------------------------------------------------

    def encrypt(self, text: str, algorithm: str = "ac3") -> str:
        validate_algorithm(algorithm)
        if algorithm == "aes":
            token = self._aes.encrypt(text)
        else:
            token = self._cipher.encrypt(text)
        logger.debug(
            "encrypted text [%s]: %d chars -> %d chars", algorithm, len(text), len(token)
        )
        return token

    def decrypt(self, token: str) -> str:
        """Auto-detecting decrypt: the envelope prefix selects the algorithm."""
        if looks_like_aes_text(token):
            text = self._aes.decrypt(token)
            alg = "aes"
        else:
            text = self._cipher.decrypt(token)
            alg = "ac3"
        logger.debug(
            "decrypted token [%s]: %d chars -> %d chars", alg, len(token), len(text)
        )
        return text

    # -- bytes ---------------------------------------------------------------

    def encrypt_bytes(self, data: bytes, algorithm: str = "ac3") -> bytes:
        validate_algorithm(algorithm)
        if algorithm == "aes":
            return self._aes.encrypt_bytes(data)
        return self._cipher.encrypt_bytes(data)

    def decrypt_bytes(self, blob: bytes) -> bytes:
        """Auto-detecting decrypt: magic bytes select the algorithm."""
        if looks_like_aes_stream(blob):
            return self._aes.decrypt_bytes(blob)
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
    def _atomic_write(dst: Path, writer) -> int:
        """Run `writer(tmp_path)` against a staging file, commit via rename.

        `writer` may stream to `tmp_path`; only if it returns without raising
        is the result renamed onto `dst`. On any failure the staging file is
        removed, so `dst` is never left truncated or half-written (and the
        no-clobber guards never see a partial file). Returns the final size.
        """
        dst.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".ac3stg-", dir=str(dst.parent))
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            writer(tmp)
            size = tmp.stat().st_size
            os.replace(tmp, dst)  # atomic on same filesystem: commit on success
            return size
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

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

    def encrypt_file(self, source, target=None, algorithm: str = "ac3",
                     chunk_size: int | None = None) -> Path:
        validate_algorithm(algorithm)
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        dst = Path(target) if target else self._default_encrypt_target(src)

        if algorithm == "aes":
            # Streaming path: constant memory regardless of file size.
            kwargs = {"chunk_size": chunk_size} if chunk_size else {}
            size = self._atomic_write(
                dst, lambda tmp: self._aes.encrypt_file(src, tmp, **kwargs)
            )
        else:
            size = self._atomic_write(
                dst,
                lambda tmp: tmp.write_bytes(
                    self._cipher.encrypt_bytes(src.read_bytes())
                ),
            )
        logger.info(
            "encrypted file [%s]: %s -> %s (%d bytes)", algorithm, src, dst, size
        )
        return dst

    def decrypt_file(self, source, target=None) -> Path:
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        with src.open("rb") as probe:
            aes_mode = looks_like_aes_stream(probe.read(8))
        alg = "aes" if aes_mode else "ac3"

        if target:
            dst = Path(target)  # explicit path: user intent is clear
            self._decrypt_file_to(src, dst, aes_mode)
            logger.info(
                "decrypted file [%s]: %s -> %s (%d bytes)",
                alg, src, dst, dst.stat().st_size,
            )
            return dst

        dst = self._default_decrypt_target(src)
        if dst.exists():
            # Stage the plaintext, then compare: never destroy differing data.
            staged = self._decrypt_file_to_temp(src, aes_mode)
            try:
                if dst.read_bytes() == staged.read_bytes():
                    logger.info("decrypted content already present: %s", dst)
                    return dst
                raise AC3Error(
                    f"Refusing to overwrite existing file with different content: "
                    f"{dst}. Pass an explicit output path instead."
                )
            finally:
                staged.unlink(missing_ok=True)

        self._decrypt_file_to(src, dst, aes_mode)
        logger.info(
            "decrypted file [%s]: %s -> %s (%d bytes)",
            alg, src, dst, dst.stat().st_size,
        )
        return dst

    def _decrypt_file_to(self, src: Path, dst: Path, aes_mode: bool) -> None:
        """Write decrypted plaintext of `src` to `dst` atomically.

        Staged in a sibling temp file and renamed into place only after the
        *entire* stream authenticates. Without this, a failed AES decrypt
        left partial plaintext at `dst` (leaking content after an
        IntegrityError) and, for an explicit target, truncated the
        pre-existing file before failing.
        """
        self._atomic_write(
            dst,
            lambda tmp: self._aes.decrypt_file(src, tmp)
            if aes_mode
            else tmp.write_bytes(self._cipher.decrypt_bytes(src.read_bytes())),
        )

    def _decrypt_file_to_temp(self, src: Path, aes_mode: bool) -> Path:
        """Decrypt into a fresh sibling temp file (for no-clobber comparison)."""
        fd, tmp_name = tempfile.mkstemp(
            prefix=".ac3tmp-", dir=str(src.parent)
        )
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            if aes_mode:
                self._aes.decrypt_file(src, tmp)
            else:
                tmp.write_bytes(self._cipher.decrypt_bytes(src.read_bytes()))
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return tmp


__all__ = ["CMainController", "ENCRYPTED_SUFFIX", "AES_TEXT_PREFIX", "EnvelopeError"]
