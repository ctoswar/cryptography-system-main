"""Application facade over the AC3-X (v3) cipher.

Keeps the thesis-era entry point (``CMainController`` with ``encrypt`` /
``decrypt``) while adding streaming file support.

Single algorithm: AC3-X is the five-layer thesis pipeline with an AES-256-CTR
keystream engine and HMAC-SHA256 integrity (see SPEC.md). Text uses the
``AC3X.`` envelope; files use the chunked stream format (``AC3X3`` magic) with
constant memory regardless of file size.

Durability contract (red-team finding V-1): every file write is staged in a
sibling temp file and renamed into place only after the whole stream
authenticates — a failed decrypt/encrypt never leaves partial output behind
and never truncates an existing target.

Never logs message contents.
"""

import logging
import os
import tempfile
from pathlib import Path

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

    def encrypt_bytes(self, data: bytes, chunk_size: int | None = None) -> bytes:
        if chunk_size:
            return self._cipher.encrypt_bytes(data, chunk_size=chunk_size)
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

    def encrypt_file(self, source, target=None, chunk_size: int | None = None) -> Path:
        """Encrypt a file with the chunked stream format (constant memory)."""
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        dst = Path(target) if target else self._default_encrypt_target(src)
        kwargs = {"chunk_size": chunk_size} if chunk_size else {}
        size = self._atomic_write(
            dst, lambda tmp: self._cipher.encrypt_file(src, tmp, **kwargs)
        )
        logger.info("encrypted file: %s -> %s (%d bytes)", src, dst, size)
        return dst

    def decrypt_file(self, source, target=None) -> Path:
        """Decrypt a file; output is committed atomically after full authentication."""
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")

        if target:
            dst = Path(target)  # explicit path: user intent is clear
            self._decrypt_file_to(src, dst)
            logger.info(
                "decrypted file: %s -> %s (%d bytes)",
                src, dst, dst.stat().st_size,
            )
            return dst

        dst = self._default_decrypt_target(src)
        if dst.exists():
            # Stage the plaintext, then compare: never destroy differing data.
            staged = self._decrypt_file_to_temp(src)
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

        self._decrypt_file_to(src, dst)
        logger.info(
            "decrypted file: %s -> %s (%d bytes)",
            src, dst, dst.stat().st_size,
        )
        return dst

    def _decrypt_file_to(self, src: Path, dst: Path) -> None:
        """Write decrypted plaintext of `src` to `dst` atomically.

        Staged in a sibling temp file and renamed into place only after the
        *entire* stream authenticates. Without this, a failed decrypt would
        leave partial plaintext at `dst` (leaking content after an
        IntegrityError) and, for an explicit target, would truncate the
        pre-existing file before failing.
        """
        self._atomic_write(dst, lambda tmp: self._cipher.decrypt_file(src, tmp))

    def _decrypt_file_to_temp(self, src: Path) -> Path:
        """Decrypt into a fresh sibling temp file (for no-clobber comparison)."""
        fd, tmp_name = tempfile.mkstemp(
            prefix=".ac3tmp-", dir=str(src.parent)
        )
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            self._cipher.decrypt_file(src, tmp)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return tmp


__all__ = ["CMainController", "ENCRYPTED_SUFFIX", "EnvelopeError"]
