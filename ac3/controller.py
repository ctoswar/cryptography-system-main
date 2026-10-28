"""Application facade over the AC3-X (v4) cipher modes.

Keeps the thesis-era entry point (``CMainController`` with ``encrypt`` /
``decrypt``) while adding streaming file support.

Modes (decrypt auto-detects from the envelope prefix):

    classic  ``AC3X.`` — the five-layer thesis pipeline, AES-CTR engine;
               carries a key ID so rotation never orphans data
    siv      ``AC3S.`` — nonce-misuse-resistant (RFC 5297); nonce reuse
               degrades to deterministic encryption instead of catastrophe
    session  ``AC3E.`` — X25519 recipient-keyed (RFC 7748); the master key
               leaves the confidentiality path (see the honest scope notes
               in ac3/session.py and SECURITY.md)

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
from .exceptions import AC3Error, EnvelopeError, InvalidKeyError
from .fips import FIPSCipher
from .keys import DEFAULT_ENV_PATH, KeyManager
from .session import SessionCipher
from .siv import SIVTextCipher

logger = logging.getLogger("ac3")

ENCRYPTED_SUFFIX = ".ac3"

MODES = ("fips", "classic", "siv", "session")


class CMainController:
    """Facade used by the Flask app, the CLI, and tests."""

    def __init__(self, env_path=DEFAULT_ENV_PATH, key_manager=None, cipher=None):
        self._keys = None
        if cipher is not None:
            self._cipher = cipher
            self._keys = getattr(cipher, "_keys", None)
        else:
            self._keys = key_manager or KeyManager(env_path)
            self._cipher = AC3Cipher(self._keys)
        self._siv = SIVTextCipher(self._cipher)
        self._fips = FIPSCipher(self._cipher)
        self._session = None  # lazily built: requires an env-backed key store

    def _session_cipher(self) -> SessionCipher:
        if self._session is None:
            self._session = SessionCipher(self._cipher._master, self._keys)
        return self._session

    def _recipient_pub(self) -> bytes:
        if self._keys is None:
            raise InvalidKeyError(
                "session mode requires an env-backed key store (X25519)."
            )
        return self._keys.x25519_public_key()

    # -- text ---------------------------------------------------------------

    def encrypt(self, text: str, mode: str = "fips") -> str:
        """Encrypt text in one of the four modes (FIPS by default)."""
        if mode == "fips":
            token = self._fips.encrypt(text)
        elif mode == "siv":
            token = self._siv.encrypt(text)
        elif mode == "session":
            token = self._session_cipher().encrypt(text, self._recipient_pub())
        elif mode == "classic":
            token = self._cipher.encrypt(text)
        else:
            raise AC3Error(
                f"Unknown mode {mode!r}; expected one of {list(MODES)}."
            )
        logger.debug("encrypted text [%s]: %d chars -> %d chars",
                     mode, len(text), len(token))
        return token

    def decrypt(self, token: str) -> str:
        """Auto-detecting decrypt: the envelope prefix selects the mode."""
        if token.startswith("AC3S."):
            text = self._siv.decrypt(token)
            mode = "siv"
        elif token.startswith("AC3E."):
            text = self._session_cipher().decrypt(token)
            mode = "session"
        elif token.startswith("AC3F."):
            text = self._fips.decrypt(token)
            mode = "fips"
        else:
            text = self._cipher.decrypt(token)
            mode = "classic"
        logger.debug("decrypted token [%s]: %d chars -> %d chars",
                     mode, len(token), len(text))
        return text

    # -- bytes ---------------------------------------------------------------

    def encrypt_bytes(self, data: bytes, chunk_size: int | None = None) -> bytes:
        if chunk_size is not None:
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

    def encrypt_file(self, source, target=None, mode: str = "fips",
                     chunk_size: int | None = None) -> Path:
        """Encrypt a file with the chunked stream format (constant memory)."""
        if mode in ("siv", "session"):
            raise AC3Error(
                f"Mode {mode!r} is text-only; use 'fips' or 'classic' for files."
            )
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        dst = Path(target) if target else self._default_encrypt_target(src)
        kwargs = {"chunk_size": chunk_size} if chunk_size is not None else {}
        if mode == "fips":
            size = self._atomic_write(
                dst, lambda tmp: self._fips.encrypt_file(src, tmp, **kwargs)
            )
        else:
            size = self._atomic_write(
                dst, lambda tmp: self._cipher.encrypt_file(src, tmp, **kwargs)
            )
        logger.info("encrypted file [%s]: %s -> %s (%d bytes)", mode, src, dst, size)
        return dst

    def decrypt_file(self, source, target=None) -> Path:
        """Decrypt a file; output is committed atomically after full authentication."""
        src = Path(source)
        if not src.is_file():
            raise AC3Error(f"Input file not found: {src}")
        with src.open("rb") as probe:
            stream_magic = probe.read(6)
        fips_mode = stream_magic == b"AC3F1\x01"
        mode = "fips" if fips_mode else "classic"

        if target:
            dst = Path(target)  # explicit path: user intent is clear
            self._decrypt_file_to(src, dst, fips_mode)
            logger.info(
                "decrypted file [%s]: %s -> %s (%d bytes)",
                mode, src, dst, dst.stat().st_size,
            )
            return dst

        dst = self._default_decrypt_target(src)
        if dst.exists():
            # Stage the plaintext, then compare: never destroy differing data.
            staged = self._decrypt_file_to_temp(src, fips_mode)
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

        self._decrypt_file_to(src, dst, fips_mode)
        logger.info(
            "decrypted file [%s]: %s -> %s (%d bytes)",
            mode, src, dst, dst.stat().st_size,
        )
        return dst

    def _decrypt_file_to(self, src: Path, dst: Path, fips_mode: bool) -> None:
        """Write decrypted plaintext of `src` to `dst` atomically.

        Staged in a sibling temp file and renamed into place only after the
        *entire* stream authenticates. Without this, a failed decrypt would
        leave partial plaintext at `dst` (leaking content after an
        IntegrityError) and, for an explicit target, would truncate the
        pre-existing file before failing.
        """
        if fips_mode:
            self._atomic_write(dst, lambda tmp: self._fips.decrypt_file(src, tmp))
        else:
            self._atomic_write(dst, lambda tmp: self._cipher.decrypt_file(src, tmp))

    def _decrypt_file_to_temp(self, src: Path, fips_mode: bool) -> Path:
        """Decrypt into a fresh sibling temp file (for no-clobber comparison)."""
        fd, tmp_name = tempfile.mkstemp(
            prefix=".ac3tmp-", dir=str(src.parent)
        )
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            if fips_mode:
                self._fips.decrypt_file(src, tmp)
            else:
                self._cipher.decrypt_file(src, tmp)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return tmp


__all__ = ["CMainController", "ENCRYPTED_SUFFIX", "EnvelopeError"]
