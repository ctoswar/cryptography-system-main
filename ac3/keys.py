"""Master key management and subkey derivation for AC3 v2.

Design decisions (differences from AC3 v1):
  * The master key is generated ONCE and persisted. It is never rotated on boot
    or after decryption, so previously encrypted data stays decryptable.
  * All layer keys are derived per message from (master key, random nonce)
    using HKDF-SHA256, so every message uses unique, independent subkeys.
    This addresses the v1 weakness where 5 stacked XOR passes with static keys
    collapsed mathematically into a single XOR.
"""

import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac

from .exceptions import InvalidKeyError

MASTER_KEY_ENV = "AC3_MASTER_KEY"
MASTER_KEY_BYTES = 32
DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# HKDF-Expand output ceiling for a single expansion (255 * SHA256 size).
_MAX_EXPAND = 255 * 32


def _read_env_value(env_path: Path, key: str):
    if not env_path.exists():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}="):
            return stripped.split("=", 1)[1].strip()
    return None


def _write_env_value(env_path: Path, key: str, value: str) -> None:
    lines = []
    if env_path.exists():
        lines = [
            line
            for line in env_path.read_text(encoding="utf-8").splitlines()
            if not line.strip().startswith(f"{key}=")
        ]
    lines.append(f"{key}={value}")
    # Write privately: the file holds the master key. 0o600 on POSIX;
    # best effort on Windows (no POSIX mode there).
    tmp_path = env_path.with_name(env_path.name + ".tmp")
    tmp_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp_path, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    os.replace(tmp_path, env_path)


def _validate_master_key(key_hex: str) -> bytes:
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise InvalidKeyError(f"{MASTER_KEY_ENV} is not valid hexadecimal.") from exc
    if len(key) != MASTER_KEY_BYTES:
        raise InvalidKeyError(
            f"{MASTER_KEY_ENV} must be {MASTER_KEY_BYTES} bytes "
            f"({MASTER_KEY_BYTES * 2} hex chars), got {len(key)} bytes."
        )
    return key


class KeyManager:
    """Loads the master key from the environment/.env, creating it on first use."""

    def __init__(self, env_path=DEFAULT_ENV_PATH, master_key_hex=None):
        self._env_path = Path(env_path)
        if master_key_hex is not None:
            self._master_key = _validate_master_key(master_key_hex)
            return
        self._master_key = self._load_or_create()

    @property
    def master_key(self) -> bytes:
        return self._master_key

    def _load_or_create(self) -> bytes:
        # 1) Process environment wins (12-factor style). Deliberately not written
        #    back to os.environ: doing so would leak this key into any other
        #    KeyManager sharing the process and defeat per-path isolation.
        from_env = os.getenv(MASTER_KEY_ENV)
        if from_env:
            return _validate_master_key(from_env.strip())
        # 2) Persisted key from .env.
        stored = _read_env_value(self._env_path, MASTER_KEY_ENV)
        if stored:
            return _validate_master_key(stored)
        # 3) First run: generate once and persist. Never regenerated afterwards.
        key = secrets.token_bytes(MASTER_KEY_BYTES)
        _write_env_value(self._env_path, MASTER_KEY_ENV, key.hex())
        return key


def _extract(master_key: bytes, nonce: bytes) -> bytes:
    """RFC 5869 HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    extract = hmac.HMAC(nonce, hashes.SHA256())
    extract.update(master_key)
    return extract.finalize()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < length:
        if counter > 255:
            raise ValueError("derivation length exceeds HKDF-Expand limit")
        block = hmac.HMAC(prk, hashes.SHA256())
        block.update(prev + info + bytes([counter]))
        prev = block.finalize()
        out.extend(prev)
        counter += 1
    return bytes(out[:length])


def derive_stream(master_key: bytes, nonce: bytes, info: bytes, length: int) -> bytes:
    """Derive `length` bytes of key material bound to (master_key, nonce, info).

    The master secret is extracted once with the nonce as salt, then expanded in
    chunks so arbitrarily long streams (files) are supported.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    if length == 0:
        return b""
    prk = _extract(master_key, nonce)
    out = bytearray()
    chunk = 0
    while len(out) < length:
        remaining = length - len(out)
        block_info = info + b"/" + chunk.to_bytes(4, "big")
        out.extend(_expand(prk, block_info, min(_MAX_EXPAND, remaining)))
        chunk += 1
        if chunk > 1_000_000:
            raise ValueError("derivation length is unreasonably large")
    return bytes(out)
