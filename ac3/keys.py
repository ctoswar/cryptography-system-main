"""Master key management and subkey derivation for AC3-X (v4).

Design decisions (differences from AC3 v1):

  * The master key is generated ONCE and persisted. It is never rotated on boot
    or after decryption, so previously encrypted data stays decryptable.
  * All layer keys are derived per message from (master key, random nonce)
    using HKDF-SHA256, so every message uses unique, independent subkeys.
    This addresses the v1 weakness where 5 stacked XOR passes with static keys
    collapsed mathematically into a single XOR.
  * v4 key rotation: the active key can be retired via :meth:`KeyManager.rotate`,
    which moves it into an in-`.env` archive (``AC3_MASTER_KEY_V{n}``) and
    generates a fresh active key. Envelopes carry a 4-byte key ID derived from
    the encrypting key, so data encrypted under a retired key remains
    decryptable — rotation never orphans history (the flaw that destroyed
    v1's data does not exist here).
  * v4 sessions: a static X25519 keypair (``AC3_X25519_SK``) is provisioned
    alongside the master key for the session envelope's ECDH handshake.
"""

import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .exceptions import InvalidKeyError

MASTER_KEY_ENV = "AC3_MASTER_KEY"
ARCHIVE_PREFIX = "AC3_MASTER_KEY_V"
X25519_SK_ENV = "AC3_X25519_SK"
MASTER_KEY_BYTES = 32
DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# HKDF-Expand output ceiling for a single expansion (255 * SHA256 size).
_MAX_EXPAND = 255 * 32

_KEY_ID_BYTES = 4


def key_id(master_key: bytes) -> bytes:
    """Deterministic 4-byte identifier for a master key.

    Envelopes carry this ID so decryption can locate the right key in the
    archive after rotation. Derived via HMAC so the ID reveals nothing about
    the key itself.
    """
    mac = hmac.HMAC(master_key, hashes.SHA256())
    mac.update(b"ac3x/v4/key-id")
    return mac.finalize()[:_KEY_ID_BYTES]


def _read_env_values(env_path: Path) -> dict:
    """All KEY=VALUE pairs in the .env (preserving order)."""
    values = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if "=" in stripped and not stripped.startswith("#"):
                name, _, value = stripped.partition("=")
                values[name.strip()] = value.strip()
    return values


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


def resolve_master_key(key_source) -> bytes:
    """Normalize a key source (KeyManager | bytes | None) to a 32-byte key.

    Shared by AC3Cipher and AESGCMCipher so both accept the same inputs.
    """
    if isinstance(key_source, KeyManager):
        return key_source.master_key
    if isinstance(key_source, (bytes, bytearray)):
        master = bytes(key_source)
        if len(master) != MASTER_KEY_BYTES:
            raise InvalidKeyError(
                f"Master key must be {MASTER_KEY_BYTES} bytes, got {len(master)}."
            )
        return master
    if key_source is None:
        return KeyManager().master_key
    raise TypeError(
        "key_source must be a KeyManager, bytes, or None; "
        f"got {type(key_source).__name__}."
    )


class KeyManager:
    """Loads the master key from the environment/.env, creating it on first use.

    v4 additions: the key archive (retired keys), rotation, key-ID lookup,
    and static X25519 provisioning for the session envelope.
    """

    def __init__(self, env_path=DEFAULT_ENV_PATH, master_key_hex=None):
        self._env_path = Path(env_path)
        self._raw_source = master_key_hex is not None
        if master_key_hex is not None:
            self._master_key = _validate_master_key(master_key_hex)
            return
        self._master_key = self._load_or_create()

    @property
    def master_key(self) -> bytes:
        return self._master_key

    @property
    def manages_archive(self) -> bool:
        """True when this manager can resolve archived keys (env-backed)."""
        return not self._raw_source

    # -- v4: key IDs and the archive ---------------------------------------

    def all_keys(self) -> dict:
        """Active key + every archived key, keyed by their 4-byte IDs."""
        keys = {key_id(self._master_key): self._master_key}
        if self.manages_archive:
            values = _read_env_values(self._env_path)
            for name, value in values.items():
                if name.startswith(ARCHIVE_PREFIX):
                    try:
                        archived = _validate_master_key(value)
                    except InvalidKeyError:
                        continue  # skip corrupt archive entries, never crash
                    keys.setdefault(key_id(archived), archived)
        return keys

    def lookup_by_key_id(self, wanted: bytes):
        """Resolve a 4-byte envelope key ID to key bytes, or None."""
        if not isinstance(wanted, (bytes, bytearray)) or len(wanted) != _KEY_ID_BYTES:
            return None
        return self.all_keys().get(bytes(wanted))

    def rotate(self) -> dict:
        """Retire the active key into the archive and generate a fresh one.

        The old key is kept under ``AC3_MASTER_KEY_V{n}`` so every ciphertext
        encrypted under it stays decryptable — v1's orphaning flaw cannot
        occur here. Returns a summary of the transition.
        """
        if self._raw_source:
            raise InvalidKeyError(
                "rotate() requires an env-backed KeyManager; this instance "
                "was constructed from a raw key."
            )
        old_key = self._master_key
        old_id = key_id(old_key)
        existing = _read_env_values(self._env_path)
        versions = [
            int(name[len(ARCHIVE_PREFIX):])
            for name in existing
            if name.startswith(ARCHIVE_PREFIX) and name[len(ARCHIVE_PREFIX):].isdigit()
        ]
        next_version = (max(versions) + 1) if versions else 1
        _write_env_value(self._env_path, f"{ARCHIVE_PREFIX}{next_version}", old_key.hex())
        new_key = secrets.token_bytes(MASTER_KEY_BYTES)
        _write_env_value(self._env_path, MASTER_KEY_ENV, new_key.hex())
        self._master_key = new_key
        return {
            "archived_as": f"{ARCHIVE_PREFIX}{next_version}",
            "old_key_id": old_id,
            "new_key_id": key_id(new_key),
        }

    # -- v4: static X25519 for the session envelope --------------------------

    def x25519_private_key(self) -> bytes:
        """The static X25519 private key (provisioned on first use)."""
        if self._raw_source:
            raise InvalidKeyError(
                "session mode requires an env-backed KeyManager to provision "
                "the static X25519 keypair."
            )
        stored = _read_env_value(self._env_path, X25519_SK_ENV)
        if stored:
            return _validate_master_key(stored)  # same 32-byte hex validation
        sk = X25519PrivateKey.generate()
        raw = sk.private_bytes_raw()
        _write_env_value(self._env_path, X25519_SK_ENV, raw.hex())
        return raw

    def x25519_public_key(self) -> bytes:
        """The public key matching this deployment's static X25519 key."""
        sk = X25519PrivateKey.from_private_bytes(self.x25519_private_key())
        return sk.public_key().public_bytes_raw()

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
