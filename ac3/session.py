"""Session mode — X25519 key agreement with the AC3-X pipeline.

Why this mode exists (v4 weakness W-3): the classic envelope derives every
key from ONE long-term master secret, which must be shared out-of-band and
whose compromise reveals all history. Session mode moves the master key out
of the confidentiality path entirely:

    1. sender generates a fresh X25519 ephemeral keypair per message
    2. shared secret = X25519(ephemeral_sk, recipient_static_pk)
    3. session master = HKDF-SHA256(shared, salt, "ac3x/v4/session")
    4. plaintext is sealed by the standard AC3-X pipeline under that
       session master (identical five layers, identical primitives)
    5. the ephemeral secret is discarded; only the recipient's static
       X25519 key can recompute it

Envelope:

    AC3E.<eph_pk>.<salt>.<nonce>.<body>.<mac>[.<keyid>]

    mac = HMAC-SHA256 tag (32) || bind tag (16)

    bind = HMAC-SHA256(bind_key, eph_pk || recipient_pk || salt)[:16]
    bind_key = HKDF-SHA256(master, salt, "ac3x/v4/session-bind")

The bind tag authenticates the handshake with the (symmetric) master key,
blocking forged-envelope and MITM substitutions in deployments where both
parties hold the master. The keyid names the master that produced the bind
so rotation never orphans sessions.

HONEST SECURITY SCOPE (mirrored in SECURITY.md):

    * This is NOT strict forward secrecy. An ECIES-style handshake against a
      static recipient key does not survive later compromise of that static
      key: an attacker holding both long-term secrets and this envelope can
      recompute the session key. What it delivers is key separation (two
      independent long-term secrets must be compromised together) and
      public-key encryption (no shared secret needed for confidentiality).
    * True forward secrecy requires a symmetric ratchet whose past keys are
      destroyed — which conflicts with this design's founding principle of
      permanent decryptability. That trade-off is documented as future work.
    * The ephemeral secret is discarded after encryption; CPython cannot
      guarantee memory zeroization.
    * Cross-party authentication (signing the handshake instead of the
      symmetric bind) is future work; the bind tag presumes the shared
      master of the symmetric deployment.
"""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .core import AC3Cipher
from .envelope import SESSION_PREFIX, decode_session, encode_text
from .exceptions import AC3Error, EnvelopeError, IntegrityError, InvalidKeyError
from .keys import derive_stream, key_id

_SALT_SIZE = 32
_INFO_SESSION = b"ac3x/v4/session"
_INFO_BIND = b"ac3x/v4/session-bind"
_BIND_SIZE = 16


class SessionCipher:
    """X25519-keyed variant of the AC3-X pipeline.

    Requires an env-backed :class:`~ac3.keys.KeyManager` (the static X25519
    keypair is provisioned there and the master authenticates the handshake).
    """

    def __init__(self, master, keys):
        self._master = master
        self._keys = keys
        if keys is None or not getattr(keys, "manages_archive", False):
            raise InvalidKeyError(
                "session mode requires an env-backed KeyManager (it provisions "
                "the static X25519 keypair and resolves rotated keys)."
            )

    # -- handshake helpers ---------------------------------------------------

    def _session_master(self, shared_secret: bytes, salt: bytes) -> bytes:
        return derive_stream(shared_secret, salt, _INFO_SESSION, 32)

    def _bind(self, master: bytes, eph_pk: bytes, recipient_pk: bytes, salt: bytes) -> bytes:
        bind_key = derive_stream(master, salt, _INFO_BIND, 32)
        mac = hmac.HMAC(bind_key, hashes.SHA256())
        mac.update(eph_pk + recipient_pk + salt)
        return mac.finalize()[:_BIND_SIZE]

    def _resolve(self, key_id_value) -> bytes:
        if key_id_value == key_id(self._master):
            return self._master
        found = self._keys.lookup_by_key_id(key_id_value)
        if found is not None:
            return found
        raise EnvelopeError(
            "Encrypted with an unknown key version: the key that produced "
            "this ciphertext is neither the active key nor in the archive."
        )

    # -- API -------------------------------------------------------------------

    def encrypt(self, text: str, recipient_pub: bytes) -> str:
        """Seal `text` to the holder of `recipient_pub` (32-byte X25519 key).

        For self-encryption pass the deployment's own public key
        (:meth:`ac3.keys.KeyManager.x25519_public_key`).
        """
        if not isinstance(text, str):
            raise TypeError(f"encrypt() expects str, got {type(text).__name__}.")
        if not isinstance(recipient_pub, (bytes, bytearray)) or len(recipient_pub) != 32:
            raise AC3Error("recipient_pub must be a 32-byte X25519 public key.")
        recipient_pub = bytes(recipient_pub)

        ephemeral = X25519PrivateKey.generate()
        eph_pk = ephemeral.public_key().public_bytes_raw()
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
        salt = secrets.token_bytes(_SALT_SIZE)
        session_master = self._session_master(shared, salt)
        # The ephemeral secret is discarded with this stack frame; CPython
        # cannot guarantee memory zeroization (documented limitation).

        inner = AC3Cipher(session_master)
        nonce = secrets.token_bytes(16)
        body, tag = inner._seal(text.encode("utf-8"), nonce)
        mac_field = tag + self._bind(self._master, eph_pk, recipient_pub, salt)
        return encode_text(
            [eph_pk, salt, nonce, body, mac_field, key_id(self._master)],
            prefix=SESSION_PREFIX,
        )

    def decrypt(self, token: str) -> str:
        eph_pk, salt, nonce, body, mac_field, key_id_value = decode_session(token)
        master = self._resolve(key_id_value)
        own_pub = self._keys.x25519_public_key()

        # Authenticate the handshake BEFORE any decryption work.
        bind_key = derive_stream(master, salt, _INFO_BIND, 32)
        verifier = hmac.HMAC(bind_key, hashes.SHA256())
        verifier.update(eph_pk + own_pub + salt)
        # The bind tag is the digest TRUNCATED to 16 bytes, so cryptography's
        # HMAC.verify() (which compares the full digest) would always fail on
        # length. Compare the truncated digest in constant time instead.
        digest = verifier.finalize()
        if not constant_time.bytes_eq(digest[:_BIND_SIZE], mac_field[32:]):
            raise IntegrityError(
                "Session handshake authentication failed: this envelope was "
                "not produced under the deployed master key."
            )

        own_sk = X25519PrivateKey.from_private_bytes(self._keys.x25519_private_key())
        shared = own_sk.exchange(X25519PublicKey.from_public_bytes(eph_pk))
        session_master = self._session_master(shared, salt)
        inner = AC3Cipher(session_master)
        try:
            plain = inner._open(nonce, body, mac_field[:32])
        except InvalidTag as exc:  # defensive: AESSIV-style parity
            raise IntegrityError(
                "Integrity check failed: ciphertext was modified or the key is wrong."
            ) from exc
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EnvelopeError(
                "Decrypted plaintext is not valid UTF-8."
            ) from exc


__all__ = ["SessionCipher", "SESSION_PREFIX"]
