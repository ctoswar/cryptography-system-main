"""Session mode — RFC 9180 HPKE key agreement with the AC3-X pipeline.

Why this mode exists (v4 weakness W-3): the classic envelope derives every
key from ONE long-term master secret, which must be shared out-of-band and
whose compromise reveals all history. Session mode moves the master key out
of the confidentiality path entirely:

    1. sender runs HPKE SetupBaseS (RFC 9180) against the recipient's
       published static X25519 public key
       (suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD)
    2. session master = HPKE exporter ("ac3x/v5/session-master", 32)
    3. the plaintext is sealed by the standard AC3-X pipeline under that
       session master (identical five layers, identical primitives)
    4. the ephemeral secret is discarded; only the holder of the
       recipient's static X25519 key can run SetupBaseR and re-derive it

Envelope (v5 profile):

    AC3E.<enc>.<nonce>.<body>.<mac>[.<keyid>]

    mac = inner HMAC tag (32) || bind tag (16)

    bind = HMAC-SHA256(HMAC-SHA256(master, "ac3x/v5/session-bind"),
                       enc ‖ recipient_pk)[:16]

The bind tag authenticates the handshake with the (symmetric) master key,
blocking forged envelopes and MITM substitution in the shared-master
deployment. The keyid names the master that produced the bind so rotation
never orphans sessions. The v4 session shape (with a salt field, 7 parts)
is still accepted for decrypt — see `_decrypt_v4`.

HONEST SECURITY SCOPE (mirrored in SECURITY.md):

    * This is **key separation and public-key encryption**, **not strict
      forward secrecy**. An ECIES-style handshake against a static
      recipient key does not survive later compromise of that static key:
      a holder of (master, X25519 static key, envelope) can recompute the
      session key. True FS requires a symmetric ratchet whose past keys are
      destroyed — which conflicts with this design's founding principle of
      permanent decryptability. That trade-off is documented as future work.
    * The HPKE construction itself is RFC 9180-conformant (verified against
      the Appendix A.7.1 vectors); the master-bind authentication and the
      AC3-X inner pipeline are this project's additions, layered per
      encrypt-then-MAC discipline.
    * The ephemeral secret is discarded after encryption; CPython cannot
      guarantee memory zeroization.
"""

import secrets

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import hpke
from .core import AC3Cipher
from .envelope import SESSION_PREFIX, decode_session, encode_text
from .exceptions import AC3Error, EnvelopeError, IntegrityError, InvalidKeyError
from .keys import key_id

_NONCE_SIZE = 16
_BIND_SIZE = 16
_INFO_HPKE = b"ac3x/v5"
_EXPORT_LABEL = b"ac3x/v5/session-master"
_BIND_INFO = b"ac3x/v5/session-bind"


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def _bind(master: bytes, enc: bytes, recipient_pk: bytes) -> bytes:
    bind_key = _hmac_sha256(master, _BIND_INFO)
    return _hmac_sha256(bind_key, enc + recipient_pk)[:_BIND_SIZE]


class SessionCipher:
    """HPKE-keyed variant of the AC3-X pipeline.

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

        # HPKE base-mode setup: the ephemeral keypair is generated inside
        # SetupBaseS and discarded with this stack frame (CPython cannot
        # guarantee memory zeroization — documented limitation).
        enc, ctx, _eph_sk = hpke.setup_base_s(recipient_pub, _INFO_HPKE)
        session_master = ctx.export(_EXPORT_LABEL, 32)

        inner = AC3Cipher(session_master)
        nonce = secrets.token_bytes(_NONCE_SIZE)
        body, tag = inner._seal(text.encode("utf-8"), nonce)
        mac_field = tag + _bind(self._master, enc, recipient_pub)
        return encode_text(
            [enc, nonce, body, mac_field, key_id(self._master)],
            prefix=SESSION_PREFIX,
        )

    def decrypt(self, token: str) -> str:
        parsed = decode_session(token)
        if parsed["profile"] == "v5":
            return self._decrypt_v5(parsed)
        return self._decrypt_v4(parsed)

    # -- v5 (HPKE) --------------------------------------------------------------

    def _decrypt_v5(self, parsed: dict) -> str:
        enc, nonce, body, mac_field, key_id_value = (
            parsed["enc"], parsed["nonce"], parsed["body"],
            parsed["mac"], parsed["key_id"],
        )
        master = self._resolve(key_id_value)
        own_pub = self._keys.x25519_public_key()

        # Authenticate the handshake BEFORE any decryption work.
        expected_bind = _bind(master, enc, own_pub)
        provided_bind = mac_field[32:]  # mac = inner tag(32) || bind(16)
        if not constant_time.bytes_eq(expected_bind, provided_bind):
            raise IntegrityError(
                "Session handshake authentication failed: this envelope was "
                "not produced under the deployed master key."
            )

        own_sk = self._keys.x25519_private_key()
        ctx = hpke.setup_base_r(enc, own_sk, _INFO_HPKE)
        session_master = ctx.export(_EXPORT_LABEL, 32)
        inner = AC3Cipher(session_master)
        try:
            plain = inner._open(nonce, body, mac_field[:32])
        except InvalidTag as exc:
            raise IntegrityError(
                "Integrity check failed: ciphertext was modified or the key is wrong."
            ) from exc
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EnvelopeError(
                "Decrypted plaintext is not valid UTF-8."
            ) from exc

    # -- v4 (pre-HPKE) fallback ---------------------------------------------------

    def _decrypt_v4(self, parsed: dict) -> str:
        """Session envelopes minted between v4.0 and the HPKE upgrade
        (salt-based key schedule). Retained decrypt-only."""
        eph_pk, salt, nonce, body, mac_field, key_id_value = (
            parsed["enc"], parsed["salt"], parsed["nonce"], parsed["body"],
            parsed["mac"], parsed["key_id"],
        )
        master = self._resolve(key_id_value)
        own_pub = self._keys.x25519_public_key()
        bind_key = derive_stream_v4_bind(master, salt)
        verifier = hmac.HMAC(bind_key, hashes.SHA256())
        verifier.update(eph_pk + own_pub + salt)
        digest = verifier.finalize()
        if not constant_time.bytes_eq(digest[:16], mac_field[32:]):
            raise IntegrityError(
                "Session handshake authentication failed: this envelope was "
                "not produced under the deployed master key."
            )
        own_sk = X25519PrivateKey.from_private_bytes(self._keys.x25519_private_key())
        shared = own_sk.exchange(X25519PublicKey.from_public_bytes(eph_pk))
        session_master = derive_stream_v4_session(shared, salt)
        inner = AC3Cipher(session_master)
        try:
            plain = inner._open(nonce, body, mac_field[:32])
        except InvalidTag as exc:
            raise IntegrityError(
                "Integrity check failed: ciphertext was modified or the key is wrong."
            ) from exc
        try:
            return plain.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EnvelopeError(
                "Decrypted plaintext is not valid UTF-8."
            ) from exc


def derive_stream_v4_bind(master: bytes, salt: bytes) -> bytes:
    """v4 bind key derivation (kept byte-identical for decrypt fallback)."""
    from .keys import derive_stream

    return derive_stream(master, salt, b"ac3x/v4/session-bind", 32)


def derive_stream_v4_session(shared: bytes, salt: bytes) -> bytes:
    from .keys import derive_stream

    return derive_stream(shared, salt, b"ac3x/v4/session", 32)


__all__ = ["SessionCipher", "SESSION_PREFIX"]
