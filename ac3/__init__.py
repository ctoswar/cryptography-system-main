"""AC3-X (v4) — the thesis five-layer pipeline with an AES-256-CTR engine.

Public surface:
    AC3Cipher       — low-level classic cipher (AC3X text + AC3X3/4 streams)
    SIVTextCipher   — nonce-misuse-resistant mode (AC3S, RFC 5297)
    SessionCipher   — X25519 recipient-keyed mode (AC3E, RFC 7748)
    CMainController — application facade (strings, files, mode routing)
    exceptions      — AC3Error hierarchy
"""

from .core import AC3Cipher, VERSION
from .controller import CMainController
from .exceptions import (
    AC3Error,
    EnvelopeError,
    IntegrityError,
    InvalidKeyError,
)
from .session import SessionCipher
from .siv import SIVTextCipher

__all__ = [
    "AC3Cipher",
    "SIVTextCipher",
    "SessionCipher",
    "CMainController",
    "VERSION",
    "AC3Error",
    "EnvelopeError",
    "IntegrityError",
    "InvalidKeyError",
]
