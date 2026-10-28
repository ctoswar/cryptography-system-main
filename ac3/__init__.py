"""AC3-X (v5) — the thesis pipeline beside a FIPS-grade AES-256-GCM core.

Public surface:
    FIPSCipher      — FIPS-grade production mode (AC3F, AES-256-GCM)
    AC3Cipher       — classic thesis pipeline (AC3X text + AC3X3/4 streams)
    SIVTextCipher   — nonce-misuse-resistant mode (AC3S, RFC 5297)
    SessionCipher   — X25519/HPKE recipient-keyed mode (AC3E, RFC 7748/9180)
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
from .fips import FIPSCipher
from .session import SessionCipher
from .siv import SIVTextCipher

__all__ = [
    "AC3Cipher",
    "FIPSCipher",
    "SIVTextCipher",
    "SessionCipher",
    "CMainController",
    "VERSION",
    "AC3Error",
    "EnvelopeError",
    "IntegrityError",
    "InvalidKeyError",
]
