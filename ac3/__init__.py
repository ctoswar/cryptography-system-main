"""AC3-X (v3) — the thesis five-layer pipeline with an AES-256-CTR engine.

Public surface:
    AC3Cipher       — low-level cipher (text envelope + chunked stream format)
    CMainController — application facade (strings, files)
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

__all__ = [
    "AC3Cipher",
    "CMainController",
    "VERSION",
    "AC3Error",
    "EnvelopeError",
    "IntegrityError",
    "InvalidKeyError",
]
