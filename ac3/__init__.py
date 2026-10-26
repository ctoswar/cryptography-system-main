"""AC3 v2 — hardened multi-layer encryption, successor to the AC3 thesis algorithm.

Public surface:
    AC3Cipher      — low-level cipher (bytes in/out, text or binary envelopes)
    CMainController — application facade (strings, files)
    exceptions     — AC3Error hierarchy
"""

from .core import AC3Cipher, VERSION
from .controller import CMainController
from .exceptions import AC3Error, EnvelopeError, IntegrityError, InvalidKeyError

__all__ = [
    "AC3Cipher",
    "CMainController",
    "VERSION",
    "AC3Error",
    "EnvelopeError",
    "IntegrityError",
    "InvalidKeyError",
]
