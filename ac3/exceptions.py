"""Exception hierarchy for AC3 v2."""


class AC3Error(Exception):
    """Base class for every AC3 error."""


class EnvelopeError(AC3Error):
    """The ciphertext envelope is malformed, truncated, or not AC3 v2."""


class IntegrityError(AC3Error):
    """The HMAC tag did not verify: ciphertext was tampered with or the key is wrong."""


class InvalidKeyError(AC3Error):
    """The master key is missing or malformed."""


class InvalidAlgorithmError(AC3Error):
    """An unknown encryption algorithm was requested."""
