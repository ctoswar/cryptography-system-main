"""RFC 9180 conformance tests — byte-exact against the published A.7.1 vectors.

RFC 9180 Appendix A.7 defines the suite AC3-X's session mode uses:
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD. These tests
reproduce the RFC's Base Setup vectors (including the three exported
values) from the published input key material — proof that our HPKE
implementation is IETF-conformant, not self-assessed.

Source: RFC 9180, Appendix A.7.1 (https://www.rfc-editor.org/rfc/rfc9180).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import hpke

# --- RFC 9180 A.7.1 Base Setup Information (verbatim) ----------------------

INFO = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
IKM_E = bytes.fromhex("55bc245ee4efda25d38f2d54d5bb6665291b99f8108a8c4b686c2b14893ea5d9")
PK_EM = bytes.fromhex("e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918")
SK_EM = bytes.fromhex("095182b502f1f91f63ba584c7c3ec473d617b8b4c2cec3fad5af7fa6748165ed")
IKM_R = bytes.fromhex("683ae0da1d22181e74ed2e503ebf82840deb1d5e872cade20f4b458d99783e31")
PK_RM = bytes.fromhex("194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664")
SK_RM = bytes.fromhex("33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848")
ENC = bytes.fromhex("e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918")
SHARED_SECRET = bytes.fromhex(
    "e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66")
KEY_SCHEDULE_CONTEXT = bytes.fromhex(
    "009bd09219212a8cf27c6bb5d54998c5240793a70ca0a892234bd5e082bc619b6"
    "a3f4c22aa6d9a0424c2b4292fdf43b8257df93c2f6adbf6ddc9c64fee26bdd292")
SECRET = bytes.fromhex("04d64e0620aa047e9ab833b0ebcd4ff026cefbe44338fd7d1a93548102ee01af")
EXPORTER_SECRET = bytes.fromhex(
    "79dc8e0509cf4a3364ca027e5a0138235281611ca910e435e8ed58167c72f79b")

# A.7.1.1 Exported Values (context, expected L=32 output)
EXPORTED = [
    (b"", "7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36"),
    (b"\x00", "d5535b87099c6c3ce80dc112a2671c6ec8e811a2f284f948cec6dd1708ee33f0"),
    (b"TestContext", "ffaabc85a776136ca0c378e5d084c9140ab552b78f039d2e8775f26efff4c70e"),
]


def test_derive_key_pair_matches_rfc():
    sk, pk = hpke.derive_key_pair(IKM_E)
    assert sk == SK_EM
    assert pk == PK_EM
    sk_r, pk_r = hpke.derive_key_pair(IKM_R)
    assert sk_r == SK_RM
    assert pk_r == PK_RM


def test_setup_base_s_matches_rfc_vectors():
    enc, ctx, _sk = hpke.setup_base_s(PK_RM, INFO, ephemeral_ikm=IKM_E)
    assert enc == ENC
    assert ctx.key_schedule_context == KEY_SCHEDULE_CONTEXT
    assert ctx.secret == SECRET
    assert ctx.key == b""       # Export-Only suite: Nk = 0
    assert ctx.base_nonce == b""
    assert ctx.exporter_secret == EXPORTER_SECRET


def test_exported_values_match_rfc():
    _, ctx, _ = hpke.setup_base_s(PK_RM, INFO, ephemeral_ikm=IKM_E)
    for exporter_context, expected_hex in EXPORTED:
        assert ctx.export(exporter_context, 32) == bytes.fromhex(expected_hex)


def test_setup_base_r_reaches_same_context():
    """Receiver side (holder of skRm) derives the identical context."""
    ctx_r = hpke.setup_base_r(ENC, SK_RM, INFO)
    assert ctx_r.key_schedule_context == KEY_SCHEDULE_CONTEXT
    assert ctx_r.exporter_secret == EXPORTER_SECRET
    for exporter_context, expected_hex in EXPORTED:
        assert ctx_r.export(exporter_context, 32) == bytes.fromhex(expected_hex)


def test_sender_receiver_exporters_interoperate():
    """The property session mode relies on: sender Export == receiver Export."""
    _, ctx_s, _ = hpke.setup_base_s(PK_RM, INFO, ephemeral_ikm=IKM_E)
    ctx_r = hpke.setup_base_r(ENC, SK_RM, INFO)
    assert ctx_s.export(b"ac3x/v5/session-master", 32) == \
        ctx_r.export(b"ac3x/v5/session-master", 32)


def test_different_export_contexts_diverge():
    _, ctx, _ = hpke.setup_base_s(PK_RM, INFO, ephemeral_ikm=IKM_E)
    values = {ctx.export(ctx_e, 32) for ctx_e, _ in EXPORTED}
    assert len(values) == 3
