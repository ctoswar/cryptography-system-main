"""Security regression tests — each test locks in a red-team finding.

Findings (2026-10 audit):
  A1  CORS wildcard             -> CORS off unless explicitly configured
  A2  missing security headers  -> after_request header set
  A5  XSS via download filename -> header sanitization + DOM-only UI (JS)
  A8/9 unbounded CPU            -> text size cap + rate limit
  A12 path-ish filename         -> basename-only download names
  ENV non-canonical base64      -> strict alphabet + canonical round-trip
  ENV .env permissions          -> 0600 on POSIX where supported
"""

import io
import json
import os
import stat
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import AC3Cipher, EnvelopeError
from ac3.envelope import _b64d, _b64e
from ac3.keys import MASTER_KEY_ENV, KeyManager


# --------------------------------------------------------------------------
# A1 — CORS must be off by default
# --------------------------------------------------------------------------

def test_no_cors_wildcard_by_default(client):
    res = client.get("/health")
    assert "Access-Control-Allow-Origin" not in res.headers, (
        "CORS header present without AC3_ALLOWED_ORIGINS — "
        "any origin could drive this API"
    )


def test_cors_rejects_foreign_origin_by_default(client):
    res = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in res.headers


# --------------------------------------------------------------------------
# A2 — security headers on every response
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/health", "/encrypt"])
def test_security_headers_present(client, path):
    if path == "/encrypt":
        res = client.post(path, json={"message": "x"})
    else:
        res = client.get(path)
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"
    assert res.headers.get("Cache-Control") == "no-store"
    assert "default-src 'none'" in res.headers.get("Content-Security-Policy", "")


def test_csp_with_nonce_on_page(client):
    res = client.get("/")
    csp = res.headers.get("Content-Security-Policy", "")
    assert "nonce-" in csp
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp
    # the rendered script tag must carry the same nonce value
    nonce = csp.split("script-src '")[1].split("'")[0].removeprefix("nonce-")
    assert f'nonce="{nonce}"' in res.get_data(as_text=True)


def test_error_responses_also_hardened(client):
    res = client.post("/decrypt", json={"ciphertext": "garbage"})
    assert res.status_code == 400
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("Cache-Control") == "no-store"


# --------------------------------------------------------------------------
# A5/A12 — filename hygiene at the header boundary
# --------------------------------------------------------------------------

def _post_file(client, route, filename, payload=b"data"):
    return client.post(
        route,
        data={"file": (io.BytesIO(payload), filename)},
        content_type="multipart/form-data",
    )


def test_download_name_is_basename_only(client):
    res = _post_file(client, "/encrypt-file", "../../../etc/passwd")
    cd = res.headers.get("Content-Disposition", "")
    assert "passwd" in cd
    assert ".." not in cd and "/" not in cd.split("filename=")[-1]


def test_download_name_has_no_control_chars(client):
    res = _post_file(client, "/encrypt-file", "evil\r\nX-Injected: 1.txt")
    cd = res.headers.get("Content-Disposition", "")
    assert "\r" not in cd and "\n" not in cd
    assert "X-Injected" not in cd.replace("filename=", "")


def test_ui_never_puts_filename_in_innerhtml():
    """The template must not build download UI via innerHTML (XSS sink)."""
    html = (Path(__file__).resolve().parent.parent / "templates" / "index.html").read_text(
        encoding="utf-8"
    )
    # innerHTML anywhere with a template-literal = the old bug
    assert ".innerHTML =" not in html.replace("document.body", "")
    assert "textContent" in html  # sanitised sink is in use


# --------------------------------------------------------------------------
# A8/A9 — resource limits
# --------------------------------------------------------------------------

def test_oversized_message_rejected(client, monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "MAX_TEXT_BYTES", 100)
    res = client.post("/encrypt", json={"message": "A" * 200})
    assert res.status_code == 413
    assert "error" in res.get_json()


def test_rate_limit_triggers_429(client, monkeypatch):
    import app as app_module

    # TESTING disables the limiter (keeps other tests fast) — turn it on here.
    monkeypatch.setattr(app_module, "RATE_LIMIT_PER_MIN", 3)
    monkeypatch.setattr(app_module, "_rate_buckets", {})
    app_module.app.config["TESTING"] = False
    try:
        statuses = [
            client.post("/encrypt", json={"message": f"m{i}"}).status_code
            for i in range(6)
        ]
    finally:
        app_module.app.config["TESTING"] = True
    assert statuses[:3] == [200, 200, 200]
    assert 429 in statuses[3:], f"rate limit never fired: {statuses}"


def test_json_body_must_be_object(client):
    res = client.post("/encrypt", json=["not", "an", "object"])
    assert res.status_code in (400, 415)


# --------------------------------------------------------------------------
# AC3-X single-mode API surface
# --------------------------------------------------------------------------

def test_encrypt_produces_ac3x_envelope(client):
    res = client.post("/encrypt", json={"message": "hybrid path"})
    assert res.status_code == 200
    assert res.get_json()["ciphertext"].startswith("AC3X.")


def test_algorithm_field_is_ignored(client):
    """v3 has one algorithm; a stale client sending 'algorithm' still succeeds."""
    res = client.post("/encrypt", json={"message": "x", "algorithm": "aes"})
    assert res.status_code == 200
    assert res.get_json()["ciphertext"].startswith("AC3X.")


def test_tampered_token_rejected(client):
    tok = client.post("/encrypt", json={"message": "tamper"}).get_json()["ciphertext"]
    prefix, nonce, body, tag = tok.split(".", 3)
    bad = "AC3X." + ".".join([nonce, ("A" if body[0] != "A" else "B") + body[1:], tag])
    res = client.post("/decrypt", json={"ciphertext": bad})
    assert res.status_code == 400


def test_legacy_text_envelopes_rejected(client):
    for legacy in ("AC3v2.aaaa.bbbb.cccc", "AC3A.aaaa.bbbb.cccc"):
        res = client.post("/decrypt", json={"ciphertext": legacy})
        assert res.status_code == 400
        assert "re-encrypt" in res.get_json()["error"].lower()


def test_file_stream_roundtrip(client):
    payload = b"AC3-X file payload " * 400
    res = client.post(
        "/encrypt-file",
        data={"file": (io.BytesIO(payload), "doc.bin")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    blob = res.get_data()
    assert blob[:6] == b"AC3X4\x01"
    back = client.post(
        "/decrypt-file",
        data={"file": (io.BytesIO(blob), "doc.bin.ac3")},
        content_type="multipart/form-data",
    )
    assert back.status_code == 200 and back.get_data() == payload


def test_file_rejects_legacy_and_garbage(client):
    for blob in (b"AC3V2\x01garbage", b"AC3AES\x01garbage", b"not a ciphertext"):
        res = client.post(
            "/decrypt-file",
            data={"file": (io.BytesIO(blob), "old.ac3")},
            content_type="multipart/form-data",
        )
        assert res.status_code == 400


# --------------------------------------------------------------------------
# Envelope canonicalisation (token-string malleability)
# --------------------------------------------------------------------------

def test_junk_characters_in_body_rejected():
    key = b"\x11" * 32
    c = AC3Cipher(key)
    nonce_b, body_b, tag_b = c.encrypt("m").split(".", 3)[1:]
    # Python's b64decode would silently discard "!" — we must not accept that
    malleated = f"AC3X.{nonce_b}.{body_b[:-2]}!!{body_b[-2:]}.{tag_b}"
    with pytest.raises(EnvelopeError):
        _b64d(malleated.split(".", 3)[2], "Body")


def test_nonstandard_b64_alphabet_rejected():
    # '+' and '/' are standard base64, not base64url
    with pytest.raises(EnvelopeError):
        _b64d("abc+def/ghi", "Body")


def test_noncanonical_padding_bits_rejected():
    # "AB" and "AA" both decode (with different pad bits) to b'\x00'
    # canonical re-encoding of AA-decoded is "AA"; "AB" must be rejected
    if _b64e(_b64d("AA", "x")) == "AB":  # pragma: no cover
        pytest.skip("decoder unexpectedly canonical")
    with pytest.raises(EnvelopeError):
        _b64d("AB", "x")


def test_valid_tokens_still_roundtrip_after_strictness(cipher):
    for text in ["", "hello", "ünï 🔐", "a" * 1000]:
        assert cipher.decrypt(cipher.encrypt(text)) == text


# --------------------------------------------------------------------------
# Key file permissions (best-effort: POSIX only)
# --------------------------------------------------------------------------

def test_env_file_private_permissions(env_dir, monkeypatch):
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    env_path = env_dir / ".env"
    KeyManager(env_path=env_path)
    if os.name == "posix":
        mode = stat.S_IMODE(env_path.stat().st_mode)
        assert mode & 0o077 == 0, f".env readable by group/other: {oct(mode)}"


def test_env_write_is_atomic_no_tmp_left(env_dir, monkeypatch):
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    env_path = env_dir / ".env"
    KeyManager(env_path=env_path)
    leftovers = list(env_dir.glob("*.tmp"))
    assert not leftovers, f"temp file left behind: {leftovers}"
