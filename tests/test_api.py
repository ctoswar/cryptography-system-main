"""Flask API tests using the test client (no server needed)."""

import io

import pytest

from app import app
from ac3 import CMainController


# The Flask test client fixture now lives in conftest.py (shared with
# test_security.py) and points the app at an isolated key store.


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_index_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"AC3" in res.data


def test_encrypt_decrypt_roundtrip(client):
    res = client.post("/encrypt", json={"message": "hello thesis 👋"})
    assert res.status_code == 200
    token = res.get_json()["ciphertext"]
    assert token.startswith("AC3F.")  # FIPS is the default mode

    res = client.post("/decrypt", json={"ciphertext": token})
    assert res.status_code == 200
    assert res.get_json()["plaintext"] == "hello thesis 👋"


def test_encrypt_requires_json(client):
    res = client.post("/encrypt", data="message=hi", content_type="text/plain")
    assert res.status_code == 415


def test_encrypt_missing_message(client):
    assert client.post("/encrypt", json={}).status_code == 400
    assert client.post("/encrypt", json={"message": ""}).status_code == 400
    assert client.post("/encrypt", json={"message": 123}).status_code == 400


def test_decrypt_missing_ciphertext(client):
    assert client.post("/decrypt", json={}).status_code == 400


def test_decrypt_rejects_garbage(client):
    res = client.post("/decrypt", json={"ciphertext": "not a real ciphertext"})
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_decrypt_rejects_tampered(client):
    token = client.post("/encrypt", json={"message": "payload"}).get_json()[
        "ciphertext"
    ]
    prefix, nonce, body, tag = token.split(".", 3)
    flipped = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1]
    tampered = "AC3X." + ".".join([nonce, flipped, tag])
    res = client.post("/decrypt", json={"ciphertext": tampered})
    # Either the MAC catches it (400) or base64 differs — must never be 200 with wrong text.
    assert res.status_code == 400


def test_file_encrypt_decrypt_roundtrip(client):
    payload = bytes(range(256)) * 8 + b"\x00binary\xff"
    res = client.post(
        "/encrypt-file",
        data={"file": (io.BytesIO(payload), "doc.bin")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    disposition = res.headers["Content-Disposition"]
    assert "attachment" in disposition
    assert "doc.bin.ac3" in disposition  # quoted or bare, depending on Werkzeug
    blob = res.data
    assert blob != payload

    res = client.post(
        "/decrypt-file",
        data={"file": (io.BytesIO(blob), "doc.bin.ac3")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    assert res.data == payload
    assert "doc.bin" in res.headers["Content-Disposition"]


def test_file_encrypt_empty_rejected(client):
    res = client.post(
        "/encrypt-file",
        data={"file": (io.BytesIO(b""), "empty.txt")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400


def test_file_decrypt_non_ciphertext_rejected(client):
    res = client.post(
        "/decrypt-file",
        data={"file": (io.BytesIO(b"just a text file"), "plain.txt")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400


def test_file_decrypt_missing_field(client):
    res = client.post("/decrypt-file", data={}, content_type="multipart/form-data")
    assert res.status_code == 400


def test_api_does_not_log_message_contents(client, caplog):
    import logging

    secret = "SUPER-SECRET-VALUE-123"
    with caplog.at_level(logging.DEBUG):
        client.post("/encrypt", json={"message": secret})
        # decrypt too — capture log records from app logger only
        token = client.post(
            "/encrypt", json={"message": "unrelated"}
        ).get_json()["ciphertext"]
        client.post("/decrypt", json={"ciphertext": token})
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert secret not in joined
