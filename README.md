# AC3 v2 — Layered Encryption with Integrity

A hardened rebuild of the **"AC3 level 5 Encryption Algorithm with Caesar Cipher and XOR Cipher"** thesis (STI College Bacoor, December 2023) — keeping the five-layer identity of the original design while fixing the cryptographic and engineering flaws of v1.

**Thesis researchers:** Miguel Florencio F. Agapay · Duncan John D. Carpiso · Carlo R. Cobey · Leonavelle Camatog

## What changed from v1 (and why)

| v1 problem | v2 fix |
|---|---|
| Five stacked XOR passes with static keys collapse to **one** XOR (k1⊕k2⊕…⊕k5) | Every layer key is derived per message via **HKDF-SHA256**(master key, random nonce) — no two messages share key material |
| No integrity checking — tampered ciphertext decrypted to garbage | **HMAC-SHA256** tag over version + nonce + body, verified in constant time before any decryption |
| Keys regenerated on every boot *and* after every decrypt → old ciphertexts permanently undecryptable | Master key generated **once**, persisted, never rotated (regression-tested) |
| `.env` corrupted by key rotation (duplicate/merged lines) | Single `AC3_MASTER_KEY`, atomic read-modify-write, validated on load |
| Caesar shift was ASCII-only (32–127) → Unicode silently destroyed | All layers operate on **bytes**; full UTF-8 round-trip (ñ, emoji, CJK, RTL) |
| `decrypt()` crashed with `NameError` (`d_text_six` undefined) | Clean pipeline, no undefined references — 68 tests prove round-trips |
| `/encrypt` returned a `bytearray` Flask can't serialize → HTTP 500 | Versioned, JSON-safe text envelope: `AC3v2.<nonce>.<body>.<tag>` |
| Plaintext written to `project_logs.log` | Logging records only sizes and outcome classes — never contents |
| `debug=True` on `0.0.0.0` | `debug=False`, binds `127.0.0.1` by default |
| Levels 2–8 were copy-paste duplicates; 6–8 never wired in | One pipeline class; layers are distinct operations |

## The five layers

```
plaintext (UTF-8 bytes)
   │
   ├─ L1  Framing          version byte + uint32 length + payload
   ├─ L2  Byte Caesar      keyed additive shift mod 256 (binary-safe)
   ├─ L3  XOR stream       XOR with message-unique keystream
   ├─ L4  Transposition    keyed column shuffle (8 columns, Fisher-Yates)
   └─ L5  XOR + HMAC       final XOR pass, then HMAC-SHA256 tag
   │
   ▼
AC3v2.<nonce>.<body>.<tag>        (binary envelope for files)
```

- **Nonce:** 16 random bytes per message — same plaintext never yields the same ciphertext.
- **Subkeys:** derived from `(master key, nonce)` with distinct HKDF info labels per layer.
- **Integrity:** tampering with *any* part of the envelope (nonce, body, or tag) or using the wrong key → `IntegrityError`, never silent garbage.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows:  source .venv/bin/activate elsewhere
pip install -r requirements.txt
```

The first run auto-creates `AC3_MASTER_KEY` in `.env` (already git-ignored). Keep it secret — anyone with the key can decrypt everything.

## Usage

### Web UI + API

```bash
python app.py
# open http://127.0.0.1:8080
```

| Endpoint | Body | Returns |
|---|---|---|
| `POST /encrypt` | `{"message": "..."}` | `{"ciphertext": "AC3v2...."}` |
| `POST /decrypt` | `{"ciphertext": "AC3v2...."}` | `{"plaintext": "..."}` |
| `POST /encrypt-file` | multipart `file` | downloadable `*.ac3` |
| `POST /decrypt-file` | multipart `file` | decrypted download |
| `GET /health` | — | `{"status": "ok", "version": 2}` |

Uploads are capped at 64 MB. Invalid or tampered input returns `400` with a reason — never a stack trace.

### CLI

```bash
python cli.py encrypt "secret message"
python cli.py decrypt "AC3v2...."
echo "from a pipe" | python cli.py encrypt -
python cli.py encrypt-file report.pdf            # -> report.pdf.ac3
python cli.py decrypt-file report.pdf.ac3        # -> report.pdf (refuses to overwrite differing files)
python cli.py keygen                             # create the master key if missing
```

### Library

```python
from ac3 import AC3Cipher, CMainController

token = AC3Cipher().encrypt("hello ñ")       # auto-loads .env key
plain = AC3Cipher().decrypt(token)

CMainController().encrypt_file("notes.txt")  # -> notes.txt.ac3
```

## Tests

```bash
python -m pytest tests/ -q        # 68 passed
```

Coverage highlights: ASCII/Unicode/emoji/empty/long round-trips, all-byte-value binary round-trips, tamper detection for every envelope region, wrong-key rejection, key stability across "restarts" (the v1 regression), file round-trips, API contract tests, clobber protection, and a log-leak test asserting plaintext never reaches the log.

## Honest security assessment

This project is an **educational artifact** and portfolio piece — not a drop-in replacement for vetted cryptography.

**What v2 genuinely provides:**
- Confidentiality well beyond the classical ciphers it layers (unique per-message keystreams, keyed transposition)
- Tamper *detection* (HMAC-SHA256) — modified ciphertext is rejected, not mis-decrypted
- Proper key hygiene: one stable random 256-bit master key, per-message nonce, HKDF separation between layers

**What it is not:**
- It is **not** AES-GCM, ChaCha20-Poly1305, or any vetted/constant-time-optimized AEAD. The layer construction is homegrown; the primitives (SHA-256/HMAC/HKDF) are standard, but the *scheme* around them has not been peer-reviewed or formally verified.
- It does not provide authenticated key exchange, forward secrecy, or protection against a full compromise of the `.env` file.
- Throughput (~1 MB per 0.3 s) is fine for text and small files, not for high-volume data.

**For production data, use `cryptography`'s `Fernet` or `AESGCM` directly.** The value of AC3 v2 is showing how a thesis-era classical design can be systematically hardened — measured, tested, and honestly documented.

## Project layout

```
ac3/                 the library
  core.py            five-layer pipeline + envelopes
  keys.py            master key management + HKDF derivation
  envelope.py        text/binary ciphertext formats
  controller.py      app facade (strings, files)
  exceptions.py      AC3Error hierarchy
app.py               Flask API + web UI server
templates/index.html single-page web UI (no build step)
cli.py               command-line interface
tests/               pytest suite (68 tests)
requirements.txt
AC3 level 5 ... .pdf the original thesis
```
