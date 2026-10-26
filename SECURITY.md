# Security Policy

## What this project is

AC3 v2 is an **educational / portfolio** encryption system: a hardened rebuild of
a thesis-era five-layer algorithm (framing → byte Caesar → XOR → transposition →
HMAC-SHA256). The primitives (SHA-256, HMAC, HKDF) are standard, but the layered
*scheme* around them has **not** been peer-reviewed or formally verified.

It also ships a **standard AES-256-GCM mode** (see below) for high-volume data.

**For real production data, use the AES mode — or call `cryptography`'s
`Fernet` / `AESGCM` directly.** Do not rely on the AC3 five-layer mode to
protect production data; it is an educational artifact.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ all fixes land here |
| 1.x     | ❌ removed — v1 had known design flaws (see README) |

## Reporting a vulnerability

Please **do not** open a public issue for security reports. Instead:

- Use GitHub's private reporting: **Security → Report a vulnerability** on this
  repository, or
- Email the maintainer via the address on the repo owner's profile.

You can expect an acknowledgement within a few days. A valid report includes:

- the affected file/endpoint,
- reproduction steps or a proof of concept,
- impact (what an attacker gains).

### Known, accepted limitations (not bugs)

These are documented on purpose and are not considered vulnerabilities:

- **AC3 mode** uses a homegrown layered construction — not a vetted AEAD;
  educational use only.
- No forward secrecy; compromise of the `.env` master key reveals all data
  encrypted under it (both modes).
- AC3-mode throughput (~1 MB / 0.3 s) is unsuitable for high-volume data —
  use the AES mode for that.
- **AES mode** uses the standard AES-256-GCM primitive but wraps it in a
  custom chunk-streamed envelope for large files (each chunk is individually
  GCM-authenticated and position-bound); the framing is not independently
  peer-reviewed.

## AES-256-GCM mode

The `aes` algorithm is AES-256-GCM via `cryptography`'s `AESGCM` — a standard,
widely reviewed AEAD — with the same HKDF-derived key material (domain-separated
from the AC3 layers). It streams large files in constant memory (~400–500 MB/s).
Its chunk-streaming framing is homegrown but binds every chunk to its index via
nonce + AAD, so reordering, truncation, and cross-file splicing fail
authentication. Prefer this mode for real data.

## Secret handling

- The master key lives in `.env` as `AC3_MASTER_KEY` and is **git-ignored**.
- Never commit `.env`, ciphertext samples containing real data, or logs with
  message contents (`project_logs.log` is ignored too).
- Application logs record only sizes and outcome classes — never plaintext.
