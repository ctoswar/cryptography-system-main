# Security Policy

## What this project is

AC3 v2 is an **educational / portfolio** encryption system: a hardened rebuild of
a thesis-era five-layer algorithm (framing → byte Caesar → XOR → transposition →
HMAC-SHA256). The primitives (SHA-256, HMAC, HKDF) are standard, but the layered
*scheme* around them has **not** been peer-reviewed or formally verified.

**Do not use AC3 v2 to protect real production data.** For that, use
`cryptography`'s `Fernet` or `AESGCM` directly.

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

- Homegrown layered construction — not a vetted AEAD; educational use only.
- No forward secrecy; compromise of the `.env` master key reveals all data
  encrypted under it.
- Throughput (~1 MB / 0.3 s) is unsuitable for high-volume data.

## Secret handling

- The master key lives in `.env` as `AC3_MASTER_KEY` and is **git-ignored**.
- Never commit `.env`, ciphertext samples containing real data, or logs with
  message contents (`project_logs.log` is ignored too).
- Application logs record only sizes and outcome classes — never plaintext.
