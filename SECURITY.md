# Security Policy

## What this project is

AC3-X (v3) is an **educational / portfolio** encryption system: the thesis-era
five-layer pipeline (framing → byte Caesar → XOR → transposition → XOR + HMAC)
with its XOR keystream engine replaced by **AES-256-CTR** (NIST SP 800-38A) and
integrity provided by **HMAC-SHA256** (FIPS 198-1) in encrypt-then-MAC order.
All subkeys derive via HKDF-SHA256 (RFC 5869). The full construction, key
schedule, and conformance vectors are specified in [`SPEC.md`](SPEC.md).

**Honest characterization:** AC3-X does not add provable strength over plain
AES-CTR + HMAC — the Caesar/transposition layers are keyed structural
whitening kept for continuity with the thesis. The scheme has **not** been
independently audited.

**For adversarial production data, call `cryptography`'s `Fernet` / `AESGCM`
directly.** AC3-X is an educational artifact.

## Supported versions

| Version | Supported |
|---------|-----------|
| 3.x (AC3-X) | ✅ all fixes land here |
| 2.x (`AC3v2.` / `AC3V2`) | ❌ removed — clean break; legacy envelopes are rejected with a re-encrypt error |
| interim AES envelopes (`AC3A.` / `AC3AES`) | ❌ removed |
| 1.x | ❌ removed — v1 had known design flaws (see README) |

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

- The layered construction wraps standard primitives but is **not** a vetted
  AEAD and has not been peer-reviewed; treat AC3-X as AES-CTR + HMAC with
  extra keyed transforms.
- **Nonce reuse is catastrophic** (CTR keystream reuse). The implementation
  generates a fresh random 16-byte nonce per message; fixed-nonce paths exist
  solely for conformance vectors and must never be used on real data.
- No forward secrecy; compromise of the `.env` master key reveals all data
  encrypted under it.
- No authenticated key exchange; the master key must be distributed out of band.
- Streaming decrypt produces plaintext chunks before the final stream tag
  verifies (inherent to streaming MACs). The reference implementation stages
  output and commits it atomically only after the tag verifies.

## What the stream format defends against

The running HMAC covers the header (including the nonce) and every frame
(flag, length, payload), so all of the following fail authentication and are
regression-tested: bit flips anywhere, truncation, chunk reordering,
splicing frames across files, flag/length forgery, and trailing data after
the final tag.

## Secret handling

- The master key lives in `.env` as `AC3_MASTER_KEY` and is **git-ignored**.
- Never commit `.env`, ciphertext samples containing real data, or logs with
  message contents (`project_logs.log` is ignored too).
- Application logs record only sizes and outcome classes — never plaintext.
