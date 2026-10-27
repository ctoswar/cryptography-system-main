# AC3-X Specification — Version 3

**Status:** stable · **Supersedes:** AC3 v2 (`AC3v2.`, `AC3V2`) — clean break, no backward compatibility

AC3-X is a hybrid authenticated-encryption scheme: the five-layer AC3 thesis
pipeline with its XOR keystream engine replaced by **AES-256-CTR**, composed
with **HMAC-SHA256** in the provably-secure encrypt-then-MAC order.

## 1. Standard primitives and security claims

| Primitive | Reference | Role |
|---|---|---|
| AES-256-CTR | NIST SP 800-38A | confidentiality (both XOR passes) |
| HMAC-SHA256 | FIPS 198-1, RFC 2104 | integrity & authenticity |
| HKDF-SHA256 | RFC 5869 | all subkeys from (master key, nonce) |
| Encrypt-then-MAC | Bellare–Namprempre 2000 | composition order (provably secure) |

**What AC3-X claims:** confidentiality and integrity anchored entirely in the
standard primitives above, given (a) a secret 256-bit master key, (b) a unique
16-byte nonce per message, and (c) an unmodified implementation.

**What AC3-X does not claim:** the Caesar/transposition layers add *no*
provable cryptographic strength. They are retained for architectural
continuity with the thesis and act as keyed structural whitening. Any security
analysis should treat AC3-X as AES-CTR + HMAC with additional keyed
transforms. It is not a replacement for an audited AEAD (AES-GCM,
ChaCha20-Poly1305) in adversarial production settings.

**Nonce rule (critical):** every message MUST use a fresh random 16-byte
nonce. Nonce reuse under the same master key reuses CTR keystreams and is
catastrophic. The `seal_deterministic`/fixed-nonce paths exist only for
conformance testing.

## 2. Key schedule

All subkeys derive from the 32-byte master key `MK` and the 16-byte message
nonce `N` via HKDF-SHA256 (RFC 5869):

```
PRK = HMAC-SHA256(salt = N, ikm = MK)              # HKDF-Extract
subkey(label, len) = HKDF-Expand(PRK, "ac3x/v3/" || label, len)
```

| Subkey | Label (`ac3x/v3/…`) | Size | Use |
|---|---|---|---|
| `shift` | `l2-shift` | 1 B | Caesar shift = (byte mod 255) + 1 → 1..255, never 0 |
| `K3` | `l3-ctr-key` | 32 B | AES-256 key for the L3 XOR pass |
| `IV3(i)` | `l3-ctr-iv/` + i(u64 BE) | 16 B | L3 counter block for chunk *i* |
| `cols` | `l4-columns` | 8 B | Fisher-Yates seed for the column order |
| `K5` | `l5-ctr-key` | 32 B | AES-256 key for the L5 XOR pass |
| `IV5(i)` | `l5-ctr-iv/` + i(u64 BE) | 16 B | L5 counter block for chunk *i* |
| `Km` | `mac` | 32 B | HMAC-SHA256 key |

Counter blocks are derived per (layer, chunk index), so no (key, counter)
pair ever repeats within a message or across messages (nonce uniqueness).

## 3. The five layers (per chunk of input `P`)

```
L2  Caesar         C2 = P.translate(table(shift))            table(s)[b] = (b+s) mod 256
L3  XOR (AES-CTR)  C3 = AES-CTR-Encrypt(K3, IV3(i), C2)      ≡ C2 XOR AES keystream
L4  Transposition  C4 = column-gather(C3, order)             8 columns, keyed order
L5  XOR (AES-CTR)  C5 = AES-CTR-Encrypt(K5, IV5(i), C4)      ≡ C4 XOR AES keystream
```

All transforms are length-preserving. Decryption is the exact inverse in
reverse order (CTR is symmetric; the transposition inverse is a keyed
scatter; Caesar inverts with `-shift`).

## 4. Text envelope (one-shot)

```
AC3X.<nonce_b64url>.<body_b64url>.<tag_b64url>
```

- Components are unpadded base64url, separated by `.`; decoders MUST reject
  characters outside the base64url alphabet and non-canonical encodings.
- `nonce` is exactly 16 bytes; `tag` is exactly 32 bytes.

Encryption of plaintext string `m` (UTF-8 encoded → `P`):

```
1. N   = random 16 bytes
2. framed = 0x03 || len(P) as u32 BE || P          # L1 framing, version 3
3. body = five layers applied to framed            # chunk index i = 0
4. tag  = HMAC-SHA256(Km, 0x03 || N || body)       # encrypt-then-MAC
```

Decryption verifies the tag **before** any decryption (constant-time compare),
then inverts the layers and checks the framed version byte and declared
length. Tampering with any region — nonce, body, or tag — raises an integrity
error; no malleability and no plaintext release.

## 5. Stream envelope (files, arbitrary size)

```
header   = "AC3X3\x01" || N(16) || chunk_size(u32 BE)          # 26 bytes
frames   = [ flag(1) || len(u32 BE) || C5_chunk ] …            # one per chunk
trailer  = stream_tag(32)
```

- Chunks are read in order; all non-final frames carry exactly `chunk_size`
  payload bytes (`flag = 0x00`); the final frame carries 0..chunk_size
  (`flag = 0x01`). Empty input is a single zero-length final frame.
- Chunk *i* is processed by the five layers with counter blocks `IV3(i)`,
  `IV5(i)` (no per-chunk L1 framing — the frame header is the framing).

The running MAC covers the complete transcript:

```
mac = HMAC-SHA256(Km)
mac.update(header)
for each frame: mac.update(flag || len || C5_chunk)
stream_tag = mac.finalize()
```

This single construction defeats every structural attack:

| Attack | Why it fails |
|---|---|
| Bit flip anywhere | MAC covers header + every frame byte |
| Truncation | final tag missing, or stream ends on a `flag=0` frame |
| Chunk reordering | MAC is order-sensitive over the frame sequence |
| Splicing across files | header (nonce) is MACed; foreign frames never verify |
| Flag/length manipulation | flag and length are inside the MAC input |
| Trailing data | decryptor rejects any byte after the final tag |

**Streaming decrypt note:** plaintext chunks are produced before the final
tag verifies (inherent to streaming MACs). Implementations MUST stage output
and commit it only after the tag verifies — the reference controller writes
to a sibling temp file and `os.replace`s it into place on success, so a
failed decrypt leaves no partial plaintext and never truncates an existing
target.

## 6. Conformance test vectors

Master key (32 B):
```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```
Nonce (16 B), used in all vectors below:
```
00112233445566778899aabbccddeeff
```

### Vector 1 — text, plaintext `AC3-X`

```
AC3X.ABEiM0RVZneImaq7zN3u_w.NLJQGzsbXKAeIA.jowNTmk6xpfjYF8ZkNxcV-5JGA4f2FJj9vA4-T_j498
```

### Vector 2 — text, empty plaintext

```
AC3X.ABEiM0RVZneImaq7zN3u_w.NLlQp-Q.CEF9AE1nMc-I5dIdcXWZ10Jvc0Bd22l_XUm6XeKJ8qI
```

### Vector 3 — stream, plaintext `AC3-X hybrid vector payload`, chunk_size = 8

```
41433358330100112233445566778899aabbccddeeff00000008000000000867c1156eea42df29
0000000008429a2e403827922c00000000084532c2f68d3369b801000000031f97af7920884500
10e69e9591e28b3277701d28d8f77075fc9f5dd831e22bdeb0b493
```

(A cross-implementation is conformant iff it reproduces these outputs
byte-for-byte and rejects every tampered variant. The reference test suite
asserts exactly this in `tests/test_hybrid.py`.)

## 7. Changes from v2

| Aspect | v2 | v3 (AC3-X) |
|---|---|---|
| Keystream source | HKDF-Expand output | AES-256-CTR under HKDF subkeys |
| Text prefix | `AC3v2.` | `AC3X.` |
| Binary format | one-shot magic `AC3V2\x01` | chunked stream `AC3X3\x01` + running MAC |
| MAC | HMAC over version\|\|nonce\|\|body | same (text) + full stream transcript (files) |
| File memory | whole file in RAM | constant (~one chunk) |
| Throughput | ~3.7 MB/s | ~150–200 MB/s (AES-NI) |
| Legacy decrypt | — | rejected with an explicit re-encrypt error |
