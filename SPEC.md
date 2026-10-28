# AC3-X Specification — Version 4

**Status:** stable · **Supersedes:** AC3 v2 (`AC3v2.`, `AC3V2`) — clean break, no backward compatibility. v4 is an **additive** revision: every v3 format parses exactly as before, and new modes/key-ID fields are optional extensions.

**Standards position:** AC3-X *composes* standard primitives in a provably
secure pattern (encrypt-then-MAC) with formal vector-verified specifications
— but as a custom construction without independent review it does **not**
claim parity with a FIPS-standard primitive. The comparative study and the
full annotated bibliography live in docs/REFERENCES.md.

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
nonce `N` via HKDF-SHA256 (RFC 5869). **The text and stream protocols use
disjoint label namespaces** (`ac3x/v3/text/…` vs `ac3x/v3/stream/…`), so no
key material is ever shared across protocols even if a nonce were reused
between them:

```
PRK = HMAC-SHA256(salt = N, ikm = MK)              # HKDF-Extract
subkey(label, len) = HKDF-Expand(PRK, "ac3x/v3/" || D || "/" || label, len)
```

where `D` = `text` for the one-shot text envelope and `stream` for the
chunked stream envelope.

| Subkey | Label (`ac3x/v3/<D>/…`) | Size | Use |
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
AC3X.ABEiM0RVZneImaq7zN3u_w.9TPrCObvpumVeQ.Q7U1gtd5xx6HggcZEWy69k4ubwj-AY1EkFEFl9_Je9Q
```

### Vector 2 — text, empty plaintext

```
AC3X.ABEiM0RVZneImaq7zN3u_w.HPKtceE.KjTQlfFhYF9ldHFdAM9hFBBuI3Rhd3jkNMaOEr8r3Ws
```

### Vector 3 — stream, plaintext `AC3-X hybrid vector payload`, chunk_size = 8

```
41433358330100112233445566778899aabbccddeeff00000008000000000884479d6de69f121f
0000000008f6d2032b063f38b000000000081ce4f663705f7b380100000003c9687cd75f72b4f25
3c3ccd2500c334478ced2a6087751c37400f0613774e809a613f4
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

## 8. v4 additions — key rotation, SIV, sessions

### 8.1 Key IDs and rotation (weakness: rotation previously unsupported)

Every v4 envelope ends with an optional **key ID** field: a 4-byte identifier
derived as `HMAC-SHA256(master_key, "ac3x/v4/key-id")[:4]`. It names the
long-term key that protected the envelope, so **rotation never orphans
data** (the flaw that destroyed v1's history).

- `AC3X.<nonce>.<body>.<tag>.<keyid>` — classic with key ID
- Stream magic `AC3X4\x01`: header = magic ‖ keyid(4) ‖ nonce(16) ‖ chunk_size(4)
  (the legacy `AC3X3` header remains valid and is resolved via
  active-then-archive fallback)
- The `.env` archive: rotating moves the active key to
  `AC3_MASTER_KEY_V{n}` and generates a fresh `AC3_MASTER_KEY`. Decryption
  resolves the envelope's key ID against the active key first, then the
  archive. Unknown IDs raise a distinct `EnvelopeError` — key-management
  errors are separated from tampering errors (`IntegrityError`).
- Tokens WITHOUT a key ID (the §6 conformance vectors) resolve
  active-then-archive; the HMAC decides.

### 8.2 SIV mode — nonce-misuse resistance (weakness: catastrophic nonce reuse)

New envelope family `AC3S.<nonce12>.<siv_output>[.<keyid>]` per **RFC 5297**
(AES-SIV-CMAC-512 via a 64-byte HKDF-derived key):

```
key    = HKDF-SHA256(master, salt = nonce12, info = "ac3x/v4/siv/key", 64)
output = AES-SIV-CMAC-512(key).encrypt(plaintext, ads = [b"ac3x/v4/siv", nonce12])
```

`output` = 16-byte synthetic IV ‖ ciphertext. Security semantics:

| Event | Classic CTR (`AC3X`) | SIV (`AC3S`) |
|---|---|---|
| Nonce reused, same message | keystream reuse — catastrophic | identical ciphertext (equality leaks only) |
| Nonce reused, different messages | plaintext XOR recovery — catastrophic | confidential, authenticated, independent-looking |
| Tampering | `IntegrityError` | `IntegrityError` |

Trade-offs: SIV ciphertext is deterministic under (key, nonce, message), and
the mode is one-shot (the chunked streaming format is classic-only in v4).

### 8.3 Session mode — HPKE key agreement (RFC 9180)

New envelope family `AC3E.<enc>.<nonce>.<body>.<mac>[.<keyid>]`, built on the
**HPKE suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD**
(kem_id 0x0020, kdf_id 0x0001, aead_id 0xFFFF — RFC 9180 Appendix A.7), the
RFC's registered suite for applications that derive their own keys:

```
enc, ctx          = HPKE-SetupBaseS(recipient_pub, info = "ac3x/v5")
session_master    = ctx.Export("ac3x/v5/session-master", 32)     # §5.3 exporter
inner             = the §3/§4 classic pipeline under session_master
bind              = HMAC-SHA256(HMAC-SHA256(master, "ac3x/v5/session-bind"),
                                enc || recipient_pk)[:16]
mac               = inner_tag(32) || bind(16)
```

The recipient verifies the bind (constant-time) before decrypting: the
handshake is authenticated by the symmetric master key, blocking forged
envelopes and MITM substitution in the shared-master deployment. Pre-HPKE
(v4 salt-based) session envelopes remain decryptable via a legacy fallback.

**Conformance:** the HPKE implementation is verified byte-for-byte against
the RFC 9180 **Appendix A.7.1** published vectors (key derivation,
encapsulation shared secret, key schedule, exporter secret, and all three
exported values) — `tests/test_hpke.py`. This is an IETF-vector conformance
claim, not a self-assessment.

**Honest security scope — read before citing:**

- This is **key separation and public-key encryption**, **not strict forward
  secrecy**. An ECIES-style handshake against a static recipient key does not
  survive later compromise of that static key: a holder of (master, X25519
  static key, envelope) can recompute the session key.
- True forward secrecy requires a symmetric ratchet that destroys past keys —
  which directly conflicts with this design's founding principle of permanent
  decryptability. That trade-off is documented, not hidden.
- The ephemeral secret is discarded after encryption; CPython cannot
  guarantee memory zeroization.
- Cross-party *authentication* (signatures instead of the symmetric bind) is
  future work; the bind presumes the shared master of the symmetric deployment.

### 8.3.1 Key commitment

Key commitment (Bellare & Hoang 2022, ePrint 2022/268) asks: can one
ciphertext verify under two different keys? For the classic envelope the tag
is `HMAC-SHA256(Km, ...)` where `Km` is determined by the master key through
HKDF — producing a token valid under two chosen masters requires an
HMAC-SHA256 collision (about 2^128 work), so the classic envelope **is
key-committing up to generic HMAC security**. The session mode additionally
binds the envelope to the master via the handshake bind tag. This matters
because non-committing AEAD enables partitioning-oracle attacks (NDSS 2022)
— the analysis here closes that question for AC3-X's layers.

### 8.4 Performance characteristics (why the measured ceiling is honest)

The classic pipeline performs ~5 full-buffer passes per byte (Caesar
translate, AES-CTR, column gather + join, AES-CTR, HMAC). On CPython +
OpenSSL this lands at **161–242 MB/s** (see
`evaluation/results/benchmarks.json`) — CPU- and memory-bandwidth-bound, not
algorithmically improvable without changing the layer structure or adding
parallelism (chunk transforms are independent; the stream MAC is sequential —
parallel execution is a documented future direction, not implemented).
Latency for small messages (~0.11 ms p50) is dominated by the per-message
HKDF schedule and two CTR context setups. SIV mode adds one CMAC pass;
session mode adds one X25519 operation plus one HKDF per message.

## 9. FIPS mode (v5) - the production layer

New envelope families `AC3F.<nonce12>.<output>[.<keyid>]` (text) and the
`AC3F1` chunked stream (files), with **zero custom cryptographic
construction**: every cryptographic operation is a FIPS-approved algorithm in
a NIST-specified mode.

```
text    key    = HKDF-SHA256(master, salt = nonce12, info = "ac3x/fips/v1/key", 32)
        output = AES-256-GCM(key, nonce12, aad = "AC3F" || keyid)
        AC3F.<nonce12>.<output>[.<keyid>]

stream  header = "AC3F1" || keyid(4) || salt(16) || nonce_prefix(8) || chunk_size(4)
        per chunk: nonce = nonce_prefix(8) || counter(4); aad = header || index(8) || flag
        sealed = AES-256-GCM(stream_key, nonce, aad, chunk)
        stream_key = HKDF-SHA256(master, salt, "ac3x/fips/v1/stream", 32)
```

| Component | FIPS/NIST status |
|---|---|
| AES-256-GCM | AES per FIPS 197; GCM per NIST SP 800-38D |
| HKDF-SHA256 | NIST SP 800-56C Rev 2 |
| HMAC-SHA256 (key IDs) | FIPS 198-1 |
| Envelope framing | non-cryptographic metadata |

**Approved is not validated (must be stated).** FIPS 140-3 validation is a
CMVP certification of a specific implementation - no Python library
qualifies. The precise claim: *uses FIPS-approved algorithms in
NIST-specified modes, structured so a future module validation of the
primitive layer would cover all cryptographic operations.*

**Documented trade-off - key commitment.** GCM is not key-committing
(Bellare & Hoang 2022, ePrint 2022/268; NDSS 2022 partitioning-oracle
literature). Classic and SIV modes retain commitment; the FIPS mode trades
it for maximal algorithmic standardness. SP 800-38D bounds are satisfied:
per-message/per-stream HKDF-derived keys mean each GCM key encrypts exactly
one message (or one stream with a 96-bit nonce space).

**AAD binding:** the key ID is inside the GCM AAD - keyid substitution (even
for a key the deployment knows) fails authentication. Chunk AADs bind the
full header plus chunk index and flag, so reordering, truncation, splicing,
flag flips, and trailing data all fail.

**Performance:** GCM fuses authentication into the encryption pass (GHASH,
hardware-accelerated) - one pass instead of the classic five. Measured:
387 MB/s encrypt, 532 MB/s decrypt on the reference environment (100 MB
file, constant ~13 MB memory) - about 2.5x the classic pipeline.

**Mode position:** FIPS mode is the production/default layer. The classic
five-layer pipeline (`AC3X`) remains unchanged as the explicitly-labeled
custom construction - the thesis identity whose security argument is
educational, sitting beside a core whose every operation is citable.
