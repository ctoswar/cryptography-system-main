# Annotated Bibliography & Standards Position

Every design decision in AC3-X is anchored to a citable source. Each entry
below states **what it is**, **which design decision it supports**, and
**which thesis chapter it feeds**. Regenerate nothing here by hand — this
file is the bridge between the repository and the written thesis.

---

## 1. Composition and provable security (the strongest claims)

| # | Source | Supports |
|---|---|---|
| 1.1 | M. Bellare, C. Namprempre. *Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm.* ASIACRYPT 2000. https://eprint.iacr.org/2000/025 | **Encrypt-then-MAC is the provably secure composition order.** AC3-X's HMAC tag covers the ciphertext (never the reverse order) — Ch. 3 Methodology, Ch. 5 Discussion |
| 1.2 | H. Krawczyk. *Cryptographic Extraction and Key Derivation: The HKDF Scheme.* CRYPTO 2010. https://eprint.iacr.org/2010/264 — spec: RFC 5869, https://datatracker.ietf.org/doc/html/rfc5869 | **All subkeys derive via HKDF-SHA256** from (master, nonce) with distinct info labels and per-protocol domain separation — Ch. 3 |
| 1.3 | M. Bellare, T. Kohno, C. Namprempre. *Breaking and provably repairing the SSH authenticated encryption scheme.* ACM CCS 2002. https://dl.acm.org/doi/10.1145/948109.948140 | **The SSH case study**: a deployed protocol with exactly this class of framing/MAC-order flaw, *provably repaired*. Mirrors the AC3 v1→v2→v3 arc — Ch. 2 Related Work, Ch. 5 |
| 1.4 | RFC 8446 (TLS 1.3), https://datatracker.ietf.org/doc/html/rfc8446 — with its symbolic analyses (e.g., Cremers et al., Tamarin-proved TLS 1.3) | The deployment benchmark for AEAD-based protocols; also the model for what formal protocol verification looks like — Ch. 2, future work |

## 2. Misuse resistance (the SIV mode)

| # | Source | Supports |
|---|---|---|
| 2.1 | P. Rogaway, T. Shrimpton. *Deterministic Authenticated-Encryption: A Provable-Security Treatment of the Key-Wrap Problem.* EUROCRYPT 2006 / ePrint 2006/221. https://eprint.iacr.org/2006/221 | **The SIV paper**: nonce-misuse-resistant AEAD, where reuse degrades to determinism (equality leaks only) — the exact property `AC3S` provides — Ch. 3, Ch. 5 |
| 2.2 | RFC 5297, *Synthetic Initialization Vector (SIV) Authenticated Encryption* — https://datatracker.ietf.org/doc/html/rfc5297 | The RFC `AC3S` implements via `cryptography`'s `AESSIV` — Ch. 3 |
| 2.3 | CAESAR competition final portfolio (incl. Deoxys-II, AEGIS — misuse-resistant AEAD): https://competitions.cr.yp.to/caesar.html | The field-wide context for misuse resistance — Ch. 2 |

## 3. Session key agreement (what the session mode is measured against)

| # | Source | Supports |
|---|---|---|
| 3.1 | **RFC 9180, Hybrid Public Key Encryption (HPKE)** — R. Barnes, K. Bhargavan, B. Lipp, C. A. Wood. https://datatracker.ietf.org/doc/html/rfc9180 | **THE standard for the session mode.** `ac3/hpke.py` implements DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, Export-Only AEAD (aead_id 0xFFFF — RFC Appendix A.7) and derives the session master through the §5.3 exporter. **Verified byte-for-byte against the A.7.1 published vectors** (`tests/test_hpke.py`) — Ch. 3, Ch. 4 |
| 3.2 | RFC 7748, *Elliptic Curves for Security* (X25519) — https://datatracker.ietf.org/doc/html/rfc7748 | The curve underneath the KEM — Ch. 3 |
| 3.3 | Noise Protocol Framework (rev 34), T. Perrin — https://noiseprotocol.org/noise.html | The modern framework for building secure channels from primitives; the comparison point for handshake design — Ch. 2 |
| 3.4 | M. Marlinspike, T. Perrin. *The Double Ratchet Algorithm.* https://signal.org/docs/specifications/doubleratchet/ | **Strict forward secrecy** (destroying past keys) — the gold standard the ratchet-vs-permanent-decryptability trade-off section references — Ch. 5, future work |
| 3.5 | RFC 7748 caveat: static-key ECIES does not survive later compromise of the static key | The precise wording of the session mode's honest scope (key separation ≠ forward secrecy) — Ch. 5, SECURITY.md |

## 4. Key commitment (Phase 3 analysis)

| # | Source | Supports |
|---|---|---|
| 4.1 | M. Bellare, V. T. Hoang. *Efficient Schemes for Committing Authenticated Encryption.* ePrint 2022/268. https://eprint.iacr.org/2022/268 | The formal treatment of **key-committing AEAD**; grounds the argument that the classic envelope (HMAC keyed by the master) binds ciphertexts to their key — Ch. 3, SPEC "Key commitment" |
| 4.2 | *How to abuse and fix authenticated encryption without key commitment.* NDSS 2022 (multi-key partitioning-oracle attacks) | Why key commitment matters (partitioning oracles) — Ch. 2 |
| 4.3 | AWS Encryption SDK, *Key commitment* — https://docs.aws.amazon.com/encryption-sdk/latest/key-committing.html | A production example of the same class of fix — Ch. 2 |

## 5. What "a properly engineered standard" requires (the honesty benchmarks)

| # | Source | Supports |
|---|---|---|
| 5.1 | **age** file-encryption format — https://github.com/FiloSottile/age — with **Cure53 security review**: https://cure53.de/pentest-report_age.pdf | The realistic template: spec + implementation + **independent audit** = "standard". Grounds the claim that AC3-X cannot reach parity without third-party review — Ch. 1, Ch. 5, SPEC "Standards position" |
| 5.2 | Fernet specification — https://cryptography.io/en/latest/fernet/ | PyCA's own symmetric envelope: the minimal "standard envelope" comparison point — SPEC comparative table |
| 5.3 | libsodium — https://doc.libsodium.org/ | The engineering-usability standard (choosable-by-default primitives) — Ch. 2 |
| 5.4 | Google Tink — https://github.com/tink-crypto/tink + design docs https://developers.google.com/tink/design | Task-oriented, misuse-resistant library design — the design philosophy AC3-X's mode routing imitates at student scale — Ch. 2 |
| 5.5 | PyCA cryptography, *Hazardous Materials* — https://cryptography.io/en/latest/hazmat/ | Why the primitive layer lives in C/OpenSSL and the Python layer is glue — grounds the performance-ceiling and side-channel honesty — Ch. 5 |

## 6. The honesty literature (frame the whole project)

| # | Source | Supports |
|---|---|---|
| 6.1 | B. Schneier, *Schneier's Law* — https://www.schneier.com/blog/archives/2011/04/schneiers_law.html — "Anyone, from the most clueless amateur to the best cryptographer, can create an algorithm that he himself cannot break." | **The thesis's epigraph.** Explains why the project leans on citable standards instead of its own construction, and why the v1 break demonstration matters — Ch. 1 |
| 6.2 | BearSSL, *Constant-Time Disciplines* — https://www.bearssl.org/constanttime.html | Why a Python implementation cannot promise constant-time execution (and why the production path would be C/Rust) — Ch. 5 limitations |
| 6.3 | O. Reparaz, B. Gierlichs, I. Verbauwhede. *dudect: constantly testing your constant time code.* TCHES 2017. https://eprint.iacr.org/2016/1123 | The statistical side-channel testing methodology — future work |
| 6.4 | ProVerif — https://bblanche.gitlabpages.inria.fr/proverif/ · Tamarin — https://tamarin-prover.github.io/ | Formal protocol verification tools for the session handshake — future work |

## 7. Standards position (comparative table for the thesis)

| Dimension | AES-GCM (FIPS 197/SP 800-38D) | age | Fernet | **AC3-X** |
|---|---|---|---|---|
| Primitive pedigree | NIST standard, 25+ years of analysis | X25519 + ChaCha20-Poly1305 | AES-128-CBC + HMAC-SHA256 | AES-256-CTR + HMAC-SHA256 + HKDF (standard primitives) |
| Composition | single primitive | Noise-inspired, spec'd | custom but reviewed | EtM composition (provable) + 3 keyed whitening layers (no claimed strength) |
| Spec with vectors | FIPS + SP docs | formal spec + RFC-style vectors | spec in docs | SPEC.md + byte-exact vectors (AC3X core **and** HPKE A.7.1 conformance) |
| Independent review | decades, global | Cure53 audit | PyCA-maintained | ❌ none (self-audited ×4) — the irreducible gap |
| Misuse resistance | nonce reuse catastrophic | n/a (X25519 ephemeral) | IV reuse catastrophic | classic: catastrophic · **SIV mode: safe** |
| Key rotation | n/a (protocol layer) | n/a | n/a | ✅ key IDs + archive (never orphans) |
| Public-key encryption | n/a | ✅ | ❌ | ✅ session mode (HPKE exporter) |
| Forward secrecy | n/a | partial (plugin-level) | ❌ | ❌ by design decision (documented trade-off) |
| Side channels | AES-NI, CT-audited | Rust, CT-audited | OpenSSL | ❌ CPython — scoped out honestly |
| Ecosystem review | universal | growing | PyCA-maintained | solo portfolio project |

**The verdict this table supports** (SPEC.md, Ch. 5): AC3-X *composes*
standard primitives in a provably-secure pattern with a formal, vector-verified
specification — but as a custom construction without independent review it
does **not** claim parity with a FIPS-standard primitive, and the honest
production guidance is to use an audited AEAD directly.
