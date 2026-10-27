"""statistics.py — classical cipher-analysis metrics for AC3-X.

Computes the four metrics a cipher-evaluation chapter is expected to report.
Each is a descriptive statistic, not a security proof — the honest framing
(ciphertexts *look* statistically random) belongs in the thesis limitations
section alongside SPEC.md's scope statement.

    * Avalanche effect   — flipping one plaintext bit changes ~50% of the
                           ciphertext bits (fixed nonce via seal_deterministic)
    * Key sensitivity    — flipping one master-key bit changes ~50% of the
                           ciphertext bits
    * Entropy            — Shannon entropy of ciphertext bodies (~8.0 bits/byte)
    * Chi-square         — byte-frequency goodness-of-fit vs uniform

Output: evaluation/results/statistics.json (+ stdout summary).

Run:  python evaluation/statistics.py
"""

from __future__ import annotations

import json
import math
import secrets
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import AC3Cipher  # noqa: E402
from ac3.core import TEXT_PREFIX  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"

AVALANCHE_SAMPLES = 64      # random plaintexts
AVALANCHE_PAYLOAD = 256     # bytes -> 2048 bits per sample
KEY_SENS_KEY = 32           # master key bits flipped individually
ENTROPY_MESSAGES = 64
ENTROPY_PAYLOAD = 4096
CHI2_MESSAGES = 32
CHI2_PAYLOAD = 4096         # -> 131,072 bytes observed over 256 classes


def _body_bits(token: str) -> bytes:
    """Extract the raw body bytes from an AC3X text token."""
    parts = token.split(".", 3)
    import base64

    return base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))


def _aes_ctr_reference_body(pt: bytes, nonce: bytes, key: bytes) -> bytes:
    """Plain AES-256-CTR baseline (no AC3-X layers) for honest comparison."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    return Cipher(algorithms.AES(key), modes.CTR(nonce[:16])).encryptor().update(pt)


def avalanche(cipher: AC3Cipher, nonce: bytes) -> dict:
    """Plaintext-bit propagation under a fixed nonce.

    HONEST INTERPRETATION (important for the thesis): stream-cipher modes —
    AES-CTR included — intentionally propagate NO diffusion: flipping
    plaintext bit j flips only ciphertext bit j. Bit-level avalanche (~50%)
    is a block-cipher property. Confidentiality in a stream mode rests on
    keystream unpredictability, and integrity on the HMAC tag — see
    key_sensitivity() for the metric that must be ~50% (and is).

    The AES-CTR baseline below proves AC3-X behaves exactly like the
    industry-standard stream mode on this metric.
    """
    ratios = []
    for _ in range(AVALANCHE_SAMPLES):
        pt = bytearray(secrets.token_bytes(AVALANCHE_PAYLOAD))
        base = _body_bits(cipher.seal_deterministic(bytes(pt), nonce))
        bit_index = secrets.randbelow(AVALANCHE_PAYLOAD * 8)
        pt[bit_index // 8] ^= 1 << (bit_index % 8)
        flipped = _body_bits(cipher.seal_deterministic(bytes(pt), nonce))
        if len(flipped) != len(base):
            ratios.append(1.0)  # length change counts as full change
            continue
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(base, flipped))
        ratios.append(diff_bits / (len(base) * 8))

    # AES-CTR baseline over the same samples (fixed key: measures plaintext-bit
    # propagation, not key change — the key must stay identical between the
    # two encryptions or the metric silently becomes key sensitivity)
    baseline_key = secrets.token_bytes(32)
    baseline = []
    for _ in range(AVALANCHE_SAMPLES):
        pt = bytearray(secrets.token_bytes(AVALANCHE_PAYLOAD))
        base = _aes_ctr_reference_body(bytes(pt), nonce, baseline_key)
        bit_index = secrets.randbelow(AVALANCHE_PAYLOAD * 8)
        pt[bit_index // 8] ^= 1 << (bit_index % 8)
        flipped = _aes_ctr_reference_body(bytes(pt), nonce, baseline_key)
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(base, flipped))
        baseline.append(diff_bits / (len(base) * 8))

    return {
        "samples": AVALANCHE_SAMPLES,
        "payload_bits": AVALANCHE_PAYLOAD * 8,
        "ac3x_mean_change_ratio": statistics.fmean(ratios),
        "ac3x_stdev": statistics.stdev(ratios),
        "aes_ctr_baseline_mean": statistics.fmean(baseline),
        "interpretation": (
            "stream modes propagate no bit diffusion by design (CTR baseline "
            "matches AC3-X); diffusion avalanche is a block-cipher property; "
            "integrity is enforced by the HMAC tag instead"
        ),
    }


def key_sensitivity(nonce: bytes) -> dict:
    """Mean ciphertext-bit change when one master-key bit flips."""
    base_master = secrets.token_bytes(KEY_SENS_KEY)
    pt = secrets.token_bytes(AVALANCHE_PAYLOAD)
    base_cipher = AC3Cipher(base_master)
    base = _body_bits(base_cipher.seal_deterministic(pt, nonce))
    ratios = []
    for bit in range(KEY_SENS_KEY * 8):
        flipped = bytearray(base_master)
        flipped[bit // 8] ^= 1 << (bit % 8)
        other = AC3Cipher(bytes(flipped))
        ct = _body_bits(other.seal_deterministic(pt, nonce))
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(base, ct))
        ratios.append(diff_bits / (len(base) * 8))
    return {
        "key_bits": KEY_SENS_KEY * 8,
        "mean_change_ratio": statistics.fmean(ratios),
        "stdev": statistics.stdev(ratios),
        "min": min(ratios),
        "max": max(ratios),
        "ideal": 0.5,
    }


def shannon_entropy(data: bytes) -> float:
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy(cipher: AC3Cipher) -> dict:
    entropies = []
    for _ in range(ENTROPY_MESSAGES):
        ct = _body_bits(cipher.encrypt(secrets.token_bytes(ENTROPY_PAYLOAD).hex()))
        entropies.append(shannon_entropy(ct))
    return {
        "messages": ENTROPY_MESSAGES,
        "payload_bytes": ENTROPY_PAYLOAD,
        "mean_bits_per_byte": statistics.fmean(entropies),
        "stdev": statistics.stdev(entropies),
        "max_possible": 8.0,
    }


def chi_square_uniform(data: bytes) -> tuple[float, bool]:
    """Chi-square goodness-of-fit against the uniform byte distribution.

    Returns (statistic, passes_at_alpha_005). df = 255; the 0.05 critical
    value for df=255 is ~293.16 (Wilson-Hilferty approximation used to
    avoid a scipy dependency).
    """
    counts = Counter(data)
    n = len(data)
    expected = n / 256
    chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))
    df = 255
    # Wilson-Hilferty: chi2_p ≈ df * (1 - 2/(9df) + z_p * sqrt(2/(9df)))^3
    z = 1.6448536269514722  # p = 0.95
    critical = df * (1 - 2 / (9 * df) + z * math.sqrt(2 / (9 * df))) ** 3
    return chi2, chi2 < critical


def chi_square(cipher: AC3Cipher) -> dict:
    blob = b"".join(
        _body_bits(cipher.encrypt(secrets.token_bytes(CHI2_PAYLOAD).hex()))
        for _ in range(CHI2_MESSAGES)
    )
    stat, passes = chi_square_uniform(blob)
    return {
        "bytes_observed": len(blob),
        "chi2_statistic": round(stat, 2),
        "df": 255,
        "critical_value_005": 293.16,
        "passes_uniform_at_005": passes,
    }


def main() -> int:
    cipher = AC3Cipher()  # auto-provisions the project .env master key
    nonce = secrets.token_bytes(16)

    print("=== plaintext bit propagation (vs AES-CTR baseline) ===")
    av = avalanche(cipher, nonce)
    print(f"  AC3-X  : {av['ac3x_mean_change_ratio'] * 100:.3f}% ± {av['ac3x_stdev'] * 100:.3f}% "
          f"(n={av['samples']})")
    print(f"  AES-CTR: {av['aes_ctr_baseline_mean'] * 100:.3f}%  <- industry-standard stream mode")
    print(f"  -> stream modes propagate no diffusion by design; integrity is the HMAC's job")

    print("=== key sensitivity (one master-key bit flipped) ===")
    ks = key_sensitivity(nonce)
    print(f"  {ks['mean_change_ratio'] * 100:.2f}% ± {ks['stdev'] * 100:.2f}% "
          f"(ideal 50%, {ks['key_bits']} bit flips)")

    print("=== ciphertext entropy ===")
    en = entropy(cipher)
    print(f"  {en['mean_bits_per_byte']:.4f} bits/byte ± {en['stdev']:.4f} "
          f"(max 8.0, n={en['messages']})")

    print("=== chi-square uniformity ===")
    chi = chi_square(cipher)
    verdict = "PASS" if chi["passes_uniform_at_005"] else "FAIL"
    print(f"  chi2 = {chi['chi2_statistic']} (df={chi['df']}, "
          f"crit {chi['critical_value_005']} @ 0.05) -> {verdict}")

    results = {"bit_propagation": av, "key_sensitivity": ks, "entropy": en, "chi_square": chi}
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "statistics.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nsaved -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
