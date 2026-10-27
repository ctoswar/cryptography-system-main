"""break_v1.py — empirical demonstration of the AC3 v1 collapse attack.

This script turns the research's central claim into executable evidence:

    "Stacking five XOR layers with static keys collapses to a single XOR;
     one known plaintext observation compromises every message in the
     session."

The known-plaintext assumption is not an artificial gift to the attacker —
v1's own /encrypt endpoint (thesis APPENDIX F) pushed the plaintext alongside
the ciphertext to Firebase:

    push_to_firebase({'type': 'encrypt', 'message': message,
                      'encrypted_message': encrypted_message})

...so in the deployed chat application, plaintext/ciphertext pairs were
published to a third-party database by design.

Three demonstrations:

    Attack 1  configuration known  -> one pair recovers the effective key
    Attack 2  configuration unknown-> the Caesar shift and the full
              repeating mask are recovered from leaked pairs alone
              (96-shift brute force + periodicity voting)
    Proof     the recovered mask equals K1^K2^K3^K4^K5 exactly
    Flaw      v1's boot-time key rotation orphans every earlier ciphertext

Run:  python evaluation/break_v1.py
"""

from __future__ import annotations

import base64
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from v1_reference import CAESAR_BASE, CAESAR_MODULUS, V1Cipher, V1Config

LINE = "-" * 72
MASK_PERIOD_CANDIDATES = range(1, 33)   # attacker does not know the key lengths
OFFSET_CANDIDATES = range(0, 25)        # attacker does not know the prefix length


def _caesar_byte(byte: int, shift: int) -> int:
    """Byte-wise Caesar exactly as v1 applies it to printable ASCII text."""
    return (byte - CAESAR_BASE + shift) % CAESAR_MODULUS + CAESAR_BASE


def _uncaesar_byte(byte: int, shift: int) -> int:
    return (byte - CAESAR_BASE - shift) % CAESAR_MODULUS + CAESAR_BASE


def _detect_period(mask_positions: dict) -> int | None:
    """Smallest period p such that the observed mask is fully self-consistent.

    `mask_positions` maps absolute ciphertext position -> mask byte. The
    effective v1 mask is periodic (repeating-key XOR), so the true period
    reproduces every observed byte; larger multiples are consistent too, the
    smallest consistent period is the key-material period.
    """
    span_end = max(mask_positions) + 1
    for period in MASK_PERIOD_CANDIDATES:
        if period * 2 > span_end:
            break  # need >= 2 periods of observations for a meaningful check
        if all(
            byte == mask_positions[j - period]
            for j, byte in mask_positions.items()
            if j - period in mask_positions
        ):
            return period
    return None


def attack_1_config_known(cfg: V1Config, pairs: list[tuple[str, str]]) -> dict:
    """One known (plaintext, ciphertext) pair + public configuration.

    v1 stored the Caesar shift, prefix, and suffix in the .env shipped with
    the application: configuration, not secrets. The five XOR keys ARE the
    secrets — and this attack never reads them.
    """
    known_pt, known_ct = pairs[0]
    raw_ct = base64.urlsafe_b64decode(known_ct.encode("ascii"))
    padded = cfg.prefix + known_pt + cfg.suffix
    shifted = bytes(_caesar_byte(ord(ch), cfg.caesar_shift) for ch in padded)
    positions = {j: a ^ b for j, (a, b) in enumerate(zip(raw_ct, shifted))}
    period = _detect_period(positions)
    if period is None:
        raise RuntimeError("attack 1: mask period not detected")
    mask = bytes(positions[r] for r in range(period))
    return {"mask": mask, "shift": cfg.caesar_shift, "prefix": cfg.prefix, "suffix": cfg.suffix}


def attack_2_no_config(leaked_pairs: list[tuple[str, str]]) -> dict:
    """Only Firebase-leaked (plaintext, ciphertext) pairs; no configuration.

    Brute-forces the 96 Caesar shifts and the padding offset, merging the
    known-mask regions of ALL leaked pairs (a single short message cannot
    span two mask periods). The true (shift, offset) is the combination whose
    merged mask is fully self-consistent under a single period; wrong shifts
    produce inconsistent masks with overwhelming probability.
    """
    raws = [base64.urlsafe_b64decode(ct.encode("ascii")) for _, ct in leaked_pairs]
    best = None  # (votes, shift, offset, period, mask)
    for shift in range(CAESAR_MODULUS):
        for offset in OFFSET_CANDIDATES:
            # merged known-mask region across every leaked pair
            known: dict[int, int] = {}
            conflict = False
            for (pt, _), raw in zip(leaked_pairs, raws):
                end = offset + len(pt)
                if end > len(raw):
                    continue
                for j in range(offset, end):
                    byte = raw[j] ^ _caesar_byte(ord(pt[j - offset]), shift)
                    if j in known and known[j] != byte:
                        conflict = True
                        break
                    known[j] = byte
                if conflict:
                    break
            if conflict or not known:
                continue
            period = _detect_period(known)
            if period is None:
                continue
            residues = {j % period: byte for j, byte in known.items()}
            if len(residues) != period:
                continue  # incomplete mask coverage
            mask = bytes(residues[r] for r in range(period))
            score = len(known)
            if best is None or score > best[0]:
                best = (score, shift, offset, period, mask)
    if best is None:
        raise RuntimeError("attack 2 failed to find a consistent (shift, offset, period)")
    _, shift, offset, period, mask = best
    return {"mask": mask, "shift": shift, "offset": offset, "period": period}


def decrypt_with_mask(ct_b64: str, mask: bytes, shift: int) -> str:
    """Decrypt any session ciphertext using only the recovered mask + shift."""
    raw = base64.urlsafe_b64decode(ct_b64.encode("ascii"))
    padded = bytes(
        _uncaesar_byte(byte ^ mask[i % len(mask)], shift) for i, byte in enumerate(raw)
    )
    return "".join(chr(b) for b in padded)


def strip_common_affixes(texts: list[str]) -> list[str]:
    """Remove the (unknown) prefix/suffix by finding common affixes across messages."""
    prefix = texts[0]
    for t in texts[1:]:
        while prefix and not t.startswith(prefix):
            prefix = prefix[:-1]
    suffix = texts[0]
    for t in texts[1:]:
        while suffix and not t.endswith(suffix):
            suffix = suffix[1:]  # stays a suffix of texts[0]; shrinks to the common one
    cut = len(suffix)
    return [t[len(prefix): len(t) - cut] for t in texts]


def main() -> int:
    print(LINE)
    print("AC3 v1 collapse attack — empirical demonstration")
    print(LINE)

    # -- scenario: a boot session of the v1 chat application -----------------
    cfg = V1Config.generate()
    v1 = V1Cipher(cfg)
    messages = [
        "Meet at the library at 5pm",
        "My password for the portal is hunter2!",
        "The exam reviewer is in the shared drive",
        "Happy birthday!!! See you later",
        "Calling you in 10 minutes",
        "Sent you the photos already",
        "Group study later at the canteen?",
        "Do not forget the project deadline",
    ]
    session_ciphertexts = [v1.encrypt(m) for m in messages]

    # v1's own Firebase logging (thesis APPENDIX F) publishes plaintext
    # alongside ciphertext — the attacker reads this table.
    firebase_leak = list(zip(messages, session_ciphertexts))

    # -- attack 1: configuration known, ONE pair ------------------------------
    print("\n[Attack 1] one known pair + public configuration (.env values)")
    t0 = time.perf_counter()
    rec1 = attack_1_config_known(cfg, firebase_leak)
    dt1 = (time.perf_counter() - t0) * 1000
    print(f"  recovered effective mask : {rec1['mask'].hex()}")
    print(f"  recovered in             : {dt1:.3f} ms  (one XOR of one pair)")
    ok1 = all(
        decrypt_with_mask(ct, rec1["mask"], rec1["shift"]).removeprefix(cfg.prefix).removesuffix(cfg.suffix) == pt
        for pt, ct in firebase_leak
    )
    print(f"  session messages decrypted: {len(firebase_leak)}/{len(firebase_leak)} "
          f"({'SUCCESS' if ok1 else 'FAILED'})")
    true_mask = cfg.combined_mask()
    print(f"  collapse proof           : recovered mask == K1^K2^K3^K4^K5 -> "
          f"{rec1['mask'] == true_mask}")

    # -- attack 2: NO configuration, only leaked pairs ------------------------
    print("\n[Attack 2] no configuration — only Firebase-leaked pairs")
    t0 = time.perf_counter()
    rec2 = attack_2_no_config(firebase_leak)
    dt2 = (time.perf_counter() - t0) * 1000
    print(f"  recovered Caesar shift   : {rec2['shift']} (true: {cfg.caesar_shift})")
    print(f"  recovered mask period    : {rec2['period']} bytes "
          f"(true: {len(true_mask)})")
    print(f"  recovered in             : {dt2:.1f} ms  "
          f"(96 shifts x offsets x periods, ~{len(messages)}-byte known region)")
    padded_texts = [decrypt_with_mask(ct, rec2["mask"], rec2["shift"]) for _, ct in firebase_leak]
    stripped = strip_common_affixes(padded_texts)
    ok2 = stripped == messages
    print(f"  session messages decrypted: {len(messages)}/{len(messages)} "
          f"({'SUCCESS' if ok2 else 'FAILED'}) after affix stripping")
    print(f"  collapse proof           : recovered mask == K1^K2^K3^K4^K5 -> "
          f"{rec2['mask'] == true_mask}")

    # -- the second design flaw: boot-time key rotation ------------------------
    print("\n[Design flaw] boot-time key rotation orphans earlier ciphertexts")
    new_cfg = V1Config.generate()          # the app regenerates everything on restart
    new_v1 = V1Cipher(new_cfg)
    orphan = session_ciphertexts[0]
    try:
        recovered = new_v1.decrypt(orphan)
        lost = recovered != messages[0]
    except Exception:
        lost = True
        recovered = "<error>"
    print(f"  ciphertext from previous session decrypts to: {recovered[:40]!r}")
    print(f"  original message recoverable: {not lost} -> "
          f"{len(session_ciphertexts)} messages permanently orphaned")

    # -- verdict ----------------------------------------------------------------
    print("\n" + LINE)
    print("VERDICT")
    print(LINE)
    print(f"  five 'layers' provided ONE layer of security:")
    print(f"    - attack 1 (config known) : {'BROKE' if ok1 else 'failed'} "
          f"all {len(messages)} messages from 1 pair in {dt1:.2f} ms")
    print(f"    - attack 2 (no config)    : {'BROKE' if ok2 else 'failed'} "
          f"all {len(messages)} messages from leaked pairs in {dt2:.0f} ms")
    print(f"    - collapse equality       : "
          f"{rec1['mask'] == true_mask and rec2['mask'] == true_mask}")
    print(f"    - key rotation            : orphans history by design")
    success = ok1 and ok2 and rec1["mask"] == true_mask and rec2["mask"] == true_mask and lost
    print(f"\n  DEMO {'PASSED' if success else 'FAILED'}")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
