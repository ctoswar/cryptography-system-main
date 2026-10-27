"""benchmarks.py — reproducible performance evaluation of AC3-X.

Methodology (designed for the thesis Results chapter):

    * payload sizes spanning 1 KB .. 100 MB
    * R repetitions per size (default 30) -> mean, stdev reported
    * latency percentiles (p50/p95/p99) from 1,000 small-message operations
    * constant-memory proof: peak traced memory while streaming 100 MB
    * environment capture (CPU model, Python and cryptography versions) so
      results are attributable to a specific machine and stack

Output: evaluation/results/benchmarks.json (+ a markdown table on stdout).

Run:  python evaluation/benchmarks.py [--reps 30] [--quick]
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ac3 import AC3Cipher, CMainController  # noqa: E402

RESULTS_DIR = Path(__file__).resolve().parent / "results"
PAYLOAD_SIZES = [1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024]
LATENCY_SAMPLES = 1_000
LATENCY_PAYLOAD = 1024


def _environment() -> dict:
    try:
        from cryptography import __version__ as crypto_version
    except Exception:  # pragma: no cover
        crypto_version = "unknown"
    cpu = platform.processor() or platform.machine()
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "cryptography": crypto_version,
        "platform": platform.platform(),
        "cpu": cpu,
        "notes": "single-process CPython, files on local disk, default 4 MiB chunks",
    }


def bench_throughput(controller: CMainController, reps: int, sizes: list[int]) -> list[dict]:
    rows = []
    for size in sizes:
        payload = bytes(size)  # zeros compress nothing here; transforms are byte-wise
        enc_times, dec_times = [], []
        blob = None
        for _ in range(reps):
            t0 = time.perf_counter()
            blob = controller.encrypt_bytes(payload)
            t1 = time.perf_counter()
            if size <= 10 * 1024 * 1024:  # keep the 100 MB cell to one decrypt
                controller.decrypt_bytes(blob)
                t2 = time.perf_counter()
                dec_times.append(t2 - t1)
            enc_times.append(t1 - t0)
        # one full decrypt of the largest payload (memory-bounded, not timed-looped)
        if size > 10 * 1024 * 1024:
            t1 = time.perf_counter()
            assert controller.decrypt_bytes(blob) == payload
            dec_times.append(time.perf_counter() - t1)
        row = {
            "payload_bytes": size,
            "reps": reps,
            "encrypt_mean_s": statistics.fmean(enc_times),
            "encrypt_stdev_s": statistics.stdev(enc_times) if reps > 1 else 0.0,
            "encrypt_MBs": size / statistics.fmean(enc_times) / 1e6,
            "decrypt_mean_s": statistics.fmean(dec_times),
            "decrypt_stdev_s": statistics.stdev(dec_times) if len(dec_times) > 1 else 0.0,
            "decrypt_MBs": size / statistics.fmean(dec_times) / 1e6,
        }
        rows.append(row)
        print(f"  {size:>10,} B  enc {row['encrypt_MBs']:7.1f} MB/s (+-{row['encrypt_stdev_s'] * 1000 / size * 1e6:5.2f} ms)  "
              f"dec {row['decrypt_MBs']:7.1f} MB/s")
    return rows


def bench_latency(controller: CMainController, samples: int) -> dict:
    payload = bytes(LATENCY_PAYLOAD)
    times = []
    token = None
    for _ in range(samples):
        t0 = time.perf_counter()
        token = controller.encrypt_bytes(payload)
        times.append(time.perf_counter() - t0)
    times.sort()

    def pct(p):
        return times[min(len(times) - 1, int(p * len(times)))]

    return {
        "payload_bytes": LATENCY_PAYLOAD,
        "samples": samples,
        "mean_ms": statistics.fmean(times) * 1000,
        "p50_ms": pct(0.50) * 1000,
        "p95_ms": pct(0.95) * 1000,
        "p99_ms": pct(0.99) * 1000,
        "max_ms": times[-1] * 1000,
    }


def bench_memory(controller: CMainController, size: int) -> dict:
    """Constant-memory proof: peak allocations while streaming a large file."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "big.bin"
        with src.open("wb") as f:
            chunk = bytes(1024 * 1024)
            for _ in range(size // len(chunk)):
                f.write(chunk)
        tracemalloc.start()
        enc = controller.encrypt_file(src, Path(tmp) / "big.enc")
        peak_enc = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        tracemalloc.start()
        controller.decrypt_file(enc, Path(tmp) / "big.out")
        peak_dec = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert (Path(tmp) / "big.out").read_bytes() == src.read_bytes()
        return {
            "payload_bytes": size,
            "peak_encrypt_bytes": peak_enc,
            "peak_decrypt_bytes": peak_dec,
            "peak_encrypt_MB": peak_enc / 1e6,
            "peak_decrypt_MB": peak_dec / 1e6,
            "memory_ratio_encrypt": peak_enc / size,
            "memory_ratio_decrypt": peak_dec / size,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=30, help="repetitions per payload size")
    parser.add_argument("--quick", action="store_true", help="skip the 100 MB cells")
    args = parser.parse_args()

    sizes = [s for s in PAYLOAD_SIZES if not (args.quick and s >= 100 * 1024 * 1024)]
    cipher = AC3Cipher()  # auto-provisions the project .env master key
    controller = CMainController(cipher=cipher)

    print("=== AC3-X throughput ===")
    rows = bench_throughput(controller, args.reps, sizes)

    print("=== AC3-X latency (1 KB text envelope) ===")
    latency = bench_latency(controller, LATENCY_SAMPLES)
    print(f"  mean {latency['mean_ms']:.3f} ms | p50 {latency['p50_ms']:.3f} ms | "
          f"p95 {latency['p95_ms']:.3f} ms | p99 {latency['p99_ms']:.3f} ms")

    print("=== AC3-X constant-memory proof (100 MB stream) ===")
    memory = bench_memory(controller, 100 * 1024 * 1024)
    print(f"  peak encrypt {memory['peak_encrypt_MB']:.1f} MB | peak decrypt {memory['peak_decrypt_MB']:.1f} MB "
          f"| ratio {memory['memory_ratio_encrypt']:.3f}x payload")

    results = {
        "environment": _environment(),
        "throughput": rows,
        "latency": latency,
        "memory": memory,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / "benchmarks.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nsaved -> {out}")

    print("\n| Payload | Encrypt (MB/s) | Encrypt (ms) | Decrypt (MB/s) | Decrypt (ms) |")
    print("|---:|---:|---:|---:|---:|")
    for r in rows:
        print(f"| {r['payload_bytes']:,} B | {r['encrypt_MBs']:.1f} | "
              f"{r['encrypt_mean_s'] * 1000:.2f} ± {r['encrypt_stdev_s'] * 1000:.2f} | "
              f"{r['decrypt_MBs']:.1f} | {r['decrypt_mean_s'] * 1000:.2f} ± "
              f"{r['decrypt_stdev_s'] * 1000:.2f} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
