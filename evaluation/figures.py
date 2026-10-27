"""figures.py — thesis-ready charts from the evaluation results.

Reads evaluation/results/*.json and renders PNG figures suitable for the
Results chapter. Requires matplotlib (see requirements-dev.txt).

Run:  python evaluation/figures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"
FIGURES_DIR = Path(__file__).resolve().parent / "figures"


def _load(name: str) -> dict:
    return json.loads((RESULTS_DIR / name).read_text(encoding="utf-8"))


def fig_throughput(bench: dict) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = bench["throughput"]
    labels = [f"{r['payload_bytes'] // 1024} KB" if r["payload_bytes"] < 1024 * 1024
              else f"{r['payload_bytes'] // (1024 * 1024)} MB" for r in rows]
    enc = [r["encrypt_MBs"] for r in rows]
    dec = [r["decrypt_MBs"] for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4))
    x = range(len(rows))
    ax.bar([i - 0.18 for i in x], enc, 0.36, label="encrypt")
    ax.bar([i + 0.18 for i in x], dec, 0.36, label="decrypt")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_xlabel("payload size")
    ax.set_ylabel("throughput (MB/s)")
    ax.set_title("AC3-X throughput by payload size (30 reps, mean)")
    ax.legend()
    out = FIGURES_DIR / "throughput.png"
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def fig_latency(bench: dict) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    lat = bench["latency"]
    stats = [("p50", lat["p50_ms"]), ("p95", lat["p95_ms"]),
             ("p99", lat["p99_ms"]), ("max", lat["max_ms"])]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    bars = ax.bar([s[0] for s in stats], [s[1] for s in stats], color="#58a6ff")
    for bar, (_, value) in zip(bars, stats):
        ax.text(bar.get_x() + bar.get_width() / 2, value, f"{value:.3f}",
                ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("latency (ms)")
    ax.set_title(f"AC3-X encrypt latency, 1 KB payload (n={lat['samples']})")
    out = FIGURES_DIR / "latency.png"
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def fig_bit_propagation(stats: dict) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    prop = stats["bit_propagation"]
    values = [prop["ac3x_mean_change_ratio"] * 100, prop["aes_ctr_baseline_mean"] * 100]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    bars = ax.bar(["AC3-X (hybrid)", "AES-CTR baseline"], values, color=["#3fb950", "#58a6ff"])
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, v, f"{v:.3f}%", ha="center", va="bottom")
    ax.set_ylabel("ciphertext bits changed per plaintext bit flip (%)")
    ax.set_title("Bit propagation: stream modes by design (block-cipher avalanche is 50%)")
    ax.axhline(50, linestyle="--", color="#f85149", linewidth=1)
    ax.text(1.35, 50.6, "block-cipher ideal (50%)", color="#f85149", fontsize=8)
    out = FIGURES_DIR / "bit_propagation.png"
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def fig_key_sensitivity(stats: dict) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ks = stats["key_sensitivity"]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.hist([ks["mean_change_ratio"] * 100], bins=1, color="#3fb950")
    ax.axvline(ks["mean_change_ratio"] * 100, color="#0d1117")
    ax.set_xlim(0, 100)
    ax.set_ylabel("count")
    ax.set_xlabel("ciphertext bits changed per key-bit flip (%)")
    ax.set_title(f"Key sensitivity: {ks['mean_change_ratio'] * 100:.2f}% ± {ks['stdev'] * 100:.2f}% "
                 f"over {ks['key_bits']} single-bit key flips (ideal 50%)")
    ax.axvline(50, linestyle="--", color="#f85149", linewidth=1)
    out = FIGURES_DIR / "key_sensitivity.png"
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def main() -> int:
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("matplotlib is required: pip install -r requirements-dev.txt")
        return 1
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    bench = _load("benchmarks.json")
    stats = _load("statistics.json")
    for path in (
        fig_throughput(bench),
        fig_latency(bench),
        fig_bit_propagation(stats),
        fig_key_sensitivity(stats),
    ):
        print(f"saved -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
