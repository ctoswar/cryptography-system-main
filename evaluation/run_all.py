"""run_all.py — regenerate every evaluation result and figure in one command.

Reproducibility is itself a research claim: a single command rebuilds the
v1 attack demonstration, the performance benchmarks, the statistical
analysis, and the thesis figures from scratch.

Run:  python evaluation/run_all.py [--quick]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script: str, *args: str) -> int:
    print(f"\n{'=' * 72}\n>>> {script} {' '.join(args)}\n{'=' * 72}")
    proc = subprocess.run(
        [sys.executable, str(HERE / script), *args],
        cwd=str(HERE.parent),
    )
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="skip the 100 MB benchmark cells")
    parser.add_argument("--reps", type=int, default=30, help="benchmark repetitions")
    args = parser.parse_args()

    failures = []
    if run("break_v1.py") != 0:
        failures.append("break_v1.py")
    bench_args = ["--reps", str(args.reps)] + (["--quick"] if args.quick else [])
    if run("benchmarks.py", *bench_args) != 0:
        failures.append("benchmarks.py")
    if run("cipher_stats.py") != 0:
        failures.append("cipher_stats.py")
    if run("figures.py") != 0:
        failures.append("figures.py")

    print(f"\n{'=' * 72}")
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    print("ALL EVALUATIONS COMPLETED — see evaluation/results/ and evaluation/figures/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
