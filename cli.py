#!/usr/bin/env python
"""AC3-X (v3) command-line interface.

Usage:
    python cli.py encrypt "message"
    python cli.py decrypt "AC3X...."
    python cli.py encrypt-file input.txt [output.ac3] [--chunk-size N]
    python cli.py decrypt-file input.ac3 [output.txt]
    python cli.py keygen

Reading '-' as the input makes encrypt/decrypt pipe-friendly:
    echo "secret" | python cli.py encrypt -

One algorithm: AC3-X — the five-layer thesis pipeline (framing, Caesar, XOR,
transposition, XOR + HMAC) with an AES-256-CTR keystream engine and HMAC-SHA256
integrity. Files stream in constant memory, so large files encrypt at disk speed.
"""

import argparse
import sys

from ac3 import AC3Error, CMainController
from ac3.core import DEFAULT_CHUNK_SIZE
from ac3.keys import DEFAULT_ENV_PATH, MASTER_KEY_ENV, KeyManager


def _configure_streams() -> None:
    """Windows consoles default to cp1252; ciphertexts and plaintext are UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _read_input(value: str) -> str:
    """'-' reads stdin; one trailing newline comes from the pipe/echo, not data."""
    if value == "-":
        return sys.stdin.read().rstrip("\r\n")
    return value


def _build_controller(args) -> CMainController:
    env_path = args.env if args.env else DEFAULT_ENV_PATH
    return CMainController(env_path=env_path)


def cmd_encrypt(args) -> int:
    controller = _build_controller(args)
    token = controller.encrypt(_read_input(args.message))
    print(token)
    return 0


def cmd_decrypt(args) -> int:
    controller = _build_controller(args)
    print(controller.decrypt(_read_input(args.message)))
    return 0


def cmd_encrypt_file(args) -> int:
    controller = _build_controller(args)
    out = controller.encrypt_file(args.input, args.output, chunk_size=args.chunk_size)
    print(f"Encrypted: {args.input} -> {out}")
    return 0


def cmd_decrypt_file(args) -> int:
    controller = _build_controller(args)
    out = controller.decrypt_file(args.input, args.output)
    print(f"Decrypted: {args.input} -> {out}")
    return 0


def cmd_keygen(args) -> int:
    from pathlib import Path

    env_path = args.env if args.env else DEFAULT_ENV_PATH
    env_file = Path(env_path)
    existed_before = (
        env_file.exists() and MASTER_KEY_ENV in env_file.read_text(encoding="utf-8")
    )
    manager = KeyManager(env_path=env_path)  # creates only if missing
    state = "already existed" if existed_before else "created"
    if args.show:
        print(f"Key (hex): {manager.master_key.hex()}")
    print(f"Master key: {state} ({MASTER_KEY_ENV} in {env_file})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ac3",
        description="AC3-X (v3) — thesis five-layer pipeline with an AES-CTR engine.",
    )
    # Shared flag lives on each subcommand so `ac3 keygen --env x` reads naturally.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--env",
        help=f"path to the .env holding {MASTER_KEY_ENV} (default: project .env)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("encrypt", help="encrypt a text message", parents=[common])
    p.add_argument("message", help="plaintext, or '-' to read stdin")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt a ciphertext", parents=[common])
    p.add_argument("message", help="AC3X... token, or '-' to read stdin")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("encrypt-file", help="encrypt a file", parents=[common])
    p.add_argument("input")
    p.add_argument("output", nargs="?", help="default: <input>.ac3")
    p.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"stream chunk size in bytes (default {DEFAULT_CHUNK_SIZE})",
    )
    p.set_defaults(func=cmd_encrypt_file)

    p = sub.add_parser("decrypt-file", help="decrypt a .ac3 file", parents=[common])
    p.add_argument("input")
    p.add_argument("output", nargs="?", help="default: <input> minus .ac3")
    p.set_defaults(func=cmd_decrypt_file)

    p = sub.add_parser("keygen", help="create the master key if missing", parents=[common])
    p.add_argument("--show", action="store_true", help="print the full key (sensitive!)")
    p.set_defaults(func=cmd_keygen)

    return parser


def main(argv=None) -> int:
    _configure_streams()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AC3Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
