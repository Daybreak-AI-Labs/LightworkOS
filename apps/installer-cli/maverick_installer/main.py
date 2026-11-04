"""Standalone entry point for the installer.

Installed as the ``maverick-init`` console script. Also reachable via
``maverick init`` when the core CLI is installed.
"""
from __future__ import annotations

import argparse
import sys

from .wizard import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="maverick-init",
        description="Interactive setup wizard for Lightwork.",
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="Skip every prompt; use recommended defaults.",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from the last unanswered wizard question.",
    )
    args = parser.parse_args(argv)
    try:
        return run(fast=args.fast, resume=args.resume)
    except (KeyboardInterrupt, EOFError):
        print("\nAborted. If setup is unfinished, you can try again later.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
