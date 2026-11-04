#!/usr/bin/env python3
"""Lightwork -- proof of guarantees.

Not unit assertions buried in a suite: a single reproducible run that drives the
REAL roster (the shipped domain packs) through the REAL enforcement code -- the
same primitives the production tool chokepoint (``agent._run_tool``) calls --
and prints a scoreboard of the product's core promises.

    python proof/run_proof.py        # exits 0 iff every guarantee holds

The governance guarantees, made checkable. Five guarantees run anywhere; two
cryptographic ones (Ed25519) need ``cryptography`` and otherwise report ``CI``
(they run in the test matrix).

The guarantees themselves live in :mod:`maverick.proof_guarantees` (the single
source of truth shared with ``maverick.proof_pack``); this file is the
standalone scoreboard around them.
"""
from __future__ import annotations

import pathlib
import sys

# Make the shipped package importable however this is launched (repo root, CI, ...).
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "packages" / "maverick-core"))


def _check(condition: bool, message: object) -> None:
    """Raise even when Python assertions are disabled with -O/PYTHONOPTIMIZE.

    Retained here (alongside ``maverick.proof_guarantees._check``) so the
    optimized-Python regression test can import this script and exercise it
    directly."""
    if not condition:
        raise AssertionError(message)


def main() -> int:
    from maverick import proof_guarantees as pg
    crypto = pg._crypto_ok()
    print("=" * 78)
    print("  MAVERICK -- PROOF OF GUARANTEES   (real roster, real enforcement code)")
    print("=" * 78)
    ran = 0
    failed = 0
    for r in pg.run_all(crypto=crypto):
        if r.skipped:
            print(f"  [ CI ]  {r.label:32}  Ed25519 -- verified in the CI test matrix")
        elif r.passed:
            ran += 1
            print(f"  [PASS]  {r.label:32}  {r.detail}")
        else:  # a proof must report its own failure
            failed += 1
            print(f"  [FAIL]  {r.label:32}  {r.detail}")
    print("=" * 78)
    crypto_note = "" if crypto else "  (+2 cryptographic checks verified in CI)"
    print(f"  {ran} checks passed, {failed} failed{crypto_note}")
    print("=" * 78)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
