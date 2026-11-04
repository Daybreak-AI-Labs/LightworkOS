"""Keep standalone demo support in sync with its shared source.

Each demo is an independent Docker build context or source archive that can be
copied to another machine. Vendoring the shared source keeps that property
while providing one maintained implementation.
"""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "demo" / "shared"
CONCIERGES = ("dsar-concierge",)
STANDALONE_STORES = ("grc-concierge", "platform-threat-hunter",
                     "environment-threat-hunter", "model-risk-ai-assurance-officer")
FILES = {
    "mailsink_transport.py": CONCIERGES,
    "local_store_lock.py": STANDALONE_STORES,
    "request_boundary.py": STANDALONE_STORES,
}


def synchronize(*, check: bool) -> list[Path]:
    """Return missing or outdated copies, optionally updating them."""
    outdated = []
    for name, demos in FILES.items():
        source = (SHARED / name).read_bytes()
        for demo in demos:
            target = ROOT / "demo" / demo / name
            if not target.is_file() or target.read_bytes() != source:
                outdated.append(target)
                if not check:
                    target.write_bytes(source)
    return outdated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if vendored copies differ")
    args = parser.parse_args()
    outdated = synchronize(check=args.check)
    if outdated and args.check:
        for path in outdated:
            print(f"out of date: {path.relative_to(ROOT)}")
        print("Run python scripts/sync_standalone_support.py")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
