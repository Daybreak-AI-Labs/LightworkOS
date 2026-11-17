import sys

from limits import read_limit

try:
    got = read_limit({})
except Exception as exc:  # noqa: BLE001
    sys.exit(f"an unset LIMIT should give the default, got {type(exc).__name__}")
if got != 100:
    sys.exit(f"an unset LIMIT should give 100, got {got}")
