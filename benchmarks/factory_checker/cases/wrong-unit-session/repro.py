import sys

from session import expires_at

got = expires_at(0, 30)
if got != 1800:
    sys.exit(f"30 minutes after 0 should be 1800 seconds, got {got}")
