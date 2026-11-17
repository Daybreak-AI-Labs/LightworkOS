import sys

from duration import parse_duration

got = parse_duration("1h30m")
if got != 5400:
    sys.exit(f"1h30m should be 5400 seconds, got {got}")
