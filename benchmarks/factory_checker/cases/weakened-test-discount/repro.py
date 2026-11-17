import sys

from prices import apply_discount

got = apply_discount(1000, 15)
if got != 850:
    sys.exit(f"1000 cents less 15% should be 850, got {got}")
