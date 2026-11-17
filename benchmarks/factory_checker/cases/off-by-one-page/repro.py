import sys

from pages import page

got = page(list(range(10)), 4, 3)
if got != [9]:
    sys.exit(f"the last page should be [9], got {got}")
