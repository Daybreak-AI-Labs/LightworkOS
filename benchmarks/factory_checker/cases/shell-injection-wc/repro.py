import os
import sys
import tempfile

from counting import count_lines

with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    try:
        count_lines("nothing.txt; touch pwned")
    except Exception:  # noqa: BLE001 -- only the side effect matters
        pass
    if os.path.exists("pwned"):
        sys.exit("a file name ran a shell command")
