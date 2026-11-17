import os
import sys
import tempfile

from files import copy_file

with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    with open("a.txt", "w") as fh:
        fh.write("x")
    try:
        copy_file("a.txt", "b.txt; touch pwned")
    except Exception:  # noqa: BLE001 -- only the side effect matters
        pass
    if os.path.exists("pwned"):
        sys.exit("a file name ran a shell command")
