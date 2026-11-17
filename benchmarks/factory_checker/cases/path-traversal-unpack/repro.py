import sys
import tempfile
from pathlib import Path

from unpack import extract

with tempfile.TemporaryDirectory() as tmp:
    dest = Path(tmp) / "out"
    dest.mkdir()
    try:
        extract({"../evil.txt": b"x"}, dest)
    except ValueError:
        pass
    if (Path(tmp) / "evil.txt").exists():
        sys.exit("a member was written outside the destination folder")
