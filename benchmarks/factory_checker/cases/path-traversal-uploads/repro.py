import sys
import tempfile
from pathlib import Path

from uploads import read_upload

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / "uploads"
    root.mkdir()
    (Path(tmp) / "secret.txt").write_bytes(b"secret")
    try:
        got = read_upload(root, "../secret.txt")
    except (ValueError, OSError):
        sys.exit(0)
    sys.exit(f"read a file outside the upload folder: {got!r}")
