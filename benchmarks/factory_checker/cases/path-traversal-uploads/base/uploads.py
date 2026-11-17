"""Read files people uploaded."""
from pathlib import Path


def read_upload(root, name):
    """The bytes of upload ``name`` in folder ``root``; plain file names only."""
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(f"not an upload name: {name!r}")
    return (Path(root) / name).read_bytes()
