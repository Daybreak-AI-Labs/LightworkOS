"""Write archive members into a folder."""
from pathlib import Path


def extract(members, dest):
    """Write each name -> bytes in ``members`` under ``dest``; refuse a name
    that would land outside it."""
    dest = Path(dest).resolve()
    for name, data in members.items():
        target = (dest / name).resolve()
        if not target.is_relative_to(dest) or target == dest:
            raise ValueError(f"unsafe member name: {name!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
