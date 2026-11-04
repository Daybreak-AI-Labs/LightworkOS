"""A small memo for the repo-walking CI gates, keyed on the tree's content.

``egress_contract``, ``dispatch_contract`` and ``audit_contract`` each walk the
source roots and parse every module -- about 1,500 files and 15 seconds per
walk. Their test modules call the walk several times each (the positive
check, the anti-vacuity check, the debt-register check, the CLI), and nothing
about the tree changes between those calls, so every walk after the first is
waste: close to a minute per test process, and the longest single-file tail
once the suite runs in parallel.

The memo keeps a few scan results per gate and replays one while its tree
is unchanged. "Unchanged" is a stat walk over the same roots -- path, size
and mtime -- so an edit, an added file or a deletion invalidates it, and the
tests that point ``REPO_ROOT``/``SEARCH_ROOTS`` at a temp tree get a different
key. The stat walk costs tens of milliseconds; the parse it replaces costs
seconds. The CLI gates in the lint job run one scan per process and are
unaffected.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

T = TypeVar("T")


def tree_fingerprint(repo_root: Path, roots: tuple[str, ...]) -> str:
    """Digest of (path, size, mtime_ns) for every ``*.py`` under ``roots``."""
    digest = hashlib.sha256()
    for root in roots:
        base = repo_root / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            try:
                st = path.stat()
            except OSError:
                continue
            digest.update(f"{path}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    return digest.hexdigest()


class ScanMemo(Generic[T]):
    """Replay scan results while the scanned tree is unchanged.

    A few entries, not one: the gates' tests alternate between the real tree
    and throwaway temp trees (``REPO_ROOT`` pointed at ``tmp_path``), and a
    single slot would be evicted by every temp scan, so the real tree got
    re-parsed on each return to it. Results are small (module -> libraries,
    a few dozen hit dicts); the bound only stops a long-lived process that
    scans many distinct trees from growing without limit.

    ``get`` returns ``copy(value)`` so callers can mutate what they receive
    without poisoning the memo for the next caller.
    """

    LIMIT = 16

    def __init__(self) -> None:
        self._entries: dict[tuple[Path, tuple[str, ...], str], T] = {}

    def get(
        self,
        repo_root: Path,
        roots: tuple[str, ...],
        compute: Callable[[], T],
        copy: Callable[[T], T],
    ) -> T:
        key = (repo_root, roots, tree_fingerprint(repo_root, roots))
        try:
            value = self._entries[key]
        except KeyError:
            value = compute()
            if len(self._entries) >= self.LIMIT:
                del self._entries[next(iter(self._entries))]
            self._entries[key] = value
        return copy(value)
