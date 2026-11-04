"""Cross-process serialization for Ekko's deployment authority boundary.

The dashboard's global ON/OFF mutation and every durable capture append share
this barrier.  Consequently a disable operation cannot return while an append
that observed the old policy is still capable of committing.  The lock is
global rather than tenant-scoped because ``[ekko] enable`` is a deployment-wide
control.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def control_barrier() -> Iterator[None]:
    """Hold the strict deployment-wide Ekko control barrier."""
    from .file_lock import cross_process_lock
    from .paths import data_dir

    target = data_dir("ekko-control", "authority", tenant=None)
    with cross_process_lock(target, strict=True):
        yield


__all__ = ["control_barrier"]
