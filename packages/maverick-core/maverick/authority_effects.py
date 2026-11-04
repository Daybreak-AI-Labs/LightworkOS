"""Short-lived fence between app-owned authority changes and external effects.

Admission checks alone leave a check/use race: a role, workspace selection,
session epoch, tenant budget, or reviewed execution profile can change after a
worker reads it but before the worker starts an external effect. App-owned
mutators and effect adapters share this strict cross-process fence. An effect
holder re-reads every bound authority while holding the fence and keeps it only
through the process-spawn boundary.

The fence coordinates this installation's local control-plane stores. A remote
control plane must provide an equivalent transactional fencing lease.
"""
from __future__ import annotations

from contextlib import contextmanager

from .file_lock import cross_process_lock, ensure_private_directory
from .paths import maverick_home


@contextmanager
def authority_effect_fence():
    """Exclude app-owned authority mutations across one effect admission."""
    target = maverick_home() / "authority-effects"
    ensure_private_directory(target.parent)
    with cross_process_lock(target, strict=True):
        yield


__all__ = ["authority_effect_fence"]
