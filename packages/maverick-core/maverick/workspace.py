"""Workspaces (tenants): one isolated home per business.

A :class:`Workspace` walls off everything the factory produces for a business --
its domain packs, its uploaded-document knowledge store, its world DB -- under
its own directory (``~/.maverick/tenants/<tenant>/``). One business literally
cannot read another's files.

Selecting a tenant is explicit: construct ``Workspace(tenant)`` or set
``MAVERICK_TENANT``. With no tenant, paths fall back to the legacy single-tenant
``~/.maverick/`` layout, so existing single-business installs are unchanged.

Tenant path segments are resolved by :mod:`maverick.paths`, the shared
collision-resistant, context-local tenancy primitive. This keeps workspaces in
lockstep with per-run tenant scopes used by the channel server and avoids lossy
slug collisions between distinct tenant IDs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .paths import _TENANT, _tenant_segment, current_tenant, data_dir


def _sanitize_tenant(tenant: str) -> str:
    """Return the collision-resistant safe path segment for ``tenant``.

    Kept for compatibility with older tests/imports; implementation delegates to
    the shared tenant path encoder so distinct tenant IDs cannot collapse onto
    the same workspace directory.
    """
    return _tenant_segment(tenant or "")


@dataclass(frozen=True)
class Workspace:
    """An isolated home for one business.

    ``tenant=None`` is the legacy single-tenant layout when constructed
    directly. Use :meth:`current` to follow the active ContextVar/env tenant.
    """

    tenant: str | None = None
    _active: bool = False

    @classmethod
    def current(cls) -> Workspace:
        """The active workspace from the shared tenant resolver.

        Explicit ContextVar tenant scopes win over ``MAVERICK_TENANT``; unset
        resolves to the single-tenant legacy layout.
        """
        scoped = _TENANT.get()
        env = os.environ.get("MAVERICK_TENANT", "").strip()
        return cls(scoped or env or None, _active=True)

    @property
    def root(self):
        if self._active:
            return data_dir()
        return data_dir(tenant=self.tenant)

    @property
    def domains_dir(self):
        """Where this business's domain packs (its sealed agents) live."""
        return self.root / "domains"

    @property
    def knowledge_path(self):
        """This business's document knowledge store (vector DB)."""
        return self.root / "knowledge.db"

    @property
    def db_path(self):
        """This business's world DB (run history, facts)."""
        return self.root / "world.db"

    @property
    def slug(self) -> str | None:
        """The encoded tenant path segment, or None for single-tenant default."""
        if self._active:
            return current_tenant()
        return _sanitize_tenant(self.tenant) if self.tenant else None
