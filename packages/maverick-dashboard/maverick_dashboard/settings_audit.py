"""One activity-record row for a deployment-wide setting changed outside
Settings > All settings (the Trust page switch, Store catalog addresses,
turning a module on). Same row shape as All settings: who made the change,
which setting, the value before and after, and whether a loosening was
confirmed. Callers pass values that are never secret."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from fastapi import HTTPException, Request


def record_setting_change(request: Request, *, section: str, key: str, old: object,
                          new: object, confirmed: bool = False,
                          phase: str | None = None,
                          changed_fields: list[str] | None = None) -> bool:
    """Write the row; :class:`maverick.audit.AuditRefused` propagates."""
    from maverick.audit import EventKind, audit_event

    from . import auth

    fields: dict[str, object] = {"phase": phase} if phase is not None else {}
    if changed_fields is not None:
        fields["changed_fields"] = changed_fields
    return audit_event(
        EventKind.SETTING_CHANGED,
        agent="dashboard",
        _global=True,
        actor=auth.caller_principal(request) or "local administrator",
        section=section,
        key=key,
        old=old,
        new=new,
        confirmed=bool(confirmed),
        **fields,
    )


@dataclass
class SettingWrite:
    """A route's non-secret projection, bound through its serialized writer."""

    request: Request
    section: str
    key: str
    project: Callable[[dict], object]
    changed_fields: Callable[[dict, dict], list[str]] | None = None
    confirmed: bool = False
    deferred: bool = False
    pending: tuple[object, object, list[str] | None] | None = None

    def prepare(self, old: dict, new: dict) -> None:
        from maverick.audit import AuditRefused

        from . import auth

        # This runs after the writer acquired its cross-process lock. A caller
        # demoted while waiting must not publish a setting under stale authority.
        auth.require_global_permission(self.request, "admin")
        before, after = self.project(old), self.project(new)
        changed = self.changed_fields(old, new) if self.changed_fields is not None else None
        try:
            result = record_setting_change(
                self.request, section=self.section, key=self.key,
                old=before, new=after, confirmed=self.confirmed, phase="prepared",
                changed_fields=changed,
            )
            if result is False:
                raise AuditRefused("settings activity record unavailable")
        except AuditRefused as exc:
            raise HTTPException(
                status_code=503,
                detail="Activity recording is unavailable. Settings were not changed; retry after it is restored.",
            ) from exc
        self.pending = (before, after, changed)

    def complete(self) -> None:
        from maverick.audit import AuditRefused

        if self.pending is None:
            return
        before, after, changed = self.pending
        try:
            result = record_setting_change(
                self.request, section=self.section, key=self.key,
                old=before, new=after, confirmed=self.confirmed, phase="completed",
                changed_fields=changed,
            )
            if result is False:
                raise AuditRefused("settings activity record unavailable")
        except AuditRefused as exc:
            raise HTTPException(
                status_code=503,
                detail="The setting may have changed, but its completion record is unavailable. Refresh Settings and Activity before retrying.",
            ) from exc
        finally:
            self.pending = None

    def on_runtime_write(self, phase: str, old: dict, new: dict) -> None:
        if phase == "prepared":
            self.prepare(old, new)
        elif phase == "completed":
            self.complete()


_current: ContextVar[SettingWrite | None] = ContextVar("settings_audit_write", default=None)


def current_write() -> SettingWrite | None:
    return _current.get()


@contextmanager
def bind_setting_write(request: Request, *, section: str, key: str,
                       project: Callable[[dict], object], confirmed: bool = False,
                       changed_fields: Callable[[dict, dict], list[str]] | None = None):
    """Bind one route to dashboard and runtime-overlay write boundaries."""
    from maverick.runtime_overrides import setting_audit_callback

    change = SettingWrite(request, section, key, project,
                          changed_fields=changed_fields, confirmed=confirmed)
    token = _current.set(change)
    try:
        with setting_audit_callback(change.on_runtime_write):
            yield change
    finally:
        _current.reset(token)


__all__ = ["record_setting_change", "bind_setting_write", "current_write"]
