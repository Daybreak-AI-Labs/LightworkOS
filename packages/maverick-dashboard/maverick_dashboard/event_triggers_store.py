"""Dashboard-owned registry of polled event triggers.

An event trigger binds a saved template to an :class:`~maverick.automation_events.EventSource`
(plus its config and operator-set default params). A scheduled poll asks the
source for items newer than the stored ``cursor``; each fires the template as a
goal. Persisted to ``~/.maverick/dashboard-event-triggers.toml`` -- dashboard-
owned like the webhook triggers, deliberately NOT merged into the kernel config.

Mirrors ``triggers_store``'s atomic, 0600, cross-process-locked write and its
JSON-in-TOML encoding for the nested ``params``/``config`` tables and the
mutable ``cursor``.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time

from maverick import config
from maverick.event_admission import EventRegistryUnavailable

# Reuse the webhook store's slug (identical charset/length rules) so the two
# can't drift.
from .triggers_store import (
    slugify,
    snapshot_from_template,
    snapshot_revision,
    validated_template_snapshot,
)

_LOCK = threading.Lock()

# URL/TOML-safe slug, same shape as webhook trigger names.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


class FormTriggerPending(RuntimeError):
    """Changing this binding would redirect accepted form submissions."""

    def __init__(self, count: int) -> None:
        self.count = count
        super().__init__(f"{count} form submissions are waiting to be checked")


class FormTriggerConflict(RuntimeError):
    """Another active public form already owns this link or storage key."""


def _locked():
    from contextlib import ExitStack

    from maverick.file_lock import cross_process_lock
    with ExitStack() as stack:
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(_path(), strict=True))
        return stack.pop_all()


def registry_lock():
    """Serialize a public form append with trigger edits across processes."""
    return _locked()


def _tomllib():
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
        import tomli as tomllib  # type: ignore
    return tomllib


def _path():
    return config.dashboard_overrides_path().parent / "dashboard-event-triggers.toml"


def _decode_obj(raw: object) -> dict:
    try:
        val = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    return val if isinstance(val, dict) else {}


def _record_key(name: str, tenant: str) -> str:
    """Return a stable TOML table key without exposing the tenant identifier."""
    if not tenant:
        return name
    digest = hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:32]
    return f"{name}--{digest}"


def _tenant_floor(tenant: str | None) -> str | None:
    """Resolve an omitted tenant to the active namespace, when one is pinned."""
    if tenant is not None:
        return str(tenant)
    from maverick.paths import current_tenant_id

    current = current_tenant_id()
    return str(current) if current else None


def _matching(triggers: list[dict], name: str, tenant: str | None) -> list[dict]:
    floor = _tenant_floor(tenant)
    matches = [t for t in triggers if t["name"] == name]
    if floor is not None:
        return [t for t in matches if t.get("tenant", "") == floor]
    # Backward-compatible for callers outside a tenant context, but never pick
    # arbitrarily once two tenants own the same public trigger name.
    return matches if len(matches) <= 1 else []


def list_triggers(*, strict: bool = False) -> list[dict]:
    """Every registered event trigger as a dict (params/config decoded)."""
    p = _path()
    try:
        with open(p, "rb") as f:
            raw = _tomllib().load(f)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        if strict:
            raise EventRegistryUnavailable("Event automations could not be read") from exc
        return []
    tables = raw.get("trigger") or {}
    if not isinstance(tables, dict):
        if strict:
            raise EventRegistryUnavailable("Event automations could not be read")
        return []
    out: list[dict] = []
    for table_key, t in tables.items():
        if not isinstance(t, dict):
            if strict:
                raise EventRegistryUnavailable("Event automations could not be read")
            continue
        try:
            template_snapshot = json.loads(t.get("template_snapshot") or "null")
        except (TypeError, ValueError):
            template_snapshot = None
        out.append({
            # Old files used the public name as the table key. New files keep
            # the public name explicitly because the table key also namespaces
            # it by tenant.
            "name": str(t.get("name") or table_key),
            "template": str(t.get("template") or ""),
            "flow": str(t.get("flow") or ""),
            "flow_owner": str(t.get("flow_owner") or ""),
            "flow_revision": str(t.get("flow_revision") or ""),
            "template_snapshot": (
                template_snapshot if isinstance(template_snapshot, dict) else None
            ),
            "template_revision": str(t.get("template_revision") or ""),
            "source": str(t.get("source") or ""),
            "config": _decode_obj(t.get("config")),
            "params": {str(k): str(v) for k, v in _decode_obj(t.get("params")).items()},
            "cursor": str(t.get("cursor") or ""),
            "cursor_format": int(t.get("cursor_format") or 0),
            "owner": str(t.get("owner") or ""),
            "tenant": str(t.get("tenant") or ""),
            "interval_seconds": int(t.get("interval_seconds") or 0),
            "created": float(t.get("created") or 0.0),
            "last_form_link_rotation": _decode_obj(t.get("last_form_link_rotation")),
        })
    out.sort(key=lambda t: (t["created"], t["name"]))
    return out


def get_trigger(name: str, *, tenant: str | None = None,
                strict: bool = False) -> dict | None:
    matches = _matching(list_triggers(strict=strict), name, tenant)
    return matches[0] if len(matches) == 1 else None


def _dump(triggers: list[dict]) -> str:
    lines = [
        "# Dashboard-managed polled event triggers. Edit via the dashboard,",
        "# not by hand. Your config.toml is never touched.",
        "",
    ]
    for t in sorted(triggers, key=lambda x: (x.get("tenant", ""), x["name"])):
        lines.append(f"[trigger.{_record_key(t['name'], t.get('tenant', ''))}]")
        lines.append(f"name = {json.dumps(str(t['name']))}")
        lines.append(f"template = {json.dumps(str(t['template']))}")
        lines.append(f"flow = {json.dumps(str(t.get('flow') or ''))}")
        lines.append(f"flow_owner = {json.dumps(str(t.get('flow_owner') or ''))}")
        lines.append(f"flow_revision = {json.dumps(str(t.get('flow_revision') or ''))}")
        lines.append(
            "template_snapshot = "
            + json.dumps(json.dumps(t.get("template_snapshot"), sort_keys=True))
        )
        lines.append(
            f"template_revision = {json.dumps(str(t.get('template_revision') or ''))}"
        )
        lines.append(f"source = {json.dumps(str(t.get('source') or ''))}")
        lines.append(f"config = {json.dumps(json.dumps(t.get('config') or {}, sort_keys=True))}")
        lines.append(f"params = {json.dumps(json.dumps(t.get('params') or {}, sort_keys=True))}")
        lines.append(f"cursor = {json.dumps(str(t.get('cursor') or ''))}")
        lines.append(f"cursor_format = {int(t.get('cursor_format') or 0)}")
        lines.append(f"owner = {json.dumps(str(t.get('owner') or ''))}")
        lines.append(f"tenant = {json.dumps(str(t.get('tenant') or ''))}")
        lines.append(f"interval_seconds = {int(t.get('interval_seconds') or 0)}")
        lines.append(f"created = {float(t.get('created') or 0.0)}")
        lines.append(
            "last_form_link_rotation = "
            + json.dumps(json.dumps(t.get("last_form_link_rotation") or {}, sort_keys=True))
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write(triggers: list[dict]) -> None:
    from maverick.file_lock import atomic_write_text
    atomic_write_text(_path(), _dump(triggers))


def pending_form_submissions(trigger: dict) -> int:
    """Count unacknowledged rows for one form, refusing a damaged cursor/store."""
    if trigger.get("source") != "form":
        return 0
    from maverick import form_store
    from maverick.automation_events import EventSourceError, _decode_cursor
    from maverick.paths import reset_tenant, set_tenant

    scope = set_tenant(str(trigger.get("tenant") or "") or None)
    try:
        cursor = str(trigger.get("cursor") or "0")
        raw = _decode_cursor(cursor, "form", int(trigger.get("cursor_format") or 0))
        if not isinstance(raw, str):
            raise form_store.FormStoreUnavailable("form cursor is unavailable")
        return form_store.pending(str((trigger.get("config") or {}).get("token") or ""), raw)
    except EventSourceError as exc:
        raise form_store.FormStoreUnavailable("form cursor is unavailable") from exc
    finally:
        reset_tenant(scope)


def _api_form_config(config: dict | None, prior: dict | None, existing: list[dict]) -> dict:
    """Reserve a server-generated public link while the registry lock is held."""
    resolved = dict(config or {})
    supplied = str(resolved.get("token") or "")
    old_token = (
        str((prior.get("config") or {}).get("token") or "")
        if prior and prior.get("source") == "form" else ""
    )
    if old_token:
        if supplied and supplied != old_token:
            raise FormTriggerConflict(
                "Keep the existing form link when updating this automation."
            )
        resolved["token"] = old_token
        return resolved
    if supplied:
        raise ValueError(
            "Leave the form link code blank. Lightwork creates a private link when you save."
        )
    for _ in range(8):
        candidate = "form-" + secrets.token_urlsafe(24)
        if not any(
            t.get("source") == "form"
            and str((t.get("config") or {}).get("token") or "") == candidate
            for t in existing
        ):
            resolved["token"] = candidate
            return resolved
    raise FormTriggerConflict("A private form link could not be reserved. Try again.")


def set_trigger(name: str, template: str, source: str, *, config: dict | None = None,
                params: dict | None = None, owner: str = "", cursor: str = "",
                interval_seconds: int = 0, tenant: str = "", flow: str = "",
                flow_owner: str = "", flow_revision: str = "",
                template_snapshot: dict | None = None,
                mint_public_form_token: bool = False,
                expected_owner: str | None = None,
                create_only: bool = False, effect_guard=None) -> dict:
    """Create or replace an event trigger (by slugified name). Raises ValueError
    on an un-sluggable name. Preserves the existing cursor on replace unless one
    is passed, so re-saving a trigger doesn't replay its whole backlog.
    ``interval_seconds`` is the per-trigger poll cadence (0 = the scheduler
    default). ``tenant`` binds the trigger to the tenant that created it, so a
    polled OAuth source reads that tenant's vault (never a cross-tenant token).
    ``flow`` targets a flow instead of a ``template`` (the two are exclusive).
    API callers mint new public links under the registry lock; direct-store
    callers can still load older tokens for migration and recovery."""
    slug = slugify(name)
    if not _NAME_RE.match(slug):
        raise ValueError("trigger name must contain a letter or digit (a-z, 0-9, -)")
    if source == "form" and cursor:
        raise ValueError("Form submission position is managed automatically.")
    if flow and template_snapshot is not None:
        raise ValueError("flow triggers cannot include a template snapshot")
    # Direct store callers get the same creation-time pinning as the REST API
    # whenever their target exists. A missing target remains a legacy/unbound
    # row and is refused by the fire path until it is re-saved safely.
    if template and template_snapshot is None:
        from maverick.paths import reset_tenant, set_tenant
        from maverick.templates import load_template

        token = set_tenant(str(tenant) or None)
        try:
            template_snapshot = snapshot_from_template(load_template(template))
        except (FileNotFoundError, ValueError):
            template_snapshot = None
        finally:
            reset_tenant(token)
    normalised_snapshot = None
    template_rev = ""
    if template_snapshot is not None:
        normalised_snapshot = validated_template_snapshot(template_snapshot)
        if normalised_snapshot["name"] != str(template):
            raise ValueError("template snapshot does not match the trigger target")
        template_rev = snapshot_revision(normalised_snapshot)
    with _locked():
        if effect_guard is not None:
            effect_guard()
        existing = list_triggers()
        tenant = str(tenant)
        kept = [
            t for t in existing
            if not (t["name"] == slug and t.get("tenant", "") == tenant)
        ]
        prior = next(
            (
                t for t in existing
                if t["name"] == slug and t.get("tenant", "") == tenant
            ),
            None,
        )
        if (prior is not None and expected_owner is not None
                and prior.get("owner", "") != expected_owner):
            raise FormTriggerConflict("This automation belongs to another person.")
        if create_only and prior is not None:
            planned = {"source": str(source), "config": dict(config or {}), "template": str(template),
                       "flow": str(flow), "params": {str(k): str(v) for k, v in (params or {}).items()},
                       "interval_seconds": int(interval_seconds)}
            if any(prior.get(key) != value for key, value in planned.items()):
                raise FormTriggerConflict("An automation already uses this name. Read its original result or choose a different name.")
            return prior
        resolved_config = (
            _api_form_config(config, prior, existing)
            if source == "form" and mint_public_form_token else dict(config or {})
        )
        bound_cursor = cursor
        if source == "form" and not bound_cursor and (
            prior is None
            or prior.get("source") != "form"
            or (prior.get("config") or {}).get("token") != resolved_config.get("token")
        ):
            # Form POSTs are admitted only after the trigger exists. Arm at the
            # current high-water mark now, so a submission before the first
            # scheduled poll is new work rather than a discarded baseline.
            from maverick import form_store
            from maverick.paths import reset_tenant, set_tenant

            scope = set_tenant(tenant or None)
            try:
                bound_cursor = form_store.since(str(resolved_config.get("token") or ""), "")[1]
            finally:
                reset_tenant(scope)
        rec = {
            "name": slug,
            "template": str(template),
            "flow": str(flow),
            "flow_owner": str(flow_owner),
            "flow_revision": str(flow_revision),
            "template_snapshot": normalised_snapshot,
            "template_revision": template_rev,
            "source": str(source),
            "config": resolved_config,
            "params": {str(k): str(v) for k, v in (params or {}).items()},
            "cursor": bound_cursor or (prior["cursor"] if prior else ""),
            "cursor_format": 0 if bound_cursor or prior is None else int(prior.get("cursor_format") or 0),
            # Preserve the prior owner on a re-save that doesn't pass one, like
            # cursor/created, so an update can't silently orphan the trigger.
            "owner": str(owner) if owner else (prior["owner"] if prior else ""),
            "tenant": tenant,
            # The create form always submits this field, so take it verbatim --
            # that's what lets an operator clear a custom cadence back to the
            # scheduler default (0) by blanking the box.
            "interval_seconds": int(interval_seconds),
            "created": (prior["created"] if prior else time.time()),
            "last_form_link_rotation": (
                prior.get("last_form_link_rotation") or {} if prior else {}
            ),
        }
        if str(source) == "form":
            from maverick import form_store

            new_key = form_store.storage_key(resolved_config.get("token"))
            if any(
                t is not prior and t.get("source") == "form"
                and str(t.get("tenant") or "") == tenant
                and form_store.storage_key((t.get("config") or {}).get("token")) == new_key
                for t in existing
            ):
                raise FormTriggerConflict("This form link is already used by another automation.")
        if prior is not None and prior.get("source") == "form":
            from .event_poll import _trigger_key

            if _trigger_key(prior) != _trigger_key(rec):
                waiting = pending_form_submissions(prior)
                if waiting:
                    raise FormTriggerPending(waiting)
        kept.append(rec)
        if effect_guard is not None:
            effect_guard()
        _write(kept)
    return rec


def set_cursor(name: str, cursor: str, *, tenant: str | None = None,
               expected_cursor: str | None = None,
               expected_generation: str | None = None,
               cursor_format: int | None = None,
               accept_peer_progress: bool = False) -> bool:
    """Advance a trigger's cursor after a poll. Returns False if it's gone.
    Skips the rewrite when the cursor is unchanged, so an idle poll (no new
    items) doesn't rewrite the whole store every tick."""
    cursor = str(cursor)
    with _locked():
        triggers = list_triggers()
        matches = _matching(triggers, name, tenant)
        if len(matches) != 1:
            return False
        match = matches[0]
        if match.get("source") == "form" and (
            expected_cursor is None or expected_generation is None
        ):
            return False
        if expected_generation is not None:
            from .event_poll import _trigger_key
            if _trigger_key(match) != expected_generation:
                return False
        if expected_cursor is not None and match["cursor"] != expected_cursor:
            # Only a caller which finished every retained delivery may retire
            # a stale batch. Preserve the peer's cursor AND format atomically;
            # source IDs are opaque and cannot be ordered to guess which won.
            return match["cursor"] == cursor or accept_peer_progress
        if match["cursor"] != cursor or (cursor_format is not None and match.get("cursor_format", 0) != cursor_format):
            match["cursor"] = cursor
            if cursor_format is not None:
                match["cursor_format"] = cursor_format
            _write(triggers)
        return True


def delete_trigger(
    name: str,
    owner: str | None = None,
    *,
    tenant: str | None = None,
) -> bool:
    """Remove a trigger. When ``owner`` is given, only if it belongs to that
    owner (ownership check + removal under one lock)."""
    with _locked():
        triggers = list_triggers()
        matches = _matching(triggers, name, tenant)
        if len(matches) != 1:
            return False
        match = matches[0]
        if owner is not None and match.get("owner", "") != owner:
            return False
        if match.get("source") == "form":
            waiting = pending_form_submissions(match)
            if waiting:
                raise FormTriggerPending(waiting)
        _write([t for t in triggers if t is not match])
    return True


def rotate_form_link(
    name: str, *, expected_generation: str, owner: str | None = None,
    tenant: str | None = None, actor: str = "",
) -> dict | None:
    """Replace a drained form's public link without discarding its old queue.

    The registry lock also surrounds public form admission. An expected binding
    generation makes retries after an uncertain response safe: the first
    successful replacement changes the generation, and a retry is refused.
    """
    from maverick import form_store
    from maverick.paths import reset_tenant, set_tenant

    from .event_poll import _trigger_key

    with _locked():
        triggers = list_triggers()
        matches = _matching(triggers, name, tenant)
        if len(matches) != 1:
            return None
        current = matches[0]
        if (owner is not None and current.get("owner", "") != owner) or current.get("source") != "form":
            return None
        if _trigger_key(current) != expected_generation:
            raise FormTriggerConflict("This form changed. Refresh it before replacing the link.")
        old_token = str((current.get("config") or {}).get("token") or "")
        if not old_token:
            raise FormTriggerConflict("This form has no active link to replace.")
        waiting = pending_form_submissions(current)
        if waiting:
            raise FormTriggerPending(waiting)

        # Never recycle a file left by an older link. A fresh token must start
        # with an empty queue and must not claim a different active form.
        scope = set_tenant(str(current.get("tenant") or "") or None)
        try:
            for _ in range(8):
                new_token = "form-" + secrets.token_urlsafe(24)
                if any(
                    t.get("source") == "form"
                    and str((t.get("config") or {}).get("token") or "") == new_token
                    for t in triggers
                ) or form_store._path(new_token).exists():
                    continue
                break
            else:
                raise FormTriggerConflict("A new private form link could not be reserved. Try again.")
        finally:
            reset_tenant(scope)

        updated = {
            **current,
            "config": {**(current.get("config") or {}), "token": new_token},
            "cursor": "0",
            "cursor_format": 0,
            # Private registry metadata, committed in the same atomic write as
            # the new link. No raw link secret is copied into event telemetry.
            "last_form_link_rotation": {
                "at": time.time(),
                "actor": str(actor or "local")[:120],
                "old_token_sha256": hashlib.sha256(old_token.encode()).hexdigest(),
                "new_token_sha256": hashlib.sha256(new_token.encode()).hexdigest(),
            },
        }
        triggers[triggers.index(current)] = updated
        _write(triggers)
        return updated
