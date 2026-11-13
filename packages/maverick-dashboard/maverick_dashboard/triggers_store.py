"""Dashboard-owned registry of inbound webhook triggers.

A trigger binds a saved template (plus operator-set default params) OR a flow
to a name. An HMAC-signed POST to ``/webhook/run`` with that name renders the
template and runs it as a goal (the inbound body may override *declared* params
at fire time), or -- for a flow target -- starts a durable flow run with the
inbound ``data`` as the run data.
Persisted to ``~/.maverick/dashboard-triggers.toml`` -- dashboard-owned,
like the Settings overlay, and deliberately NOT merged into the kernel config
(``load_config`` never reads it). Mirrors ``settings_store``'s atomic, 0600
write and hand-rolled TOML so we add no serialization dependency.

Params are stored as a JSON string inside the TOML table to avoid hand-rolling
nested tables; ``list_triggers`` decodes them back to a dict.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time

from maverick import config

# Serializes the triggers load-modify-save in-process; cross_process_lock in
# _locked() extends it across processes (multiple dashboard workers).
_TRIGGERS_LOCK = threading.Lock()


def _locked():
    from contextlib import ExitStack

    from maverick.file_lock import cross_process_lock
    with ExitStack() as stack:
        stack.enter_context(_TRIGGERS_LOCK)
        stack.enter_context(cross_process_lock(_path(), strict=True))
        return stack.pop_all()

# Trigger names are URL/TOML-safe slugs: they appear in the signed webhook body
# and as a bare TOML table key, so keep them to [a-z0-9-].
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_PARAM_RE = re.compile(r"^[A-Za-z_]\w{0,127}$")
_MAX_TEMPLATE_BODY = 100_000
_MAX_TEMPLATE_PARAMS = 128


def _tomllib():
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
        import tomli as tomllib  # type: ignore
    return tomllib


def _path():
    # Next to the Settings overlay (~/.maverick), resolved dynamically so a
    # patched HOME/MAVERICK_HOME (test isolation) is honored.
    return config.dashboard_overrides_path().parent / "dashboard-triggers.toml"


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", (name or "").strip().lower()).strip("-")
    return s[:48]


def _normalise_template_snapshot(snapshot: dict) -> dict:
    """Validate and canonicalise the immutable template execution surface."""
    if not isinstance(snapshot, dict):
        raise ValueError("template snapshot must be an object")
    name = str(snapshot.get("name") or "")
    title = str(snapshot.get("title") or "")
    body = str(snapshot.get("body") or "")
    if not name or len(name) > 80:
        raise ValueError("template snapshot name is invalid")
    if not title or len(title) > 10_000:
        raise ValueError("template snapshot title is invalid")
    if not body or len(body) > _MAX_TEMPLATE_BODY:
        raise ValueError("template snapshot body is invalid")
    raw_params = snapshot.get("params") or []
    if not isinstance(raw_params, list) or len(raw_params) > _MAX_TEMPLATE_PARAMS:
        raise ValueError("template snapshot params are invalid")
    params: list[str] = []
    for raw in raw_params:
        param = str(raw)
        if not _PARAM_RE.fullmatch(param) or param in params:
            raise ValueError("template snapshot params are invalid")
        params.append(param)
    try:
        budget_dollars = float(snapshot["budget_dollars"]) if snapshot.get("budget_dollars") is not None else None
        budget_wall_seconds = float(snapshot["budget_wall_seconds"]) if snapshot.get("budget_wall_seconds") is not None else None
    except (TypeError, ValueError):
        raise ValueError("template snapshot budgets are invalid") from None
    if any(v is not None and (not math.isfinite(v) or v < 0) for v in (budget_dollars, budget_wall_seconds)):
        raise ValueError("template snapshot budgets are invalid")
    return {
        "name": name,
        "title": title,
        "body": body,
        "params": params,
        # Bind the same governed execution ceilings used by workflow saves.
        "budget_dollars": budget_dollars,
        "budget_wall_seconds": budget_wall_seconds,
    }


def _snapshot_json(snapshot: dict) -> str:
    return json.dumps(
        _normalise_template_snapshot(snapshot),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _snapshot_revision(snapshot: dict) -> str:
    return hashlib.sha256(_snapshot_json(snapshot).encode("utf-8")).hexdigest()


def validated_template_snapshot(snapshot: dict) -> dict:
    """Public validator shared by other durable automation bindings."""
    return _normalise_template_snapshot(snapshot)


def snapshot_revision(snapshot: dict) -> str:
    """Content revision for a validated template execution snapshot."""
    return _snapshot_revision(snapshot)


def snapshot_from_template(template) -> dict:
    """Capture a parsed template as an immutable, bounded execution snapshot."""
    return _normalise_template_snapshot({
        "name": template.name,
        "title": template.title,
        "body": template.body,
        "params": list(template.params),
        "budget_dollars": template.budget_dollars,
        "budget_wall_seconds": template.budget_wall_seconds,
    })


def bound_template(trigger: dict):
    """Rebuild and verify the exact template revision bound to ``trigger``.

    Legacy/name-only or malformed rows are deliberately refused. Re-saving the
    trigger through the dashboard captures a safe immutable revision.
    """
    snapshot = trigger.get("template_snapshot")
    revision = str(trigger.get("template_revision") or "")
    if not isinstance(snapshot, dict) or not revision:
        raise ValueError("trigger has no immutable template binding")
    normalised = _normalise_template_snapshot(snapshot)
    if not hmac.compare_digest(_snapshot_revision(normalised), revision):
        raise ValueError("trigger template binding is invalid")
    if normalised["name"] != str(trigger.get("template") or ""):
        raise ValueError("trigger template binding does not match its target")
    from maverick.templates import Template

    return Template(**normalised)


def list_triggers(*, include_snapshot: bool = False, strict: bool = False) -> list[dict]:
    """Every registered trigger as ``{name, template, params, created}``."""
    p = _path()
    if not p.exists():
        return []
    try:
        with open(p, "rb") as f:
            raw = _tomllib().load(f)
    except (OSError, ValueError) as exc:
        if strict:
            raise RuntimeError("Connected starts could not be checked") from exc
        return []
    if not isinstance(raw.get("trigger") or {}, dict):
        if strict:
            raise RuntimeError("Connected starts could not be checked")
        return []
    out: list[dict] = []
    for name, t in (raw.get("trigger") or {}).items():
        if not isinstance(t, dict):
            if strict:
                raise RuntimeError("Connected starts could not be checked")
            continue
        try:
            params = json.loads(t.get("params") or "{}")
        except ValueError:
            params = {}
        try:
            template_snapshot = json.loads(t.get("template_snapshot") or "null")
        except ValueError:
            template_snapshot = None
        rec = {
            "name": name,
            "template": str(t.get("template") or ""),
            # Flow target: when set the webhook starts this flow instead of
            # rendering a template ("" for template triggers / pre-flow rows).
            "flow": str(t.get("flow") or ""),
            "params": params if isinstance(params, dict) else {},
            "created": float(t.get("created") or 0.0),
            # Owner principal that registered the trigger ("" for admin/auth-off
            # or triggers armed before owner tracking); used to scope the list.
            "owner": str(t.get("owner") or ""),
            # Durable namespace + flow-generation binding. Older rows decode to
            # empty values and are admitted only by the auth-off compatibility
            # rule at fire time.
            "tenant": str(t.get("tenant") or ""),
            "flow_owner": str(t.get("flow_owner") or ""),
            "flow_revision": str(t.get("flow_revision") or ""),
            # Safe to expose: identifies the immutable revision without
            # returning the potentially sensitive prompt body.
            "template_revision": str(t.get("template_revision") or ""),
        }
        if include_snapshot:
            rec["template_snapshot"] = (
                template_snapshot if isinstance(template_snapshot, dict) else None
            )
        out.append(rec)
    out.sort(key=lambda t: (t["created"], t["name"]))
    return out


def get_trigger(name: str) -> dict | None:
    for t in list_triggers(include_snapshot=True):
        if t["name"] == name:
            return t
    return None


def _dump(triggers: list[dict]) -> str:
    lines = [
        "# Dashboard-managed inbound webhook triggers. Edit via the workflow",
        "# builder, not by hand. Your config.toml is never touched.",
        "",
    ]
    for t in sorted(triggers, key=lambda x: x["name"]):
        params_json = json.dumps(t.get("params") or {}, sort_keys=True)
        lines.append(f"[trigger.{t['name']}]")
        lines.append(f"template = {json.dumps(str(t['template']))}")
        lines.append(f"flow = {json.dumps(str(t.get('flow') or ''))}")
        lines.append(f"params = {json.dumps(params_json)}")
        lines.append(f"created = {float(t.get('created') or 0.0)}")
        lines.append(f"owner = {json.dumps(str(t.get('owner') or ''))}")
        lines.append(f"tenant = {json.dumps(str(t.get('tenant') or ''))}")
        lines.append(f"flow_owner = {json.dumps(str(t.get('flow_owner') or ''))}")
        lines.append(f"flow_revision = {json.dumps(str(t.get('flow_revision') or ''))}")
        snapshot = t.get("template_snapshot")
        snapshot_json = _snapshot_json(snapshot) if isinstance(snapshot, dict) else "null"
        lines.append(f"template_snapshot = {json.dumps(snapshot_json)}")
        lines.append(f"template_revision = {json.dumps(str(t.get('template_revision') or ''))}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write(triggers: list[dict]) -> None:
    # Unique temp + os.replace (0600): the fixed ".toml.tmp" collided between two
    # concurrent workers. RMW serialization is in the mutators via _locked().
    from maverick.file_lock import atomic_write_text
    atomic_write_text(_path(), _dump(triggers))


def set_trigger(
    name: str, template: str, params: dict | None = None, owner: str = "",
    flow: str = "", tenant: str = "", flow_owner: str = "",
    flow_revision: str = "", template_snapshot: dict | None = None,
) -> dict:
    """Create or replace a trigger (by slugified name). Raises ValueError on a
    name that can't be made into a valid slug. ``owner`` records the principal
    that registered it so the dashboard can scope the list per tenant. Exactly
    one of ``template`` / ``flow`` should be set (the API layer enforces it).
    Raises RuntimeError, writing nothing, when the existing file cannot be
    parsed: saving over it would drop every other trigger."""
    slug = slugify(name)
    if not _NAME_RE.match(slug):
        raise ValueError("trigger name must contain a letter or digit (a-z, 0-9, -)")
    normalised_snapshot = None
    template_revision = ""
    if template_snapshot is not None:
        if flow:
            raise ValueError("flow triggers cannot include a template snapshot")
        normalised_snapshot = _normalise_template_snapshot(template_snapshot)
        if normalised_snapshot["name"] != str(template):
            raise ValueError("template snapshot does not match the trigger target")
        template_revision = _snapshot_revision(normalised_snapshot)
    rec = {
        "name": slug,
        "template": str(template),
        "flow": str(flow or ""),
        "params": {str(k): str(v) for k, v in (params or {}).items()},
        "created": time.time(),
        "owner": str(owner or ""),
        "tenant": str(tenant or ""),
        "flow_owner": str(flow_owner or ""),
        "flow_revision": str(flow_revision or ""),
        "template_snapshot": normalised_snapshot,
        "template_revision": template_revision,
    }
    with _locked():
        kept = [
            t for t in list_triggers(include_snapshot=True, strict=True)
            if t["name"] != slug
        ]
        kept.append(rec)
        _write(kept)
    return rec


def delete_trigger(name: str, owner: str | None = None) -> bool:
    """Remove a trigger by name. When ``owner`` is given, delete only if the
    trigger belongs to that owner (returns False otherwise) -- the ownership
    check and removal happen under one lock, so there is no read-then-delete
    race and only a single file read. ``owner=None`` (admin / auth-off) deletes
    regardless of owner. Like ``set_trigger`` it raises RuntimeError rather
    than rewrite a file it could not parse."""
    with _locked():
        triggers = list_triggers(include_snapshot=True, strict=True)
        match = next((t for t in triggers if t["name"] == name), None)
        if match is None or (owner is not None and match.get("owner", "") != owner):
            return False
        _write([t for t in triggers if t["name"] != name])
    return True
