"""Exact, owner-selected account inputs. A selection is a restriction, never a grant."""
from __future__ import annotations

import base64
import contextlib
import contextvars
import json

from .paths import current_tenant_id_strict

_active = contextvars.ContextVar("template_connection_selection", default=None)
_FIELDS = {"name", "revision", "connector", "owner", "tenant"}


class SelectionUnavailable(ValueError):
    pass


def _authority(actor):
    from maverick_dashboard import auth, rbac

    from . import connections
    from .config import config_source_errors, load_config
    from .personal_identity import principal_current

    tenant = current_tenant_id_strict()
    if (config_source_errors(include_tenant=True) or not connections.enabled()
            or load_config().get("workflows", {}).get("typed_inputs", True) is not True
            or not principal_current(actor)):
        raise SelectionUnavailable("Connected account inputs require enabled Connections and your current named workspace account.")
    role = rbac.get_tenant_role(tenant, actor) if tenant else auth.global_role_for_principal(actor)
    if "operate" not in rbac.permissions_for(role):
        raise SelectionUnavailable("Current permission to run tasks is required for this account selection.")


def encode(reference):
    return "lwconn1." + base64.urlsafe_b64encode(json.dumps(reference, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")


def decode(value):
    try:
        if not isinstance(value, str) or not value.startswith("lwconn1.") or len(value) > 2048:
            raise ValueError
        raw = value.split(".", 1)[1]
        reference = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if (not isinstance(reference, dict) or set(reference) != _FIELDS
                or any(not isinstance(v, str) or len(v) > 256 for v in reference.values())
                or any(not reference[k] for k in _FIELDS - {"tenant"})):
            raise ValueError
        return reference
    except (ValueError, TypeError, UnicodeError) as exc:
        raise SelectionUnavailable("Choose a current connected account from the list.") from exc


def _reference(record, actor):
    return {"name": record["name"], "revision": record["revision"], "connector": record["connector"],
            "owner": actor, "tenant": current_tenant_id_strict() or ""}


def _supported(connector):
    from .tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES, READ_CONNECTOR_NAMES
    return connector in {"gdrive", *ENTERPRISE_CONNECTOR_NAMES, *READ_CONNECTOR_NAMES}


def choices(actor):
    from .connections import list_connections
    _authority(actor)
    return [{"value": encode(_reference(rec, actor)), "name": rec["name"], "connector": rec["connector"]}
            for rec in list_connections(owner=actor)
            if _supported(rec.get("connector")) and rec.get("has_token") and rec.get("revision")
            and (not rec.get("oauth") or rec["oauth"].get("available") is True)]


def validate(actor, references):
    if not isinstance(references, list) or len(references) > 100:
        raise SelectionUnavailable("Choose at most 100 connected accounts.")
    if not references:
        return []
    from .connections import list_connections
    _authority(actor)
    current = {rec["name"]: rec for rec in list_connections(owner=actor)}
    result, providers = [], {}
    for supplied in references:
        ref = decode(encode(supplied))
        rec = current.get(ref["name"])
        if (not rec or not _supported(rec.get("connector")) or ref != _reference(rec, actor) or not rec.get("has_token")
                or rec.get("oauth") and rec["oauth"].get("available") is not True):
            raise SelectionUnavailable("A selected account or its permissions changed. Return to the template and select your current account again.")
        if ref["connector"] in providers and providers[ref["connector"]] != ref["name"]:
            raise SelectionUnavailable("Choose one account per service so execution cannot select an ambiguous account.")
        providers[ref["connector"]] = ref["name"]
        if ref not in result:
            result.append(ref)
    return result


def parameters(template, actor, values):
    from .template_parameters import resolve_parameters
    resolved = resolve_parameters(template.params, template.parameter_schema, values)
    selected = {key: decode(resolved[key]) for key, field in template.parameter_schema.get("fields", {}).items()
                if field["type"] == "connection" and resolved.get(key)}
    refs = validate(actor, list(selected.values()))
    for key, ref in selected.items():
        resolved[key] = ref["name"] + " (" + ref["connector"] + ")"
    return resolved, refs


def packed(actor, references):
    refs = validate(actor, references)
    return json.dumps({"owner": actor, "tenant": current_tenant_id_strict() or "", "references": refs}, sort_keys=True) if refs else ""


def for_goal(world, goal_id):
    """Read through parents, so subagents and chat continuations retain the ceiling."""
    seen, selected, owner = set(), [], None
    while goal_id:
        if goal_id in seen or len(seen) >= 100:
            raise SelectionUnavailable("Task account ancestry could not be verified.")
        seen.add(goal_id)
        goal = world.get_goal(goal_id)
        if goal is None:
            if len(seen) == 1:
                return []
            raise SelectionUnavailable("The selected account's task is unavailable.")
        owner = goal.owner if owner is None else owner
        raw = world.goal_connection_selection(goal_id)
        if raw:
            try:
                record = json.loads(raw)
                if record["owner"] != owner or record["owner"] != goal.owner or record["tenant"] != (current_tenant_id_strict() or ""):
                    raise ValueError
                selected.extend(record["references"])
            except (ValueError, KeyError, TypeError) as exc:
                raise SelectionUnavailable("Task account binding could not be verified. Prepare a new reviewed task.") from exc
        goal_id = goal.parent_id
    return validate(owner, selected)


@contextlib.contextmanager
def bind_goal(world, goal_id, principal):
    refs = for_goal(world, goal_id)
    if refs and refs[0]["owner"] != principal:
        raise SelectionUnavailable("This account selection belongs to a different execution identity.")
    token = _active.set(refs or None)
    try:
        yield
    finally:
        _active.reset(token)


def active():
    return _active.get() is not None


def selected(connector, actor):
    refs = _active.get()
    if refs is None:
        return None
    refs = validate(actor, refs)
    matching = [ref for ref in refs if ref["connector"] == connector or ref["name"] == connector]
    if len(matching) != 1:
        raise SelectionUnavailable("This task has no unambiguous selected account for this service.")
    return matching[0]


def recheck_active():
    refs = _active.get()
    if refs:
        validate(refs[0]["owner"], refs)
