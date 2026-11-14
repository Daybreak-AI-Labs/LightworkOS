"""Immutable workflow snapshots, reviewed publication and local input fixtures.

Fixture checking only renders strings. It never invokes the model, a tool,
worker, or connector. Publication does not migrate an existing schedule.
"""
from __future__ import annotations

import hashlib
import json
import time

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .templates import Template, _validate_template_name, load_template, user_templates_dir


def enabled():
    from ._envparse import coerce_bool
    from .config import config_source_errors, load_config

    # A string such as "true" (or an unrecognized value) keeps the review gate
    # on; only an explicit false turns it off.
    value = (load_config().get("workflows") or {}).get("versioning", True)
    return not config_source_errors(include_tenant=True) and coerce_bool(value, default=True)


def _path(name):
    _validate_template_name(name)
    return user_templates_dir() / ".versions" / (name + ".json")


def _load(name):
    path = _path(name)
    if not path.exists():
        return {"schema": 1, "published": None, "snapshots": {}, "events": [], "fixtures": []}
    value = json.loads(atomic_read_text(path, encoding="utf-8"))
    if value.get("schema") != 1 or not isinstance(value.get("snapshots"), dict):
        raise ValueError("Workflow history is unavailable. No version was changed.")
    return value


def _save(name, value, *, effect_guard=None):
    path = _path(name)
    ensure_private_directory(path.parent)
    if effect_guard is None:
        atomic_write_text(path, json.dumps(value, ensure_ascii=True, sort_keys=True))
    else:
        atomic_write_text(path, json.dumps(value, ensure_ascii=True, sort_keys=True), effect_guard=effect_guard)


def _snapshot(state, content, name):
    digest = hashlib.sha256(content.encode()).hexdigest()
    if digest not in state["snapshots"]:
        template = Template.parse(content, name)
        state["snapshots"][digest] = {"content": content, "generation": template.generation,
                                     "label": "Version " + str(template.generation), "created_at": time.time()}
    return digest


def before_save(name, content, previous=None, *, effect_guard=None):
    """Called under the template lock before publishing the draft file.

    An interrupted file write can leave a prepared snapshot in history, but
    cannot alter the current draft or published pointer. Content hashes never
    get overwritten or reused for a different draft.
    """
    if not enabled():
        return
    first_history = not _path(name).exists()
    state = _load(name)
    if previous is not None:
        prior = _snapshot(state, previous, name)
        if first_history:
            state["published"] = prior
            state["events"].append({"kind": "adopted", "version": prior, "at": time.time(), "actor": "system"})
    _snapshot(state, content, name)
    if effect_guard is None:
        _save(name, state)
    else:
        _save(name, state, effect_guard=effect_guard)


def _current(name, actor, *, admin=False):
    template = load_template(name)
    # Retain the keyword for callers; administrative policy authority is not
    # authority over a person's unpublished drafts and private fixtures.
    del admin
    if template.owner != actor:
        raise PermissionError("Only the workflow owner can review or change its private version history.")
    content = atomic_read_text(template.path, encoding="utf-8")
    return template, hashlib.sha256(content.encode()).hexdigest(), content


def history(name, actor, *, admin=False):
    _validate_template_name(name)
    with cross_process_lock(user_templates_dir() / (name + ".md"), strict=True):
        template, current, content = _current(name, actor, admin=admin)
        state = _load(name)
        _snapshot(state, content, name)
        return {"name": name, "current": current, "generation": template.generation,
                "params": template.params, "parameter_schema": template.parameter_schema,
                "published": state["published"], "versions": [dict(version=key, **value,
                    current=key == current, published=key == state["published"])
                    for key, value in state["snapshots"].items()], "events": state["events"],
                "fixtures": [{k: v for k, v in item.items() if k != "inputs"} for item in state["fixtures"]],
                "fixture_scope": "Input validation and rendered output only; no model, tool, or external write is executed."}


def record_fixture(name, actor, *, expected_version, inputs, expected_contains="", label="Sample", admin=False):
    _validate_template_name(name)
    if not enabled():
        raise PermissionError("Workflow version management is disabled in Settings.")
    if len(json.dumps(inputs)) > 32000 or len(expected_contains) > 4000:
        raise ValueError("Use a smaller reviewed sample.")
    with cross_process_lock(user_templates_dir() / (name + ".md"), strict=True):
        template, current, content = _current(name, actor, admin=admin)
        if current != expected_version:
            raise FileExistsError("The draft changed. Review the current version before checking the sample.")
        title, body = template.render_for(actor, **inputs)
        passed = not expected_contains or expected_contains in body
        state = _load(name)
        _snapshot(state, content, name)
        result = {"version": current, "label": label[:100], "inputs": inputs,
                  "expected_contains": expected_contains, "passed": passed, "at": time.time(),
                  "actor": actor, "scope": "render-only", "external_actions": 0}
        state["fixtures"].append(result)
        state["fixtures"] = state["fixtures"][-50:]
        _save(name, state)
        return {**{k: v for k, v in result.items() if k != "inputs"}, "title": title, "body": body}


def publish(name, actor, *, expected_version, label, admin=False):
    _validate_template_name(name)
    if not enabled():
        raise PermissionError("Workflow version management is disabled in Settings.")
    if not label.strip() or len(label) > 100:
        raise ValueError("Name this publication in 100 characters or fewer.")
    with cross_process_lock(user_templates_dir() / (name + ".md"), strict=True):
        _, current, content = _current(name, actor, admin=admin)
        if current != expected_version:
            raise FileExistsError("The draft changed. Review and check the current version before publishing.")
        state = _load(name)
        _snapshot(state, content, name)
        if not any(item["version"] == current and item["passed"] for item in state["fixtures"]):
            raise ValueError("Check a reviewed input fixture for this draft before publishing.")
        state["snapshots"][current]["label"] = label.strip()
        state["published"] = current
        state["events"].append({"kind": "published", "version": current, "actor": actor, "at": time.time()})
        _save(name, state)
        return {"published": current, "label": label.strip(), "schedules_migrated": 0}


def restore(name, version, actor, *, expected_generation, new_name=None, admin=False):
    """Restore as a new draft; publication and admitted work are unchanged."""
    from .templates import save_user_template

    _validate_template_name(name)
    if not enabled():
        raise PermissionError("Workflow version management is disabled in Settings.")
    _validate_template_name(name)
    with cross_process_lock(user_templates_dir() / (name + ".md"), strict=True):
        _, current, content = _current(name, actor, admin=admin)
        state = _load(name)
        _snapshot(state, content, name)
        selected = state["snapshots"].get(version)
        if selected is None:
            raise ValueError("That version is unavailable.")
        template = Template.parse(selected["content"], name)
    # save_user_template performs the generation/owner check under its own
    # lock, so a concurrent edit cannot be overwritten by a stale restoration.
    return save_user_template(new_name or name, title=template.title, body=template.body,
        params=template.params, parameter_schema=template.parameter_schema,
        budget_dollars=template.budget_dollars, budget_wall_seconds=template.budget_wall_seconds,
        owner=actor if new_name else (template.owner or actor), admin_override=admin,
        overwrite=not bool(new_name), expected_generation=None if new_name else expected_generation)


def execution_template(name):
    """Resolve a publication for a new schedule; its rendered body is then pinned."""
    from .config import config_source_errors

    if config_source_errors(include_tenant=True):
        raise ValueError("Workflow policy is unavailable. Repair Settings before starting work.")
    if not enabled() or not _path(name).exists():
        template = load_template(name)
        return template, ""
    with cross_process_lock(user_templates_dir() / (name + ".md"), strict=True):
        state = _load(name)
        version = state["published"]
        if not version:
            raise ValueError("Publish a reviewed version in Workflow builder before scheduling it.")
        selected = state["snapshots"].get(version)
        if selected is None:
            raise ValueError("The published workflow snapshot is unavailable.")
        return Template.parse(selected["content"], name), version
