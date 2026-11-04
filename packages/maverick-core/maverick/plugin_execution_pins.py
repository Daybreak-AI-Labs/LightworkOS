"""Durable per-task and per-flow-run plugin bytes; no automatic migration."""
from __future__ import annotations

import json
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .paths import data_dir

_flow = ContextVar("plugin_flow_execution", default=None)


@contextmanager
def flow_scope(run_id, owner, revision):
    token = _flow.set({"run_id": run_id, "owner": owner or "", "revision": revision or ""})
    try:
        yield
    finally:
        _flow.reset(token)


def flow_path(run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise ValueError("Invalid workflow run identity.")
    return data_dir() / "plugin-flow-pins" / (run_id + ".json")


def pin_key(group, name, distribution):
    return distribution + ":" + name if group in {"maverick.tools", "maverick.ts"} else group + ":" + distribution + ":" + name


def check_pin(group, name, distribution, fingerprint):
    from .audit.writer import _current_goal
    from .connections import current_principal

    flow = _flow.get()
    goal = _current_goal.get()
    if flow is not None:
        path = flow_path(flow["run_id"])
        identity = {**flow, "scope": "flow"}
    elif goal is not None:
        path = data_dir() / "plugin-task-pins" / (str(int(goal)) + ".json")
        identity = {"goal_id": goal, "owner": current_principal() or "", "scope": "task"}
    else:
        return  # No durable work record exists; the constructed instance still verifies its bytes.
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        pins = json.loads(atomic_read_text(path, encoding="utf-8")) if path.exists() else {}
        key = pin_key(group, name, distribution)
        existing = pins.get(key)
        if existing and (existing["fingerprint"] != fingerprint or existing["owner"] != identity["owner"]
                or (flow is not None and existing.get("revision") != identity["revision"])):
            raise PermissionError("This work retains an earlier plugin version. Review migration; no action was dispatched.")
        pins[key] = {**(existing or {}), **identity, "group": group, "fingerprint": fingerprint,
                     "distribution": distribution, "name": name, "updated_at": time.time()}
        atomic_write_text(path, json.dumps(pins, sort_keys=True))


def entry_guard(group, name, distribution, fingerprint):
    from . import plugins
    from .plugin_lock import _dist_content_hash
    from .plugin_workbench import config

    config()
    entries = list(plugins._entry_points(group))
    entry = next((item for item in entries if item.name == name and plugins._ep_dist_name(item) == distribution), None)
    granted, enforce = plugins._permission_policy()
    if entry is None or not plugins._gate(entry, group, plugins._allowed_plugin_names(), plugins._name_dist_map(entries), granted, enforce):
        raise PermissionError("Current plugin policy no longer permits this implementation.")
    if _dist_content_hash(distribution) != fingerprint:
        raise PermissionError("Plugin bytes changed. Review its pinned version before continuing.")
    check_pin(group, name, distribution, fingerprint)


def bind_entry(group, name, distribution, target):
    from .plugin_lock import _dist_content_hash

    fingerprint = _dist_content_hash(distribution)
    if not fingerprint:
        raise ValueError("Plugin bytes cannot be pinned.")
    def guard():
        entry_guard(group, name, distribution, fingerprint)
    if group == "maverick.skills":
        import copy

        target = copy.copy(target)
        target._plugin_binding = (group, name, distribution, fingerprint)
        return target
    if group == "maverick.personas":
        def render():
            guard()
            return target()
        return render
    if group == "maverick.channels":
        class BoundChannel(target):
            def __init__(self, *args, **kwargs):
                guard()
                super().__init__(*args, **kwargs)
            async def start(self):
                guard()
                return await super().start()
            async def send(self, *args, **kwargs):
                guard()
                return await super().send(*args, **kwargs)
            async def send_threaded(self, *args, **kwargs):
                guard()
                return await super().send_threaded(*args, **kwargs)
            async def dispatch(self, *args, **kwargs):
                guard()
                return await super().dispatch(*args, **kwargs)
            # stop remains available after revocation so owned cleanup can finish.
        return BoundChannel
    raise ValueError("Unsupported plugin entry kind.")


def check_skill(skill):
    binding = getattr(skill, "_plugin_binding", None)
    if binding is not None:
        entry_guard(*binding)
