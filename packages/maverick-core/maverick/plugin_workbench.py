"""Version-bound plugin checks; no imports or external effects on the host.

A check may run only in a locally reviewed immutable Linux image through the
strict research runner. The image must contain the exact installed distribution.
A completed sample is scoped sandbox evidence, never live-service acceptance.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import time
from contextlib import contextmanager
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .paths import data_dir


def config():
    from .config import config_source_errors, load_config

    if config_source_errors(include_tenant=True):
        raise PermissionError("Plugin qualification policy is unavailable. Repair Settings.")
    value = (load_config().get("plugins") or {})
    if value.get("workbench", False) is not True:
        raise PermissionError("Enable the plugin qualification workbench in Settings.")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def snapshot():
    from dataclasses import asdict

    from . import plugins
    from .plugin_lock import _dist_content_hash

    policy = config()
    harness = hashlib.sha256(b"".join((Path(__file__).parent / "sandbox" / name).read_bytes()
        for name in ("plugin_probe.py", "plugin_contracts.py"))).hexdigest()
    rows = []
    allow, (granted, enforce) = plugins._allowed_plugin_names(), plugins._permission_policy()
    for group in plugins._PLUGIN_GROUPS:
        entries = list(plugins._entry_points(group))
        for ep in entries:
            manifest = plugins._find_manifest(ep)
            dist = plugins._ep_dist_name(ep)
            row = {"group": group, "name": ep.name, "distribution": dist or "", "entry": ep.value,
                   "version": str(getattr(getattr(ep, "dist", None), "version", "") or ""),
                   "content_sha256": _dist_content_hash(dist) if dist else None,
                   "sandbox_content_sha256": _dist_content_hash(dist, portable_paths=True) if dist else None,
                   "manifest": asdict(manifest) if manifest else None,
                   "missing_permissions": plugins._permission_violations(manifest, granted),
                   "permission_enforcement": enforce, "qualification_image": policy.get("workbench_image", ""),
                   "harness_sha256": harness}
            try:
                row["policy_allowed"] = plugins._gate(ep, group, allow, plugins._name_dist_map(entries), granted, enforce)
                # Negative control: the same runtime gate rejects a denied entry
                # before ep.load. This is host admission evidence, not a claim
                # that arbitrary plugin code obeys its declared permissions.
                row["permission_denial_checked"] = not plugins._gate(ep, group, set(), plugins._name_dist_map(entries), set(), True)
            except Exception:
                row["policy_allowed"] = row["permission_denial_checked"] = False
            row["eligible"] = bool(row["policy_allowed"] and manifest
                and manifest.is_compatible() and not manifest.warnings and not row["missing_permissions"]
                and row["content_sha256"] and row["sandbox_content_sha256"] and row["version"])
            row["fingerprint"] = _digest(row)
            row["scope"] = {"maverick.tools": "Python tool schema and invocation",
                "maverick.channels": "Channel lifecycle, normalized dispatch and send",
                "maverick.skills": "Skill lexical selection and prompt rendering",
                "maverick.personas": "Persona prompt rendering"}[group] + " in the restricted container; no live-service acceptance."
            row["sample_example"] = {"maverick.tools": {}, "maverick.personas": {},
                "maverick.skills": {"goal": "synthetic trigger phrase"},
                "maverick.channels": {"user_id": "synthetic-user", "text": "synthetic input", "reply": "synthetic reply", "startup_seconds": 0}}[group]
            rows.append(row)
    from .plugin_workbench_ts import rows as node_rows

    rows.extend(node_rows(policy, harness, _digest))
    from .plugin_workbench_grpc import rows as grpc_rows
    rows.extend(grpc_rows(policy, harness, _digest))
    return rows


def selected(fingerprint):
    item = next((row for row in snapshot() if row["fingerprint"] == fingerprint), None)
    if item is None:
        raise ValueError("Plugin bytes, version or policy changed. Review the current plugin.")
    return item


def _path(context):
    if not re.fullmatch(r"[a-f0-9]{64}", context):
        raise ValueError("invalid account context")
    return data_dir() / "plugin-workbench" / (context + ".json")


def _read(path):
    if not path.exists():
        return {"schema": 1, "checks": {}, "publications": []}
    value = json.loads(atomic_read_text(path, encoding="utf-8"))
    if value.get("schema") != 1 or not isinstance(value.get("checks"), dict):
        raise ValueError("Qualification history is unavailable; no action was started.")
    return value


def _edit(context, mutate):
    path = _path(context)
    ensure_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        state = _read(path)
        result = mutate(state)
        atomic_write_text(path, json.dumps(state, sort_keys=True))
        return result


def history(context):
    state = _read(_path(context))
    fingerprints = {row["fingerprint"] for row in snapshot()}
    return {"checks": [{**row, "current": row["fingerprint"] in fingerprints}
                        for row in state["checks"].values()],
            "publications": [{**row, "current": row["fingerprint"] in fingerprints}
                             for row in state["publications"]]}


def cancel(context, operation):
    def mutate(state):
        row = state["checks"].get(operation)
        if row is None:
            raise LookupError("This check is not recorded. Refresh before another request.")
        if row["state"] == "running_or_interrupted":
            row["cancel_requested"] = True
        return row
    return _edit(context, mutate)


def _cancelled(context, operation):
    return bool(_read(_path(context))["checks"][operation].get("cancel_requested"))


def _check_files(row, payload):
    directory = Path(__file__).parent / "sandbox"
    files = {"main.py": (directory / "plugin_probe.py").read_bytes(),
             "plugin_contracts.py": (directory / "plugin_contracts.py").read_bytes()}
    if row.get("group") == "maverick.ts":
        from .plugin_workbench_ts import configured_command, source
        payload["source_suffix"] = row["source_suffix"]
        contents = source(configured_command(row["command_identity"]))
        if hashlib.sha256(contents).hexdigest() != row["content_sha256"]:
            raise ValueError("Node source changed before dispatch.")
        files["plugin" + row["source_suffix"]] = contents
    if row.get("group") == "maverick.grpc":
        from .plugin_workbench_grpc import current, source
        value = current(row["command_identity"])
        contents, runtime, suffix = source(value)
        if hashlib.sha256(contents).hexdigest() != row["content_sha256"]:
            raise ValueError("gRPC server source changed before dispatch.")
        payload.update(source_suffix=suffix, runtime=runtime, target=value["target"])
        files["plugin" + suffix] = contents
    files["sample.json"] = json.dumps(payload, allow_nan=False).encode()
    return files


def run_check(context, operation, fingerprint, sample, mode, *, authorize, expected=None, input_schema_sha256=None):
    from .budget import Budget
    from .sandbox.research import ResearchContainerRunner, ResearchLimits

    authorize()
    policy = config()
    row = selected(fingerprint)
    if not row["eligible"]:
        raise ValueError("This plugin needs a valid compatible manifest, current permission approval and inspectable installed bytes before a sandbox check.")
    if not re.fullmatch(r"[a-f0-9]{32}", operation) or mode not in {"sample", "timeout", "cancellation"}:
        raise ValueError("Choose a supported check and a new operation identifier.")
    if type(sample) is not dict or len(json.dumps(sample, allow_nan=False).encode()) > 16384:
        raise ValueError("Use an object sample smaller than 16 KiB; do not include credentials or private production data.")
    if len(json.dumps(expected, allow_nan=False).encode()) > 16384:
        raise ValueError("Expected sample result must be smaller than 16 KiB.")
    if input_schema_sha256 is not None and not re.fullmatch(r"[a-f0-9]{64}", input_schema_sha256):
        raise ValueError("Review the exact practice questions before starting this check.")
    expected_result = hashlib.sha256(json.dumps(expected, sort_keys=True, allow_nan=False).encode()).hexdigest()
    image = str(policy.get("workbench_image") or "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Select a locally installed, reviewed immutable Linux image in Settings. No image is downloaded and host execution is forbidden.")
    initial = {"id": operation, "fingerprint": fingerprint, "plugin": row["name"], "distribution": row["distribution"],
               "version": row["version"], "mode": mode, "started_at": time.time(), "state": "running_or_interrupted",
               "sample_sha256": _digest(sample), "expected_result_sha256": expected_result, "input_schema_sha256": input_schema_sha256,
               "attempts": 0, "replay": "never", "external_outcome": "unknown"}
    def reserve(state):
        if operation in state["checks"]:
            raise ValueError("This operation was already recorded. Refresh its result; it will not be replayed.")
        if len(state["checks"]) >= 1000:
            raise ValueError("This account's qualification ledger reached its 1000-check limit. Retain/export its evidence before an administrator reviews retention.")
        state["checks"][operation] = initial
    _edit(context, reserve)
    started = time.monotonic()
    def interrupted():
        return _cancelled(context, operation) or (mode == "cancellation" and time.monotonic() - started >= 5)
    @contextmanager
    def guard():
        authorize()
        selected(fingerprint)
        if _cancelled(context, operation):
            raise PermissionError("Check was cancelled before dispatch.")
        yield
    try:
        payload = {"group": row.get("group", "maverick.tools"), "entry": row["entry"], "distribution": row["distribution"], "version": row["version"],
                   "content_sha256": row.get("sandbox_content_sha256") or row["content_sha256"], "operation": operation,
                   "sample": sample, "input_schema_sha256": input_schema_sha256}
        files = _check_files(row, payload)
        result = ResearchContainerRunner(image, limits=ResearchLimits(timeout_seconds=0.5 if mode == "timeout" else 15)).run(
            files,
            budget=Budget(max_wall_seconds=45, max_tool_calls=1, max_dollars=0), effect_guard=guard, cancelled=interrupted)
        authorize()
        selected(fingerprint)
        observed, dispatched = {}, False
        for line in result.stdout.splitlines():
            try:
                frame = json.loads(line)
            except ValueError:
                continue
            if not isinstance(frame, dict) or frame.get("operation") != operation:
                continue
            if frame.get("phase") == "dispatch":
                dispatched = True
            elif frame.get("phase") == "result" and result.reason == "completed" and result.exit_code == 0:
                observed = frame
        completed = bool(dispatched and result.reason == "completed" and result.exit_code == 0
            and observed.get("schema_valid") is True and observed.get("sample_valid") is True
            and observed.get("completed") is True and observed.get("content_sha256") == payload["content_sha256"]
            and observed.get("result_sha256") == expected_result)
        interrupted_after_dispatch = bool(dispatched and ((mode == "timeout" and result.reason == "timeout")
            or (mode == "cancellation" and result.reason == "cancelled")))
        passed = bool(result.cleanup_verified and (completed or interrupted_after_dispatch))
        final = {"state": "passed_scoped_check" if passed else "not_qualified", "finished_at": time.time(),
                 "reason": result.reason, "attempts": 1, "plugin_dispatch_observed": dispatched, "cleanup_verified": result.cleanup_verified,
                 "image_id": result.image_id, "policy_sha256": result.policy_sha256,
                 "permission_denial_checked": row["permission_denial_checked"],
                 "completion_observed": completed, "interruption_observed": interrupted_after_dispatch,
                 "check_observation": "exact result completed before interruption" if completed and mode != "sample" else ("interruption after dispatch" if interrupted_after_dispatch else result.reason),
                 "schema_valid": observed.get("schema_valid") is True,
                 "result_sha256": observed.get("result_sha256") if mode == "sample" else None,
                 "invocation_outcome": "completed" if observed.get("completed") is True else "unknown",
                 "external_outcome": "not attempted: no network or credentials" if result.reason == "completed" and result.exit_code == 0 else "unknown; no replay",
                 "scope": "Restricted-container behavior only. No live service or write capability was accepted."}
    except Exception:
        final = {"state": "not_qualified", "finished_at": time.time(), "reason": "check unavailable or authority changed",
                 "external_outcome": "unknown; no replay", "scope": "Review current plugin policy, local container readiness and immutable image. Do not retry an uncertain operation."}
    def finish(state):
        state["checks"][operation].update(final)
        return state["checks"][operation]
    return _edit(context, finish)


def publish(context, fingerprint, rollback, *, authorize, operation=None):
    authorize()
    selected(fingerprint)
    if not isinstance(rollback, str) or not 10 <= len(rollback.strip()) <= 2000:
        raise ValueError("Record a concrete rollback and affected-work review plan (10-2000 characters).")
    def mutate(state):
        authorize()
        selected(fingerprint)
        if operation is not None:
            if not re.fullmatch(r"[a-f0-9]{32}", operation):
                raise ValueError("Invalid publication operation identifier.")
            previous = next((row for row in state["publications"] if row.get("operation_id") == operation), None)
            if previous is not None:
                return previous
        checks = [row for row in state["checks"].values() if row["fingerprint"] == fingerprint
                  and row["state"] == "passed_scoped_check" and row.get("cleanup_verified")
                  and row.get("permission_denial_checked")]
        if {row["mode"] for row in checks} != {"sample", "timeout", "cancellation"}:
            raise ValueError("A current sample, timeout and cancellation check must pass before publishing scoped readiness.")
        receipt = {"fingerprint": fingerprint, "created_at": time.time(), "rollback": rollback, "operation_id": operation,
                   "checks": [row["id"] for row in checks], "scope": "sandbox-only; external read/write acceptance unverified",
                   "observations": [{"mode": row["mode"], "completion_observed": bool(row.get("completion_observed")),
                                     "interruption_observed": bool(row.get("interruption_observed"))} for row in checks]}
        state["publications"].append(receipt)
        return receipt
    return _edit(context, mutate)


def pinned_factory(name, distribution, factory):
    """Keep each already constructed task tool bound to its installed bytes.

    Goal pins survive a restart. Drift refuses dispatch; this never swaps in a
    newly installed implementation or replays the old operation automatically.
    """
    from .plugin_lock import _dist_content_hash

    fingerprint = _dist_content_hash(distribution)
    if not fingerprint:
        raise ValueError("Plugin bytes cannot be pinned for this task.")
    def construct():
        if _dist_content_hash(distribution) != fingerprint:
            raise PermissionError("Plugin changed before tool construction. Review its current version.")
        def check():
            config()
            from . import plugins

            entries = list(plugins._entry_points("maverick.tools"))
            entry = next((ep for ep in entries if ep.name == name and plugins._ep_dist_name(ep) == distribution), None)
            grants, enforce = plugins._permission_policy()
            if entry is None or not plugins._gate(entry, "maverick.tools", plugins._allowed_plugin_names(), plugins._name_dist_map(entries), grants, enforce):
                raise PermissionError("Current plugin policy no longer permits this task tool.")
            if _dist_content_hash(distribution) != fingerprint:
                raise PermissionError("Plugin version changed. Restore its pinned version or explicitly review migration before resuming this task.")
            from .plugin_execution_pins import check_pin

            check_pin("maverick.tools", name, distribution, fingerprint)
        check()
        tool = factory()
        original = tool.fn
        if inspect.iscoroutinefunction(original):
            async def invoke(args):
                check()
                return await original(args)
        else:
            def invoke(args):
                check()
                return original(args)
        tool.fn = invoke
        return tool
    return construct
