"""Exact restricted-container contracts for ordinary plugin practice forms.

Inspection never grants readiness and never invokes a declared tool action.
Uncertain inspections are retained, not retried with the same identity.
"""
from __future__ import annotations

import json
import re
import time
from contextlib import contextmanager

from . import plugin_workbench as workbench

MAX_CONTRACT_BYTES = 192 * 1024


def _contracts(value):
    if type(value) is not list or not 1 <= len(value) <= 20:
        raise ValueError("This plugin's practice questions could not be verified.")
    if len(json.dumps(value, allow_nan=False).encode()) > MAX_CONTRACT_BYTES:
        raise ValueError("This plugin has too many practice questions for a guided form.")
    from .sandbox.plugin_contracts import validator

    names = set()
    for item in value:
        if (type(item) is not dict or set(item) != {"name", "input_schema"}
                or type(item["name"]) is not str or not 1 <= len(item["name"]) <= 200
                or any(ord(char) < 32 for char in item["name"]) or item["name"] in names):
            raise ValueError("This plugin's practice questions are unavailable.")
        names.add(item["name"])
        schema = item["input_schema"]
        validator(schema)
        stack, count = [schema], 0
        while stack:
            child = stack.pop()
            count += 1
            if count > 2048:
                raise ValueError("This plugin's practice questions are too complex for this form.")
            if isinstance(child, dict):
                if child.get("writeOnly") is True or child.get("format") == "password":
                    raise ValueError("This plugin requires protected information. Practice checks cannot use passwords or keys.")
                stack.extend(child.values())
            elif isinstance(child, list):
                stack.extend(child)
    return value


def _record(context, operation):
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise ValueError("Choose a saved practice-question review.")
    row = workbench._read(workbench._path(context)).get("contracts", {}).get(operation)
    if not isinstance(row, dict):
        raise LookupError("This practice-question review is unavailable.")
    return row


def read_contract(context, operation, *, authorize, fingerprint=None):
    authorize()
    row = _record(context, operation)
    if fingerprint is not None and row.get("fingerprint") != fingerprint:
        raise ValueError("These questions belong to another plugin version. Read this version's questions again.")
    workbench.selected(row["fingerprint"])
    if row["state"] == "ready":
        _contracts(row["contracts"])
        if row.get("revision") != workbench._digest(row["contracts"]):
            raise ValueError("The saved practice questions changed. Nothing was submitted.")
    authorize()
    return row


def current_contract(context, fingerprint, *, authorize):
    authorize()
    workbench.selected(fingerprint)
    rows = workbench._read(workbench._path(context)).get("contracts", {})
    selected = max((row for row in rows.values() if row.get("fingerprint") == fingerprint),
                   key=lambda row: (row["started_at"], row["id"]), default=None)
    return read_contract(context, selected["id"], authorize=authorize, fingerprint=fingerprint) if selected else None


def inspect_contract(context, operation, fingerprint, *, authorize):
    from .budget import Budget
    from .sandbox.research import ResearchContainerRunner, ResearchLimits

    authorize()
    row = workbench.selected(fingerprint)
    if not row["eligible"]:
        raise ValueError("Approve this installed plugin and its current access before reading its practice questions.")
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise ValueError("A new reviewed practice request is required.")
    image = str(workbench.config().get("workbench_image") or "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Choose an already installed, reviewed restricted image in Settings. No image is downloaded here.")
    initial = {"id": operation, "fingerprint": fingerprint, "plugin": row["name"], "version": row["version"],
               "state": "unconfirmed", "started_at": time.time(), "notice": "The original inspection needs a status check; it will not be repeated."}

    def reserve(state):
        values = state.setdefault("contracts", {})
        existing = values.get(operation)
        if existing:
            if existing.get("fingerprint") != fingerprint:
                raise ValueError("This request belongs to another plugin version.")
            return False
        if len(values) >= 1000:
            raise ValueError("The practice review history is full. Ask an administrator to review retained evidence.")
        values[operation] = initial
        return True

    if not workbench._edit(context, reserve):
        return read_contract(context, operation, authorize=authorize, fingerprint=fingerprint)

    @contextmanager
    def guard():
        authorize()
        workbench.selected(fingerprint)
        yield

    try:
        payload = {"group": row["group"], "name": row["name"], "entry": row["entry"], "distribution": row["distribution"],
                   "version": row["version"], "content_sha256": row.get("sandbox_content_sha256") or row["content_sha256"],
                   "operation": operation, "sample": {}, "inspect_only": True}
        result = ResearchContainerRunner(image, limits=ResearchLimits(timeout_seconds=15, output_bytes=256 * 1024)).run(
            workbench._check_files(row, payload), budget=Budget(max_wall_seconds=45, max_tool_calls=1, max_dollars=0), effect_guard=guard)
        authorize()
        workbench.selected(fingerprint)
        frames = []
        for line in result.stdout.splitlines():
            try:
                frame = json.loads(line)
            except ValueError:
                continue
            if isinstance(frame, dict) and frame.get("operation") == operation and frame.get("phase") == "contract":
                frames.append(frame)
        if (result.reason != "completed" or result.exit_code != 0 or not result.cleanup_verified or len(frames) != 1
                or frames[0].get("content_sha256") != payload["content_sha256"]):
            final = {"state": "unavailable", "notice": "Practice questions were not confirmed in the restricted image. Check the installed image and plugin version. No action was run."}
        else:
            contracts = _contracts(frames[0].get("contracts"))
            final = {"state": "ready", "contracts": contracts, "revision": workbench._digest(contracts),
                     "notice": "Questions were read from this exact plugin in the restricted image. No tool action ran; readiness still requires completed practice checks."}
    except (ValueError, LookupError, PermissionError) as exc:
        final = {"state": "unavailable", "notice": str(exc)}
    except Exception:
        final = {"state": "unconfirmed", "notice": "The original inspection could not be confirmed. Read its saved outcome before another request; nothing is automatically repeated."}
    final["finished_at"] = time.time()

    def finish(state):
        state["contracts"][operation].update(final)
        return state["contracts"][operation]
    value = workbench._edit(context, finish)
    authorize()
    return value


def practice_input(context, operation, fingerprint, revision, tool_name, sample, *, authorize):
    row = read_contract(context, operation, authorize=authorize, fingerprint=fingerprint)
    if row["state"] != "ready" or row["revision"] != revision:
        raise ValueError("Review this plugin's current practice questions before starting a check.")
    contract = next((item for item in row["contracts"] if item["name"] == tool_name), None)
    if contract is None:
        raise ValueError("Choose a named practice action from this exact review.")
    if type(sample) is not dict:
        raise ValueError("Complete the ordinary practice questions before starting a check.")
    if len(json.dumps(sample, allow_nan=False).encode()) > 16384:
        raise ValueError("Use fewer practice details before starting this check.")
    from jsonschema import ValidationError

    from .sandbox.plugin_contracts import validate

    try:
        validate(contract["input_schema"], sample)
    except ValidationError as exc:
        raise ValueError("The practice answers do not match this action's current questions. Check the form before continuing.") from exc
    selected = workbench.selected(fingerprint)
    return {"tool": tool_name, "arguments": sample} if selected["group"] in {"maverick.ts", "maverick.grpc"} else sample
