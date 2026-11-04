"""Isolated JSON worker for the research-component contract.

The controller starts this file with ``python -I`` and a scrubbed environment.
Only a bounded component descriptor plus the permitted learner observation enter
the process.  The software-world fixture, oracle, action authority, credentials,
and accounting adapter remain in the controller process.

This is an internal process entry point, not a public plugin execution surface.
Only the two audited deterministic baseline implementations are accepted.
"""
from __future__ import annotations

import json
import math
import sys
from collections import Counter
from typing import Any

_MAX_INPUT_BYTES = 1_048_576
_MAX_TRANSITIONS = 10_000
_INTERFACE_VERSION = "maverick.research-component.v1"
_IMPLEMENTATIONS = {
    "tabular-v1": (
        "tabular-baseline-v1",
        "deterministic tabular transition baseline",
    ),
    "feature-prefix-backoff-v1": (
        "feature-prefix-backoff-baseline-v1",
        "deterministic feature-prefix backoff baseline; "
        "not a proven learned world model",
    ),
}
_ACTIONS = frozenset({"read", "upsert", "list"})


class _Refusal(ValueError):
    pass


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Refusal(f"{label} must be an object")
    return value


def _text(value: object, label: str, maximum: int = 4000) -> str:
    if not isinstance(value, str):
        raise _Refusal(f"{label} must be text")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise _Refusal(f"{label} is invalid")
    return cleaned


def _descriptor(value: object) -> dict[str, Any]:
    descriptor = _object(value, "descriptor")
    if descriptor.get("schema") != "maverick.research-component-descriptor.v1":
        raise _Refusal("descriptor schema is unsupported")
    if descriptor.get("interface_version") != _INTERFACE_VERSION:
        raise _Refusal("component interface version is unsupported")
    implementation = _text(descriptor.get("implementation"), "implementation", 64)
    expected = _IMPLEMENTATIONS.get(implementation)
    if expected is None:
        raise _Refusal("component implementation is not registered")
    if (
        descriptor.get("component_id") != expected[0]
        or descriptor.get("baseline_label") != expected[1]
    ):
        raise _Refusal("component identity does not match its registered implementation")
    transitions = descriptor.get("transitions")
    if (
        not isinstance(transitions, list)
        or not transitions
        or len(transitions) > _MAX_TRANSITIONS
    ):
        raise _Refusal("component transitions are invalid")
    for transition in transitions:
        row = _object(transition, "transition")
        if not isinstance(row.get("state"), list) or len(row["state"]) > 32:
            raise _Refusal("transition state is invalid")
        if row.get("action") not in _ACTIONS:
            raise _Refusal("transition action is unsupported")
        outcome = row.get("outcome")
        if outcome is not None and (
            isinstance(outcome, bool)
            or not isinstance(outcome, (int, float))
            or not math.isfinite(float(outcome))
        ):
            raise _Refusal("transition outcome is invalid")
    memories = descriptor.get("memories", [])
    if not isinstance(memories, list) or len(memories) > 1000:
        raise _Refusal("component memories are invalid")
    for memory in memories:
        row = _object(memory, "memory")
        if row.get("action") not in _ACTIONS:
            raise _Refusal("memory action is unsupported")
        if any(
            isinstance(row.get(name), bool)
            or not isinstance(row.get(name), (int, float))
            or not math.isfinite(float(row[name]))
            for name in ("benefit", "strength")
        ):
            raise _Refusal("memory weights are invalid")
    return descriptor


def _proposal(value: object) -> dict[str, Any]:
    proposal = _object(value, "proposal")
    action = proposal.get("action")
    if action not in _ACTIONS:
        raise _Refusal("proposal action is unsupported")
    key = proposal.get("key", "")
    content = proposal.get("value", "")
    cursor = proposal.get("cursor", "")
    limit = proposal.get("limit", 2)
    if not isinstance(key, str) or len(key) > 256:
        raise _Refusal("proposal key is invalid")
    if not isinstance(content, str) or len(content) > 4000:
        raise _Refusal("proposal value is invalid")
    if not isinstance(cursor, str) or (cursor and (not cursor.isdigit() or len(cursor) > 8)):
        raise _Refusal("proposal cursor is invalid")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise _Refusal("proposal limit is invalid")
    return {
        "action": action,
        "key": key,
        "value": content,
        "cursor": cursor,
        "limit": limit,
    }


def _observation(value: object) -> dict[str, Any]:
    observation = _object(value, "observation")
    if (
        observation.get("schema") != "maverick.software-world-observation.v1"
        or observation.get("interface_version") != _INTERFACE_VERSION
        or observation.get("evidence_class") != "simulated"
    ):
        raise _Refusal("learner observation boundary is invalid")
    if not isinstance(observation.get("task"), dict) or not isinstance(
        observation.get("records"), dict
    ):
        raise _Refusal("learner observation data is invalid")
    _text(observation.get("scenario_id"), "scenario_id", 128)
    _text(observation.get("mechanism_family"), "mechanism_family", 128)
    _text(observation.get("application_family"), "application_family", 128)
    _text(observation.get("status"), "status", 64)
    return observation


def _result(value: object) -> dict[str, Any]:
    result = _object(value, "result")
    if (
        result.get("schema") != "maverick.software-world-result.v1"
        or result.get("interface_version") != _INTERFACE_VERSION
        or result.get("evidence_class") != "simulated"
        or result.get("result_class") != "simulation"
        or result.get("live_effect") is not False
        or result.get("can_accept_business_outcome") is not False
    ):
        raise _Refusal("simulation result boundary is invalid")
    if not isinstance(result.get("success"), bool) or not isinstance(
        result.get("visible_records"), dict
    ):
        raise _Refusal("simulation result data is invalid")
    _text(result.get("scenario_id"), "scenario_id", 128)
    _text(result.get("operation_id"), "operation_id", 128)
    return result


def _policy(descriptor: dict[str, Any], state: list[object]) -> Counter[str]:
    transitions = descriptor["transitions"]
    if descriptor["implementation"] == "tabular-v1":
        return Counter(row["action"] for row in transitions if row["state"] == state)
    fallback: Counter[str] = Counter()
    for length in range(len(state), -1, -1):
        counts = Counter(
            row["action"]
            for row in transitions
            if row["state"][:length] == state[:length]
        )
        if counts:
            fallback = fallback or counts
            if sum(counts.values()) >= 1:
                return counts
    return fallback


def _propose(descriptor: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    state = [
        observation["mechanism_family"],
        observation["application_family"],
        observation["status"],
    ]
    policy = _policy(descriptor, state)
    remembered = [
        row["action"]
        for row in sorted(
            descriptor.get("memories", []),
            key=lambda row: float(row["strength"]),
            reverse=True,
        )
    ]
    selected = next((action for action in remembered if action in policy), None)
    if selected is None:
        selected = sorted(policy, key=lambda action: (-policy[action], action))[0] if policy else "read"
    task = observation["task"]
    proposal = {
        "action": selected,
        "key": str(task.get("key") or ""),
        "value": str(task.get("value") or ""),
        "cursor": "",
        "limit": 2,
    }
    # The isolated component's execute interface emits an intent. It cannot
    # perform the effect because no worker/world capability exists here.
    return _proposal(proposal)


def _handle(request: object) -> dict[str, Any]:
    body = _object(request, "request")
    descriptor = _descriptor(body.get("descriptor"))
    command = body.get("command")
    if command == "propose_execute":
        observation = _observation(body.get("observation"))
        proposal = _propose(descriptor, observation)
        return {
            "ok": True,
            "interface_version": _INTERFACE_VERSION,
            "component_id": descriptor["component_id"],
            "proposal": proposal,
            "method_trace": ["propose", "execute"],
            "process_boundary": True,
            "oracle_material_received": False,
        }
    if command == "observe_evaluate":
        observation = _observation(body.get("observation"))
        result = _result(body.get("result"))
        if (
            observation["scenario_id"] != result["scenario_id"]
            or observation.get("step") != result.get("step")
        ):
            raise _Refusal("observation and result do not match")
        key = str(observation["task"].get("key") or "")
        expected = observation["task"].get("value")
        passed = bool(result["success"] and observation["records"].get(key) == expected)
        return {
            "ok": True,
            "interface_version": _INTERFACE_VERSION,
            "component_id": descriptor["component_id"],
            "evaluation": {
                "component_id": descriptor["component_id"],
                "passed": passed,
                "reason": (
                    "permitted observation matches the requested simulated value"
                    if passed
                    else "permitted observation does not establish simulated success"
                ),
            },
            "method_trace": ["observe", "evaluate"],
            "process_boundary": True,
            "oracle_material_received": False,
        }
    raise _Refusal("component command is unsupported")


def main() -> int:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > _MAX_INPUT_BYTES:
        response = {"ok": False, "error": "component request size is invalid"}
    else:
        try:
            response = _handle(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, _Refusal, KeyError, TypeError, ValueError):
            response = {"ok": False, "error": "component request was refused"}
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return 0 if response.get("ok") else 2


if __name__ == "__main__":  # pragma: no cover - exercised through the controller
    raise SystemExit(main())
