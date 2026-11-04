"""Versioned, local-process gRPC qualification descriptors; no host execution."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path


def descriptor(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("target"), str):
        raise ValueError("Choose a local gRPC target and an exact server command.")
    command = entry.get("command")
    if command is None and isinstance(entry.get("program"), str) and isinstance(entry.get("args", []), list):
        command = [entry["program"], *entry.get("args", [])]
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise ValueError("A connection-only server has no inspectable version. Configure its exact local server entry before qualification.")
    return {"target": entry["target"].strip(), "command": command}


def source(value):
    from .grpc_plugin_host import _is_local_grpc_target
    command = value["command"]
    if not _is_local_grpc_target(value["target"]) or len(command) != 2:
        raise ValueError("Use a loopback target and a bundled Python or Node server entry without command-line secrets.")
    program = Path(command[0]).name.lower()
    runtime = "python3" if re.fullmatch(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", program) else "node" if program in {"node", "node.exe", "nodejs"} else None
    path = Path(command[1]).expanduser()
    suffixes = {".py"} if runtime == "python3" else {".js", ".mjs", ".cjs"} if runtime else set()
    if path.suffix.lower() not in suffixes or not path.is_file() or path.is_symlink():
        raise ValueError("Bundle this server into a readable Python or Node entry for the reviewed image.")
    with path.open("rb") as stream:
        contents = stream.read(2 * 1024 * 1024 + 1)
    if len(contents) > 2 * 1024 * 1024:
        raise ValueError("The bundled server entry exceeds 2 MiB.")
    return contents, runtime, path.suffix.lower()


def current(identity, policy=None):
    from .plugin_workbench import _digest, config
    if policy is None:
        policy = config()
    for entry in policy.get("grpc", []) or []:
        try:
            value = descriptor(entry)
        except ValueError:
            continue
        if _digest(value) == identity:
            return value
    raise PermissionError("This exact local gRPC server is no longer configured.")


def rows(policy, harness, digest):
    result = []
    for index, entry in enumerate(policy.get("grpc", []) or []):
        row = {"group": "maverick.grpc", "name": "gRPC plugin " + str(index + 1), "pin_name": "gRPC plugin",
               "entry": "grpc", "version": "configured source", "content_sha256": None, "manifest": None,
               "missing_permissions": [], "permission_enforcement": True, "policy_allowed": False,
               "permission_denial_checked": False, "qualification_image": policy.get("workbench_image", ""),
               "harness_sha256": harness, "scope": "Local gRPC server contract in the restricted image; no live-service acceptance.",
               "sample_example": {"tool": "declared_tool_name", "arguments": {}}, "eligible": False}
        try:
            value = descriptor(entry)
            identity = digest(value)
            row["distribution"] = "grpc-command:" + identity
            row["command_identity"] = identity
            row["policy_allowed"] = current(identity, policy) == value
            try:
                current(identity, {})
            except PermissionError:
                row["permission_denial_checked"] = True
            contents, runtime, suffix = source(value)
            row.update(content_sha256=hashlib.sha256(contents).hexdigest(), runtime=runtime, source_suffix=suffix, eligible=True)
        except (ValueError, OSError) as exc:
            row["blocked"] = str(exc)
            row.setdefault("distribution", "unversioned-grpc:" + str(index))
        row["fingerprint"] = digest(row)
        result.append(row)
    return result


def admit(value):
    from .plugin_execution_pins import check_pin
    from .plugin_workbench import _digest
    identity = _digest(value)
    current(identity)
    fingerprint = hashlib.sha256(source(value)[0]).hexdigest()
    check_pin("maverick.grpc", "gRPC plugin", "grpc-command:" + identity, fingerprint)
    return fingerprint


def pin_tools(value, tools):
    from .plugin_workbench import _digest
    identity = _digest(value)
    fingerprint = admit(value)
    for tool in tools:
        original = tool.fn
        def invoke(arguments, call=original):
            current_value = current(identity)
            if admit(current_value) != fingerprint:
                raise PermissionError("gRPC source changed. Review migration before invoking it.")
            return call(arguments)
        tool.fn = invoke
    return tools
