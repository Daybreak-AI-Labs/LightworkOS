"""Inspect configured Node plugin source without executing it on the host."""
from __future__ import annotations

import hashlib
from pathlib import Path

MAX_SOURCE_BYTES = 2 * 1024 * 1024


def source(command):
    if len(command) != 2 or Path(command[0]).name.lower() not in {"node", "node.exe", "nodejs"}:
        raise ValueError("Use a bundled Node JavaScript entry with no command-line secrets; other launch forms require a reviewed bundled entry.")
    path = Path(command[1]).expanduser()
    if path.suffix.lower() not in {".js", ".mjs", ".cjs"} or not path.is_file() or path.is_symlink():
        raise ValueError("The configured Node entry must be a readable regular JavaScript file.")
    with path.open("rb") as stream:
        value = stream.read(MAX_SOURCE_BYTES + 1)
    if len(value) > MAX_SOURCE_BYTES:
        raise ValueError("Bundle this plugin into a JavaScript entry smaller than 2 MiB.")
    return value


def rows(policy, harness, digest):
    from .ts_plugin_host import _entry_command

    result = []
    for index, entry in enumerate(policy.get("ts", []) or []):
        command = _entry_command(entry)
        if command is None:
            continue
        identity = digest(command)
        row = {"group": "maverick.ts", "name": "Node plugin " + str(index + 1),
               "distribution": "ts-command:" + identity, "entry": "node", "pin_name": "Node plugin",
               "version": "configured source", "command_identity": identity,
               "content_sha256": None, "manifest": None, "missing_permissions": [],
               "permission_enforcement": True, "qualification_image": policy.get("workbench_image", ""),
               "harness_sha256": harness, "policy_allowed": command_for(identity, policy) is not None,
               "permission_denial_checked": command_for(identity, {}) is None,
               "scope": "Bundled Node NDJSON tool contract in the restricted container; no live-service acceptance.",
               "sample_example": {"tool": "declared_tool_name", "arguments": {}}}
        try:
            row["content_sha256"] = hashlib.sha256(source(command)).hexdigest()
            row["source_suffix"] = Path(command[1]).suffix.lower()
            row["eligible"] = True
        except (ValueError, OSError) as exc:
            row["eligible"] = False
            row["blocked"] = str(exc)
        row["fingerprint"] = digest(row)
        result.append(row)
    return result


def command_for(identity, policy):
    from .plugin_workbench import _digest
    from .ts_plugin_host import _entry_command

    for entry in policy.get("ts", []) or []:
        command = _entry_command(entry)
        if command is not None and _digest(command) == identity:
            return command
    return None


def configured_command(identity):
    from .plugin_workbench import config

    command = command_for(identity, config())
    if command is None:
        raise PermissionError("This Node plugin is no longer configured; no dispatch occurred.")
    return command


def admit(command):
    from .plugin_execution_pins import check_pin
    from .plugin_workbench import _digest

    identity = _digest(command)
    configured_command(identity)
    fingerprint = hashlib.sha256(source(command)).hexdigest()
    check_pin("maverick.ts", "Node plugin", "ts-command:" + identity, fingerprint)
    return fingerprint


def pin_tools(command, tools):
    from .plugin_execution_pins import check_pin
    from .plugin_workbench import _digest

    identity = _digest(command)
    fingerprint = hashlib.sha256(source(command)).hexdigest()
    for tool in tools:
        original = tool.fn
        def invoke(arguments, call=original):
            current = configured_command(identity)
            if hashlib.sha256(source(current)).hexdigest() != fingerprint:
                raise PermissionError("Node plugin source changed. Review migration before dispatch.")
            check_pin("maverick.ts", "Node plugin", "ts-command:" + identity, fingerprint)
            return call(arguments)
        tool.fn = invoke
    return tools
