"""Discord slash-command framework.

Produce the JSON Discord expects when registering an application (slash) command
— the ``name`` / ``description`` / ``options`` payload for the
``applications/{id}/commands`` endpoint. This builds and validates the registration
body offline; the actual HTTP PUT is a separate step (http_fetch). Deterministic;
offline; pure stdlib (json). No disk, no network.

op:
  - build(name, description, options=[{name, description, type, required?}])
    -> the command-registration JSON (json.dumps, sorted keys).

Validation: command/option name matches ^[a-z0-9_-]{1,32}$; option ``type`` is an
int in 3..10 (or a string alias: string, integer, boolean, user, channel, role,
mentionable, number); required options are ordered before optional ones (Discord
rejects an optional-before-required ordering).
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import Tool

_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")

# Discord ApplicationCommandOptionType: the value-carrying subset (3..10).
# SUB_COMMAND(1)/SUB_COMMAND_GROUP(2) are not value options, so out of scope.
_TYPE_ALIASES = {
    "string": 3,
    "integer": 4,
    "boolean": 5,
    "user": 6,
    "channel": 7,
    "role": 8,
    "mentionable": 9,
    "number": 10,
}
_VALID_TYPES = set(_TYPE_ALIASES.values())  # {3,...,10}


def _coerce_type(value: Any) -> int | str:
    """Return the integer option type, or an ERROR string."""
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        return "ERROR: option type must be an int 3..10 or a type name"
    if isinstance(value, int):
        if value in _VALID_TYPES:
            return value
        return f"ERROR: option type {value} out of range (3..10)"
    if isinstance(value, str):
        alias = value.strip().lower()
        if alias in _TYPE_ALIASES:
            return _TYPE_ALIASES[alias]
        return f"ERROR: unknown option type {value!r}"
    return "ERROR: option type must be an int 3..10 or a type name"


def _build_option(opt: Any) -> dict[str, Any] | str:
    if not isinstance(opt, dict):
        return "ERROR: each option must be an object {name, description, type, required?}"
    name = str(opt.get("name") or "").strip()
    description = str(opt.get("description") or "").strip()
    if not _NAME_RE.match(name):
        return f"ERROR: option name {name!r} must match ^[a-z0-9_-]{{1,32}}$"
    if not description:
        return f"ERROR: option {name!r} missing description"
    otype = _coerce_type(opt.get("type"))
    if isinstance(otype, str):
        return otype
    built: dict[str, Any] = {
        "type": otype,
        "name": name,
        "description": description,
        "required": bool(opt.get("required", False)),
    }
    return built


def _build(args: dict[str, Any]) -> str:
    name = str(args.get("name") or "").strip()
    description = str(args.get("description") or "").strip()
    if not _NAME_RE.match(name):
        return f"ERROR: name {name!r} must match ^[a-z0-9_-]{{1,32}}$"
    if not description:
        return "ERROR: description is required"

    options = args.get("options")
    built_opts: list[dict[str, Any]] = []
    if options is not None:
        if not isinstance(options, list):
            return "ERROR: options must be an array"
        for opt in options:
            built = _build_option(opt)
            if isinstance(built, str):
                return built
            built_opts.append(built)
        # Discord requires required options before optional ones.
        seen_optional = False
        for opt in built_opts:
            if opt["required"]:
                if seen_optional:
                    return (
                        f"ERROR: required option {opt['name']!r} must come "
                        "before optional options"
                    )
            else:
                seen_optional = True

    command: dict[str, Any] = {
        "name": name,
        "description": description,
        "type": 1,  # CHAT_INPUT (a slash command)
    }
    if built_opts:
        command["options"] = built_opts
    return json.dumps(command, sort_keys=True)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "build"):
        return f"ERROR: unknown op {args.get('op')!r} (expected build)"
    return _build(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["build"]},
        "name": {"type": "string", "description": "command name (^[a-z0-9_-]{1,32}$)"},
        "description": {"type": "string"},
        "options": {
            "type": "array",
            "description": "each {name, description, type, required?}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "type": {
                        "description": "int 3..10 or a name (string/integer/boolean/user/channel/role/mentionable/number)",
                    },
                    "required": {"type": "boolean"},
                },
                "required": ["name", "description", "type"],
            },
        },
    },
    "required": ["name", "description"],
}


def discord_slash() -> Tool:
    return Tool(
        name="discord_slash",
        description=(
            "Build a Discord slash-command registration JSON (does not send). "
            "op=build {name, description, options:[{name, description, type, "
            "required?}]}. Validates name ^[a-z0-9_-]{1,32}$, option type in "
            "3..10 (or a name: string/integer/boolean/user/channel/role/"
            "mentionable/number), and required-before-optional ordering. Returns "
            "json.dumps. Deterministic; offline; stdlib json only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
