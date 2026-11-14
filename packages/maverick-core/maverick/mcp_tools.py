"""Build maverick Tool objects from an MCPClient's discovered tools.

External MCP server tools become `mcp_<server>__<tool>` in the agent's
tool registry. The agent calls them just like any other tool; under
the hood we route to the MCPClient and return the response text.

Kept in its own module to avoid a circular import between tools/ and
mcp_client.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import asdict

from .connector_attempts import CONTROL_ERRORS
from .mcp_catalog import bind_call_guard
from .mcp_client import MCPClient, MCPServerSpec
from .tools import Tool

log = logging.getLogger(__name__)

# A tool name comes from the external MCP server's `tools/list` response, so
# it is attacker-controlled if that server is hostile/compromised (the same
# threat MCPClient.pin_sha256 guards against). Constrain it to an identifier
# charset so it can't (a) inject newlines/control chars into log lines, or
# (b) smuggle the `__` namespace separator to collide with / shadow another
# server's `mcp_<server>__<tool>` entry in the registry. Matches the MCP
# spec's recommended tool-name shape.
_VALID_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
# The registered name is sent to the model unchanged, and model APIs accept
# only this shape: one unacceptable name would fail every call that lists it.
_MODEL_TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_MAX_SCHEMA_SCAN_DEPTH = 64


def current_mcp_servers() -> dict[str, dict]:
    """Current exact configuration, privately held; never connects a server.

    New specialist grants require the physical overlay, not the legacy reader's
    last-known-good fallback. Reuse its bounded parser, schema and secret codec.
    """
    from . import config, runtime_overrides
    from .paths import current_tenant_id_strict

    cfg = config.load_config()
    if config.config_source_errors():
        raise ValueError("Current tool-server settings could not be checked.")
    configured = cfg.get("mcp_servers", {})
    if not isinstance(configured, dict):
        raise ValueError("Current tool-server settings could not be checked.")
    path = runtime_overrides.overrides_path()
    try:
        path.lstat()
    except FileNotFoundError:
        overlay = {}
    else:
        state = runtime_overrides._validate_loaded_state(runtime_overrides._read_overlay(path))
        overlay = {name: runtime_overrides._unseal_mcp_spec(value)
                   for name, value in state.get("mcp_servers", {}).items()}
    scope = current_tenant_id_strict()
    result = {}
    for name, raw in {**overlay, **configured}.items():
        spec, enabled = None, False
        try:
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
                    or name.endswith("_") or "__" in name or not isinstance(raw, dict)
                    or type(raw.get("enabled", True)) is not bool):
                raise ValueError("Unsupported tool-server configuration")
            enabled = raw.get("enabled", True)
            spec = MCPServerSpec.from_config(name, raw)
            material = asdict(spec)
        except (TypeError, ValueError, KeyError):
            material = raw
        revision = hashlib.sha256(json.dumps([scope, name, enabled, material],
            sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        result[name] = {"spec": spec, "enabled": enabled, "revision": revision}
    return result


def selected_tools_from_mcp(clients, servers, *, authorize=None, binding_guards=None):
    """Bind selected already-connected clients; discovery grants no new tools later."""
    from .paths import current_tenant_id_strict

    scope = current_tenant_id_strict()
    current = current_mcp_servers()
    selected = set(servers)
    out = []
    for client in clients or ():
        name = client.spec.name
        row = current.get(name)
        if name not in selected or not row or not row["enabled"] or row["spec"] != client.spec:
            continue
        expected = row["revision"]

        def source_current(n=name, revision=expected, workspace=scope):
            try:
                if current_tenant_id_strict() != workspace:
                    return False
                row = current_mcp_servers().get(n)
                return bool(row and row["enabled"] and row["spec"] is not None and row["revision"] == revision)
            except Exception:
                return False

        out.extend(tools_from_mcp(client, authorize=authorize, binding_guards=binding_guards,
                                  source_guard=source_current))
    return out


def tools_from_mcp(client: MCPClient, *, authorize: Callable[[str], bool] | None = None, binding_guards: dict[str, Callable[[], bool]] | None = None, source_guard: Callable[[], bool] | None = None) -> list[Tool]:
    """Return a Tool per MCP-exposed tool, namespaced by server.

    MCP tool descriptions and inputSchema
    fields were rendered into the agent's tool catalog verbatim, so a
    hostile MCP server could put attack instructions in a description
    that the LLM would treat as authoritative. Each description is now
    run through Shield.scan_input; tools that fail are silently dropped
    with a warning log.
    """
    out: list[Tool] = []
    server = str(client.spec.name)
    if server.endswith("_") or "__" in server:
        # ``mcp_<server>__<tool>`` must split one way only: a server "a_"
        # with tool "b" and a server "a" with tool "_b" would otherwise both
        # register as ``mcp_a___b`` and one would silently shadow the other.
        log.warning("mcp server %r rejected: its name may not end with '_' or contain '__'",
                    server)
        return out
    shield = _try_shield()
    if hasattr(client, "catalog"):
        # Read metadata and its identity from ONE immutable generation, even
        # if another thread publishes a refresh while Shield inspects it.
        generation = client.catalog.generation
        descriptors = [(json.loads(encoded), identity) for _, encoded, identity in generation.entries]
    else:
        descriptors = [(spec, None) for spec in client.tools]
    for spec, identity in descriptors:
        name = spec.get("name")
        if not name:
            continue
        if (not isinstance(name, str) or not _VALID_TOOL_NAME.fullmatch(name) or "__" in name
                or name.startswith("_")):
            # %r escapes any control chars, so the rejection log itself can't
            # be used to forge log lines.
            log.warning(
                "mcp tool from %s rejected: invalid name %r "
                "(must match [A-Za-z0-9_.-], <=128 chars, no '__', not starting with '_')",
                client.spec.name, name,
            )
            continue
        if not _spec_passes_shield(name, spec, shield):
            log.warning(
                "mcp tool %s.%s rejected by Shield; not registering",
                client.spec.name, name,
            )
            continue
        prefixed = f"mcp_{client.spec.name}__{name}"
        if not _MODEL_TOOL_NAME.fullmatch(prefixed):
            log.warning(
                "mcp tool from %s rejected: registered name %r is not a valid model tool "
                "name ([A-Za-z0-9_-], <=64 chars)", client.spec.name, prefixed,
            )
            continue
        if hasattr(client, "catalog") and client.catalog.identity(name) != identity:
            continue
        if source_guard is not None and not source_guard():
            continue
        out.append(_build_tool(client, prefixed, name, spec, identity=identity, authorize=authorize, source_guard=source_guard))
        if binding_guards is not None and identity is not None:
            binding_guards[prefixed] = lambda c=client.catalog, n=name, i=identity, s=source_guard: c.identity(n) == i and (s is None or s())
    return out


def _try_shield():
    try:
        from maverick_shield import Shield  # type: ignore
        return Shield.from_config()
    except ImportError:
        return None


def _collect_schema_strings(node, out: list[str], _depth: int = 0) -> bool:
    """Walk a JSON Schema dict and collect every string leaf.

    A hostile MCP server can put attack text in description / title /
    enum / examples inside nested properties; the agent sees those
    verbatim. Shield must inspect the full string-leaf set, not just
    the top-level description field. Returns ``False`` if the schema
    exceeds the bounded scan depth so callers can fail closed instead
    of exposing unscanned nested metadata to the model.
    """
    # Depth cap: the schema is parsed from a hostile MCP server's wire data,
    # so a ~990-deep nested object (which json.loads still accepts) would blow
    # the Python stack here (RecursionError) during connect. Real schemas are
    # shallow; fail closed past a generous bound rather than silently skipping
    # deeper strings that would still be sent to the model as tool metadata.
    if _depth > _MAX_SCHEMA_SCAN_DEPTH:
        return False
    if isinstance(node, dict):
        for k, v in node.items():
            # Collect EVERY string value, not an allowlist of keys: a hostile
            # server can hide attack text under const / $comment / examples / a
            # custom key, and the agent is shown the whole schema as tool
            # metadata, so the shield must see all of it -- keys included (a
            # property name is shown to the model too).
            out.append(str(k))
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, (dict, list)):
                if not _collect_schema_strings(v, out, _depth + 1):
                    return False
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (dict, list)) and not _collect_schema_strings(
                item, out, _depth + 1
            ):
                return False
    return True


def _spec_passes_shield(name: str, spec: dict, shield) -> bool:
    if shield is None:
        return True
    description = spec.get("description", "") or ""
    parts: list[str] = [f"tool: {name}", f"description: {description}"]
    schema = spec.get("inputSchema") or {}
    leaves: list[str] = []
    if not _collect_schema_strings(schema, leaves):
        log.warning(
            "mcp tool %r rejected: inputSchema exceeds scan depth %s",
            name,
            _MAX_SCHEMA_SCAN_DEPTH,
        )
        return False
    parts.extend(f"schema_text: {leaf}" for leaf in leaves)
    payload = "\n".join(parts)
    try:
        v = shield.scan_input(payload)
        return bool(v.allowed)
    except Exception as e:
        # Shield is PRESENT but its scan raised: fail toward the gate (drop the
        # tool metadata), matching shield_policy.scan_block and this function's
        # own over-depth branch above. This is the chokepoint that keeps a
        # hostile MCP server's tool description/schema out of the agent's
        # catalog, so a scan error must NOT admit it. The shield-ABSENT path
        # returned True earlier (kernel rule 1: fail open, warn); only a
        # present-but-erroring scan rejects here.
        log.warning("mcp tool %r shield scan errored (failing closed): %s", name, e)
        return False


def _build_tool(client: MCPClient, prefixed: str, original: str, spec: dict, *, identity: str | None = None, authorize: Callable[[str], bool] | None = None, source_guard: Callable[[], bool] | None = None) -> Tool:
    description = spec.get("description", "") or "(no description)"
    schema = spec.get("inputSchema") or {"type": "object", "properties": {}}

    async def fn(args: dict) -> str:
        try:
            def admitted() -> bool:
                return (
                    (identity is None or client.catalog.identity(original) == identity)
                    and (authorize is None or authorize(prefixed))
                    and (source_guard is None or source_guard())
                )

            with bind_call_guard(admitted):
                return await client.call_tool(original, args)
        except CONTROL_ERRORS:
            raise
        except Exception as e:
            log.exception("mcp tool %s failed", prefixed)
            return f"ERROR: {type(e).__name__}: {e}"

    return Tool(
        name=prefixed,
        description=f"[mcp:{client.spec.name}] {description}",
        input_schema=schema,
        fn=fn,
    )
