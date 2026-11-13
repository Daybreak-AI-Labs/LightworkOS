"""Agent dependency and MCP-server governance projection.

The projection combines two authorities without pretending either is the other:
the existing entity graph supplies governed operational lineage, while current
domain capability profiles and MCP configuration supply the reachability edges
an operator actually configured. MCP credentials, environment values, header
values, URL paths, and query strings are never returned or written to inventory.

MCP servers can be synchronized into the Model Risk & AI Assurance inventory as
``tool`` assets with ``metadata.kind == 'mcp_server'``. Their exact safe manifest
digest, supply-chain pin posture, transport boundary, and referencing agents are
therefore governed without expanding the assurance officer's stable asset-type
vocabulary.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import model_risk_assurance as mra

TOPOLOGY_SCHEMA = "lightwork.agent-topology.v1"
BLAST_RADIUS_SCHEMA = "lightwork.agent-blast-radius.v1"
MCP_INVENTORY_SOURCE = "mcp_config"

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_MAX_AGENTS = 5_000
_MAX_NODES = 2_000
_MAX_EDGES = 8_000


class AgentTopologyError(RuntimeError):
    """Base failure for the topology and blast-radius plane."""


class AgentTopologyConfigError(AgentTopologyError):
    """The explicit topology feature or a required dependency is unavailable."""


class AgentTopologyStateError(AgentTopologyError):
    """A capability profile, MCP spec, or graph projection is malformed."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _name(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _host_pattern(value: object, label: str) -> str:
    """Validate one ``allow_hosts`` entry or a query for one.

    Pack host lists are fnmatch globs (``Capability.host_ok``) and the pack
    linter only requires non-empty strings, so a wildcard such as
    ``*.example.com`` is a normal entry. ``_name`` would refuse it and take
    the whole projection down with it; bound the text instead.
    """

    text = str(value or "").strip()
    if not text or len(text) > 253 or any(
        ord(char) < 32 or ord(char) == 127 for char in text
    ):
        raise ValueError(f"{label} is invalid")
    return text


def _origin(raw_url: object) -> str:
    """Return scheme/host/port only; never expose a credential, path, or query."""

    parsed = urlsplit(str(raw_url or ""))
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise AgentTopologyStateError("MCP endpoint is invalid")
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme.lower()}://{host}{port}"


def _pin(value: object) -> str | None:
    if value in {None, ""}:
        return None
    text = str(value).strip().lower()
    if not _DIGEST_RE.fullmatch(text):
        raise AgentTopologyStateError("MCP pin_sha256 is malformed")
    return text.removeprefix("sha256:")


def _settings() -> dict[str, bool]:
    try:
        from .config import config_source_errors, load_global_config

        config = load_global_config()
        if config_source_errors(include_tenant=False) or not isinstance(config, dict):
            raise AgentTopologyConfigError("agent-topology configuration is unreadable")
    except AgentTopologyConfigError:
        raise
    except Exception as exc:
        raise AgentTopologyConfigError("agent-topology configuration is unavailable") from exc
    section = config.get("agent_topology") or {}
    if not isinstance(section, dict):
        raise AgentTopologyConfigError("agent_topology must be a table")
    unknown = set(section) - {"enable"}
    if unknown:
        raise AgentTopologyConfigError(
            f"unknown agent_topology keys: {', '.join(sorted(unknown))}"
        )
    value = section.get("enable", False)
    if not isinstance(value, bool):
        raise AgentTopologyConfigError("agent_topology.enable must be a boolean")
    return {"enable": value}


def enabled() -> bool:
    try:
        from . import entity_graph

        return bool(_settings()["enable"] is True and entity_graph.enabled() and mra.enabled())
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise AgentTopologyConfigError(
            "agent topology requires [agent_topology] enable = true plus enabled "
            "entity-graph and model-risk-assurance dependencies"
        )


def _profiles() -> dict[str, Any]:
    from .domain import enabled_domains

    profiles = enabled_domains()
    if not isinstance(profiles, Mapping) or len(profiles) > _MAX_AGENTS:
        raise AgentTopologyStateError("enabled agent profiles exceed the operational limit")
    return {str(name): profile for name, profile in profiles.items()}


def _safe_mcp_manifest(spec: Any) -> dict[str, Any]:
    name = _name(getattr(spec, "name", ""), "MCP server name")
    url = getattr(spec, "url", None)
    if url:
        endpoint = _origin(url)
        launch_digest = None
        transport = "streamable_http"
        boundary = "network"
    else:
        command = str(getattr(spec, "command", "") or "").strip()
        if not command:
            raise AgentTopologyStateError("stdio MCP server has no command")
        # The command and arguments can contain workstation/user paths. Bind
        # them, but expose only the executable basename and aggregate digest.
        args = [str(value) for value in (getattr(spec, "args", None) or [])]
        launch_digest = _sha256({"command": command, "args": args})
        endpoint = Path(command).name or "configured-executable"
        transport = "stdio"
        boundary = "process"
    pin = _pin(getattr(spec, "pin_sha256", None))
    if url:
        if getattr(spec, "oauth", None):
            auth_mode = "oauth2"
        elif getattr(spec, "auth_token", None):
            auth_mode = "static_bearer"
        else:
            auth_mode = "none"
    else:
        auth_mode = "process_environment" if getattr(spec, "env", None) else "none"
    return {
        "name": name,
        "transport": transport,
        "trust_boundary": boundary,
        "endpoint": endpoint,
        "launch_sha256": launch_digest,
        "pin_sha256": pin,
        "supply_chain_status": "pinned" if pin else "unpinned",
        "auth_mode": auth_mode,
        "sensitive_values_persisted": False,
    }


def _mcp_manifests() -> dict[str, dict[str, Any]]:
    from .mcp_client import load_mcp_specs_from_config

    specs = load_mcp_specs_from_config()
    if len(specs) > 512:
        raise AgentTopologyStateError("MCP server count exceeds the operational limit")
    manifests: dict[str, dict[str, Any]] = {}
    for spec in specs:
        manifest = _safe_mcp_manifest(spec)
        name = manifest["name"]
        if name in manifests and manifests[name] != manifest:
            raise AgentTopologyStateError("duplicate MCP server identity")
        manifests[name] = manifest
    return manifests


def _node(kind: str, name: str, **attributes: object) -> dict[str, Any]:
    return {
        "id": f"{kind}:{name}",
        "kind": kind,
        "name": name,
        "attributes": dict(attributes),
    }


def _edge(
    source: str,
    relation: str,
    target: str,
    *,
    trust_boundary: str,
    authority: str,
) -> dict[str, str]:
    return {
        "source": source,
        "relation": relation,
        "target": target,
        "trust_boundary": trust_boundary,
        "authority": authority,
    }


def _agent_projection(
    agent_name: str,
    profile: Any,
    manifests: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    agent = _name(agent_name, "agent name")
    agent_id = f"agent:{agent}"
    nodes = [_node(
        "agent",
        agent,
        compartment=str(getattr(profile, "compartment", "") or agent),
        max_risk=getattr(profile, "max_risk", None),
    )]
    edges: list[dict[str, str]] = []

    for tool in sorted(set(getattr(profile, "allow_tools", None) or [])):
        target = _name(tool, "tool name")
        nodes.append(_node("tool", target))
        edges.append(_edge(
            agent_id,
            "may_use",
            f"tool:{target}",
            trust_boundary="capability_allowlist",
            authority=f"domain_profile:{agent}",
        ))
    for server_name in sorted(set(getattr(profile, "mcp_servers", None) or [])):
        server = _name(server_name, "MCP server name")
        manifest = manifests.get(server)
        nodes.append(_node(
            "mcp_server",
            server,
            configured=manifest is not None,
            supply_chain_status=(manifest or {}).get("supply_chain_status", "missing"),
            pin_sha256=(manifest or {}).get("pin_sha256"),
        ))
        edges.append(_edge(
            agent_id,
            "may_call",
            f"mcp_server:{server}",
            trust_boundary="external_mcp",
            authority=f"domain_profile:{agent}",
        ))
        if manifest is not None:
            endpoint = str(manifest["endpoint"])
            nodes.append(_node(
                "endpoint",
                endpoint,
                transport=manifest["transport"],
                auth_mode=manifest["auth_mode"],
            ))
            edges.append(_edge(
                f"mcp_server:{server}",
                "crosses_to",
                f"endpoint:{endpoint}",
                trust_boundary=str(manifest["trust_boundary"]),
                authority=f"mcp_config:{server}",
            ))
    for host in sorted(set(getattr(profile, "allow_hosts", None) or [])):
        target = _host_pattern(host, "allowed host")
        nodes.append(_node("data_endpoint", target))
        edges.append(_edge(
            agent_id,
            "may_reach",
            f"data_endpoint:{target}",
            trust_boundary="egress_allowlist",
            authority=f"domain_profile:{agent}",
        ))
    for raw_path in sorted(set(getattr(profile, "allow_paths", None) or [])):
        path = str(raw_path).strip()
        if not path or len(path) > 512 or any(ord(char) < 32 for char in path):
            raise AgentTopologyStateError("allowed path is malformed")
        path_id = _sha256(path)[:24]
        nodes.append(_node(
            "data_path",
            path_id,
            configured_path=path,
        ))
        edges.append(_edge(
            agent_id,
            "may_read_or_write",
            f"data_path:{path_id}",
            trust_boundary="filesystem_capability",
            authority=f"domain_profile:{agent}",
        ))
    for source in sorted(set(getattr(profile, "knowledge_sources", None) or [])):
        target = _name(source, "knowledge source")
        nodes.append(_node("knowledge_source", target))
        edges.append(_edge(
            agent_id,
            "may_consult",
            f"knowledge_source:{target}",
            trust_boundary="retrieval_boundary",
            authority=f"domain_profile:{agent}",
        ))
    models = getattr(profile, "models", None) or {}
    if not isinstance(models, Mapping):
        raise AgentTopologyStateError("agent model routing is malformed")
    for role, model in sorted(models.items(), key=lambda row: str(row[0])):
        model_name = _name(model, "model route")
        nodes.append(_node("model", model_name, role=str(role)))
        edges.append(_edge(
            agent_id,
            "may_invoke_model",
            f"model:{model_name}",
            trust_boundary="model_provider",
            authority=f"domain_profile:{agent}",
        ))

    deduped_nodes = {node["id"]: node for node in nodes}
    deduped_edges = {
        (edge["source"], edge["relation"], edge["target"]): edge for edge in edges
    }
    if len(deduped_nodes) > _MAX_NODES or len(deduped_edges) > _MAX_EDGES:
        raise AgentTopologyStateError("agent topology exceeds the operational limit")
    return (
        sorted(deduped_nodes.values(), key=lambda row: row["id"]),
        sorted(
            deduped_edges.values(),
            key=lambda row: (row["source"], row["relation"], row["target"]),
        ),
    )


def agent_names() -> list[str]:
    """Names of the configured agents whose topology can be viewed."""

    _require_enabled()
    return sorted(_profiles())


def agent_view(agent_name: str) -> dict[str, Any]:
    """Return everything one configured agent can reach, transitively."""

    _require_enabled()
    agent = _name(agent_name, "agent name")
    profiles = _profiles()
    profile = profiles.get(agent)
    if profile is None:
        return {
            "schema": TOPOLOGY_SCHEMA,
            "found": False,
            "agent": agent,
            "nodes": [],
            "edges": [],
            "operational_lineage": None,
        }
    nodes, edges = _agent_projection(agent, profile, _mcp_manifests())
    from . import entity_graph

    lineage = entity_graph.neighborhood("agent", agent, depth=4)
    return {
        "schema": TOPOLOGY_SCHEMA,
        "found": True,
        "agent": agent,
        "nodes": nodes,
        "edges": edges,
        "reachable_count": max(0, len(nodes) - 1),
        "trust_boundaries": sorted({edge["trust_boundary"] for edge in edges}),
        "operational_lineage": lineage,
        "generated_from": ["domain_profiles", "mcp_config", "entity_graph"],
        "limitations": [
            "only configured capability and observed operational edges are visible",
            "in-process behavior outside declared capabilities is not inferred",
            "MCP tool lists are runtime data and are not guessed from configuration",
        ],
    }


def blast_radius(kind: str, name: str) -> dict[str, Any]:
    """Return configured agents and downstream resources exposed to one node."""

    _require_enabled()
    target_kind = _name(kind, "kind")
    if target_kind not in {
        "tool",
        "mcp_server",
        "endpoint",
        "data_endpoint",
        "data_path",
        "knowledge_source",
        "model",
    }:
        raise ValueError("unsupported blast-radius kind")
    # A data endpoint is named by its allow_hosts glob, wildcard included.
    target_name = (
        _host_pattern(name, "name") if target_kind == "data_endpoint"
        else _name(name, "name")
    )
    profiles = _profiles()
    manifests = _mcp_manifests()
    target_id = f"{target_kind}:{target_name}"
    affected: list[dict[str, Any]] = []
    downstream: dict[str, dict[str, Any]] = {}
    for agent, profile in sorted(profiles.items()):
        nodes, edges = _agent_projection(agent, profile, manifests)
        direct = [edge for edge in edges if edge["target"] == target_id]
        if not direct:
            continue
        affected.append({
            "agent": agent,
            "via": sorted({edge["relation"] for edge in direct}),
            "trust_boundaries": sorted({edge["trust_boundary"] for edge in direct}),
        })
        reachable_ids = {target_id}
        changed = True
        while changed:
            changed = False
            for edge in edges:
                if edge["source"] in reachable_ids and edge["target"] not in reachable_ids:
                    reachable_ids.add(edge["target"])
                    changed = True
        for node in nodes:
            if node["id"] in reachable_ids and node["id"] != target_id:
                downstream[node["id"]] = node
    return {
        "schema": BLAST_RADIUS_SCHEMA,
        "found": bool(affected),
        "entity": {"kind": target_kind, "name": target_name},
        "affected_agents": affected,
        "downstream": sorted(downstream.values(), key=lambda row: row["id"]),
        "affected_count": len(affected),
    }


def sync_mcp_inventory(*, actor: str) -> dict[str, Any]:
    """Observe configured MCP servers as governed tool assets without secrets."""

    _require_enabled()
    operator = _name(actor, "actor")
    profiles = _profiles()
    manifests = _mcp_manifests()
    officer = mra.ModelRiskAssuranceOfficer()
    items: list[dict[str, Any]] = []
    for server, manifest in sorted(manifests.items()):
        referencing_agents = sorted(
            agent
            for agent, profile in profiles.items()
            if server in set(getattr(profile, "mcp_servers", None) or [])
        )
        safe_manifest = {
            **manifest,
            "referencing_agents": referencing_agents,
        }
        digest = _sha256(safe_manifest)
        asset_id = mra.stable_asset_id("tool", MCP_INVENTORY_SOURCE, server)
        current = officer.get_observation(asset_id)
        observed = officer.observe_asset(
            asset_type="tool",
            source=MCP_INVENTORY_SOURCE,
            source_id=server,
            display_name=f"MCP server: {server}",
            version_digest=digest,
            actor=operator,
            expected_revision=int((current or {}).get("revision") or 0),
            metadata={
                "kind": "mcp_server",
                "transport": manifest["transport"],
                "trust_boundary": manifest["trust_boundary"],
                "endpoint": manifest["endpoint"],
                "pin_sha256": manifest["pin_sha256"],
                "supply_chain_status": manifest["supply_chain_status"],
                "auth_mode": manifest["auth_mode"],
                "sensitive_values_persisted": False,
                "referencing_agents": referencing_agents,
                "safe_manifest_sha256": digest,
            },
            dependencies=referencing_agents,
        )
        items.append({
            "asset_id": observed["asset_id"],
            "observation_revision": observed["revision"],
            "version_digest": observed["version_digest"],
            "server": server,
            "supply_chain_status": manifest["supply_chain_status"],
        })
    return {
        "items": items,
        "count": len(items),
        "legal_certification": False,
    }


__all__ = [
    "BLAST_RADIUS_SCHEMA",
    "MCP_INVENTORY_SOURCE",
    "TOPOLOGY_SCHEMA",
    "AgentTopologyConfigError",
    "AgentTopologyError",
    "AgentTopologyStateError",
    "agent_names",
    "agent_view",
    "blast_radius",
    "enabled",
    "sync_mcp_inventory",
]
