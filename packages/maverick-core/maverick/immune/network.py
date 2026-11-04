"""Composition risk: what agents can do together that no single policy sees.

The "Rule of Two": no agent system should combine *sensitive data*, *state
change* and *external reach* without a control. Per-agent audits check each
agent alone; data moves between agents (shared blackboard, peer messaging,
delegation), so the envelope that matters is the one along a data-flow path.

Findings carry a witness -- the concrete tools and path -- and pack findings are
proven by the runtime :class:`~maverick.capability.Capability` itself
(``cap.permits(tool)``) under stated settings, not by a heuristic.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..capability import COORDINATION_TOOLS
from ..safety.tool_risk import risk_rank, tool_risk

SENSITIVE, MUTATE, EXTERNAL = "sensitive", "mutate", "external"

# Tools that read tenant data. Non-public enterprise connectors are added by
# :func:`classify` as sensitive: the tenant's own SaaS is inside its trust
# boundary. Unknown remote (``mcp_*``) tools are treated as all three. A tool can
# be both (``gmail`` reads a mailbox and sends to any address).
_SENSITIVE = frozenset({
    "read_file", "list_dir", "knowledge_search", "sql_query", "sql_query_read",
    "spreadsheet", "spreadsheet_read", "database", "memory", "kv_memory",
    "read_attachment", "read_pdf", "ocr", "pandas_query", "salesforce", "hubspot",
    "snowflake", "bigquery", "mongodb", "notion", "confluence", "msgraph", "jira",
    "gmail", "s3", "dropbox", "github_issues",
})
# Tools whose inputs can reach a destination outside the tenant chosen in the
# call (query strings count).
_EXTERNAL = frozenset({
    "email", "notify", "calendar", "http_fetch", "web_search", "web_archive",
    "browser", "computer", "websocket", "teams", "gmail", "sendgrid", "mailgun",
    "twilio", "ses", "sns",
    "slack_bot", "discord_bot", "telegram", "twitter", "github_issues",
    "openapi_runner", "git_advanced",
})
# Code execution reaches outside only when the sandbox allows egress.
# (``wasm_run`` is WASI with no network: never a sink.)
_SANDBOXED = frozenset({"shell", "notebook_exec", "code_exec", "repl_exec"})
# Backends that honour ``allow_network``. ``ssh`` runs on a remote host with its
# full network and unknown names degrade to ``local``: both count as egress.
_ISOLATED_BACKENDS = frozenset({"docker", "podman", "gvisor", "kubernetes",
                                "devcontainer", "modal"})


def _sandbox_egress() -> bool:
    """Whether sandboxed code can reach the network. ``local`` runs on the host
    with its full network; firecracker uses ``network``; the container backends
    honour ``allow_network``; anything unknown is assumed to have egress."""
    try:
        from ..config import load_config
        cfg = (load_config() or {}).get("sandbox") or {}
    except Exception:  # noqa: BLE001 -- unreadable config: assume egress (conservative)
        return True
    backend = str(cfg.get("backend") or "local").strip().lower()
    if backend == "local":
        try:
            from ..sandbox import container_backend_required
            if container_backend_required():
                backend = "docker"  # build_sandbox upgrades local to a container here
        except Exception:  # noqa: BLE001 -- unknown: keep the host (egress) answer
            pass
    if backend == "firecracker":
        return str(cfg.get("network", "egress-deny")).strip().lower() != "egress-deny"
    if backend not in _ISOLATED_BACKENDS:
        return True
    v = cfg.get("allow_network", False)
    return v is True or str(v).strip().lower() in ("1", "true", "yes", "on")


def classify(tool: str) -> frozenset[str]:
    """The Rule-of-Two classes a tool contributes (possibly several)."""
    from ..tools.enterprise_connectors import (
        ENTERPRISE_CONNECTOR_NAMES,
        PUBLIC_DATA_CONNECTOR_NAMES,
    )
    if tool in COORDINATION_TOOLS:  # modelled as data flows, not as powers
        return frozenset()
    if tool.startswith("mcp_"):
        return frozenset({SENSITIVE, MUTATE, EXTERNAL})
    out = set()
    if (tool in PUBLIC_DATA_CONNECTOR_NAMES or tool in _EXTERNAL
            or (tool in _SANDBOXED and _sandbox_egress())):
        out.add(EXTERNAL)
    if tool in _SENSITIVE or (tool in ENTERPRISE_CONNECTOR_NAMES
                              and tool not in PUBLIC_DATA_CONNECTOR_NAMES) or tool.endswith("_read"):
        out.add(SENSITIVE)
    if tool_risk(tool) == "high":
        out.add(MUTATE)
    return frozenset(out)


@dataclass
class Graph:
    """Agents (name -> reachable tools) and directed data flows between them."""
    agents: dict[str, frozenset[str]]
    flows: set[tuple[str, str]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self._succ: dict[str, list[str]] = {n: [] for n in self.agents}
        for a, b in sorted(self.flows):
            self._succ[a].append(b)

    def successors(self, node: str) -> list[str]:
        return self._succ[node]

    def classes(self, node: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {SENSITIVE: [], MUTATE: [], EXTERNAL: []}
        for tool in sorted(self.agents[node]):
            for cls in classify(tool):
                out[cls].append(tool)
        return out


@dataclass(frozen=True)
class Finding:
    kind: str                       # "trifecta" | "exfiltration"
    path: tuple[str, ...]           # agents, data flowing left to right
    witness: dict[str, tuple[str, str]]  # class -> (agent, tool)
    sink_risk: str                  # risk of the lowest-risk way out; "high"
                                    # sinks are the ones secure defaults escalate


def _paths_from(g: Graph, src: str) -> dict[str, tuple[str, ...]]:
    """Shortest data-flow path from ``src`` to every reachable agent (BFS),
    in BFS order so the first match is a shortest one."""
    seen = {src: (src,)}
    queue = deque([src])
    while queue:
        node = queue.popleft()
        for nxt in g.successors(node):
            if nxt not in seen:
                seen[nxt] = seen[node] + (nxt,)
                queue.append(nxt)
    return seen


def findings(g: Graph) -> list[Finding]:
    """One minimal finding per agent holding sensitive data.

    ``trifecta``: the data can flow through an agent with a state-changing tool
    and on to external reach. Otherwise ``exfiltration``: the data can reach an
    external sink. The witness names the concrete tools; the path is shortest.
    """
    cls = {n: g.classes(n) for n in g.agents}

    def sink(node: str) -> str:  # worst case: the least-guarded way out
        return min(cls[node][EXTERNAL], key=lambda t: (risk_rank(tool_risk(t)), t))

    out: list[Finding] = []
    for src in sorted(g.agents):
        if not cls[src][SENSITIVE]:
            continue
        reach = _paths_from(g, src)
        found = None
        for mid, head in reach.items():
            if not cls[mid][MUTATE]:
                continue
            tail = next(((d, p) for d, p in _paths_from(g, mid).items()
                         if cls[d][EXTERNAL]), None)
            if tail:
                found = ("trifecta", head + tail[1][1:], tail[0], (mid, cls[mid][MUTATE][0]))
                break
        if not found:
            dst = next((d for d in reach if cls[d][EXTERNAL]), None)
            if dst is None:
                continue
            found = ("exfiltration", reach[dst], dst, None)
        kind, path, dst, mutate = found
        witness = {SENSITIVE: (src, cls[src][SENSITIVE][0]), EXTERNAL: (dst, sink(dst))}
        if mutate:
            witness[MUTATE] = mutate
        out.append(Finding(kind, path, witness, tool_risk(witness[EXTERNAL][1])))
    return out


def blast_radius(g: Graph) -> dict[str, int]:
    """How many other agents each agent's output can reach (compromise spread)."""
    return {n: len(_paths_from(g, n)) - 1 for n in sorted(g.agents)}


def runtime_tools(profile, *, levels: bool | None = None,
                  grounding: bool | None = None) -> frozenset[str]:
    """Tools a pack can actually call: the runtime capability, not the TOML.

    ``levels`` / ``grounding`` evaluate the pack under an explicit autonomy /
    data-grounding dial; ``None`` keeps the deployment's current setting. The
    dials are passed to the capability builder, never written to the process
    environment, so a what-if check cannot change how running agents behave.
    """
    from ..domain import domain_capability
    cap = domain_capability(profile, None, f"agent:{profile.name}",
                            levels=levels, grounding=grounding)
    # An empty allowlist means EVERY tool (Capability semantics), not none.
    if cap.allow_tools:
        candidates = cap.allow_tools
    else:
        from ..tools import base_tool_names
        candidates = frozenset(base_tool_names() or ())
    return frozenset(t for t in candidates if cap.permits(t))


def roster_graph(domains=None, *, swarm: bool = False, levels: bool | None = None,
                 grounding: bool | None = None) -> Graph:
    """Graph of every pack. ``swarm=True`` adds the orchestrator hub: peer
    messaging and the shared blackboard are coordination tools no pack
    allowlist can remove, so every member's data can reach every other.
    ``levels`` / ``grounding`` as in :func:`runtime_tools`."""
    from ..domain import available_domains
    domains = domains if domains is not None else available_domains()
    agents = {name: runtime_tools(p, levels=levels, grounding=grounding)
              for name, p in sorted(domains.items())}
    flows: set[tuple[str, str]] = set()
    if swarm:
        agents["orchestrator"] = frozenset()
        for name in domains:
            flows |= {(name, "orchestrator"), ("orchestrator", name)}
    return Graph(agents, flows)


def load_graph(data: dict) -> Graph:
    """Build a graph from ``{"agents": {name: [tools]}, "flows": [[a, b]]}``."""
    agents = {str(k): frozenset(map(str, v)) for k, v in data["agents"].items()}
    flows = {(str(a), str(b)) for a, b in data.get("flows", [])}
    unknown = {n for pair in flows for n in pair} - agents.keys()
    if unknown:
        raise ValueError(f"flows reference unknown agents: {sorted(unknown)}")
    return Graph(agents, flows)
