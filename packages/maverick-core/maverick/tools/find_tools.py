"""find_tools: the deferred-tool discovery meta-tool.

With deferred loading on (``ToolRegistry.enable_deferred``), the model only
sees a small core set + this tool. Calling ``find_tools(query)`` ranks the
hidden long-tail tools by relevance, ACTIVATES the best matches (so they
appear in the catalog on the next turn and become callable), and returns
their names + descriptions so the model knows what it just unlocked.

Ranking is lexical (token overlap of the query against each tool's name +
description, with a name-match bias) -- no embedding dependency, so it runs
in the kernel with zero extra installs.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool
from ._lazy import search_tokens

_TOKEN = re.compile(r"[a-z0-9]+")

# Dropped from the QUERY so filler words don't manufacture matches (e.g.
# "create a Jira issue" shouldn't activate every tool whose description
# happens to contain "a" or "issue").
_STOP = frozenset({
    "a", "an", "the", "and", "or", "to", "of", "for", "in", "on", "with",
    "my", "is", "are", "be", "i", "need", "want", "please", "can", "you",
    "use", "using", "via", "that", "this", "it", "do", "get", "set",
})


def _tokens(s: str) -> set[str]:
    return set(_TOKEN.findall((s or "").lower()))


def _query_tokens(s: str) -> set[str]:
    return _tokens(s) - _STOP


def _score(query_tokens: set[str], tool: Tool) -> int:
    body, name = search_tokens(tool.name, tool.description)
    if not body:
        return 0
    # A name hit is worth more than a description hit.
    return len(query_tokens & body) + 2 * len(query_tokens & name)


def find_tools(registry) -> Tool:
    """Build the find_tools meta-tool bound to ``registry``."""

    def run(args: dict[str, Any]) -> str:
        query = str(args.get("query", "")).strip()
        if not query:
            return "Provide a 'query' describing the capability you need."
        try:
            max_results = int(args.get("max_results", 5) or 5)
        except (TypeError, ValueError):
            max_results = 5
        max_results = max(1, min(max_results, 20))

        qt = _query_tokens(query)
        if not qt:
            return "Provide a 'query' describing the capability you need."
        scored = [(_score(qt, t), t) for t in registry.deferred_tools()]
        scored = [(s, t) for s, t in scored if s > 0]
        if not scored:
            return (
                f"No additional tools matched {query!r}. The tools already "
                "available to you cover the rest -- proceed with those."
            )
        # Tool-failure taxonomy, recall side: demote tools the loop guard has
        # repeatedly caught failing the same way (persisted ``tool_flaky``
        # reflexions) so a known-flaky connector loses ties to a healthy one.
        # Demotion, never exclusion -- it may still be the only match. So the
        # near-best threshold filter runs on the BASE (pre-demotion) scores;
        # the 0.5 factor only weakens the sort/tie-break, never fully excludes a
        # sole viable match below the threshold.
        _flaky: frozenset[str] | set[str] = frozenset()
        try:
            from .. import reflexion as _reflexion
            if _reflexion.enabled():
                _flaky = _reflexion.flaky_tools() or frozenset()
        except Exception:  # pragma: no cover -- never blocks tool discovery
            _flaky = frozenset()

        # Keep only matches near the best hit, so a weak coincidental overlap
        # doesn't activate (and pollute the catalog with) an unrelated tool.
        top_score = max(s for s, _ in scored)
        threshold = max(1.0, top_score / 2)
        scored = [(s, t) for s, t in scored if s >= threshold]
        # Sort on the demoted score so flaky tools lose ties to healthy ones,
        # while the threshold filter above (on base scores) has already kept a
        # sole flaky match viable.
        def _sort_key(item: tuple[int, Tool]) -> tuple[float, str]:
            s, t = item
            eff = s * 0.5 if t.name in _flaky else float(s)
            return (-eff, t.name)

        scored.sort(key=_sort_key)
        top = [t for _, t in scored[:max_results]]
        # The catalog prefers the most recently activated tool when the model
        # has fewer slots than matches. Activate lowest-ranked first so the
        # strongest match is the one that remains callable.
        activated = set(registry.activate([t.name for t in reversed(top)]))
        top = [t for t in top if t.name in activated]
        if not top:
            return (
                "This model's tool limit leaves no room for another action. "
                "Ask an administrator to raise the tool limit in AI model settings."
            )
        lines = [f"Activated {len(top)} tool(s); you can call them now:"]
        for t in top:
            first = (t.description or "").strip().splitlines()
            desc = first[0][:140] if first else ""
            lines.append(f"- {t.name}: {desc}")
        return "\n".join(lines)

    return Tool(
        name=registry.META_TOOL,
        description=(
            "Search for and activate additional tools by capability when the "
            "tools already available don't cover what you need (e.g. 'create a "
            "Jira issue', 'query a Postgres database', 'send a Slack message', "
            "'transcribe audio'). Returns the matching tools and makes them "
            "callable on your next turn. Call this BEFORE concluding a "
            "capability is unavailable."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The capability you need, in plain words.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max tools to activate (default 5, max 20).",
                },
            },
            "required": ["query"],
        },
        fn=run,
    )


__all__ = ["find_tools"]
