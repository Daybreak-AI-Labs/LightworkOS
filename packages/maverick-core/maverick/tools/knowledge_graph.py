"""Knowledge-graph builder tool.

Turns text or explicit triples into a small entity/relation graph the agent
can query without an external graph DB. Stateless like every tool: the caller
passes the triples (or text to extract them from) on each call.

ops:
  - extract(text)            — pull (subject, relation, object) triples from
                               prose using a deterministic relation-verb
                               heuristic, plus structured ``S | R | O`` lines.
  - query(triples, ...)      — filter triples by subject / relation / object.
  - neighbors(triples, node) — entities one hop from ``node`` (either direction).
  - dot(triples)             — render the graph as Graphviz DOT.

Triples are ``[subject, relation, object]`` lists. Extraction is heuristic, not
a parser — it is honest about that and only emits a triple when a known
relation verb anchors the sentence.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Relation verbs we recognise in prose, longest first so "depends on" wins over
# a bare "on" and "is part of" beats "is". Each maps to a normalised relation.
_RELATIONS: list[tuple[str, str]] = [
    (r"depends on", "depends_on"),
    (r"is part of", "part_of"),
    (r"are part of", "part_of"),
    (r"belongs to", "part_of"),
    (r"consists of", "has_part"),
    (r"contains", "contains"),
    (r"includes", "contains"),
    (r"requires", "requires"),
    (r"produces", "produces"),
    (r"uses", "uses"),
    (r"use", "uses"),
    (r"has", "has"),
    (r"have", "has"),
    (r"is a", "is_a"),
    (r"are a", "is_a"),
    (r"is an", "is_a"),
    (r"is", "is_a"),
    (r"are", "is_a"),
]


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().strip(".,;:")


def _extract(text: str) -> list[list[str]]:
    triples: list[list[str]] = []
    for raw in re.split(r"[.\n;]+", text or ""):
        line = raw.strip()
        if not line:
            continue
        # Structured "S | R | O" or "S -> R -> O" wins over the heuristic.
        # Split on the bare separator; _clean trims the parts. Folding the
        # surrounding \s* into the pattern made a long space run quadratic.
        parts = re.split(r"\||->", line)
        if len(parts) == 3 and all(p.strip() for p in parts):
            triples.append([_clean(parts[0]), _clean(parts[1]), _clean(parts[2])])
            continue
        low = line.lower()
        for verb, rel in _RELATIONS:
            m = re.search(rf"\b{verb}\b", low)
            if not m:
                continue
            subj = _clean(line[: m.start()])
            obj = _clean(line[m.end():])
            # Drop a leading article on the object ("a/an/the").
            obj = re.sub(r"^(a|an|the)\s+", "", obj, flags=re.IGNORECASE)
            if subj and obj:
                triples.append([subj, rel, obj])
            break
    return triples


def _as_triples(raw: Any) -> list[list[str]]:
    out: list[list[str]] = []
    if not isinstance(raw, (list, tuple)):
        return out
    for t in raw:
        if isinstance(t, (list, tuple)) and len(t) == 3:
            out.append([str(t[0]).strip(), str(t[1]).strip(), str(t[2]).strip()])
    return out


def _query(triples: list[list[str]], subj: str, rel: str, obj: str) -> str:
    def match(have: str, want: str) -> bool:
        return not want or have.lower() == want.lower()

    hits = [t for t in triples if match(t[0], subj) and match(t[1], rel) and match(t[2], obj)]
    if not hits:
        return "no matching triples"
    return "\n".join(f"{s} --{r}--> {o}" for s, r, o in hits)


def _neighbors(triples: list[list[str]], node: str) -> str:
    node_l = node.lower()
    out: list[str] = []
    for s, r, o in triples:
        if s.lower() == node_l:
            out.append(f"{node} --{r}--> {o}")
        elif o.lower() == node_l:
            out.append(f"{s} --{r}--> {node}")
    return "\n".join(out) if out else f"no edges touching {node!r}"


def _dot_id(value: str) -> str:
    """DOT accepts double-quoted IDs only; escape backslash and quote."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _dot(triples: list[list[str]]) -> str:
    lines = ["digraph knowledge {"]
    for s, r, o in triples:
        lines.append(f"  {_dot_id(s)} -> {_dot_id(o)} [label={_dot_id(r)}];")
    lines.append("}")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "extract":
        triples = _extract(str(args.get("text") or ""))
        if not triples:
            return "no triples extracted"
        return "\n".join(f"{s} | {r} | {o}" for s, r, o in triples)
    triples = _as_triples(args.get("triples"))
    if op == "query":
        return _query(
            triples,
            str(args.get("subject") or "").strip(),
            str(args.get("relation") or "").strip(),
            str(args.get("object") or "").strip(),
        )
    if op == "neighbors":
        node = str(args.get("node") or "").strip()
        if not node:
            return "ERROR: neighbors requires node"
        return _neighbors(triples, node)
    if op == "dot":
        return _dot(triples) if triples else "ERROR: dot requires triples"
    return f"ERROR: unknown op {op!r}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["extract", "query", "neighbors", "dot"]},
        "text": {"type": "string", "description": "prose to extract triples from (op=extract)"},
        "triples": {
            "type": "array",
            "items": {"type": "array", "items": {"type": "string"}},
            "description": "[subject, relation, object] triples (query/neighbors/dot)",
        },
        "subject": {"type": "string"},
        "relation": {"type": "string"},
        "object": {"type": "string"},
        "node": {"type": "string", "description": "entity to find neighbors of"},
    },
    "required": ["op"],
}


def knowledge_graph() -> Tool:
    return Tool(
        name="knowledge_graph",
        description=(
            "Build and query a small knowledge graph. ops: extract (text -> "
            "subject|relation|object triples via a relation-verb heuristic; "
            "also parses 'S | R | O' lines), query (filter triples by "
            "subject/relation/object), neighbors (one-hop entities of a node), "
            "dot (render triples as Graphviz DOT). Triples are passed in on "
            "each call; no external graph DB."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
