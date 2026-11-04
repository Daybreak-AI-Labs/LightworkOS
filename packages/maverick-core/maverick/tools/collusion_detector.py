"""Multi-agent collusion detector.

The swarm's safety story leans on *independent* checks — and independence
fails two different ways, so this tool detects both:

* **op=scan** — *content collusion* in a batch of agent messages: echoed
  reasoning (high lexical overlap between distinct agents) and
  rubber-stamping (an agent that approves every review). The tell-tales
  that independent voices have collapsed into one.
* **op=detect** — *voting collusion* across rounds: an independent-quorum
  guarantee (N agents must independently approve) is defeated if a bloc
  always votes together. Given each agent's vote sequence, link any pair
  whose agreement is at/above a threshold and report the connected blocs,
  flagging any large enough to swing a quorum.

Both checks are pure counting/lexical overlap — deterministic and offline, no
model.

ops:
  - scan(messages[, threshold])  — messages: [{agent, text, verdict?}].
  - detect(votes[, threshold, quorum])  — votes: {agent: [v, ...]} with
    equal-length sequences; threshold default 1.0 (perfect correlation);
    a bloc of >= quorum agents is flagged quorum-defeating.

With ``op`` omitted, the payload disambiguates: ``messages`` -> scan,
``votes`` -> detect.
"""
from __future__ import annotations

import re
from itertools import combinations
from typing import Any

from . import Tool

# ---- op=scan: content collusion ---------------------------------------------

_APPROVE = {"approve", "approved", "accept", "accepted", "pass", "lgtm", "yes", "ok"}
_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(str(text).lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _scan(args: dict[str, Any]) -> str:
    msgs = args.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return "ERROR: messages must be a non-empty array of {agent, text}"
    threshold = args.get("threshold", 0.85)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 < threshold <= 1:
        return "ERROR: threshold must be a number in (0, 1]"

    rows: list[tuple[str, str, str | None]] = []
    for m in msgs:
        if not isinstance(m, dict) or "agent" not in m or "text" not in m:
            return "ERROR: each message needs 'agent' and 'text'"
        verdict = m.get("verdict")
        rows.append((str(m["agent"]), str(m["text"]), str(verdict).lower() if verdict is not None else None))

    signals: list[str] = []

    # Echoed reasoning: high lexical overlap between DISTINCT agents.
    toks = [(a, _tokens(t)) for a, t, _ in rows]
    seen: set[tuple[int, int]] = set()
    for i in range(len(toks)):
        for j in range(i + 1, len(toks)):
            if toks[i][0] == toks[j][0] or (i, j) in seen:
                continue
            sim = _jaccard(toks[i][1], toks[j][1])
            if sim >= threshold:
                seen.add((i, j))
                signals.append(
                    f"echoed reasoning: {toks[i][0]} ~ {toks[j][0]} (similarity {sim:.2f})"
                )

    # Rubber-stamp: an agent whose verdicts are present and all approvals.
    by_agent: dict[str, list[str]] = {}
    for a, _, v in rows:
        if v is not None:
            by_agent.setdefault(a, []).append(v)
    for a, verdicts in sorted(by_agent.items()):
        approvals = sum(1 for v in verdicts if v in _APPROVE)
        if len(verdicts) >= 3 and approvals == len(verdicts):
            signals.append(f"rubber-stamp: {a} approved all {len(verdicts)} reviews")

    lines = [f"agents: {len({a for a, _, _ in rows})}  messages: {len(rows)}"]
    if signals:
        lines.append(f"verdict: COLLUSION SIGNALS ({len(signals)})")
        lines.extend(f"  - {s}" for s in signals)
    else:
        lines.append("verdict: CLEAN")
    return "\n".join(lines)


# ---- op=detect: voting collusion --------------------------------------------

def _agreement(a: list, b: list) -> float:
    rounds = len(a)
    matches = sum(1 for x, y in zip(a, b, strict=False) if x == y)
    return matches / rounds


def _detect(votes: dict, threshold: float, quorum: int | None) -> str:
    agents = list(votes.keys())
    seqs: dict[str, list] = {}
    length = None
    for name in agents:
        seq = votes[name]
        if not isinstance(seq, list) or not seq:
            return f"ERROR: agent {name!r} must have a non-empty list of votes"
        if length is None:
            length = len(seq)
        elif len(seq) != length:
            return "ERROR: all agents must have the same number of rounds"
        seqs[name] = [str(v) for v in seq]

    # Union-find over agent pairs that agree at/above the threshold.
    parent = {name: name for name in agents}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    pair_agree: dict[tuple[str, str], float] = {}
    for a, b in combinations(agents, 2):
        ag = _agreement(seqs[a], seqs[b])
        pair_agree[(a, b)] = ag
        if ag >= threshold:
            parent[find(a)] = find(b)

    blocs: dict[str, list[str]] = {}
    for name in agents:
        blocs.setdefault(find(name), []).append(name)

    flagged = []
    for members in blocs.values():
        if len(members) < 2:
            continue
        members = sorted(members)
        cohesion = min(
            pair_agree[(a, b)] if (a, b) in pair_agree else pair_agree[(b, a)]
            for a, b in combinations(members, 2)
        )
        flagged.append((members, cohesion))

    flagged.sort(key=lambda x: (-len(x[0]), x[0]))

    header = f"{len(agents)} agents, {length} rounds, threshold {threshold:g}"
    if not flagged:
        return f"CLEAR: no collusion blocs ({header})"

    quorum_hits = [m for m, _ in flagged if quorum is not None and len(m) >= quorum]
    verdict = "COLLUSION" if quorum_hits else "SUSPECT"
    lines = [f"{verdict}: {len(flagged)} bloc(s) ({header}):"]
    for members, cohesion in flagged:
        tag = ""
        if quorum is not None and len(members) >= quorum:
            tag = f" -- quorum-defeating (>= {quorum})"
        lines.append(f"  {{{', '.join(members)}}} cohesion {cohesion:g}{tag}")
    return "\n".join(lines)


def _run_detect(args: dict[str, Any]) -> str:
    votes = args.get("votes")
    if not isinstance(votes, dict) or len(votes) < 2:
        return "ERROR: votes must be an object of >=2 agents -> [votes]"
    threshold = args.get("threshold", 1.0)
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return "ERROR: threshold must be a number in [0, 1]"
    if not 0.0 <= threshold <= 1.0:
        return "ERROR: threshold must be a number in [0, 1]"
    quorum = args.get("quorum")
    if quorum is not None:
        if isinstance(quorum, bool) or not isinstance(quorum, int) or quorum < 2:
            return "ERROR: quorum must be an integer >= 2"
    return _detect(votes, threshold, quorum)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op is None:
        # Payload disambiguates the two converged surfaces.
        op = "detect" if "votes" in args else "scan"
    if op == "scan":
        return _scan(args)
    if op == "detect":
        return _run_detect(args)
    return f"ERROR: unknown op {op!r}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["scan", "detect"]},
        "messages": {
            "type": "array",
            "description": "scan: agent messages [{agent, text, verdict?}]",
            "items": {
                "type": "object",
                "properties": {
                    "agent": {"type": "string"},
                    "text": {"type": "string"},
                    "verdict": {"type": "string"},
                },
                "required": ["agent", "text"],
            },
        },
        "votes": {
            "type": "object",
            "description": "detect: {agent: [vote, ...]} equal-length sequences",
        },
        "threshold": {
            "type": "number",
            "description": "scan: similarity cutoff (default 0.85); detect: agreement cutoff (default 1.0)",
        },
        "quorum": {"type": "integer", "description": "detect: flag blocs >= this size"},
    },
}


def collusion_detector() -> Tool:
    return Tool(
        name="collusion_detector",
        description=(
            "Detect collusion between supposedly independent swarm agents. "
            "op=scan ('messages': [{agent, text, verdict?}]) flags echoed "
            "reasoning and rubber-stamping. op=detect ('votes': {agent: "
            "[v, ...]}, optional 'quorum') finds voting blocs whose agreement "
            "is >= 'threshold' and flags quorum-defeating ones. "
            "Deterministic; no model call."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
