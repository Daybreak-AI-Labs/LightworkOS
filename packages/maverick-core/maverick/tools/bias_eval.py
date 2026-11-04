"""Group-fairness metrics for model/decision outcomes.

Given per-group outcome counts, computes the standard disparate-impact metrics:
the **four-fifths rule** (each group's selection rate must be >= 0.8x the best
group's, else adverse-impact), the **demographic-parity difference** (max - min
selection rate), and, when per-group true-positive data is supplied, the
**equal-opportunity difference** (max - min true-positive rate). Pure ratios —
deterministic and offline. A screening aid, not a legal determination.

ops:
  - evaluate(groups, [threshold])  — ``groups`` is
    ``{name: {selected, total, [tp], [positives]}}``. Reports PASS/FAIL on the
    four-fifths rule (``threshold`` default 0.8), each group's selection rate +
    impact ratio, the demographic-parity difference, and (if tp/positives given)
    the equal-opportunity difference.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _evaluate(groups: dict, threshold: float) -> str:
    rates: dict[str, float] = {}
    tprs: dict[str, float] = {}
    for name, g in groups.items():
        if not isinstance(g, dict) or "selected" not in g or "total" not in g:
            return f"ERROR: group {name!r} needs 'selected' and 'total'"
        try:
            selected = int(g["selected"])
            total = int(g["total"])
        except (TypeError, ValueError):
            return f"ERROR: group {name!r} selected/total must be integers"
        if total <= 0:
            return f"ERROR: group {name!r} total must be > 0"
        if not 0 <= selected <= total:
            return f"ERROR: group {name!r} requires 0 <= selected <= total"
        rates[str(name)] = selected / total

        if "tp" in g or "positives" in g:
            if "tp" not in g or "positives" not in g:
                return f"ERROR: group {name!r} needs both 'tp' and 'positives' for equal-opportunity"
            try:
                tp = int(g["tp"])
                positives = int(g["positives"])
            except (TypeError, ValueError):
                return f"ERROR: group {name!r} tp/positives must be integers"
            if positives <= 0:
                return f"ERROR: group {name!r} positives must be > 0"
            if not 0 <= tp <= positives:
                return f"ERROR: group {name!r} requires 0 <= tp <= positives"
            tprs[str(name)] = tp / positives

    best = max(rates.values())
    lines = []
    failing = []
    for name in sorted(rates):
        rate = rates[name]
        ratio = rate / best if best > 0 else 1.0
        flag = ""
        if ratio < threshold:
            flag = " <-- adverse impact"
            failing.append(name)
        lines.append(f"  {name}: rate {rate:.3f}, impact ratio {ratio:.3f}{flag}")

    parity = best - min(rates.values())
    verdict = "FAIL" if failing else "PASS"
    out = [
        f"{verdict}: four-fifths rule (threshold {threshold:g})",
        *lines,
        f"demographic-parity difference: {parity:.3f}",
    ]
    if tprs:
        eo = max(tprs.values()) - min(tprs.values())
        out.append(f"equal-opportunity difference: {eo:.3f}")
        for name in sorted(tprs):
            out.append(f"  {name}: TPR {tprs[name]:.3f}")
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "evaluate"):
        return f"ERROR: unknown op {args.get('op')!r}"
    groups = args.get("groups")
    if not isinstance(groups, dict) or len(groups) < 2:
        return "ERROR: groups must be an object of >=2 groups -> {selected, total}"
    threshold = args.get("threshold", 0.8)
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return "ERROR: threshold must be a number in (0, 1]"
    if not 0 < threshold <= 1:
        return "ERROR: threshold must be in (0, 1]"
    return _evaluate(groups, threshold)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["evaluate"]},
        "groups": {
            "type": "object",
            "description": (
                "group name -> {selected, total, [tp], [positives]}; "
                "tp/positives enable the equal-opportunity difference"
            ),
        },
        "threshold": {
            "type": "number",
            "description": "four-fifths rule threshold (default 0.8)",
        },
    },
    "required": ["groups"],
}


def bias_eval() -> Tool:
    return Tool(
        name="bias_eval",
        description=(
            "Compute group-fairness metrics for decision/model outcomes. "
            "op=evaluate with 'groups' ({name: {selected, total, [tp], "
            "[positives]}}). Reports PASS/FAIL on the four-fifths rule "
            "('threshold' default 0.8), per-group selection rate + impact ratio, "
            "the demographic-parity difference, and the equal-opportunity "
            "difference when tp/positives are supplied. Screening aid, not legal "
            "advice. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
