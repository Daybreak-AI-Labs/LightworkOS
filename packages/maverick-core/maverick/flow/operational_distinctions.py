"""Exact finite distinguishing sets and observed cells, not generalization.

Authority and source custody belong to the existing native capture/comparison
services. This module receives their complete authorized snapshots only.
"""
from __future__ import annotations

import itertools
import json
from collections import Counter

from ..budget import Budget
from . import action_choice as choice
from . import action_recipe as recipe
from . import action_recipe_transforms as transforms


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def field_label(source):
    path = " / ".join(str(part).replace("_", " ") for part in source["path"]) or "value"
    return ("Input: " if source["source"] == "input" else "Earlier result: ") + path


def observations(episodes, domain, tools):
    episodes, _tools, groups = choice._episodes(episodes, tools)
    domain = choice._domain(domain, groups)
    catalog, _definitions, columns = transforms._catalog(episodes, 1, {"inputs": domain["inputs"], "steps": [domain["prefix"]]})
    if len(catalog) != sum(1 for _source, _values in recipe._sources(episodes, 1)):
        raise ValueError("discovery requires complete text, whole-number or yes/no observations; unsupported observations cannot be silently omitted")
    rows = [{name: values[index] for name, values in columns.items()} for index in range(len(episodes))]
    return episodes, catalog, rows


def analyze(episodes, domain, tools, base_fields):
    """Find every smallest separator, preserving full-information collisions.

    Six native observations imply at most 64 subsets and 496 conflicting pairs.
    Whole-field lookup is the strong same-information empirical comparator.
    """
    episodes, catalog, rows = observations(episodes, domain, tools)
    names = [source["name"] for source in catalog]
    if (type(base_fields) is not list or len(set(base_fields)) != len(base_fields)
            or any(type(name) is not str or name not in names for name in base_fields)):
        raise ValueError("choose distinct available observations")
    base = sorted(base_fields)
    labels = [episode["steps"][1]["tool"] for episode in episodes]

    def key(index, fields):
        return canonical({name: rows[index][name] for name in fields})

    pairs = [(left, right) for left in range(len(rows)) for right in range(left + 1, len(rows))
             if labels[left] != labels[right] and key(left, base) == key(right, base)]
    extra = [name for name in names if name not in base]
    separators = [{name for name in extra if canonical(rows[left][name]) != canonical(rows[right][name])} for left, right in pairs]
    unresolved = [pair for pair, fields in zip(pairs, separators, strict=True) if not fields]
    sets = []
    if not unresolved:
        for size in range(len(extra) + 1):
            sets = [sorted([*base, *subset]) for subset in itertools.combinations(extra, size)
                    if all(set(subset) & fields for fields in separators) and len(base) + size > 0]
            if sets:
                break

    def bound(fields):
        cells = {}
        for index, label in enumerate(labels):
            cells.setdefault(key(index, fields), Counter())[label] += 1
        return sum(max(counts.values()) for counts in cells.values())

    return {"catalog": catalog, "rows": rows, "labels": labels, "base": base, "pairs": [list(pair) for pair in pairs],
            "unresolved": [list(pair) for pair in unresolved], "minimal_sets": sets,
            "projection_maximum_matches": bound(base), "whole_information_maximum_matches": bound(names),
            "cases": len(rows), "search_subsets": 2 ** len(extra)}


def qualified_fields(episodes, domain, tools, analysis):
    """Try the minimal separators through the unchanged native qualification.

    Never weaken distinct-fork or grammar requirements to make a finding look
    usable. A sufficient separator can still be outside the native rule grammar.
    """
    budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=10)
    for fields in analysis["minimal_sets"]:
        budget.check()
        try:
            artifact = choice.synthesize_choice(episodes, allowed_tools=tools, domain={**domain, "guard_fields": fields}, max_operations=1)
        except ValueError:
            continue
        budget.check()
        return fields, artifact
    return None, None


def observed_cells(comparisons):
    """Summarize exact recorded full-input cells within one immutable arm pair."""
    if type(comparisons) is not list or not 1 <= len(comparisons) <= 20:
        raise ValueError("choose one to twenty native comparisons")
    cells = {}
    for record in comparisons:
        if record.get("case_use") != "owner_authorized_evaluation_and_exact_release_review":
            raise ValueError("native comparison authorization is unavailable")
        version_pair = canonical([record["flow_id"], record["root"], record.get("candidate_manifest", {}),
                                  record["baseline"], record["output"]])
        for index, case in enumerate(record["cases"]):
            pair = record.get("results", [])[index] if record["state"] == "done" and index < len(record.get("results", [])) else None
            cell = cells.setdefault((version_pair, canonical(case["inputs"])), {"inputs": case["inputs"], "evidence": [], "classifications": set()})
            classification = "unknown"
            if pair and all(pair[arm]["status"] == "completed" and pair[arm]["result"] is not None for arm in ("baseline", "candidate")):
                matches = [pair[arm]["matches"] for arm in ("baseline", "candidate")]
                classification = ("candidate supported" if matches == [False, True] else "candidate contradicted" if matches == [True, False]
                                  else "both matched" if all(matches) else "neither matched")
            cell["classifications"].add(classification)
            cell["evidence"].append({"comparison": record["id"], "source_run": case["run_id"], "source_version": case["version"],
                                     "expected": case["expected"], "baseline": pair["baseline"]["result"] if pair else None,
                                     "candidate": pair["candidate"]["result"] if pair else None,
                                     "baseline_definition": record["baseline"]["definition_digest"], "candidate_definition": record["root"],
                                     "candidate_version": record["version"], "output": record["output"], "classification": classification})
    return [{"inputs": cell["inputs"], "classification": next(iter(cell["classifications"])) if len(cell["classifications"]) == 1 else "ambiguous",
             "evidence": cell["evidence"]} for _key, cell in sorted(cells.items())]
