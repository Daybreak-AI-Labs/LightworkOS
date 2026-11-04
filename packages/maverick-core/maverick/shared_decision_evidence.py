"""Exact finite decision entailment and shared observation acquisition.

This is an authored model, not a claim about the completeness or truth of a
business process. No business action is executed. Operator assertions are
conditional premises; independent verification cannot be supplied by a score.
"""
from __future__ import annotations

import itertools
import math
import re

from .commitment_viability import Evidence
from .governed_operations import digest

MAX_FACTS, MAX_CASES, MAX_ACTIONS, MAX_STATES = 8, 16, 4, 128
SUFFICIENT_REASON = "This choice satisfies its authored conditions in every remaining modeled state. Its business premises are operator-supplied."


def _text(value, label, maximum=240):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(label + " must be complete bounded text")


def _integer(value, label, minimum=0, maximum=1_000_000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(label + " is outside the finite model's bounds")


def _identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", value):
        raise ValueError("choose a bounded portable identity")


def _definitions(facts, cases):
    fact_ids, case_ids = set(), set()
    for fact in facts:
        if set(fact) != {"id", "name", "meaning", "source", "values", "cost", "fresh_hours"}:
            raise ValueError("each fact needs its exact meaning, source and finite values")
        for key in ("id", "name", "meaning", "source"):
            _text(fact[key], "Fact " + key, 1000 if key == "meaning" else 160)
        _identity(fact["id"])
        if fact["id"] in fact_ids:
            raise ValueError("fact identities must be unique")
        fact_ids.add(fact["id"])
        if (not isinstance(fact["values"], list) or not 2 <= len(fact["values"]) <= 8
                or len(set(fact["values"])) != len(fact["values"])):
            raise ValueError("each fact requires two to eight distinct possible quantities")
        for value in fact["values"]:
            _integer(value, "Possible quantity")
        _integer(fact["cost"], "Observation effort points", 1, 1000)
        _integer(fact["fresh_hours"], "Source review hours", 1, 168)
    for case in cases:
        if set(case) != {"id", "name", "due_at", "actions"}:
            raise ValueError("each case requires its name, deadline and finite actions")
        _text(case["id"], "Case identity", 160)
        _identity(case["id"])
        _text(case["name"], "Case name", 200)
        if case["id"] in case_ids:
            raise ValueError("case identities must be unique")
        case_ids.add(case["id"])
        if (type(case["due_at"]) not in {int, float} or not math.isfinite(case["due_at"]) or case["due_at"] <= 0
                or not isinstance(case["actions"], list) or not 1 <= len(case["actions"]) <= MAX_ACTIONS):
            raise ValueError("each case needs a deadline and one to four acceptable choices")
        actions = set()
        for action in case["actions"]:
            if set(action) != {"id", "name", "conditions"}:
                raise ValueError("each choice requires exact authored conditions")
            _text(action["id"], "Action identity", 160)
            _identity(action["id"])
            _text(action["name"], "Action name", 200)
            if action["id"] in actions or not isinstance(action["conditions"], list) or not 1 <= len(action["conditions"]) <= 8:
                raise ValueError("each choice needs one to eight complete conditions")
            actions.add(action["id"])
            for condition in action["conditions"]:
                if (set(condition) != {"fact", "operator", "value"} or condition["fact"] not in fact_ids
                        or condition["operator"] not in {"at_least", "at_most", "equals"}):
                    raise ValueError("choose an existing fact and an exact comparison")
                _integer(condition["value"], "Required quantity")
    return fact_ids


def validate(model):
    """Reject incomplete/oversized models; never retain a truncated model."""
    required = {"title", "facts", "cases", "states", "question_budget", "effort_budget"}
    if set(model) not in (required, required | {"robust"}):
        raise ValueError("choose a complete finite decision model")
    _text(model["title"], "Review name", 200)
    facts, cases, states = model["facts"], model["cases"], model["states"]
    if not isinstance(facts, list) or not 1 <= len(facts) <= MAX_FACTS:
        raise ValueError("choose one to eight facts")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("choose one to sixteen cases")
    if not isinstance(states, list) or not 1 <= len(states) <= MAX_STATES:
        raise ValueError("explicitly retain one to 128 possible joint states")
    _integer(model["question_budget"], "Question budget", maximum=100)
    _integer(model["effort_budget"], "Effort-point budget", maximum=10_000)
    fact_ids = _definitions(facts, cases)
    definitions = {fact["id"]: fact for fact in facts}
    for state in states:
        if not isinstance(state, dict) or set(state) != fact_ids or any(type(state[key]) is not int or state[key] not in definitions[key]["values"] for key in state):
            raise ValueError("each joint state must give exactly one declared value for every fact")
    if len({digest(state) for state in states}) != len(states):
        raise ValueError("joint states must be unique")
    if "robust" in model:
        from .robust_decisions import validate_section
        validate_section(model, model["robust"])
    return model


def all_states(facts):
    """Authoring convenience: show the entire bounded product before selection."""
    count = math.prod(len(fact["values"]) for fact in facts)
    if count > MAX_STATES:
        raise ValueError("this full set exceeds 128 joint states; reduce the model, no states were dropped")
    return [dict(zip((fact["id"] for fact in facts), values, strict=True))
            for values in itertools.product(*(fact["values"] for fact in facts))]


def _holds(condition, state):
    actual, target = state[condition["fact"]], condition["value"]
    return actual >= target if condition["operator"] == "at_least" else actual <= target if condition["operator"] == "at_most" else actual == target


class Solver:
    """Bitset world intersection plus exact minimum-cardinality certificates."""

    def __init__(self, model, sources, now, *, questions_used=0, effort_used=0, pending_facts=()):
        self.model = validate(model)
        self.sources, self.now = sources, now
        self.pending_facts = set(pending_facts)
        self.questions_left = max(0, model["question_budget"] - questions_used)
        self.effort_left = max(0, model["effort_budget"] - effort_used)
        self.facts = {fact["id"]: fact for fact in model["facts"]}
        self.all = (1 << len(model["states"])) - 1
        self.masks = {(fact["id"], value): sum(1 << index for index, state in enumerate(model["states"]) if state[fact["id"]] == value)
                      for fact in model["facts"] for value in fact["values"]}
        self.actions = {(case["id"], action["id"]): sum(1 << index for index, state in enumerate(model["states"])
                        if all(_holds(condition, state) for condition in action["conditions"]))
                        for case in model["cases"] for action in case["actions"]}

    def source_current(self, fact, case):
        row = self.sources.get(fact)
        if (not row or not row.get("available") or case not in row.get("consent_cases", [])
                or row.get("definition") != digest(self.facts[fact]) or row.get("quality") != "operator_supplied"):
            return False
        try:
            evidence = Evidence(fact, row["revision"], row["observed_at"], row["expires_at"])
            return evidence.current(self.now, {fact: row["revision"]})
        except (KeyError, ValueError, TypeError):
            return False

    def observations(self, case, hypothetical=None):
        values = {key: row["value"] for key, row in self.sources.items()
                  if key in self.facts and self.source_current(key, case) and type(row.get("value")) is int and row["value"] in self.facts[key]["values"]}
        if hypothetical and self.source_current(hypothetical[0], case):
            values[hypothetical[0]] = hypothetical[1]
        return values

    def worlds(self, observations):
        mask = self.all
        for fact, value in observations.items():
            mask &= self.masks[(fact, value)]
        return mask

    def sufficient(self, case, hypothetical=None, *, minimal=True):
        if self.now >= case["due_at"]:
            return {"case": case["id"], "status": "unknown", "reason": "The decision deadline has passed."}
        observed = self.observations(case["id"], hypothetical)
        possible = self.worlds(observed)
        if not possible:
            return {"case": case["id"], "status": "unknown", "reason": "Reported observations contradict the authored joint states."}
        for action in case["actions"]:
            obligations = sorted({condition["fact"] for condition in action["conditions"]})
            if any(not self.source_current(fact, case["id"]) for fact in obligations):
                continue
            acceptable = self.actions[(case["id"], action["id"])]
            if possible & ~acceptable:
                continue
            subset = tuple(sorted(observed))
            if minimal:
                for size in range(len(subset) + 1):
                    found = next((trial for trial in itertools.combinations(subset, size)
                                  if self.worlds({fact: observed[fact] for fact in trial}) and not
                                  self.worlds({fact: observed[fact] for fact in trial}) & ~acceptable), None)
                    if found is not None:
                        subset = found
                        break
            dependency_ids = sorted(set(obligations) | set(subset))
            dependencies = [{"fact": fact, "source_revision": self.sources[fact]["revision"],
                "meaning_sha256": self.sources[fact]["definition"], "consent_case": case["id"],
                "expires_at": self.sources[fact]["expires_at"],
                "observation": observed[fact] if fact in subset else None} for fact in dependency_ids]
            material = {"model": digest(self.model), "case": case["id"], "action": action["id"], "dependencies": dependencies,
                        "observed_subset": list(subset), "remaining_states": self.worlds({fact: observed[fact] for fact in subset}).bit_count(),
                        "decision_before": min([case["due_at"]] + [row["expires_at"] for row in dependencies])}
            return {**material, "id": digest(material), "status": "model_sufficient", "case": case["id"],
                    "reason": SUFFICIENT_REASON,
                    "business_verified": False}
        return {"case": case["id"], "status": "unknown", "reason": "No authorized, current choice meets its conditions across all remaining modeled states."}

    def assessment(self):
        certificates = [self.sufficient(case) for case in self.model["cases"]]
        graph = {fact: [row["case"] for row in certificates if row["status"] == "model_sufficient"
                       and any(item["fact"] == fact for item in row["dependencies"])] for fact in self.facts}
        return {"certificates": certificates, "dependency_graph": graph,
                "budget": {"questions_left": self.questions_left, "effort_points_left": self.effort_left},
                "states": len(self.model["states"]), "evaluated_at": self.now}

    def _baseline_sufficient(self, case, hypothetical=None):
        """Strong authored comparator: exhaustive states and the same permissions."""
        if self.now >= case["due_at"]:
            return False
        observations = self.observations(case["id"], hypothetical)
        worlds = [state for state in self.model["states"] if all(state[fact] == value for fact, value in observations.items())]
        return bool(worlds) and any(all(self.source_current(condition["fact"], case["id"]) for condition in action["conditions"])
            and all(all(_holds(condition, state) for condition in action["conditions"]) for state in worlds) for action in case["actions"])

    def acquisition(self):
        """Select one observation; uniform branch weighting is an authored proxy."""
        current = {case["id"]: self.sufficient(case, minimal=False)["status"] == "model_sufficient" for case in self.model["cases"]}
        candidates, baseline = [], []
        if self.questions_left:
            for fact in self.model["facts"]:
                if (fact["cost"] > self.effort_left or fact["id"] in self.pending_facts
                        or self.sources.get(fact["id"], {}).get("value") is not None):
                    continue
                applicable = [case for case in self.model["cases"] if self.source_current(fact["id"], case["id"]) and not current[case["id"]]]
                if not applicable:
                    continue
                # All declared outcomes remain possible unless currently
                # consented cached observations exclude them for every case.
                outcomes = [value for value in fact["values"] if any(self.worlds(self.observations(case["id"])) & self.masks[(fact["id"], value)] for case in applicable)]
                branches, reference = [], []
                for value in outcomes:
                    resolved = [case["id"] for case in applicable if self.sufficient(case, (fact["id"], value), minimal=False)["status"] == "model_sufficient"]
                    exact = [case["id"] for case in applicable if self._baseline_sufficient(case, (fact["id"], value))]
                    branches.append({"value": value, "new_cases": resolved})
                    reference.append(len(exact))
                if not branches:
                    continue
                gains = [len(row["new_cases"]) for row in branches]
                score = (min(gains), sum(gains) / len(gains) / fact["cost"], -min(case["due_at"] for case in applicable), -fact["cost"])
                refscore = (min(reference), sum(reference) / len(reference) / fact["cost"], -min(case["due_at"] for case in applicable), -fact["cost"])
                candidates.append({"fact": fact["id"], "cost": fact["cost"], "worst_case_new_cases": min(gains),
                    "uniform_branch_mean_new_cases": sum(gains) / len(gains), "branches": branches,
                    "applicable_cases": [case["id"] for case in applicable], "score": score})
                baseline.append((refscore, fact["id"]))
        ranked = sorted(candidates, key=lambda row: (tuple(-value for value in row["score"]), row["fact"]))
        selected = ranked[0] if ranked and ranked[0]["uniform_branch_mean_new_cases"] > 0 else None
        baseline.sort(key=lambda row: (tuple(-value for value in row[0]), row[1]))
        baseline_selected = baseline[0][1] if baseline and baseline[0][0][1] > 0 else None
        return {"selected": {key: value for key, value in selected.items() if key != "score"} if selected else None,
                "candidates": [{key: value for key, value in row.items() if key != "score"} for row in ranked],
                "objective": "Maximize the worst-case number of newly sufficient cases; then uniform declared-outcome mean per effort point, earliest case deadline, lower cost and fact identity. This is a one-observation objective, not global business optimality.",
                "budget": {"questions_left": self.questions_left, "effort_points_left": self.effort_left},
                "strong_authored_baseline": {"method": "Exhaustive complete-state acquisition with identical shared cache, permissions, outcomes, budget and objective.",
                    "selected_fact": baseline_selected, "same_selection": baseline_selected == (selected["fact"] if selected else None),
                    "claim": "No novelty or superiority has been established."},
                "unknown": selected is None}


def check_certificate(certificate, model, sources, now):
    """Check only actual minimal dependencies; unrelated observations need not invalidate."""
    try:
        return _check_certificate(certificate, model, sources, now)
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        return False


def _check_certificate(certificate, model, sources, now):
    material_keys = ("model", "case", "action", "dependencies", "observed_subset", "remaining_states", "decision_before")
    if (not isinstance(certificate, dict) or set(certificate) != set(material_keys) | {"id", "status", "reason", "business_verified"}
            or certificate["status"] != "model_sufficient" or certificate["business_verified"] is not False
            or certificate["reason"] != SUFFICIENT_REASON or certificate["model"] != digest(model)
            or type(certificate["decision_before"]) not in {int, float} or not math.isfinite(certificate["decision_before"])
            or now >= certificate["decision_before"]):
        return False
    solver = Solver(model, sources, now)
    case = next((row for row in model["cases"] if row["id"] == certificate["case"]), None)
    action = next((row for row in case["actions"] if row["id"] == certificate["action"]), None) if case else None
    if case is None or action is None:
        return False
    if not solver.worlds(solver.observations(case["id"])):
        return False
    subset, dependencies = certificate["observed_subset"], certificate["dependencies"]
    if (not isinstance(subset, list) or len(subset) > MAX_FACTS or len(set(subset)) != len(subset)
            or any(fact not in solver.facts for fact in subset) or not isinstance(dependencies, list) or len(dependencies) > MAX_FACTS):
        return False
    obligations = {condition["fact"] for condition in action["conditions"]}
    required = obligations | set(subset)
    observed, found = {}, set()
    for dependency in dependencies:
        if (not isinstance(dependency, dict) or set(dependency) != {"fact", "source_revision", "meaning_sha256", "consent_case", "expires_at", "observation"}
                or dependency["fact"] not in required or dependency["fact"] in found):
            return False
        fact, row = dependency["fact"], sources.get(dependency["fact"], {})
        if (not solver.source_current(fact, case["id"]) or row.get("revision") != dependency["source_revision"]
                or dependency["meaning_sha256"] != digest(solver.facts[fact]) or dependency["consent_case"] != case["id"]
                or dependency["expires_at"] != row.get("expires_at")):
            return False
        if fact in subset:
            if (type(dependency["observation"]) is not int or dependency["observation"] not in solver.facts[fact]["values"]
                    or type(row.get("value")) is not int or row["value"] != dependency["observation"]):
                return False
            observed[fact] = dependency["observation"]
        elif dependency["observation"] is not None:
            return False
        found.add(fact)
    if found != required:
        return False
    possible = solver.worlds(observed)
    acceptable = solver.actions[(case["id"], action["id"])]
    if (not possible or possible & ~acceptable or type(certificate["remaining_states"]) is not int
            or certificate["remaining_states"] != possible.bit_count()
            or certificate["decision_before"] != min([case["due_at"]] + [sources[fact]["expires_at"] for fact in required])):
        return False
    for size in range(len(subset)):
        for trial in itertools.combinations(sorted(subset), size):
            smaller = solver.worlds({fact: observed[fact] for fact in trial})
            if smaller and not smaller & ~acceptable:
                return False
    return certificate["id"] == digest({key: certificate[key] for key in material_keys})
