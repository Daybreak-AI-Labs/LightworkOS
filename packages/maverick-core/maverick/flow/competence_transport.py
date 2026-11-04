"""Structural rule release and finite local adapter qualification.

Released structure is intentionally public. Names, literal values, evidence and
domain bounds are not included. Equality of exported bytes is asserted only at
an identical released structural projection, never as general privacy.
"""
from __future__ import annotations

import copy
import itertools
import json
import math
import time

from ..budget import Budget
from . import learned_operator as scalar
from . import runner
from .evolve import attach_learned_operator
from .selective_qualification import digest

SCHEMA = "lightwork.portable-rule-structure.v1"
KINDS = {"boolean", "integer", "string"}
MAX_ADAPTERS = 4096


def _abstract(program, spec):
    fields, parameters, types, kinds = {}, {}, [], []
    def abstract(part):
        if part[0] == "field":
            key = part[1]
            if key not in fields:
                fields[key] = len(fields)
                types.append(spec["inputs"][key]["type"])
            return ["input", fields[key]]
        if part[0] == "literal":
            key = scalar._canonical(part[1])
            if key not in parameters:
                parameters[key] = len(parameters)
                kinds.append(scalar._type(part[1]))
            return ["parameter", parameters[key]]
        return [part[0], *(abstract(child) for child in part[1:])]
    tree = abstract(program)
    return {"inputs": types, "parameters": kinds, "output": spec["output_type"], "program": tree}


def extract(artifact):
    scalar.validate_artifact(artifact)
    if len(artifact["candidates"]) > 32:
        raise ValueError("This rule has too many unresolved procedures to share. Add distinguishing examples first.")
    templates = {_key: item for item in (_abstract(program, artifact["spec"]) for program in artifact["candidates"]) for _key in [digest(item)]}
    return {"schema": SCHEMA, "templates": sorted(templates.values(), key=scalar._canonical)}


def _kind(item, node, depth=0):
    if type(node) is not list or not node or type(node[0]) is not str or depth > 3:
        raise ValueError("Only bounded supported teaching rules can be imported.")
    op = node[0]
    if op in {"input", "parameter"}:
        options = item["inputs" if op == "input" else "parameters"]
        if len(node) != 2 or type(node[1]) is not int or not 0 <= node[1] < len(options):
            raise ValueError("A structural value binding is invalid.")
        return options[node[1]]
    arity = 3 if op == "if" else 1 if op in {"strip", "lower", "upper", "not"} else 2
    if op not in {"if", "strip", "lower", "upper", "not", "add", "sub", "mul", "min", "max", "eq", "lt", "le"} or len(node) != arity + 1:
        raise ValueError("A structural operation is unsupported.")
    children = [_kind(item, child, depth + 1) for child in node[1:]]
    if op == "if":
        if children[0] != "boolean" or children[1] != children[2] or not all(child[0] in {"input", "parameter"} for child in node[2:]):
            raise ValueError("The structural choice has incompatible result types.")
        if node[1][0] not in {"input", "parameter", "eq", "lt", "le"}:
            raise ValueError("The structural choice condition is unsupported.")
        if node[2] == node[3]:
            raise ValueError("The structural choice repeats an identical answer arm.")
        return children[1]
    if not all(child[0] in {"input", "parameter"} for child in node[1:]):
        raise ValueError("Use the supported bounded scalar rule structure.")
    if op in {"strip", "lower", "upper", "not"}:
        expected = "boolean" if op == "not" else "string"
        if children != [expected]:
            raise ValueError("The structural transformation has an incompatible type.")
        return expected
    if children[0] != children[1] or op != "eq" and children != ["integer", "integer"]:
        raise ValueError("The structural comparison has incompatible value types.")
    if all(child[0] == "parameter" for child in node[1:]):
        raise ValueError("The supported teaching rules require an input in arithmetic and comparison steps.")
    return "boolean" if op in {"eq", "lt", "le"} else "integer"


def validate(package):
    scalar._canonical(package)
    if type(package) is not dict or set(package) != {"schema", "templates"} or package["schema"] != SCHEMA:
        raise ValueError("Choose a supported structural rule file. Source values and arbitrary instructions are not accepted.")
    templates = package["templates"]
    if type(templates) is not list or not 1 <= len(templates) <= 32:
        raise ValueError("A structural rule file must contain one to thirty-two complete patterns.")
    for item in templates:
        if type(item) is not dict or set(item) != {"inputs", "parameters", "output", "program"}:
            raise ValueError("The structural file contains unsupported fields.")
        for key in ("inputs", "parameters"):
            if type(item[key]) is not list or len(item[key]) > 6 or any(type(kind) is not str or kind not in KINDS for kind in item[key]):
                raise ValueError("The structural rule's value types are unsupported.")
        if type(item["output"]) is not str or item["output"] not in KINDS:
            raise ValueError("The structural result type is unsupported.")
        if _kind(item, item["program"]) != item["output"]:
            raise ValueError("The structural result type does not match its declared operations.")
    if len({digest(item) for item in templates}) != len(templates):
        raise ValueError("The structural file repeats a pattern.")
    return copy.deepcopy(package)


def domain(spec):
    spec = scalar._spec(spec)
    if not 1 <= len(spec["inputs"]) <= 3 or any(item["type"] not in {"boolean", "integer"} for item in spec["inputs"].values()):
        raise ValueError("Choose a local rule with at most three yes/no or bounded whole-number inputs for complete finite qualification.")
    values = []
    for declaration in spec["inputs"].values():
        if declaration["type"] == "boolean":
            values.append([False, True])
        else:
            size = declaration["max"] - declaration["min"] + 1
            if size > 64:
                raise ValueError("This rule's complete input range is larger than sixty-four combinations. Narrow its ordinary teaching input bounds first.")
            values.append(list(range(declaration["min"], declaration["max"] + 1)))
    if not 2 <= math.prod(len(item) for item in values) <= 64:
        raise ValueError("This rule has more than sixty-four complete input combinations. Narrow the teaching bounds first.")
    return [dict(zip(spec["inputs"], row, strict=True)) for row in itertools.product(*values)]


def _bind(tree, fields, parameters):
    if tree[0] == "input":
        return ["field", fields[tree[1]]]
    if tree[0] == "parameter":
        return ["literal", parameters[tree[1]]]
    return [tree[0], *(_bind(child, fields, parameters) for child in tree[1:])]


def _pool(spec, cases, points):
    result = {"boolean": [False, True], "integer": [-1, 0, 1], "string": []}
    for row in points:
        for value in row.values():
            if type(value) is int:
                result["integer"].append(value)
    for row in cases:
        kind = scalar._type(row["expected"])
        try:
            scalar._scalar(row["expected"], kind)
        except ValueError:
            continue  # A valid large result is not a permitted local literal.
        result[kind].append(row["expected"])
    return {kind: [json.loads(key) for key in sorted({scalar._canonical(value) for value in values})] for kind, values in result.items()}


def _assign(options, distinct=False):
    def search(index, current):
        if index == len(options):
            yield tuple(current)
            return
        for value in options[index]:
            if distinct and any(scalar._canonical(value) == scalar._canonical(previous) for previous in current):
                continue
            yield from search(index + 1, [*current, value])
    yield from search(0, [])


def _ordinary_bind(part, fields, parameters):
    if part[0] == "input":
        return ["field", fields[part[1]]]
    if part[0] == "parameter":
        return ["literal", parameters[part[1]]]
    return [part[0], *(_ordinary_bind(child, fields, parameters) for child in part[1:])]


def _find(package, spec, pool, matches, counts):
    found, baseline = {}, {}
    for template in package["templates"]:
        if template["output"] != spec["output_type"]:
            continue
        field_options = [[name for name, item in spec["inputs"].items() if item["type"] == kind] for kind in template["inputs"]]
        parameter_options = [pool[kind] for kind in template["parameters"]]
        for fields in _assign(field_options, distinct=True):
            for parameters in _assign(parameter_options, distinct=True):
                counts["adapter_checks"] += 1
                if counts["adapter_checks"] > MAX_ADAPTERS:
                    raise ValueError("The complete adapter search is too large. No partial mapping was accepted.")
                program = _bind(template["program"], fields, parameters)
                if matches(program):
                    found[digest(program)] = program
        # Independent ordinary Cartesian template enumeration with identical
        # source information, domains, equality constraints and expected cases.
        for fields in itertools.product(*field_options):
            if len(set(fields)) != len(fields):
                continue
            for parameters in itertools.product(*parameter_options):
                if len({scalar._canonical(value) for value in parameters}) != len(parameters):
                    continue
                counts["baseline_checks"] += 1
                if counts["baseline_checks"] > MAX_ADAPTERS:
                    raise ValueError("The complete ordinary comparison is too large. No advantage or qualification was established.")
                program = _ordinary_bind(template["program"], fields, parameters)
                if matches(program):
                    baseline[digest(program)] = program
    if found != baseline:
        raise ValueError("The ordinary same-information comparison disagreed. No qualified rule was produced.")
    return found


def _constants(part):
    if part[0] == "literal":
        return [part[1]]
    if part[0] == "field":
        return []
    return [value for child in part[1:] for value in _constants(child)]


def _verify(flow, behavior, points, cases, check, original, counts, outcomes):
    node = flow.nodes[flow.start]
    spec = node.learned_operator["artifact"]["spec"]
    check()
    artifact = scalar.synthesize({**spec, "constants": _constants(behavior["program"])},
        [{"inputs": point, "output": value} for point, value in zip(points, behavior["values"], strict=True)])
    candidate = attach_learned_operator(flow, node.id, artifact)
    def observed(*_args):
        counts["native_steps"] += 1
        check()
    def refuse(*_args):
        raise ValueError("This local rule never calls AI or connected actions.")
    exact = True
    for row in cases:
        check()
        actual = runner.run_flow(candidate, data=copy.deepcopy(row["inputs"]), run_id=original,
            agent_fn=refuse, action_fn=refuse, on_node=observed)
        counts["native_runs"] += 1
        check()
        agreement = actual.status == runner.STATUS_COMPLETED and scalar._canonical(actual.data.get(node.output)) == scalar._canonical(row["expected"])
        outcomes.append({"case": row["id"], "expected": row["expected"], "actual": actual.data.get(node.output), "complete": actual.status == runner.STATUS_COMPLETED, "agreement": agreement})
        exact = exact and agreement
    return artifact if exact else None


def qualify(package, flow, cases, *, guard, original, max_seconds=30):
    package = validate(package)
    node = flow.nodes[flow.start]
    spec = node.learned_operator["artifact"]["spec"]
    points = domain(spec)
    pool = _pool(spec, cases, points)
    budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=max_seconds)
    started = time.perf_counter()
    counts = {"adapter_checks": 0, "baseline_checks": 0, "rule_evaluations": 0, "native_runs": 0, "native_steps": 0}
    def check():
        budget.check()
        guard()
        budget.check()
    def matches(program):
        for row in cases:
            counts["rule_evaluations"] += 1
            if counts["rule_evaluations"] % 128 == 0:
                check()
            try:
                value = scalar._run(program, row["inputs"])
            except (ValueError, KeyError, TypeError, OverflowError):
                return False
            if scalar._canonical(value) != scalar._canonical(row["expected"]):
                return False
        return True
    check()
    found = _find(package, spec, pool, matches, counts)
    check()
    behaviors = {}
    for program in found.values():
        vector = []
        for point in points:
            counts["rule_evaluations"] += 1
            if counts["rule_evaluations"] % 128 == 0:
                check()
            value = scalar._run(program, point)
            scalar._scalar(value, spec["output_type"], output=True)
            vector.append(value)
        behaviors.setdefault(digest(vector), {"program": program, "values": vector})
    check()
    result = {"observed_mappings": len(found), "finite_behaviors": len(behaviors), "domain_points": len(points),
              "ordinary_comparison_matched": True, "counts": counts, "qualified": False, "cases": [], "unresolved": []}
    for index, point in enumerate(points):
        answers = {scalar._canonical(behavior["values"][index]): behavior["values"][index] for behavior in behaviors.values()}
        if len(answers) > 1:
            result["unresolved"].append({"inputs": point, "answers": list(answers.values())[:8], "answer_count": len(answers)})
    if not behaviors or len(behaviors) > 4:
        result["reason"] = "No mapping fits every expected answer." if not behaviors else "Too many different complete local behaviors remain. Add distinguishing local cases."
    else:
        verified = []
        for behavior in behaviors.values():
            artifact = _verify(flow, behavior, points, cases, check, original, counts, result["cases"])
            if artifact is not None:
                verified.append(artifact)
        result["qualified"] = len(behaviors) == len(verified) == 1
        result["reason"] = "One complete behavior matches within the displayed finite local input bounds." if result["qualified"] else "The selected examples leave different local behaviors or an unsuccessful native comparison unresolved."
        if result["qualified"]:
            result["artifact"] = verified[0]
    check()
    result["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return result
