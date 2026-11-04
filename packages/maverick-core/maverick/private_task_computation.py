"""Closed local predicates, exhaustive finite validation and reduced decision DAGs.

This establishes byte equivalence for one fixed result projection. It makes no
timing, rare-structure, cumulative-inference or independent business-fact claim.
"""
from __future__ import annotations

import csv
import io
import itertools
import math
import operator
import re

from .budget import Budget

SCHEMA = "lightwork.private-task-computation.v1"
RESULTS = ("MEETS_ENTERED_CONDITIONS", "DOES_NOT_MEET_ENTERED_CONDITIONS")
MAX_BYTES, MAX_ROWS, MAX_COLUMNS, MAX_STATES = 131072, 200, 12, 65536


def _text(value, maximum):
    if type(value) is not str or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ValueError("Enter complete bounded text.")
    return value


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("Use the complete supported fields, without additional program instructions.")


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Enter an integer within the supported range.")
    return value


def domain(field):
    kind = field["kind"]
    if kind == "boolean":
        _keys(field, ("name", "kind"))
        return [False, True]
    if kind == "integer":
        _keys(field, ("name", "kind", "minimum", "maximum"))
        low = _integer(field["minimum"], -1000000, 1000000)
        high = _integer(field["maximum"], low, low + 15)
        return list(range(low, high + 1))
    if kind == "choice":
        _keys(field, ("name", "kind", "choices"))
        choices = field["choices"]
        if type(choices) is not list or not 1 <= len(choices) <= 8:
            raise ValueError("Enter one to eight choices.")
        values = [_text(value, 100) for value in choices]
        if len(set(values)) != len(values):
            raise ValueError("Choices must be distinct.")
        return values
    raise ValueError("Choose Yes/No, a small integer range, or named choices.")


def _condition(condition, fields, domains):
    _keys(condition, ("field", "operator", "right"))
    left = condition["field"]
    if left not in fields or condition["operator"] not in {"equal", "at_least", "at_most"}:
        raise ValueError("Choose a declared field and supported comparison.")
    right = condition["right"]
    if type(right) is not dict:
        raise ValueError("Choose a fixed value or another declared field.")
    if right.get("kind") == "field":
        _keys(right, ("kind", "field"))
        if right["field"] not in fields or fields[left]["kind"] != fields[right["field"]]["kind"]:
            raise ValueError("Compared fields need the same declared type.")
    elif right.get("kind") == "value":
        _keys(right, ("kind", "value"))
        if not any(type(right["value"]) is type(value) and right["value"] == value for value in domains[left]):
            raise ValueError("The fixed comparison value must be a declared possibility.")
    else:
        raise ValueError("Choose a fixed value or another declared field.")
    if condition["operator"] != "equal" and fields[left]["kind"] != "integer":
        raise ValueError("Only integer fields support range comparisons.")


def validate(model):
    _keys(model, ("fields", "conditions", "mode", "purpose", "basis", "expires_at", "approved_result"))
    if type(model["fields"]) is not list or not 1 <= len(model["fields"]) <= 6:
        raise ValueError("Declare one to six fields.")
    if type(model["conditions"]) is not list or not 1 <= len(model["conditions"]) <= 8:
        raise ValueError("Enter one to eight conditions.")
    if model["mode"] not in {"all", "any"} or model["approved_result"] not in RESULTS:
        raise ValueError("Choose how conditions combine and the only releasable result.")
    _text(model["purpose"], 500)
    _text(model["basis"], 2000)
    if len(model["basis"].strip()) < 10:
        raise ValueError("Enter a complete basis for current source rights.")
    expiry = model["expires_at"]
    if type(expiry) not in {int, float} or not math.isfinite(expiry) or expiry <= 0:
        raise ValueError("Choose a complete future permission expiry.")
    fields, domains = {}, {}
    for field in model["fields"]:
        if type(field) is not dict:
            raise ValueError("Enter a complete field declaration.")
        name = _text(field.get("name"), 100)
        if name in fields:
            raise ValueError("Field names must be distinct.")
        fields[name], domains[name] = field, domain(field)
    if math.prod(len(values) for values in domains.values()) > MAX_STATES:
        raise ValueError("The complete declared combinations exceed 65536; narrow the declared ranges.")
    for condition in model["conditions"]:
        _condition(condition, fields, domains)
    return fields, domains


def reference(model, values):
    """Plain authored-condition reference, without executable user code."""
    outcomes = []
    for condition in model["conditions"]:
        left = values[condition["field"]]
        right = condition["right"]
        other = values[right["field"]] if right["kind"] == "field" else right["value"]
        outcomes.append({"equal": operator.eq, "at_least": operator.ge,
                         "at_most": operator.le}[condition["operator"]](left, other))
    return all(outcomes) if model["mode"] == "all" else any(outcomes)


def _dag(names, domains, truth, budget):
    nodes, interned = {}, {}

    def build(depth, results):
        budget.check()
        if all(value == results[0] for value in results):
            return int(results[0])
        width = len(domains[names[depth]])
        step = len(results) // width
        children = tuple(build(depth + 1, results[start:start + step]) for start in range(0, len(results), step))
        if len(set(children)) == 1:
            return children[0]
        key = (names[depth], children)
        if key not in interned:
            identifier = len(nodes) + 2
            interned[key] = identifier
            nodes[identifier] = {"field": names[depth], "children": list(children)}
        return interned[key]

    root = build(0, truth)
    return root, nodes


def execute(program, values, *, budget=None):
    """Read only fields on the compiled path; record that exact local dependency."""
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    current, read = program["root"], []
    while current not in (0, 1):
        budget.check()
        node = program["nodes"][current]
        field = node["field"]
        value = values[field]
        choices = program["domains"][field]
        matches = [index for index, candidate in enumerate(choices) if type(value) is type(candidate) and candidate == value]
        if len(matches) != 1:
            raise ValueError("A needed value is outside its complete declared range.")
        read.append(field)
        current = node["children"][matches[0]]
    budget.check()
    return RESULTS[0] if current else RESULTS[1], read


def compile_program(model, *, budget=None):
    """Extract exact essential fields and verify two independent ordinary references."""
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    _fields, domains = validate(model)
    names = list(domains)
    truth, indexed = [], {}
    for combination in itertools.product(*(domains[name] for name in names)):
        budget.check()
        outcome = reference(model, dict(zip(names, combination, strict=True)))
        truth.append(outcome)
        indexed[combination] = RESULTS[0] if outcome else RESULTS[1]
    root, nodes = _dag(names, domains, truth, budget)
    essential = [name for name in names if any(node["field"] == name for node in nodes.values())]
    program = {"schema": SCHEMA, "root": root, "nodes": nodes, "domains": domains,
               "essential_fields": essential, "declared_states": len(truth)}
    for combination in itertools.product(*(domains[name] for name in names)):
        budget.check()
        values = dict(zip(names, combination, strict=True))
        actual, _read = execute(program, values, budget=budget)
        plain = RESULTS[0] if reference(model, values) else RESULTS[1]
        if actual != plain or actual != indexed[combination]:
            raise ValueError("Complete local validation disagreed; no result can be released.")
    program["verification"] = {"complete_states": len(truth), "plain_conditions": True,
        "complete_indexed_projection": True, "byte_equivalence_only": True,
        "novelty_or_superiority_claimed": False}
    return program


def parse_csv(data, *, budget=None):
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    if type(data) is not bytes or not 1 <= len(data) <= MAX_BYTES:
        raise ValueError("Choose a complete local CSV file of at most 128 KiB.")
    text = data.decode("utf-8-sig", errors="strict")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    rows = list(reader)
    budget.check()
    if not 2 <= len(rows) <= MAX_ROWS + 1:
        raise ValueError("The complete file needs one header and one to 200 data rows.")
    headers = rows[0]
    if not 1 <= len(headers) <= MAX_COLUMNS or len(set(headers)) != len(headers):
        raise ValueError("Use one to twelve distinct column names.")
    for header in headers:
        _text(header, 100)
    seen = set()
    for row in rows[1:]:
        budget.check()
        if len(row) != len(headers) or any(len(value) > 4000 or "\x00" in value for value in row):
            raise ValueError("Every complete row must match the header and bounded cell sizes.")
        if tuple(row) in seen:
            raise ValueError("Duplicate complete rows are refused; select an unambiguous source.")
        seen.add(tuple(row))
    return headers, rows[1:]


def _cell(field, raw, choices):
    kind = field["kind"]
    if kind == "boolean":
        if raw not in {"true", "false"}:
            raise ValueError("Yes/No columns must contain exactly true or false.")
        value = raw == "true"
    elif kind == "integer":
        if not re.fullmatch(r"-?(0|[1-9][0-9]*)", raw):
            raise ValueError("Integer columns need complete ordinary integers.")
        value = int(raw)
    else:
        value = raw
    if value not in choices:
        raise ValueError("The complete source includes a value outside its declared possibilities.")
    return value


def compute(model, data, row_number, *, budget=None):
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    fields, domains = validate(model)
    headers, rows = parse_csv(data, budget=budget)
    _integer(row_number, 1, len(rows))
    if not set(fields) <= set(headers):
        raise ValueError("Every declared field must exist in the complete source.")
    positions = {name: headers.index(name) for name in fields}
    selected = None
    for index, row in enumerate(rows, 1):
        budget.check()
        values = {name: _cell(field, row[positions[name]], domains[name]) for name, field in fields.items()}
        if index == row_number:
            selected = values
    program = compile_program(model, budget=budget)
    result, read = execute(program, selected, budget=budget)
    return {"result": result, "fields_read": read, "essential_fields": program["essential_fields"],
            "verification": program["verification"], "declared_states": program["declared_states"],
            "nodes": len(program["nodes"]), "source_rows": len(rows), "source_columns": len(headers)}


def artifact(result):
    if result not in RESULTS:
        raise ValueError("Only a fixed approved result may be released.")
    return ("result\n" + result + "\n").encode("ascii")
