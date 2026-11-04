"""Bounded checks over owner-supplied structured evidence; never fetches sources.

The same engine qualifies bundled fixtures and prepares customer worklists.
It does not impersonate specialist inference or provider connection testing.
"""
from __future__ import annotations

import copy
import json
import math
import re
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

from .budget import budget_from_config
from .governed_operations import digest

DATA = Path(__file__).with_name("starter_team_data")
MAX_ROWS = 1000
MAX_INPUT_BYTES = 2_000_000
KINDS = frozenset({"required", "equals", "compare", "deadline", "unique", "reference"})
_KEY = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")


def catalog() -> list[dict]:
    """Read the packaged versioned catalog, with no installed-pack side effects."""
    teams = []
    for path in sorted(DATA.glob("*.json")):
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, list):
            raise ValueError("Starter team catalog must contain a list")
        teams.extend(values)
    seen = set()
    for team in teams:
        _validate_team(team)
        if team["id"] in seen:
            raise ValueError("Duplicate starter team")
        seen.add(team["id"])
    return teams


def _validate_team(team):
    for key in ("id", "title", "summary", "owner_role", "sample_goal", "deliverable", "cadence"):
        if not isinstance(team.get(key), str) or not team[key].strip():
            raise ValueError(f"Starter team needs {key}")
    if not _KEY.fullmatch(team["id"]):
        raise ValueError("Invalid starter team identity")
    for key in ("specialists", "inputs", "connections", "acceptance", "stop_conditions", "blocked_actions", "rules"):
        if not isinstance(team.get(key), list) or not team[key]:
            raise ValueError(f"Starter team needs {key}")
    if not 2 <= len(set(team["specialists"])) <= 4:
        raise ValueError("Starter teams need two to four distinct specialists")
    inputs = {item["key"]: set(item["columns"]) for item in team["inputs"]}
    if len(inputs) != len(team["inputs"]):
        raise ValueError("Duplicate input table")
    for key, columns in inputs.items():
        if not _KEY.fullmatch(key) or not {"id", "source"} <= columns:
            raise ValueError("Input tables require identity and source columns")
    rule_ids = set()
    for rule in team["rules"]:
        if rule["id"] in rule_ids or rule["kind"] not in KINDS:
            raise ValueError("Invalid or duplicate starter rule")
        rule_ids.add(rule["id"])
        fields = list(rule.get("fields", []))
        fields.extend(rule[key] for key in ("field", "other_field", "unless_field") if key in rule)
        if not set(fields) <= inputs.get(rule["table"], set()):
            raise ValueError("Rule refers to an undeclared column")
        if rule["kind"] == "reference" and rule["reference_field"] not in inputs.get(rule["reference_table"], set()):
            raise ValueError("Reference rule needs a declared source column")
        if not rule.get("title") or not rule.get("action"):
            raise ValueError("Rule requires a finding title and proposed action")


def get_team(team_id: str) -> dict:
    for team in catalog():
        if team["id"] == team_id:
            return team
    raise KeyError("This starter team is unavailable")


def team_digest(team: dict) -> str:
    return digest({"schema": "lightwork.starter-team.v1", "team": team})


def _iso_date(value) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Use a complete YYYY-MM-DD date")
    return date.fromisoformat(value)


def validate_tables(team, tables, *, max_rows=MAX_ROWS):
    if not isinstance(tables, dict):
        raise ValueError("Provide named evidence tables")
    spec = {item["key"]: item for item in team["inputs"]}
    if set(tables) != set(spec):
        raise ValueError("Provide every listed input table and no additional tables")
    total = 0
    for name, rows in tables.items():
        if not isinstance(rows, list) or not rows:
            raise ValueError("Each evidence table needs at least one row")
        total += len(rows)
        if total > max_rows:
            raise ValueError(f"Evidence exceeds the {max_rows} row limit")
        seen = set()
        for row in rows:
            _validate_row(row, set(spec[name]["columns"]), seen)
    if len(json.dumps(tables, allow_nan=False).encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("Evidence exceeds the two megabyte input limit")
    return total


def _validate_row(row, columns, seen):
    if not isinstance(row, dict) or not set(row) <= columns:
        raise ValueError("Evidence row has unrecognized columns")
    for key in ("id", "source"):
        if not isinstance(row.get(key), str) or not row[key].strip() or len(row[key]) > 1000:
            raise ValueError("Every row needs a bounded identity and source reference")
    if row["id"] in seen:
        raise ValueError("Evidence row identities must be unique within each table")
    seen.add(row["id"])
    for value in row.values():
        if value is None or type(value) in (bool, int):
            continue
        if isinstance(value, float) and math.isfinite(value):
            continue
        if isinstance(value, str) and len(value) <= 4000:
            continue
        raise ValueError("Evidence cells must be bounded text, finite numbers, booleans or empty")


def _number(value):
    if type(value) not in (int, float) or abs(value) > 1e100 or not math.isfinite(value):
        raise ValueError("Numeric comparison needs finite numbers in both columns")
    return value


def _indices(rule, tables):
    if rule["kind"] == "unique":
        return Counter(tuple(row.get(field) for field in rule["fields"]) for row in tables[rule["table"]])
    if rule["kind"] == "reference":
        return Counter(row.get(rule["reference_field"]) for row in tables[rule["reference_table"]])
    return {}


def _fails(rule, row, as_of, index):
    kind = rule["kind"]
    value = row.get(rule.get("field"))
    if kind == "required":
        return value is None or (isinstance(value, str) and not value.strip())
    if kind == "equals":
        if rule["field"] not in row or value is None:
            raise ValueError("Required comparison input is missing")
        return type(value) is not type(rule["value"]) or value != rule["value"]
    if kind == "compare":
        left, right = _number(value), _number(row.get(rule["other_field"]))
        return not {"eq": left == right, "gte": left >= right, "lte": left <= right}[rule["operator"]]
    if kind == "deadline":
        if "unless_field" in rule and row.get(rule["unless_field"]) == rule["unless_value"]:
            return False
        return _iso_date(value) <= as_of + timedelta(days=rule["within_days"])
    if kind == "unique":
        keys = tuple(row.get(field) for field in rule["fields"])
        if any(value is None or value == "" for value in keys):
            raise ValueError("Duplicate check needs every matching-key field")
        return index[keys] > 1
    if value is None or value == "":
        raise ValueError("Reference key is missing")
    if index.get(value, 0) > 1:
        raise ValueError("Reference key is ambiguous in the supplied evidence")
    return index.get(value, 0) == 0


def _findings(team, tables, as_of, budget):
    findings = []
    for rule in team["rules"]:
        index = _indices(rule, tables)
        for row in tables[rule["table"]]:
            budget.check()
            error = ""
            try:
                failed = _fails(rule, row, as_of, index)
            except (ValueError, TypeError) as exc:
                failed, error = True, str(exc)
            if failed:
                findings.append({
                    "id": f"{rule['id']}:{row['id']}", "rule_id": rule["id"],
                    "title": rule["title"], "table": rule["table"], "row_id": row["id"],
                    "source": row["source"], "evidence_sha256": digest(row),
                    "kind": "input_exception" if error else "review_required",
                    "reason": error or "The supplied row did not meet this check.",
                    "proposed_action": "Ask the source owner to correct the input: " + error if error else rule["action"],
                    "owner_role": team["owner_role"], "status": "awaiting_human_review",
                })
    return findings


def evaluate(team_id, tables, *, as_of, budget=None):
    """Prepare reproducible findings and provenance without any external effects."""
    team = get_team(team_id)
    day = _iso_date(as_of)
    rows = validate_tables(team, tables)
    tables = copy.deepcopy(tables)
    bounded = budget_from_config(defaults={"max_wall_seconds": 30}) if budget is None else budget
    # No configuration can turn this bounded preparation path into an
    # unbounded worker. A caller's tighter Budget continues to take precedence.
    if bounded.max_wall_seconds is None or bounded.max_wall_seconds > 30:
        bounded.max_wall_seconds = 30
    bounded.check()
    findings = _findings(team, tables, day, bounded)
    evidence = [{"table": name, "row_id": row["id"], "source": row["source"],
                 "sha256": digest(row), "record": row} for name, values in tables.items() for row in values]
    stages = (("intake", "Validated source references and bounded structured input", team["specialists"][0]),
              ("analysis", "Applied the team's declared deterministic checks", team["specialists"][1]),
              ("review", "Prepared findings for the named human owner", team["specialists"][-1]))
    handoffs = [{"stage": stage, "summary": label, "specialist": specialist,
                 "execution": "deterministic_check_engine", "input_sha256": digest(tables),
                 "finding_ids": [finding["id"] for finding in findings]} for stage, label, specialist in stages]
    bounded.check()
    return {"schema": "lightwork.starter-team-output.v1", "team_id": team_id,
            "deliverable": team["deliverable"], "as_of": as_of, "row_count": rows,
            "findings": findings, "evidence": evidence, "handoffs": handoffs,
            "input_sha256": digest(tables), "catalog_sha256": team_digest(team),
            "acceptance": team["acceptance"], "readiness": "structured_inputs_only",
            "method": "Declared deterministic checks over supplied exports; specialist roles are handoff destinations, not evidence of AI execution.",
            "external_effects": [], "usage": {"provider_calls": 0, "tool_calls": 0, "dollars": 0},
            "business_acceptance": "pending_human_review"}
