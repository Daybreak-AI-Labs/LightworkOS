"""Safe Sigma-compatible rule loading and deterministic event matching."""
from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..platform_hunt.models import Finding, deterministic_id
from .models import TelemetryEvent, credential_text_detected, redact_credential_text

_MAX_RULE_BYTES = 1024 * 1024
_MAX_RULES = 256
_LEVELS = {"informational": 20, "low": 30, "medium": 50, "high": 75, "critical": 95}
_SEVERITIES = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


class SigmaRule:
    def __init__(self, value: dict[str, Any]):
        rule_id = value.get("id")
        title = value.get("title")
        detection = value.get("detection")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("Sigma rule requires an id")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Sigma rule requires a title")
        if not isinstance(detection, dict):
            raise ValueError("Sigma rule requires a detection mapping")
        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            raise ValueError("Sigma rule requires a condition")
        if len(rule_id.strip()) > 240 or len(condition.strip()) > 4000:
            raise ValueError("Sigma rule id or condition is too long")
        if credential_text_detected(rule_id) or credential_text_detected(condition):
            raise ValueError("Sigma rule identity and condition cannot contain credentials")
        self.id = rule_id.strip()
        self.title = redact_credential_text(title.strip(), limit=300)
        self.description = redact_credential_text(value.get("description", ""), limit=4000)
        self.logsource = dict(value.get("logsource") or {})
        self.detection = dict(detection)
        self.condition = condition.strip()
        tags = value.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        self.tags = tuple(
            redact_credential_text(tag, limit=200) for tag in list(tags)[:128]
        )
        level = str(value.get("level", "medium")).lower()
        self.level = level if level in _LEVELS else "medium"

    @property
    def mitre_techniques(self) -> tuple[str, ...]:
        found = []
        for tag in self.tags:
            match = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
            if match:
                found.append(match.group(1).upper())
        return tuple(sorted(set(found)))


def _event_value(event: TelemetryEvent, field: str) -> Any:
    aliases = {
        "event.category": "category",
        "event.action": "action",
        "user.name": "principal",
        "host.name": "target",
        "event.outcome": "outcome",
    }
    path = aliases.get(field, field)
    structural = {
        "event_id": event.event_id,
        "source": event.source,
        "observed_at": event.observed_at,
        "category": event.category,
        "action": event.action,
        "principal": event.principal,
        "target": event.target,
        "outcome": event.outcome,
        "tenant": event.tenant,
    }
    if path in structural:
        return structural[path]
    current: Any = event.attributes
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _string_match(actual: object, expected: object, modifiers: set[str]) -> bool:
    values = actual if isinstance(actual, (list, tuple, set)) else [actual]
    expected_values = expected if isinstance(expected, list) else [expected]
    comparisons = []
    for candidate in values:
        text = str(candidate).lower()
        for raw in expected_values:
            wanted = str(raw).lower()
            if "contains" in modifiers:
                comparisons.append(wanted in text)
            elif "startswith" in modifiers:
                comparisons.append(text.startswith(wanted))
            elif "endswith" in modifiers:
                comparisons.append(text.endswith(wanted))
            elif "cidr" in modifiers:
                comparisons.append(text == wanted)  # safe subset; exact network labels only
            elif "*" in wanted or "?" in wanted:
                comparisons.append(fnmatch.fnmatchcase(text, wanted))
            else:
                comparisons.append(text == wanted)
    if "all" in modifiers:
        return bool(comparisons) and all(comparisons)
    return any(comparisons)


def _selector_matches(event: TelemetryEvent, selector: object) -> bool:
    if isinstance(selector, list):
        return any(_selector_matches(event, item) for item in selector)
    if not isinstance(selector, dict):
        return False
    for expression, expected in selector.items():
        parts = str(expression).split("|")
        field = parts[0]
        modifiers = {part.lower() for part in parts[1:]}
        if "re" in modifiers:
            # Customer regex is deliberately unsupported: untrusted catastrophic
            # backtracking must not become a sensor denial-of-service primitive.
            return False
        if not _string_match(_event_value(event, field), expected, modifiers):
            return False
    return True


def _condition_matches(condition: str, selectors: dict[str, bool]) -> bool:
    normalized = " ".join(condition.lower().split())
    if normalized in selectors:
        return selectors[normalized]
    match = re.fullmatch(r"(1|all) of ([a-z0-9_*?-]+|them)", normalized)
    if match:
        mode, pattern = match.groups()
        if pattern == "them":
            pattern = "*"
        values = [value for key, value in selectors.items() if fnmatch.fnmatchcase(key, pattern)]
        return bool(values) and (all(values) if mode == "all" else any(values))
    tokens = re.findall(r"\(|\)|\b(?:and|or|not)\b|[a-z0-9_*?-]+", normalized)
    if " ".join(tokens).replace("( ", "(").replace(" )", ")") != normalized:
        return False
    index = 0

    def atom() -> bool:
        nonlocal index
        if index >= len(tokens):
            raise ValueError
        if tokens[index] == "(":
            index += 1
            value = expression()
            if index >= len(tokens) or tokens[index] != ")":
                raise ValueError
            index += 1
            return value
        name = tokens[index]
        index += 1
        if "*" in name or "?" in name:
            return any(value for key, value in selectors.items() if fnmatch.fnmatchcase(key, name))
        if name not in selectors:
            raise ValueError
        return selectors[name]

    def negation() -> bool:
        nonlocal index
        if index < len(tokens) and tokens[index] == "not":
            index += 1
            return not negation()
        return atom()

    def conjunction() -> bool:
        nonlocal index
        value = negation()
        while index < len(tokens) and tokens[index] == "and":
            index += 1
            right = negation()
            value = value and right
        return value

    def expression() -> bool:
        nonlocal index
        value = conjunction()
        while index < len(tokens) and tokens[index] == "or":
            index += 1
            right = conjunction()
            value = value or right
        return value

    try:
        result = expression()
    except ValueError:
        return False
    return index == len(tokens) and result


def rule_matches(rule: SigmaRule, event: TelemetryEvent) -> bool:
    product = str(rule.logsource.get("product", "")).lower()
    service = str(rule.logsource.get("service", "")).lower()
    if product and product not in f"{event.source} {event.category}".lower():
        return False
    if service and service not in f"{event.source} {event.category}".lower():
        return False
    selectors = {
        str(name).lower(): _selector_matches(event, selector)
        for name, selector in rule.detection.items()
        if name != "condition"
    }
    return _condition_matches(rule.condition, selectors)


def detect(
    events: Iterable[TelemetryEvent], rules: Iterable[SigmaRule] | None = None,
) -> tuple[Finding, ...]:
    active = tuple(rules if rules is not None else curated_rules())
    findings = []
    for event in sorted(events, key=lambda item: (item.observed_at, item.event_id)):
        for rule in sorted(active, key=lambda item: item.id):
            if not rule_matches(rule, event):
                continue
            quote = (
                f"Sigma {rule.id} matched event {event.event_id}: "
                f"{event.category}/{event.action} principal={event.principal or '-'} "
                f"target={event.target or '-'}"
            )
            findings.append(Finding(
                finding_id=deterministic_id("ef", rule.id, event.event_id),
                rule_id=rule.id,
                title=rule.title,
                severity=_SEVERITIES[rule.level],
                verdict=f"Sigma condition '{rule.condition}' matched the cited event",
                mitre_techniques=rule.mitre_techniques,
                evidence=(event.evidence(quote),),
                score=_LEVELS[rule.level],
                suggested_containment="Open an investigation and validate the event before responding.",
                created_at=event.observed_at,
                metadata={"sigma_tags": list(rule.tags), "description": rule.description},
            ))
    return tuple(findings)


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [] if not inner else [_parse_scalar(part) for part in inner.split(",")]
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "none", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw.strip() == "---":
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ValueError("Sigma YAML indentation must use spaces")
        content = raw.lstrip()
        if "!!" in content or re.search(r"(?:^|[\s:\-\[,])[&*][A-Za-z_][\w-]*", content):
            raise ValueError("Sigma YAML aliases and custom tags are unsupported")
        lines.append((len(raw) - len(content), content))
    return lines


def _parse_block(
    lines: list[tuple[int, str]], index: int, indent: int,
) -> tuple[Any, int]:
    is_list = lines[index][1].startswith("- ")
    container: Any = [] if is_list else {}
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent != indent:
            raise ValueError("Sigma YAML has inconsistent indentation")
        if is_list:
            if not content.startswith("- "):
                break
            item = content[2:].strip()
            if not item:
                if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
                    container.append(None)
                    index += 1
                    continue
                value, index = _parse_block(lines, index + 1, lines[index + 1][0])
                container.append(value)
                continue
            container.append(_parse_scalar(item))
            index += 1
            continue
        if content.startswith("- ") or ":" not in content:
            raise ValueError("Sigma YAML mapping entry is invalid")
        key, raw_value = content.split(":", 1)
        key = key.strip()
        if not key or key in container:
            raise ValueError("Sigma YAML contains an empty or duplicate key")
        raw_value = raw_value.strip()
        if raw_value:
            container[key] = _parse_scalar(raw_value)
            index += 1
            continue
        if index + 1 >= len(lines) or lines[index + 1][0] <= indent:
            container[key] = {}
            index += 1
            continue
        value, index = _parse_block(lines, index + 1, lines[index + 1][0])
        container[key] = value
    return container, index


def _load_document(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        lines = _yaml_lines(text)
        if not lines:
            raise ValueError("Sigma rule file is empty") from exc
        value, index = _parse_block(lines, 0, lines[0][0])
        if index != len(lines):
            raise ValueError("Sigma YAML contains trailing invalid content") from exc
        return value


def _append_document_rules(
    rules: list[SigmaRule], ids: set[str], text: str, *, label: str,
) -> None:
    if len(text.encode("utf-8")) > _MAX_RULE_BYTES:
        raise ValueError(f"Sigma content exceeds {_MAX_RULE_BYTES} bytes: {label}")
    document = _load_document(text)
    values = document if isinstance(document, list) else [document]
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("Sigma document must contain a rule mapping")
        rule = SigmaRule(value)
        if rule.id in ids:
            raise ValueError(f"duplicate Sigma rule id: {rule.id}")
        ids.add(rule.id)
        rules.append(rule)
        if len(rules) > _MAX_RULES:
            raise ValueError(f"Sigma import exceeds {_MAX_RULES} rules")


def load_sigma_rules(paths: Iterable[str | Path]) -> tuple[SigmaRule, ...]:
    rules: list[SigmaRule] = []
    ids: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path)
        if path.stat().st_size > _MAX_RULE_BYTES:
            raise ValueError(f"Sigma file exceeds {_MAX_RULE_BYTES} bytes: {path.name}")
        _append_document_rules(
            rules, ids, path.read_text(encoding="utf-8"), label=path.name,
        )
    return tuple(sorted(rules, key=lambda item: item.id))


def load_sigma_texts(texts: Iterable[str]) -> tuple[SigmaRule, ...]:
    """Load bounded customer rules from request bodies, never server paths."""
    rules: list[SigmaRule] = []
    ids: set[str] = set()
    for index, text in enumerate(texts):
        if not isinstance(text, str):
            raise TypeError("Sigma request content must be text")
        _append_document_rules(rules, ids, text, label=f"request[{index}]")
    return tuple(sorted(rules, key=lambda item: item.id))


_CURATED = (
    {
        "id": "LW-SIGMA-001",
        "title": "Cloud console login without MFA",
        "description": "Potential initial access through an account without MFA.",
        "logsource": {"product": "aws", "service": "cloudtrail"},
        "detection": {
            "selection": {"action": "ConsoleLogin", "mfa": "No"},
            "condition": "selection",
        },
        "tags": ["attack.t1078"],
        "level": "high",
    },
    {
        "id": "LW-SIGMA-002",
        "title": "New cloud access key",
        "description": "Persistence through creation of a cloud access key.",
        "logsource": {"product": "aws", "service": "cloudtrail"},
        "detection": {"selection": {"action": "CreateAccessKey"}, "condition": "selection"},
        "tags": ["attack.t1098.001"],
        "level": "high",
    },
    {
        "id": "LW-SIGMA-003",
        "title": "Kubernetes cluster-admin binding",
        "description": "Persistence or privilege escalation via a cluster role binding.",
        "logsource": {"product": "kubernetes", "service": "audit"},
        "detection": {
            "selection": {"action": ["create", "patch"], "target|contains": "clusterrolebindings"},
            "condition": "selection",
        },
        "tags": ["attack.t1098", "attack.t1548"],
        "level": "critical",
    },
    {
        "id": "LW-SIGMA-004",
        "title": "Large outbound endpoint transfer",
        "description": "Endpoint telemetry recorded a large outbound transfer.",
        "logsource": {"product": "edr"},
        "detection": {
            "selection": {"action": ["network_connection", "upload"], "bytes_out": "10485760"},
            "condition": "selection",
        },
        "tags": ["attack.t1041", "attack.t1567"],
        "level": "high",
    },
    {
        "id": "LW-SIGMA-005",
        "title": "Identity provider application grant",
        "description": "New application or service-principal grant can establish persistence.",
        "logsource": {"product": "identity"},
        "detection": {
            "selection": {"action|contains": ["application.lifecycle.create", "add service principal"]},
            "condition": "selection",
        },
        "tags": ["attack.t1098"],
        "level": "high",
    },
)


def curated_rules() -> tuple[SigmaRule, ...]:
    return tuple(SigmaRule(value) for value in _CURATED)


__all__ = [
    "SigmaRule",
    "curated_rules",
    "detect",
    "load_sigma_rules",
    "load_sigma_texts",
    "rule_matches",
]
