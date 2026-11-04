"""Versioned, bounded template input definitions shared by every render path."""
from __future__ import annotations

import datetime
import json
import re


def normalize_schema(value, names):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError) as exc:
            raise ValueError("Template input definitions could not be read.") from exc
    if not value:
        return {}
    if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("fields"), dict):
        raise ValueError("Template inputs need schema version 1.")
    fields = value["fields"]
    if len(fields) > 100 or set(fields) - set(names):
        raise ValueError("Input definitions must match the template's listed inputs.")
    cleaned = {}
    for name, field in fields.items():
        if not isinstance(field, dict) or set(field) - {"type", "label", "help", "required", "default", "choices", "show_when"}:
            raise ValueError("Unsupported input definition.")
        kind = field.get("type", "text")
        if kind not in {"text", "date", "enum", "number", "email", "connection"}:
            raise ValueError("Choose a supported input type.")
        required = field.get("required", True)
        if not isinstance(required, bool):
            raise ValueError("Input required flag must be true or false.")
        item = {"type": kind, "required": required}
        for key, limit in (("label", 100), ("help", 500), ("default", 10000)):
            val = field.get(key, "")
            if not isinstance(val, str) or len(val) > limit:
                raise ValueError("Input label, help or default is too long.")
            item[key] = val
        choices = field.get("choices", [])
        if not isinstance(choices, list) or len(choices) > 100 or any(not isinstance(c, str) or not c or len(c) > 200 for c in choices):
            raise ValueError("Choose up to 100 short, non-empty options.")
        if kind == "enum" and not choices:
            raise ValueError("A choice input needs at least one option.")
        item["choices"] = list(dict.fromkeys(choices))
        when = field.get("show_when")
        if when is not None:
            if not isinstance(when, dict) or set(when) != {"field", "value"} or when["field"] not in names or when["field"] == name or not isinstance(when["value"], str):
                raise ValueError("Conditional input must refer to another listed input and a text value.")
            item["show_when"] = when
        if kind == "connection" and item["default"]:
            raise ValueError("Connected account inputs cannot save a default; each person selects their own account.")
        if item["default"]:
            _validate_value(name, item["default"], item)
        cleaned[name] = item
    return {"version": 1, "fields": cleaned}


def _validate_value(name, value, field):
    if len(value) > 10000:
        raise ValueError(f"{name}: use at most 10,000 characters.")
    kind = field.get("type", "text")
    if not value:
        if field.get("required", True):
            raise ValueError(f"{name}: enter a value.")
        return
    if kind == "connection":
        from .template_connections import decode
        decode(value)
    if kind == "enum" and value not in field.get("choices", []):
        raise ValueError(f"{name}: choose one of the listed options.")
    if kind == "date":
        try:
            parsed = datetime.date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"{name}: enter a valid date.") from exc
        if parsed.isoformat() != value:
            raise ValueError(f"{name}: enter a date as year-month-day.")
    if kind == "number" and not re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        raise ValueError(f"{name}: enter a number.")
    if kind == "email" and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError(f"{name}: enter an email address.")


def resolve_parameters(names, schema, values):
    fields = schema.get("fields", {})
    resolved = dict(values)
    for name in names:
        field = fields.get(name)
        if field is None:
            if name not in values:
                raise ValueError(f"{name}: enter a value.")
            continue
        value = values.get(name, "") or field.get("default", "")
        if not isinstance(value, str):
            raise ValueError(f"{name}: input must be text.")
        resolved[name] = value
    for name, field in fields.items():
        when = field.get("show_when")
        if when and resolved.get(when["field"]) != when["value"]:
            resolved[name] = ""
            continue
        _validate_value(name, resolved[name], field)
    return resolved
