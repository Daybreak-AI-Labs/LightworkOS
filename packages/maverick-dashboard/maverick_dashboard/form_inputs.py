"""Validate public-form answers against the exact saved automation target."""
from __future__ import annotations

import math
import re
from datetime import date


class FormInputError(ValueError):
    """A received answer cannot safely start the bound automation."""


def public_form_fields(target, defaults: dict, *, is_flow: bool) -> list[dict]:
    """Describe the fields a public caller may supply to one saved target."""
    from maverick import form_store

    if is_flow:
        raw_fields = [
            {"key": spec.get("key"), "label": spec.get("label"),
             "type": spec.get("type") or "text",
             "required": bool(spec.get("required")) and "default" not in spec
             and spec.get("key") not in defaults}
            for spec in target.inputs
        ]
    else:
        raw_fields = [
            {"key": key, "label": key.replace("_", " "), "type": "text",
             "required": key not in defaults}
            for key in target.params
        ]
    if not raw_fields:
        raw_fields = [{"key": "message", "label": "What would you like to share?",
                       "type": "text", "required": True, "long": True}]
    if len(raw_fields) > form_store._MAX_FIELDS:
        raise FormInputError("This form has too many fields.")
    fields = []
    seen = set()
    for spec in raw_fields:
        key = str(spec.get("key") or "").strip()
        kind = str(spec.get("type") or "text")
        if not key or len(key) > 200 or key in seen or kind not in {"text", "number", "bool", "date"}:
            raise FormInputError("This form's saved fields need repair before submission.")
        seen.add(key)
        fields.append({
            "key": key, "label": str(spec.get("label") or key).strip()[:200] or key,
            "type": kind, "required": bool(spec.get("required")),
            "long": bool(spec.get("long")),
        })
    return fields


def validate_public_form_fields(fields: dict, allowed: list[dict],
                                *, trusted_keys: frozenset[str] = frozenset()) -> None:
    """Refuse caller-controlled keys absent from the bound public form."""
    names = {field["key"] for field in allowed}
    if any(key not in names and key not in trusted_keys for key in fields):
        raise FormInputError("This submission includes fields not on the saved form.")


def validate_template_form(template, defaults: dict, fields: dict) -> None:
    """Refuse a missing required immutable-template parameter before append."""
    values = {**(defaults or {}), **fields}
    missing = [key for key in template.params if values.get(key) in (None, "")]
    if missing:
        raise FormInputError("Complete the required form fields: " + ", ".join(missing[:5]))


def coerce_flow_form(flow, data: dict) -> dict:
    """Use the published flow's declarations; reject ambiguous scalar values."""
    from maverick.flow.ir import coerce_inputs

    coerced, errors = coerce_inputs(flow, data)
    for spec in flow.inputs or []:
        key = str(spec.get("key") or "").strip()
        kind = str(spec.get("type") or "text")
        if not key or len(key) > 200 or kind not in {"text", "number", "bool", "date"}:
            raise FormInputError("This form's saved fields need repair before submission.")
        value = data.get(key)
        if value in (None, "") and "default" in spec:
            value = spec["default"]
        if value in (None, ""):
            continue
        if kind == "number":
            try:
                parsed = float(value) if not isinstance(value, bool) else float("nan")
            except (TypeError, ValueError):
                parsed = float("nan")
            if not math.isfinite(parsed):
                errors.append(f"Enter a valid number for {key}.")
            else:
                coerced[key] = parsed
        elif kind == "bool":
            answer = str(value).strip().lower()
            if not isinstance(value, bool) and answer not in {
                "true", "false", "1", "0", "yes", "no", "on", "off"
            }:
                errors.append(f"Choose Yes or No for {key}.")
            else:
                coerced[key] = value if isinstance(value, bool) else answer in {"true", "1", "yes", "on"}
        elif kind == "date":
            raw = str(value)
            try:
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
                    raise ValueError("date format")
                date.fromisoformat(raw)
            except ValueError:
                errors.append(f"Enter a valid date for {key}.")
    if errors:
        raise FormInputError(errors[0])
    return coerced
