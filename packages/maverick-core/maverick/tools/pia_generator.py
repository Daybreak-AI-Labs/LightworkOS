"""Privacy Impact Assessment generator.

Render a structured Privacy Impact Assessment (PIA / DPIA) as a markdown
document from structured inputs, and surface the obvious risk flags a reviewer
should not miss: special-category (sensitive) data, third-country transfers,
and an unbounded retention period. Deterministic and offline — pure templating
over the supplied fields. No disk, no network.

ops:
  - generate(system, data_categories, purposes[, retention_days][, transfers])

A risk flag is raised when:
  - a declared data category is a special category (health, biometric, ...);
  - ``transfers`` lists any third country (non-EU/EEA recipient);
  - ``retention_days`` is missing or <= 0 (no retention limit).
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Special (sensitive) categories under GDPR Art. 9 / common privacy regimes.
# Matched as a substring against each declared category (case-insensitive).
_SPECIAL_CATEGORIES = (
    "health", "medical", "biometric", "genetic", "race", "ethnic",
    "political", "religion", "religious", "philosophical", "trade union",
    "sex life", "sexual orientation", "criminal",
)

# EU/EEA recipient codes treated as NOT a third-country transfer.
_EEA = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "IS", "LI", "NO", "EU", "EEA",
}


def _special_hits(categories: list[str]) -> list[str]:
    hits: list[str] = []
    for cat in categories:
        low = cat.lower()
        for special in _SPECIAL_CATEGORIES:
            if special in low:
                hits.append(cat)
                break
    return hits


def _third_countries(transfers: list[str]) -> list[str]:
    out: list[str] = []
    for t in transfers:
        code = t.strip()
        if code and code.upper() not in _EEA:
            out.append(code)
    return out


def _str_list(value: Any) -> list[str]:
    return [str(x).strip() for x in value if str(x).strip()]


def _generate(args: dict[str, Any]) -> str:
    system = str(args.get("system") or "").strip()
    if not system:
        return "ERROR: system (name of the processing system) is required"
    cats_raw = args.get("data_categories")
    if not isinstance(cats_raw, list) or not _str_list(cats_raw):
        return "ERROR: data_categories (non-empty array of strings) is required"
    purposes_raw = args.get("purposes")
    if not isinstance(purposes_raw, list) or not _str_list(purposes_raw):
        return "ERROR: purposes (non-empty array of strings) is required"

    categories = _str_list(cats_raw)
    purposes = _str_list(purposes_raw)
    transfers = _str_list(args.get("transfers") or [])

    retention = args.get("retention_days")
    retention_val: int | None
    try:
        retention_val = int(retention) if retention is not None else None
    except (TypeError, ValueError):
        retention_val = None

    flags: list[str] = []
    special = _special_hits(categories)
    if special:
        flags.append(
            "special-category (sensitive) data processed: "
            + ", ".join(special)
        )
    third = _third_countries(transfers)
    if third:
        flags.append("third-country transfer to: " + ", ".join(third))
    if retention_val is None or retention_val <= 0:
        flags.append("no retention limit set (data kept indefinitely)")

    risk = "HIGH" if flags else "LOW"
    retention_line = (
        f"{retention_val} days" if retention_val and retention_val > 0
        else "UNBOUNDED (no limit)"
    )

    lines = [
        f"# Privacy Impact Assessment: {system}",
        "",
        f"Overall risk: {risk}",
        "",
        "## Data categories",
        *[f"- {c}" for c in categories],
        "",
        "## Purposes",
        *[f"- {p}" for p in purposes],
        "",
        "## Retention",
        f"- {retention_line}",
        "",
        "## Transfers",
        *([f"- {t}" for t in transfers] if transfers else ["- none declared"]),
        "",
        "## Risk flags",
    ]
    if flags:
        lines.extend(f"- {f}" for f in flags)
    else:
        lines.append("- none")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "generate"):
        return f"ERROR: unknown op {args.get('op')!r} (expected generate)"
    return _generate(args)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["generate"]},
        "system": {"type": "string", "description": "name of the processing system"},
        "data_categories": {
            "type": "array",
            "description": "categories of personal data processed",
            "items": {"type": "string"},
        },
        "purposes": {
            "type": "array",
            "description": "processing purposes",
            "items": {"type": "string"},
        },
        "retention_days": {
            "type": "integer",
            "description": "retention period in days; missing/<=0 flags 'no limit'",
        },
        "transfers": {
            "type": "array",
            "description": "recipient countries/codes; non-EU/EEA flags a transfer",
            "items": {"type": "string"},
        },
    },
    "required": ["system", "data_categories", "purposes"],
}


def pia_generator() -> Tool:
    return Tool(
        name="pia_generator",
        description=(
            "Generate a Privacy Impact Assessment (PIA/DPIA) markdown document. "
            "op=generate with 'system', 'data_categories', 'purposes', optional "
            "'retention_days' and 'transfers'. Raises risk flags for "
            "special-category data, third-country (non-EU/EEA) transfers, and "
            "missing retention limits. Returns a structured markdown PIA. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
