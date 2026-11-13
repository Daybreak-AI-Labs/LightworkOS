"""License compliance scanner: classify installed packages' licenses.

Reads installed distribution metadata (``importlib.metadata``) and classifies
each package's license into an SPDX-ish category — permissive / weak-copyleft /
strong-copyleft / public-domain / unknown — via a keyword map over the license
``License-Expression``, Trove classifiers, or the legacy ``License`` field, in
that order. ``policy_check`` flags packages whose category is in a denylist
(default: ``strong-copyleft`` — GPL/AGPL/SSPL — the licenses whose copyleft
terms can extend to a larger work that includes the package).

The classifier and policy check are pure and unit-tested; ``scan_distributions``
accepts an injectable iterable so tests don't depend on the real environment.
Exposed as the ``license_scan`` tool.
"""
from __future__ import annotations

import re

# Order matters: AGPL/LGPL must be matched before the bare "GPL" substring,
# and "GPL"/"copyleft" before the permissive families.
_RULES: list[tuple[str, str]] = [
    (r"\bagpl|affero", "strong-copyleft"),
    (r"\bsspl\b|server[\s-]?side\s+public", "strong-copyleft"),
    # "library general public" is LGPL-2.0's historical official title; without
    # it, that string falls through to the GPL rule and is over-flagged.
    (r"\blgpl|lesser general public|library general public", "weak-copyleft"),
    (r"\bgpl|general public license|gplv", "strong-copyleft"),
    # "epl" and "isc" are whole tokens: unanchored they also match inside
    # ordinary words ("deployment", "disclaimer").
    (r"\bmpl|mozilla public|\bepl\b|eclipse public|cddl|cpl ", "weak-copyleft"),
    (r"public domain|unlicense|\bcc0\b|wtfpl|0bsd", "public-domain"),
    (r"\bmit\b|expat", "permissive"),
    (r"bsd|apache|\bisc\b|\bzlib\b|python software foundation|\bpsf\b|"
     r"boost|\bmit-0\b", "permissive"),
]
_DEFAULT_DENIED = frozenset({"strong-copyleft"})


def classify_license(text: str) -> str:
    """Map a free-text license string to a category. ``unknown`` when unmatched."""
    t = (text or "").strip().lower()
    if not t or t in {"unknown", "none", "other/proprietary license"}:
        return "proprietary" if "proprietary" in t else "unknown"
    for pattern, category in _RULES:
        if re.search(pattern, t):
            return category
    return "unknown"


def _license_from_metadata(meta) -> str:
    """Return the distribution's best governing-license declaration.

    PEP 639's SPDX ``License-Expression`` is authoritative. For older metadata,
    a structured Trove classifier is more reliable than the legacy free-text
    ``License`` field: projects commonly put bundled third-party notices and
    complete license texts in that field, which must not be mistaken for the
    distribution's governing license.
    """
    expression = (meta.get("License-Expression") or "").strip()
    if expression and expression.lower() not in {"unknown", "license"}:
        return expression

    parts: list[str] = []
    # importlib metadata exposes repeated headers via get_all.
    getter = getattr(meta, "get_all", None)
    classifiers = getter("Classifier") if getter else []
    for c in classifiers or []:
        if c.startswith("License ::"):
            parts.append(c.split("::")[-1].strip())
    if parts:
        return "; ".join(parts)

    field = (meta.get("License") or "").strip()
    if field and field.lower() not in {"unknown", "license"}:
        return field
    return ""


def scan_distributions(dists=None) -> list[dict]:
    """Return ``{name, version, license, category}`` for each installed dist.

    ``dists`` defaults to ``importlib.metadata.distributions()``; pass a list of
    metadata-bearing objects in tests.
    """
    if dists is None:
        from importlib import metadata
        dists = metadata.distributions()
    out: list[dict] = []
    seen: set[str] = set()
    for d in dists:
        try:
            meta = d.metadata
            name = meta.get("Name") or getattr(d, "name", "") or "?"
        except Exception:  # pragma: no cover -- broken dist metadata
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        lic = _license_from_metadata(meta)
        out.append({
            "name": name,
            "version": meta.get("Version") or "",
            "license": lic or "unknown",
            "category": classify_license(lic),
        })
    out.sort(key=lambda r: r["name"].lower())
    return out


def policy_check(scanned: list[dict], denied: set[str] | None = None) -> list[dict]:
    """Return the scanned rows whose category is in ``denied`` (default
    strong-copyleft)."""
    deny = set(denied) if denied is not None else set(_DEFAULT_DENIED)
    return [r for r in scanned if r.get("category") in deny]


_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "check"], "default": "check"},
        "denied": {
            "type": "array", "items": {"type": "string"},
            "description": "categories to flag (default: strong-copyleft)",
        },
    },
}


def _run(args: dict) -> str:
    import json as _json
    op = args.get("op") or "check"
    scanned = scan_distributions()
    if op == "list":
        return _json.dumps(scanned, indent=2)
    denied = set(args.get("denied") or []) or None
    violations = policy_check(scanned, denied)
    if not violations:
        return f"OK: no license-policy violations across {len(scanned)} packages."
    lines = [f"{len(violations)} package(s) violate license policy "
             f"(denied: {sorted(denied or _DEFAULT_DENIED)}):"]
    lines += [f"  - {v['name']} {v['version']}: {v['license']} ({v['category']})"
              for v in violations]
    return "\n".join(lines)


def license_scan():
    from .tools import Tool
    return Tool(
        name="license_scan",
        description=(
            "Scan installed Python packages' licenses and flag policy violations. "
            "ops: check (default; flags strong-copyleft/GPL by default), list (all "
            "packages + categories). Categories: permissive, weak-copyleft, "
            "strong-copyleft, public-domain, proprietary, unknown."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )


__all__ = [
    "classify_license", "scan_distributions", "policy_check", "license_scan",
]
