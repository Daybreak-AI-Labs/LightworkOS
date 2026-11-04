"""Explicit reset semantics for the deployment-global dashboard overlay.

Only the dashboard-owned overlay interprets this metadata. Installer/operator/
tenant dictionaries retain ordinary merge semantics. Each reviewed marker removes
installer rows before dashboard values merge; operator values still win after it.
"""
from __future__ import annotations

METADATA = "_dashboard_resets"


def reset_spec(setting) -> dict:
    return {"path": list(setting.path), "keep": list(setting.fixed_keys),
            "entries": setting.key_kind == "entries",
            "preserve_tables": setting.key_kind == "entries" and setting.row_kind not in {"grid", "named"},
            "remove_value": setting.control != "table"}


def _specs(overlay: dict):
    metadata = overlay.get(METADATA, {})
    if not isinstance(metadata, dict):
        raise ValueError("Dashboard reset metadata is unreadable.")
    for identifier, spec in metadata.items():
        if not isinstance(identifier, str) or not isinstance(spec, dict):
            raise ValueError("Dashboard reset metadata is unreadable.")
        path, keep = spec.get("path"), spec.get("keep")
        if (set(spec) != {"path", "keep", "entries", "preserve_tables", "remove_value"}
                or not isinstance(path, list) or not 1 <= len(path) <= 12
                or any(not isinstance(part, str) or not part or part.startswith("_") for part in path)
                or not isinstance(keep, list) or any(not isinstance(key, str) for key in keep)
                or not isinstance(spec.get("entries"), bool)
                or not isinstance(spec.get("preserve_tables"), bool)
                or not isinstance(spec.get("remove_value"), bool)):
            raise ValueError("Dashboard reset metadata is unreadable.")
        yield identifier, spec


def is_reset(overlay: dict, setting) -> bool:
    return any(identifier == setting.id and spec == reset_spec(setting) for identifier, spec in _specs(overlay))


def apply_to_base(base: dict, overlay: dict) -> dict:
    """Copy only the affected paths; never mutate the installer snapshot."""
    result = dict(base)
    for _identifier, spec in _specs(overlay):
        node = result
        for part in spec["path"][:-1]:
            child = node.get(part)
            child = dict(child) if isinstance(child, dict) else {}
            node[part] = child
            node = child
        key = spec["path"][-1]
        existing = node.get(key)
        existing = existing if isinstance(existing, dict) else {}
        if spec["remove_value"]:
            node.pop(key, None)
        elif spec["entries"]:
            node[key] = {name: value for name, value in existing.items()
                         if name in spec["keep"] or (spec["preserve_tables"] and isinstance(value, dict))}
        else:
            node[key] = {}
    return result


def merge_dashboard(base: dict, overlay: dict, merge) -> dict:
    return merge(apply_to_base(base, overlay), {key: value for key, value in overlay.items() if key != METADATA})
