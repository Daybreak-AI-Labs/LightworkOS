"""Pure helpers shared by the wizard facade and its step modules.

Input parsing (``_safe_int``, ``_safe_float``, ``_csv_list``) and TOML
rendering (``_toml_str``, ``_emit_kv``, ``_append_nested_product_config``).
Nothing here prompts or touches the filesystem, so the step modules import
these directly.
"""
from __future__ import annotations

from typing import Any


def _safe_int(s: str, *, default: int) -> int:
    """``int()`` that doesn't crash on whitespace, empty, or junk input."""
    try:
        return int(str(s or "").strip())
    except (TypeError, ValueError):
        return default


def _csv_list(raw: str, *, lower: bool = False) -> list[str]:
    """Split a comma-separated prompt answer into trimmed, non-empty items."""
    items = [x.strip() for x in str(raw or "").split(",") if x.strip()]
    return [x.lower() for x in items] if lower else items


def _safe_float(s: str, *, default: float) -> float:
    """``float()`` that doesn't crash on whitespace, empty, or junk input."""
    try:
        return float(str(s or "").strip())
    except (TypeError, ValueError):
        return default


def _toml_str(v: Any) -> str:
    """Render a value as a TOML basic string with proper escaping.

    Windows paths (e.g. a sandbox workdir ``C:\\Users\\x\\ws``) contain
    backslashes; emitted raw into a ``"..."`` basic string, ``\\U`` is parsed
    as a unicode escape and the config.toml the wizard just wrote can't be read
    back (``TOMLDecodeError: Invalid hex value``). Escape backslashes and
    double-quotes so the round-trip holds on every platform.
    """
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _emit_kv(lines: list[str], k: str, v: Any) -> None:
    """Append one TOML key=value line, type-dispatched."""
    if isinstance(v, bool):
        lines.append(f"{k} = {str(v).lower()}")
    elif isinstance(v, (int, float)):
        lines.append(f"{k} = {v}")
    elif isinstance(v, list):
        rendered = ", ".join(
            str(x).lower() if isinstance(x, bool) else str(x) if isinstance(x, (int, float)) else _toml_str(x)
            for x in v
        )
        lines.append(f"{k} = [{rendered}]")
    else:
        lines.append(f"{k} = {_toml_str(v)}")


def _append_nested_product_config(
    lines: list[str],
    section: str,
    values: dict[str, Any],
) -> None:
    def append_table(path: str, table: dict[str, Any]) -> None:
        lines.extend(("", f"[{path}]"))
        for key, value in table.items():
            if not isinstance(value, dict):
                _emit_kv(lines, key, value)
        for subsystem, nested in table.items():
            if isinstance(nested, dict):
                append_table(f"{path}.{subsystem}", nested)

    append_table(section, values)
