"""Every setting in effect and where it comes from (the whole-configuration view).

``maverick config show`` prints the installation settings file. This module is
the structured form of the same question for the dashboard: each section and
key that any settings layer sets, the value that wins after the normal merge,
and which layer supplied it. Layers, lowest precedence first, match
:func:`maverick.config.load_config`:

``file``       the installation settings file (config.toml)
``dashboard``  the dashboard's own settings overlay
``operator``   the operator overlay named by the deployment
``workspace``  the active workspace's own settings file

A value written as ``${NAME}`` is filled from the environment when read; such
keys report ``environment`` as their source together with the variable names.
Secret values are never returned: a secret key reports only whether it is set.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

_SECRET_WORDS = ("api_key", "apikey", "secret", "token", "password", "passphrase",
                 "private_key", "credential", "client_secret", "access_key", "session_key",
                 "signing_key", "webhook_url", "dsn", "auth_header", "authorization")
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_KEYS = 5000


def is_secret_key(name: str) -> bool:
    lowered = str(name).lower()
    return any(word in lowered for word in _SECRET_WORDS)


def _layers() -> list[tuple[str, Path | None]]:
    from .config import (
        CONFIG_OVERLAY_ENV,
        config_path,
        dashboard_overrides_path,
        tenant_config_path,
    )
    overlay = os.environ.get(CONFIG_OVERLAY_ENV, "").strip()
    return [
        ("file", config_path()),
        ("dashboard", dashboard_overrides_path()),
        ("operator", Path(overlay).expanduser() if overlay else None),
        ("workspace", tenant_config_path()),
    ]


def _flatten(table: dict, prefix: tuple[str, ...], out: dict[tuple[str, ...], Any]) -> None:
    for key, value in table.items():
        path = (*prefix, str(key))
        if isinstance(value, dict) and value:
            _flatten(value, path, out)
        else:
            out[path] = value


def _lookup(tree: Any, path: tuple[str, ...]) -> tuple[bool, Any]:
    node = tree
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _env_refs(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return _ENV_REF.findall(raw)
    if isinstance(raw, list):
        return [name for item in raw for name in _env_refs(item)]
    return []


def _is_set(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, list, dict, tuple)):
        return bool(value)
    return True


def describe() -> dict[str, Any]:
    """The whole effective configuration, grouped by top-level section.

    Returns ``{"sections": [{"name", "keys": [...]}], "layers": {...},
    "unreadable": [...], "truncated": bool}``. Each key row carries ``path``
    (dotted), ``section`` (dotted table), ``key``, ``source``, ``env`` (the
    variable names a ``${NAME}`` value reads), ``secret``, ``set`` and --
    only when not secret -- ``value``.
    """
    from .config import _read_toml_raw, config_source_errors, load_config

    winners: dict[tuple[str, ...], tuple[str, Any]] = {}
    present: dict[str, bool] = {}
    for name, path in _layers():
        if path is None or not path.exists():
            present[name] = False
            continue
        present[name] = True
        flat: dict[tuple[str, ...], Any] = {}
        _flatten(_read_toml_raw(path), (), flat)
        for key_path, raw in flat.items():
            winners[key_path] = (name, raw)
    effective = load_config() or {}
    rows: dict[str, list[dict[str, Any]]] = {}
    for count, key_path in enumerate(sorted(winners)):
        if count >= MAX_KEYS:
            break
        source, raw = winners[key_path]
        env = _env_refs(raw)
        found, value = _lookup(effective, key_path)
        if not found:
            value = raw
        secret = is_secret_key(key_path[-1]) or (isinstance(raw, str) and raw.startswith("MVKAR1:"))
        row: dict[str, Any] = {
            "path": ".".join(key_path),
            "section": ".".join(key_path[:-1]),
            "key": key_path[-1],
            "source": "environment" if env else source,
            "layer": source,
            "env": env,
            "secret": secret,
            "set": _is_set(value),
        }
        if not secret:
            row["value"] = value
        rows.setdefault(key_path[0] if len(key_path) > 1 else "", []).append(row)
    errors = config_source_errors(include_tenant=True)
    return {
        "sections": [{"name": name, "keys": keys} for name, keys in sorted(rows.items())],
        "layers": present,
        "unreadable": sorted(Path(path).name for path in errors),
        "truncated": len(winners) > MAX_KEYS,
    }


__all__ = ["describe", "is_secret_key", "MAX_KEYS"]
