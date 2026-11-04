"""Architecture guard for the authoritative world-backend boundary.

Production code that opens the canonical world must use ``open_world()``.
Constructing ``WorldModel()`` directly silently selects SQLite and can split
state from a configured Postgres deployment.  Explicit paths remain valid for
throwaway benchmarks, migrations, and caller-selected SQLite maintenance.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RUNTIME_ROOTS = (
    REPO / "packages" / "maverick-core" / "maverick",
    REPO / "packages" / "maverick-channels" / "maverick_channels",
    REPO / "packages" / "maverick-dashboard" / "maverick_dashboard",
    REPO / "packages" / "maverick-mcp" / "maverick_mcp",
)
FACTORY_MODULE = REPO / "packages" / "maverick-core" / "maverick" / "world_model.py"


def _is_world_model_call(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Name) and func.id == "WorldModel"
    ) or (
        isinstance(func, ast.Attribute) and func.attr == "WorldModel"
    )


def _uses_canonical_path_alias(node: ast.Call) -> bool:
    if not node.args:
        path_kw = next((kw.value for kw in node.keywords if kw.arg == "path"), None)
        if path_kw is None:
            return True
        first = path_kw
    else:
        first = node.args[0]
    if isinstance(first, ast.Constant) and first.value is None:
        return True
    if isinstance(first, ast.Name) and first.id == "DEFAULT_DB":
        return True
    return (
        isinstance(first, ast.Call)
        and isinstance(first.func, ast.Name)
        and first.func.id == "default_db_path"
    )


def test_runtime_canonical_worlds_go_through_backend_factory():
    violations: list[str] = []
    for root in RUNTIME_ROOTS:
        for path in root.rglob("*.py"):
            if path == FACTORY_MODULE:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and _is_world_model_call(node)
                    and _uses_canonical_path_alias(node)
                ):
                    violations.append(
                        f"{path.relative_to(REPO).as_posix()}:{node.lineno}"
                    )
    assert violations == [], (
        "canonical world bypasses open_world(); direct WorldModel construction "
        "would ignore the configured backend: " + ", ".join(violations)
    )
