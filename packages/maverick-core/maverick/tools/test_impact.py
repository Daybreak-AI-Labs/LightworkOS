"""Test-impact analyzer.

Given a git diff (or list of changed files), predict which test files
the agent should re-run instead of the full suite. Drastically cuts
iteration time on large repos where a 30-minute pytest run drowns
out the inner loop.

Heuristic (intentionally simple, no AST):

  1. Walk the repo's test dir(s) (``tests/`` and ``test/``).
  2. Cache each test file's import lines + literal-string references
     to module paths.
  3. For each changed file, compute the dotted module name (e.g.
     ``packages/maverick-core/maverick/foo.py`` ->
     ``maverick.foo``) plus the bare basename (``foo``).
  4. A test file is "impacted" when ANY of its cached references
     matches one of the candidate strings for any changed file.

Better than the naïve "rerun everything" without dragging in heavy
deps like pytest-testmon. Tracks call graphs only as far as imports
go — that's good enough to slash the test surface 5-10× in practice.

ops:
  - analyze(diff)               — diff blob -> impacted test files
  - analyze_files(paths)        — explicit changed-file list

Both ops accept an optional ``test_dirs`` arg (defaults to
``["tests", "test"]`` searched from the configured workdir).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import Tool

# This is a production tool module, not a pytest module.  Its public factory
# keeps the registry name ``test_impact`` without being collected as a test.
__test__ = False

log = logging.getLogger(__name__)


_IMPACT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["analyze", "analyze_files"]},
        "diff": {"type": "string", "description": "Unified diff blob (analyze)."},
        "paths": {
            "type": "array", "items": {"type": "string"},
            "description": "Changed file paths (analyze_files).",
        },
        "test_dirs": {
            "type": "array", "items": {"type": "string"},
            "description": "Test directories to scan (default: tests, test).",
        },
    },
    "required": ["op"],
}


_DIFF_PATH_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)


def _changed_from_diff(diff: str) -> list[str]:
    """Parse ``+++ b/<path>`` lines out of a unified diff."""
    if not diff:
        return []
    out: list[str] = []
    for m in _DIFF_PATH_RE.finditer(diff):
        p = m.group(1).strip()
        if p and p != "/dev/null":
            out.append(p)
    return out


def _module_candidates(rel_path: str) -> set[str]:
    """Heuristics for what symbols a test file might mention to ref this file."""
    p = Path(rel_path)
    parts = list(p.with_suffix("").parts)
    cand: set[str] = set()
    if not parts:
        return cand
    # bare basename ("foo" for foo.py)
    cand.add(parts[-1])
    # dotted module path with as many trailing pieces as possible
    for i in range(len(parts)):
        suffix = parts[i:]
        if any(s in {"", "__init__"} for s in suffix):
            continue
        cand.add(".".join(suffix))
    cand.discard("")
    return cand


def _scan_test_file(path: Path) -> set[str]:
    """Extract import names + bare module references from a test file."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return set()
    refs: set[str] = set()
    # import maverick.foo / from maverick.foo import bar
    for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z0-9_.]+)", text, re.MULTILINE):
        mod = m.group(1)
        refs.add(mod)
        # Also each prefix so 'maverick.foo' matches scanning 'maverick'.
        parts = mod.split(".")
        for i in range(1, len(parts) + 1):
            refs.add(".".join(parts[:i]))
        # Bare leaf basename.
        refs.add(parts[-1])
    # Free-form mentions ("foo.bar" or "foo") in test code / docstrings.
    for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_.]{2,}", text):
        refs.add(m.group(0))
    return refs


def _walk_test_files(roots: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for r in roots:
        if not r.exists() or not r.is_dir():
            continue
        for p in r.rglob("test_*.py"):
            if "__pycache__" in p.parts:
                continue
            out.append(p)
        for p in r.rglob("*_test.py"):
            if "__pycache__" in p.parts:
                continue
            out.append(p)
    return out


def _resolve_roots(workdir: Path, test_dirs: list[str]) -> list[Path]:
    roots: list[Path] = []
    for d in test_dirs:
        if not isinstance(d, str) or not d.strip():
            continue
        rel = Path(d.strip())
        if rel.is_absolute() or ".." in rel.parts:
            continue
        candidate = (workdir / rel).resolve()
        try:
            candidate.relative_to(workdir)
        except ValueError:
            continue
        if candidate.is_dir():
            roots.append(candidate)
    return roots


def _analyze(changed: list[str], workdir: Path, test_dirs: list[str]) -> str:
    if not changed:
        return "no changed files"
    roots = _resolve_roots(workdir, test_dirs)
    if not roots:
        return f"no test directories found under {workdir} ({test_dirs})"

    candidates_per_change: list[tuple[str, set[str]]] = [
        (cf, _module_candidates(cf)) for cf in changed
    ]
    impacted: list[tuple[str, list[str]]] = []
    for tf in _walk_test_files(roots):
        refs = _scan_test_file(tf)
        hits = []
        for cf, cands in candidates_per_change:
            if cands & refs:
                hits.append(cf)
        if hits:
            try:
                rel = tf.resolve().relative_to(workdir.resolve())
                impacted.append((str(rel), hits))
            except ValueError:
                impacted.append((str(tf), hits))

    if not impacted:
        return "no impacted tests (full suite still recommended for safety)"

    lines = [f"{len(impacted)} impacted test file(s) for {len(changed)} change(s):"]
    for rel, hits in sorted(impacted):
        lines.append(f"  {rel}")
        for h in hits[:3]:
            lines.append(f"      via {h}")
        if len(hits) > 3:
            lines.append(f"      (+{len(hits) - 3} more)")
    return "\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    workdir = Path.cwd().resolve()
    test_dirs = args.get("test_dirs") or ["tests", "test"]
    try:
        if op == "analyze":
            return _analyze(
                _changed_from_diff(args.get("diff") or ""),
                workdir, test_dirs,
            )
        if op == "analyze_files":
            paths = [str(p) for p in (args.get("paths") or []) if p]
            return _analyze(paths, workdir, test_dirs)
    except Exception as e:
        return f"ERROR: test_impact failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def test_impact() -> Tool:
    return Tool(
        name="test_impact",
        description=(
            "Predict which test files are impacted by a change. "
            "ops: analyze (unified diff string -> impacted tests), "
            "analyze_files (explicit file list). Heuristic: walks "
            "tests/ matching imports + bare module references. "
            "Optional test_dirs override."
        ),
        input_schema=_IMPACT_SCHEMA,
        fn=_run,
    )
