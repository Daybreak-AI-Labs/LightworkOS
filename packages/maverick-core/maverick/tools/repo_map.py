"""repo_map tool — give the agent a structured codebase view.

Aider's `--map` and OpenHands' "Locator" sub-agent both materially
help on SWE-bench by short-circuiting the "ls; grep; ls; grep" loop
the agent burns turns on at start. We ship the same here.

Returns a compressed view of the workdir:
  - top-level files + directories (depth 1)
  - one-line "what's in here" for top-level dirs (depth 2 listing)
  - language detection (presence of pyproject.toml / package.json /
    Cargo.toml / etc) so the agent picks the right test runner

The tool is opt-in: the agent must invoke `repo_map` (it's not
auto-injected into context). That keeps token usage bounded.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path

from ..cache.file import _workdir_signature
from . import Tool

_MAX_TOP_ENTRIES = 80
_MAX_NESTED_PER_DIR = 30
_MAX_OUTPUT_BYTES = 8000  # Hard token cap
_IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", "target", ".pytest_cache", ".mypy_cache",
    ".tox", ".idea", ".vscode", "coverage",
}

# Cache per-workdir so a chatty agent calling
# repo_map every turn doesn't pay the walk cost N times.
# Bounded LRU. Best-of-N
# with per-attempt worktrees would each carry a distinct
# cache key; a 500-instance × 4-attempt sweep would otherwise
# accumulate ~2000 entries (60MB+) in this dict. Also: cache key
# includes workdir mtime so the cache invalidates when files
# change. Cap at 64 entries.
_CACHE: OrderedDict[str, str] = OrderedDict()
_CACHE_MAX = 64
# The tool is parallel_safe, so this module cache is hit from multiple threads
# (FastAPI threadpool + agent threads). Guard every access -- an unlocked dict
# raised "dict changed size during iteration" during eviction under concurrency.
_CACHE_LOCK = threading.Lock()


def _inside_workspace(root: Path, candidate: Path) -> bool:
    """True when candidate resolves under root."""
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def clear_repo_map_cache() -> None:
    """Invalidate the repo_map cache. Called by the harness between
    instances when the workdir is reset to a different commit."""
    with _CACHE_LOCK:
        _CACHE.clear()


def _detect_languages(root: Path) -> list[str]:
    markers = {
        "Python (pyproject)": "pyproject.toml",
        "Python (setup.py)":  "setup.py",
        "Python (requirements)": "requirements.txt",
        "Node":               "package.json",
        "Rust":               "Cargo.toml",
        "Go":                 "go.mod",
        "Ruby":               "Gemfile",
        "Java (gradle)":      "build.gradle",
        "Java (maven)":       "pom.xml",
        "Make":               "Makefile",
        "Docker":             "Dockerfile",
    }
    hits = []
    for label, fname in markers.items():
        if (root / fname).exists():
            hits.append(label)
    return hits


def repo_map(sandbox) -> Tool:
    """Build the repo_map Tool bound to `sandbox.workdir`."""
    def fn(args: dict) -> str:
        root = Path(getattr(sandbox, "workdir", ".")).expanduser()
        if not root.exists():
            return f"ERROR: workdir {root} does not exist"

        # Key includes a workdir signature so the cache actually invalidates
        # when files change (the old key was the path alone -> stale forever,
        # contradicting the comment above).
        cache_key = f"{root.resolve()}::{_workdir_signature(root)}"
        with _CACHE_LOCK:
            cached = _CACHE.get(cache_key)
            if cached is not None:
                _CACHE.move_to_end(cache_key)  # true LRU
        if cached is not None:
            return cached + "\n\n(cached; repo unchanged since first call this run)"

        lines: list[str] = [f"Repo map for {root}:"]

        langs = _detect_languages(root)
        if langs:
            lines.append("Languages / build systems: " + ", ".join(langs))

        # Top-level directory listing.
        try:
            entries = sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name))
        except OSError:
            return f"ERROR: cannot list {root}"
        entries = [e for e in entries if e.name not in _IGNORE_DIRS][:_MAX_TOP_ENTRIES]

        for entry in entries:
            # Never follow top-level symlinks; they may point outside the workspace.
            if entry.is_symlink():
                lines.append(f"  {entry.name}@    [symlink skipped]")
                continue

            if entry.is_dir():
                # One-line summary: top N files within.
                try:
                    children = sorted(
                        x.name for x in entry.iterdir()
                        if (
                            x.name not in _IGNORE_DIRS
                            and (not x.is_symlink())
                            and _inside_workspace(root, x)
                        )
                    )[:_MAX_NESTED_PER_DIR]
                except OSError:
                    children = ["(unreadable)"]
                preview = ", ".join(children[:8])
                if len(children) > 8:
                    preview += f", ... ({len(children)} total)"
                lines.append(f"  {entry.name}/    {preview}")
            else:
                size = entry.stat().st_size if entry.exists() else 0
                size_h = (
                    f"{size}B" if size < 1024
                    else f"{size // 1024}KB" if size < 1024 * 1024
                    else f"{size // (1024 * 1024)}MB"
                )
                lines.append(f"  {entry.name}    [{size_h}]")

        # Test discovery hint.
        test_dirs = [d.name for d in root.iterdir()
                     if d.is_dir() and d.name in ("tests", "test")]
        if test_dirs:
            lines.append(f"\nTest dir(s): {', '.join(test_dirs)}")
        elif any(f.name.startswith("test_") for f in root.iterdir() if f.is_file()):
            lines.append("\nTests look colocated (test_*.py at root level)")

        # README hint.
        for readme in ("README.md", "README.rst", "README"):
            if (root / readme).exists():
                lines.append(f"\n{readme} present (use read_file to read)")
                break

        text = "\n".join(lines)
        if len(text) > _MAX_OUTPUT_BYTES:
            text = text[:_MAX_OUTPUT_BYTES] + (
                f"\n\n... [truncated to {_MAX_OUTPUT_BYTES}B; "
                f"use `list_dir` for specifics]"
            )
        # LRU eviction under the lock: OrderedDict.popitem(last=False) drops
        # the least-recently-used entry (move_to_end on hit keeps it true LRU).
        with _CACHE_LOCK:
            _CACHE[cache_key] = text
            _CACHE.move_to_end(cache_key)
            while len(_CACHE) > _CACHE_MAX:
                _CACHE.popitem(last=False)
        return text

    return Tool(
        name="repo_map",
        description=(
            "Get a one-shot structured view of the working directory: "
            "top-level files + dirs, detected language / build system, "
            "test layout hint. Call ONCE near the start of a coding "
            "task to orient yourself; avoid re-calling on every turn."
        ),
        input_schema={"type": "object", "properties": {}},
        fn=fn,
        parallel_safe=True,
    )
