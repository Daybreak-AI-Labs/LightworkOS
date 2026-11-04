#!/usr/bin/env python3
"""Choose the pytest paths a pull request needs from the files it changes.

The merge queue and pushes to ``main`` always run the complete suite (ci.yml:
``test`` on the queue's commit, plus ``test-window`` and ``posture``), so this
decides only what the floor-interpreter ``test`` legs run on a ``pull_request``
event. Selecting too little costs a later failure in the queue, where the whole
suite runs anyway; selecting too much costs runner minutes. The rules err
toward running everything:

* A change under the kernel (``packages/maverick-core/maverick``), the shared
  test bootstrap (any ``conftest.py``, ``test_support/``, ``pyproject.toml``,
  ``requirements/``), ``.github/``, ``scripts/`` or ``benchmarks/`` selects the
  full suite: every package imports the kernel, and the tests read the
  workflows and scripts.
* A change inside another package or Python app selects that package's own
  tests plus every test file anywhere that names its import package.
* A changed test file is always selected.
* Any other file (docs, deploy, READMEs, SDKs, native apps) selects every test
  file whose text names the file's repository path, its basename, or a quoted
  component of its directory path, because the claims and deployment tests
  reference such files by path (``_read("README.md")``,
  ``REPO_ROOT / "deploy" / "helm"``).
* When nothing matches, the mode is ``none`` and the legs report success
  without running pytest.

The same change set decides which of the heavier ci.yml jobs a pull request
needs (``jobs`` in the output, one boolean per job id): each job runs when a
changed path is under one of its ``JOB_PREFIXES`` or when the full suite is
selected, and is skipped otherwise. The merge queue and ``main`` never consult
this; they run every job.

Usage::

    python scripts/select_pr_tests.py --git BASE HEAD --github-output "$GITHUB_OUTPUT"
    python scripts/select_pr_tests.py --full "push: everything runs" --github-output "$GITHUB_OUTPUT"
    python scripts/select_pr_tests.py --files-from changed.txt --output selection.json
    git diff --name-only BASE HEAD | python scripts/select_pr_tests.py --stdin

``--git`` diffs HEAD against its merge base with BASE (what the pull request
itself changes, even after the base branch moved) and selects the full suite
when git cannot answer, so a selection failure never skips tests. ``--full``
is what the other events (pushes, the merge queue, workflow_dispatch) run: the
whole suite and every gated job. The output JSON is ``{"mode": "full" |
"paths" | "none", "paths": [...], "reasons": [...], "jobs": {...}}``;
``paths`` are repository-relative pytest targets. ``--github-output`` appends
``mode=``, ``paths=`` (the JSON array) and ``jobs=`` (the JSON map, one entry
per gated job) lines for a workflow step. ci.yml skips a gated job only on the
literal ``"<job>": false`` in that map, so the map is always complete and a
missing map or entry runs the job.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Any change here means the whole suite: shared fixtures, the kernel every
#: package imports, the workflows and scripts the tests read.
FULL_SUITE_PREFIXES = (
    "packages/maverick-core/maverick/",
    "test_support/",
    "requirements/",
    ".github/",
    "scripts/",
    "benchmarks/",
)
FULL_SUITE_FILES = frozenset({"conftest.py", "pyproject.toml", "release-cohort.toml"})

#: Import package name per distribution directory.
PACKAGE_MODULES = {
    "packages/maverick-shield": "maverick_shield",
    "packages/maverick-channels": "maverick_channels",
    "packages/maverick-evolve": "maverick_evolve",
    "packages/maverick-dashboard": "maverick_dashboard",
    "packages/maverick-mcp": "maverick_mcp",
    "packages/maverick-knowledge": "maverick_knowledge",
    "apps/installer-cli": "maverick_installer",
}

_TEST_FILE = re.compile(r"(^|/)test_[^/]+\.py$")

#: ci.yml jobs a pull request may skip, with the paths that make each one
#: necessary. The job id is the key; a prefix ending in "/" is a directory.
#: Anything under FULL_SUITE_PREFIXES / FULL_SUITE_FILES runs every job.
#: Jobs not listed here (lint, test, test-window, posture, the Windows window
#: legs) are never gated.
JOB_PREFIXES: dict[str, tuple[str, ...]] = {
    # LaTeX/document conversion tests plus the offline document-worker image.
    "document-engines": ("packages/maverick-core/", "deploy/docker/"),
    # The deploy image installs every package; its Dockerfile lives under deploy/docker.
    "docker": ("packages/", "apps/installer-cli/", "deploy/docker/", ".dockerignore"),
    # Live Postgres and pgvector tests of the core, knowledge and dashboard packages.
    "postgres": ("packages/maverick-core/", "packages/maverick-knowledge/", "packages/maverick-dashboard/"),
    # OSV/pip-audit/bandit/SBOM over every dependency surface and all Python code.
    "audit": (
        "packages/", "apps/", "benchmarks/", "demo/", "examples/", "rust/", "go/", "sdks/",
        "extensions/", "deploy/", "vendor/", "osv-scanner.toml",
    ),
    # Wheel builds and package metadata of the release cohort.
    "release-cohort": ("packages/", "apps/installer-cli/"),
    # Shield red-team corpus.
    "redteam": ("packages/maverick-core/", "packages/maverick-shield/"),
    # Eval-harness smoke over the core.
    "eval-smoke": ("packages/maverick-core/",),
    # Governance-frontier and harness-overhead benchmarks over core + shield.
    "governance-frontier-offline": ("packages/maverick-core/", "packages/maverick-shield/"),
    "harness-overhead": ("packages/maverick-core/", "packages/maverick-shield/"),
    # Windows Job Object containment of the local sandbox backend.
    "windows-process-containment": ("packages/maverick-core/",),
}


def test_files(root: Path = REPO_ROOT) -> list[Path]:
    """Every pytest file the root pyproject collects (packages, apps, benchmarks)."""
    found: list[Path] = []
    for base in ("packages", "apps", "benchmarks"):
        top = root / base
        if top.is_dir():
            found.extend(p for p in top.rglob("test_*.py") if ".venv" not in p.parts)
    return sorted(found)


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_test_file(rel: str) -> bool:
    return bool(_TEST_FILE.search(rel)) and rel.startswith(("packages/", "apps/", "benchmarks/"))


def _full_reason(rel: str) -> str | None:
    if rel in FULL_SUITE_FILES:
        return f"{rel} is shared by the whole suite"
    if PurePosixPath(rel).name == "conftest.py":
        return f"{rel} is a shared fixture file"
    for prefix in FULL_SUITE_PREFIXES:
        if rel.startswith(prefix):
            return f"{rel} is under {prefix}"
    return None


def _package_of(rel: str) -> tuple[str, str] | None:
    for directory, module in PACKAGE_MODULES.items():
        if rel.startswith(directory + "/"):
            return directory, module
    return None


def _reference_candidates(rel: str) -> set[str]:
    """Literals a test might use to name ``rel``: the path, its basename, and
    quoted directory components (``"deploy"``, ``'terraform'``)."""
    path = PurePosixPath(rel)
    candidates = {rel, path.name}
    for part in path.parts[:-1]:
        candidates.add(f'"{part}"')
        candidates.add(f"'{part}'")
    # The path with any leading directory stripped, as docs link to each other.
    for i in range(1, len(path.parts) - 1):
        candidates.add("/".join(path.parts[i:]))
    return candidates


_GIT_REF = re.compile(r"[0-9A-Za-z][0-9A-Za-z._/-]*")


def changed_files_from_git(base: str, head: str, root: Path = REPO_ROOT) -> tuple[list[str] | None, str]:
    """The files ``head`` changes since its merge base with ``base``.

    Returns ``(paths, merge_base)``, or ``(None, reason)`` when git cannot
    answer (unknown ref, no common history, no git); the caller then selects
    the full suite. ``--no-renames`` lists both names of a moved file so the
    tests naming either are selected. NUL-delimited output preserves paths
    that Git would otherwise quote, including non-ASCII names.
    """
    for ref in (base, head):
        if not _GIT_REF.fullmatch(ref):
            return None, f"refusing to pass {ref!r} to git"
    git = ["git", "-C", str(root)]
    try:
        merge_base = subprocess.run(
            [*git, "merge-base", base, head], check=True, capture_output=True, text=True
        ).stdout.strip()
        diff = subprocess.run(
            [*git, "diff", "--name-only", "--no-renames", "-z", merge_base, head],
            check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        detail = (getattr(exc, "stderr", "") or str(exc)).strip()
        return None, f"git could not diff {base}...{head}: {detail}"
    paths = [path for path in diff.split("\0") if path]
    # ``select`` also accepts hand-entered Windows paths and normalizes them.
    # A literal backslash in a POSIX Git path, or a path whose outer whitespace
    # would be stripped, cannot safely pass through that normalization. Control
    # characters also make diagnostics and downstream path lists ambiguous.
    if any(path != path.strip() or "\\" in path or any(ord(c) < 32 for c in path) for path in paths):
        return None, "git returned a path that cannot be safely normalized; run the full suite"
    return paths, merge_base


def jobs_needed(changed: list[str]) -> dict[str, bool]:
    """Which gated ci.yml jobs the changed paths make necessary."""
    return {
        job: any(rel.startswith(prefixes) for rel in changed)
        for job, prefixes in JOB_PREFIXES.items()
    }


def select(changed: list[str], root: Path = REPO_ROOT) -> dict:
    """Return ``{"mode", "paths", "reasons", "jobs"}`` for the changed repository paths."""
    changed = sorted({c.strip().replace("\\", "/") for c in changed if c.strip()})
    reasons: list[str] = []
    for rel in changed:
        reason = _full_reason(rel)
        if reason:
            return {"mode": "full", "paths": [], "reasons": [reason],
                    "jobs": dict.fromkeys(JOB_PREFIXES, True)}
    jobs = jobs_needed(changed)

    # A test-only change selects exactly the changed test files. Avoid reading
    # every test in the repository just to rediscover those paths; this does not
    # alter the conservative full-suite rules above or package/reference scans.
    if changed and all(_is_test_file(rel) for rel in changed):
        existing = [rel for rel in changed if (root / rel).exists()]
        if not existing:
            return {"mode": "none", "paths": [], "reasons": ["no files changed"], "jobs": jobs}
        return {
            "mode": "paths",
            "paths": sorted(existing),
            "reasons": [f"{rel} changed" for rel in existing],
            "jobs": jobs,
        }

    all_tests = test_files(root)
    texts = {t: t.read_text(encoding="utf-8", errors="ignore") for t in all_tests}
    selected: set[Path] = set()

    for rel in changed:
        if _is_test_file(rel):
            path = root / rel
            if path.exists():
                selected.add(path)
                reasons.append(f"{rel} changed")
            continue
        package = _package_of(rel)
        if package and rel.endswith(".py"):
            directory, module = package
            own = root / directory / "tests"
            if own.is_dir():
                selected.update(t for t in all_tests if own in t.parents)
            importers = [t for t in all_tests if module in texts[t] and own not in t.parents]
            selected.update(importers)
            reasons.append(f"{rel}: {directory}/tests plus {len(importers)} files naming {module}")
            continue
        candidates = _reference_candidates(rel)
        hits = [t for t in all_tests if any(c in texts[t] for c in candidates)]
        selected.update(hits)
        reasons.append(f"{rel}: {len(hits)} files name it")

    if not selected:
        return {"mode": "none", "paths": [], "reasons": reasons or ["no files changed"], "jobs": jobs}
    return {
        "mode": "paths",
        "paths": sorted(_rel(t, root) for t in selected),
        "reasons": reasons,
        "jobs": jobs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--full", metavar="REASON",
        help="select the whole suite and every gated job (pushes, the merge queue, workflow_dispatch)",
    )
    source.add_argument("--files-from", metavar="FILE", help="newline-separated changed paths")
    source.add_argument("--stdin", action="store_true", help="read changed paths from stdin")
    source.add_argument("--files", nargs="+", metavar="PATH", help="changed paths")
    source.add_argument(
        "--git", nargs=2, metavar=("BASE", "HEAD"),
        help="diff HEAD against its merge base with BASE; full suite if git cannot",
    )
    parser.add_argument("--output", metavar="FILE", help="write the selection JSON here")
    parser.add_argument(
        "--github-output", metavar="FILE",
        help="append mode= and paths= lines for a workflow step ($GITHUB_OUTPUT)",
    )
    parser.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="repository root (default: this checkout)"
    )
    args = parser.parse_args(argv)

    result: dict | None = None
    if args.full:
        result = {"mode": "full", "paths": [], "reasons": [args.full],
                  "jobs": dict.fromkeys(JOB_PREFIXES, True)}
    elif args.files_from:
        changed = Path(args.files_from).read_text(encoding="utf-8").splitlines()
    elif args.stdin:
        changed = sys.stdin.read().splitlines()
    elif args.git:
        changed, note = changed_files_from_git(*args.git, root=args.root)
        if changed is None:
            result = {"mode": "full", "paths": [], "reasons": [note],
                      "jobs": dict.fromkeys(JOB_PREFIXES, True)}
        else:
            print(f"{len(changed)} files changed since merge base {note}")
    else:
        changed = list(args.files)

    if result is None:
        result = select(changed, args.root)
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as handle:
            handle.write(
                f"mode={result['mode']}\npaths={json.dumps(result['paths'])}\n"
                f"jobs={json.dumps(result['jobs'])}\n"
            )
    skipped = sorted(job for job, needed in result["jobs"].items() if not needed)
    print(f"mode={result['mode']} paths={len(result['paths'])} jobs skipped={skipped or 'none'}")
    for reason in result["reasons"][:20]:
        print(f"  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
