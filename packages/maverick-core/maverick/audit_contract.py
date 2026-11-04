"""CI gate: an audit write must not be wrapped in a refusal-swallowing except.

The audit subsystem raises :class:`~maverick.audit.errors.AuditRefused` when it
*declines* to write -- a compliance floor mandates a signed chain and the signer
will not start, or custody policy forbids a co-located key. A caller that
catches it and continues converts "we could not record this action" into "we
recorded nothing and did it anyway", which is the exact failure the guarantee
exists to prevent.

A contract that lives only in a docstring is easy to break: a ``record()``
call wrapped in a bare ``except Exception: pass`` silently drops the event.
This gate makes the contract structural.

**Preferred fix:** call :func:`maverick.audit.audit_event` instead of wrapping
``record()`` yourself. It applies the contract and logs other failures with a
traceback, so a permanently broken audit path stops looking like a healthy one.

**Otherwise:** re-raise the base class before the broad handler::

    try:
        record(...)
    except AuditRefused:
        raise
    except Exception:
        log.warning(..., exc_info=True)

Catching ``AuditWriteRefused`` alone is NOT sufficient and this gate says so:
its sibling ``OffHostSigningRequiredError`` fires under the strictest posture
the product supports, and the one hardened call site in the tree was hardened
against the wrong half of the pair.

CLI: ``python -m maverick.audit_contract --ci`` exits non-zero on any new
violation. Existing violations are ratcheted in ``audit_contract.baseline.json``
so the gate lands green and blocks regressions; the baseline is a debt register
to shrink, not a permanent exemption. ``--regen`` rewrites it.

Vacuous-gate protection: the gate exits non-zero if it inspects zero files, so a
broken path or a bad filter can never be mistaken for a pass.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

from .source_fingerprint import ScanMemo

#: Names that, when called, write an audit row.
AUDIT_WRITERS = frozenset({"record", "record_global"})

#: Handler types that satisfy the contract when caught and re-raised.
CONTRACT_TYPES = frozenset({"AuditRefused"})

#: Handler types that look like the contract but are only half of it.
PARTIAL_TYPES = frozenset({"AuditWriteRefused", "OffHostSigningRequiredError"})

#: Known superclasses of AuditRefused; each can catch it before a typed handler.
BROAD_TYPES = frozenset({"RuntimeError", "Exception", "BaseException"})

SEARCH_ROOTS = ("packages", "apps", "benchmarks")

REPO_ROOT = Path(__file__).resolve().parents[3]
BASELINE = Path(__file__).resolve().parent / "audit_contract.baseline.json"


def _is_test_path(p: Path) -> bool:
    parts = set(p.parts)
    return "tests" in parts or p.name.startswith("test_") or p.name == "conftest.py"


def _is_generated_path(p: Path) -> bool:
    """Return whether *p* is packaging output rather than maintained source.

    ``python -m build`` leaves importable copies below ``build/lib``. Scanning
    them double-counts every finding and, because the directory is gitignored,
    can make CI results depend on which packaging command happened to run
    first. The maintained module remains in the scan; only its generated copy
    is excluded.
    """
    return any(
        part == "build" and index + 1 < len(p.parts) and p.parts[index + 1] == "lib"
        for index, part in enumerate(p.parts)
    )


def _handler_names(handler: ast.ExceptHandler) -> set[str]:
    t = handler.type
    if t is None:
        return {"BaseException"}  # bare `except:`
    nodes = t.elts if isinstance(t, ast.Tuple) else [t]
    out = set()
    for n in nodes:
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    """Recognize a reachable re-raise of the exception this handler caught.

    This is a conservative syntax check, not a control-flow interpreter. A
    straight-line prefix (for example logging) followed by bare ``raise`` or
    ``raise <unchanged caught name>`` qualifies. Returns, replacement exceptions
    and compound control flow require review rather than receiving credit for
    an arbitrary Raise node somewhere in the handler.
    """
    caught_name = handler.name
    prefix_types = (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign,
                    ast.Delete, ast.Pass, ast.Import, ast.ImportFrom)
    for stmt in handler.body:
        if isinstance(stmt, ast.Raise):
            return stmt.exc is None or (
                isinstance(stmt.exc, ast.Name) and stmt.exc.id == caught_name
            )
        if not isinstance(stmt, prefix_types):
            return False
        for node in ast.walk(stmt):
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                return False
            if (isinstance(node, ast.Name) and node.id == caught_name
                    and isinstance(node.ctx, (ast.Store, ast.Del))):
                caught_name = None
            if isinstance(node, ast.alias) and (node.asname or node.name) == caught_name:
                caught_name = None
    return False


def _imports_audit_writer(tree: ast.AST) -> bool:
    """Does this module import record/record_global from the audit package?

    Avoids flagging unrelated ``.record()`` methods -- a metrics recorder, a
    dataclass field -- which is how a naive name match inflates the count.
    """
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            mod = (n.module or "")
            if "audit" in mod.split(".") or mod.endswith("audit"):
                if any(a.name in AUDIT_WRITERS for a in n.names):
                    return True
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.endswith("audit"):
                    return True
    return False


def _audit_calls(tree: ast.AST) -> list[int]:
    lines = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id in AUDIT_WRITERS:
            lines.append(n.lineno)
        elif isinstance(f, ast.Attribute) and f.attr in AUDIT_WRITERS:
            # audit.record(...) / writer.record_global(...)
            base = f.value
            base_name = base.id if isinstance(base, ast.Name) else (
                base.attr if isinstance(base, ast.Attribute) else "")
            if "audit" in str(base_name).lower() or "writer" in str(base_name).lower():
                lines.append(n.lineno)
    return lines


def _span(nodes: list[ast.stmt]) -> tuple[int, int]:
    if not nodes:
        return (0, -1)
    return (nodes[0].lineno, max((n.end_lineno or n.lineno) for n in nodes))


def _enclosing_functions(tree: ast.AST) -> list[tuple[int, int, str]]:
    """(start, end, qualified-name) for every function, innermost last."""
    spans: list[tuple[int, int, str]] = []

    def walk(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{child.name}"
                spans.append((child.lineno, child.end_lineno or child.lineno, name))
                walk(child, prefix=f"{name}.")
            elif isinstance(child, ast.ClassDef):
                walk(child, prefix=f"{prefix}{child.name}.")
            else:
                walk(child, prefix=prefix)

    walk(tree)
    return spans


def _func_at(spans, line: int) -> str:
    best = ""
    best_span = None
    for lo, hi, name in spans:
        if lo <= line <= hi and (best_span is None or (hi - lo) <= best_span):
            best, best_span = name, hi - lo
    return best


def scan_file(path: Path) -> list[dict]:
    """Violations in one file: audit writes under a refusal-swallowing handler."""
    try:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except (OSError, SyntaxError, UnicodeDecodeError):  # pragma: no cover
        return []
    if not _imports_audit_writer(tree):
        return []
    calls = _audit_calls(tree)
    if not calls:
        return []

    spans = _enclosing_functions(tree)
    out: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        lo, hi = _span(node.body)
        covered = sorted(c for c in calls if lo <= c <= hi)
        if not covered:
            continue

        handlers = [(h, _handler_names(h)) for h in node.handlers]
        swallowed: set[str] = set()
        partial = {name for _, names in handlers for name in names & PARTIAL_TYPES}
        for refusal in CONTRACT_TYPES | PARTIAL_TYPES:
            for handler, names in handlers:
                if not (names & (CONTRACT_TYPES | BROAD_TYPES) or refusal in names):
                    continue
                # Python runs only the first matching handler. Neither a later
                # base-class re-raise nor a sibling's handler can repair a
                # refusal already swallowed here.
                if not _handler_reraises(handler):
                    swallowed.update(names & (CONTRACT_TYPES | PARTIAL_TYPES | BROAD_TYPES))
                break

        if not swallowed:
            continue
        for line in covered:
            out.append({
                "file": _rel(path),
                "func": _func_at(spans, line),
                "line": line,
                "catches": sorted(swallowed),
                "partial": sorted(partial),
            })
    return out


def _rel(path: Path) -> str:
    """Stable POSIX-style path, repo-relative where possible.

    Baseline keys are committed once and consumed on Windows and POSIX runners.
    ``str(Path)`` made every slash differ on Windows, so all known debt appeared
    simultaneously fixed and newly introduced.  Serialize paths independently
    of the host filesystem convention.
    """
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


_MEMO: ScanMemo[tuple[list[dict], int]] = ScanMemo()


def scan(roots: tuple[str, ...] | None = None) -> tuple[list[dict], int]:
    """Return (violations, files_inspected).

    ``roots`` defaults to the module-level :data:`SEARCH_ROOTS` read at call
    time, not at definition time -- a default argument would bind the tuple
    once and make the vacuous-gate test unable to redirect it, which would
    leave the anti-vacuity check itself untested.

    Memoised on the tree's content (see ``source_fingerprint``).
    """
    chosen = tuple(SEARCH_ROOTS if roots is None else roots)
    return _MEMO.get(
        REPO_ROOT, chosen, lambda: _scan_uncached(chosen),
        lambda result: ([dict(v) for v in result[0]], result[1]),
    )


def _scan_uncached(roots: tuple[str, ...]) -> tuple[list[dict], int]:
    violations: list[dict] = []
    inspected = 0
    for root in roots:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if _is_test_path(p) or _is_generated_path(p):
                continue
            inspected += 1
            violations.extend(scan_file(p))
    # Nested try blocks report the same call once per enclosing handler; the
    # call site is the unit of debt, not the handler.
    seen: set[str] = set()
    deduped: list[dict] = []
    for v in sorted(violations, key=lambda v: (v["file"], v["line"])):
        k = _key(v)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(v)
    return deduped, inspected


def _key(v: dict) -> str:
    """Stable identity for a baselined violation.

    Deliberately NOT the line number. Keying on ``file:line`` meant any edit
    above a violation renumbered it, so the gate reported the same site as both
    "fixed" and "new" in one run -- which trains whoever sees it to run --regen
    without reading, and a ratchet regenerated blindly is not a ratchet. The
    enclosing function is stable across unrelated edits and still unique enough
    to be worth reviewing when it changes.
    """
    return f"{v['file']}::{v.get('func') or '<module>'}"


def load_baseline() -> set[str]:
    if not BASELINE.exists():
        return set()
    try:
        return set(json.loads(BASELINE.read_text(encoding="utf-8")).get("known", []))
    except (OSError, ValueError):  # pragma: no cover
        return set()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ci", action="store_true", help="exit non-zero on a new violation")
    ap.add_argument("--regen", action="store_true", help="rewrite the ratchet baseline")
    args = ap.parse_args(argv)

    violations, inspected = scan()

    # Vacuous-gate protection. A gate that inspects nothing and exits 0 is worse
    # than no gate: it reports a guarantee it never checked.
    if inspected == 0:
        print("audit-contract: ERROR -- inspected 0 files. The search roots are "
              f"wrong or missing: {SEARCH_ROOTS} under {REPO_ROOT}", file=sys.stderr)
        return 2

    if args.regen:
        BASELINE.write_text(
            json.dumps({
                "_comment": "Ratcheted pre-existing violations of the audit refusal "
                            "contract. This is a debt register, not an exemption "
                            "list -- shrink it. Regenerate with "
                            "`python -m maverick.audit_contract --regen`.",
                "known": sorted(_key(v) for v in violations),
            }, indent=2) + "\n",
            encoding="utf-8")
        print(f"audit-contract: baseline rewritten with {len(violations)} known "
              f"violation(s) across {inspected} files")
        return 0

    known = load_baseline()
    new = [v for v in violations if _key(v) not in known]
    fixed = sorted(known - {_key(v) for v in violations})

    print(f"audit-contract: {inspected} files inspected, {len(violations)} "
          f"violation(s), {len(known)} baselined, {len(new)} new")

    if fixed:
        print(f"  {len(fixed)} baselined violation(s) fixed -- "
              "run --regen to shrink the baseline:")
        for k in fixed[:10]:
            print(f"    + {k}")

    if not new:
        return 0

    print("\naudit-contract: NEW violation(s) -- an audit write is wrapped in a "
          "handler that swallows AuditRefused:", file=sys.stderr)
    for v in new:
        extra = ""
        if v["partial"]:
            extra = (f"  (catches {', '.join(v['partial'])}, which is only half "
                     "the pair -- catch the base AuditRefused)")
        print(f"  {v['file']}:{v['line']}  except {', '.join(v['catches'])}{extra}",
              file=sys.stderr)
    print("\nFix: call maverick.audit.audit_event(...) instead of wrapping "
          "record() yourself, or add `except AuditRefused: raise` BEFORE the "
          "broad handler (order matters -- Python matches in sequence).",
          file=sys.stderr)
    return 1 if args.ci else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
