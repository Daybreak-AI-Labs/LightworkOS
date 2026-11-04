"""CI gate: tool dispatch must go through an authorization gate.

``Agent._run_tool`` runs eleven ordered gates before a tool executes, and it
must be the only way into the tool registry: an ungated dispatch site (for
example a flow step bound at ``automation_queue``) would reach every registered
connector -- stripe, gmail, s3, salesforce, sap, workday -- with a partial
check and no audit row.

The missing audit row is the structural problem, not just the missing checks.
The attestation bundle asserts that *no recorded action violated the policy
envelope*; an action dispatched through an ungated path is never recorded, so
it satisfies that sentence by construction. That turns the platform's central
governance claim from incomplete into **unfalsifiable**, and a claim a hostile
auditor cannot attack is not a strong claim.

This gate keeps the property: a new ``registry.run(...)`` outside the sanctioned
sites fails the build, so the next dispatch site cannot be added ungated by
accident. It is deliberately a structural check rather than a grep -- a grep for
``.run(`` matches hundreds of unrelated calls.

CLI: ``python -m maverick.dispatch_contract --ci``.

Vacuous-gate protection: exits non-zero if it inspects zero files, and if it
cannot find the agent's own known-good dispatch (which proves the detector still
recognises the shape it is looking for).
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

from .source_fingerprint import ScanMemo

REPO_ROOT = Path(__file__).resolve().parents[3]
SEARCH_ROOTS = ("packages", "apps")
_GENERATED_PARTS = frozenset({
    "__pycache__",
    ".tox",
    ".venv",
    "build",
    "dist",
    "site-packages",
})

#: Files allowed to dispatch directly. agent.py owns the eleven-gate chain;
#: tool_authz.py is the gate every other site routes through.
SANCTIONED = frozenset({
    "packages/maverick-core/maverick/agent.py",
    "packages/maverick-core/maverick/tool_authz.py",
})

#: Dispatches whose tool name is a fixed literal are not model- or
#: template-routable, so they cannot be steered into a connector. Recorded with
#: the literal so the exemption is auditable rather than a blanket pass.
LITERAL_EXEMPT = {
    ("packages/maverick-core/maverick/perf_sla.py", "noop"),
}

#: Sites exempt only because nothing in production reaches them. This is the
#: dangerous kind of exemption -- the premise rots the moment somebody wires the
#: code up -- so it is CHECKED, not asserted: :func:`unreachable_exemption_broken`
#: fails the build if a production caller appears, which is exactly when the
#: site needs gating.
#:
#: ``Workflow.run`` takes a caller-supplied registry, so its tools need not
#: appear in the deployment's risk classifier; applying the flow gate would
#: reject every in-process registry rather than protect anything.
UNREACHABLE_EXEMPT = {
    "packages/maverick-core/maverick/workflow.py": ("Workflow", "run"),
}


def unreachable_exemption_broken() -> list[str]:
    """Exempt-because-unreachable sites that now have a production caller."""
    broken = []
    for rel, (cls, meth) in sorted(UNREACHABLE_EXEMPT.items()):
        callers = _production_callers_of(rel, cls, meth)
        if callers:
            broken.append(
                f"{rel}: {cls}.{meth} is exempt from the dispatch gate only "
                f"because nothing in production calls it, but it is now called "
                f"from {', '.join(callers)}. Gate it via tool_authz.authorize "
                "or remove the exemption.")
    return broken


def _production_callers_of(rel: str, cls: str, meth: str) -> list[str]:
    """Non-test modules that construct ``cls`` and call ``.meth`` on it."""
    out = []
    for root in SEARCH_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if _is_test(p) or _is_generated(p) or _rel(p) == rel:
                continue
            try:
                tree = ast.parse(p.read_text(encoding="utf-8"))
            except (OSError, SyntaxError, UnicodeDecodeError):  # pragma: no cover
                continue
            names = {
                n.func.id for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            }
            if cls not in names:
                continue
            if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == meth for n in ast.walk(tree)):
                out.append(f"{_rel(p)}")
    return out

#: Receiver names that denote the tool registry.
REGISTRY_NAMES = frozenset({"reg", "registry", "tools", "_registry", "base_registry"})


def _rel(p: Path) -> str:
    try:
        # Contract identities are repository paths, not host-OS paths. The
        # allowlists and anti-blindness sentinel deliberately use `/` on every
        # runner, so normalize Windows paths too.
        return p.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return p.as_posix()


def _is_test(p: Path) -> bool:
    return "tests" in p.parts or p.name.startswith("test_")


def _is_generated(p: Path) -> bool:
    """Ignore build/install copies that are not editable product source."""
    try:
        parts = p.relative_to(REPO_ROOT).parts
    except ValueError:
        parts = p.parts
    return any(part in _GENERATED_PARTS for part in parts) or any(
        part.startswith("maverick_agent-") for part in parts
    )


def scan_file(path: Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):  # pragma: no cover
        return []
    rel = _rel(path)
    out = []
    # Map each function to whether it calls the gate, so a dispatch guarded a
    # few lines above is recognised. Scoping to the enclosing function is the
    # honest granularity: any wider and "somewhere in this module" would count,
    # which is not a guarantee about this call.
    gated_spans: list[tuple[int, int]] = []
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for c in ast.walk(n):
            if isinstance(c, ast.Call):
                nm = (c.func.id if isinstance(c.func, ast.Name)
                      else getattr(c.func, "attr", ""))
                if nm == "authorize":
                    gated_spans.append((n.lineno, n.end_lineno or n.lineno))
                    break

    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if not (isinstance(f, ast.Attribute) and f.attr == "run"):
            continue
        recv = f.value
        name = recv.id if isinstance(recv, ast.Name) else (
            recv.attr if isinstance(recv, ast.Attribute) else "")
        if name not in REGISTRY_NAMES:
            continue
        literal = None
        if n.args and isinstance(n.args[0], ast.Constant):
            literal = n.args[0].value
        gated = any(lo <= n.lineno <= hi for lo, hi in gated_spans)
        out.append({"file": rel, "line": n.lineno, "recv": name,
                    "literal": literal, "gated": gated})
    return out


_MEMO: ScanMemo[tuple[list[dict], int]] = ScanMemo()


def scan(roots: tuple[str, ...] | None = None) -> tuple[list[dict], int]:
    """Memoised on the tree's content (see ``source_fingerprint``)."""
    chosen = tuple(SEARCH_ROOTS if roots is None else roots)
    return _MEMO.get(
        REPO_ROOT, chosen, lambda: _scan_uncached(chosen),
        lambda result: ([dict(h) for h in result[0]], result[1]),
    )


def _scan_uncached(roots: tuple[str, ...]) -> tuple[list[dict], int]:
    hits: list[dict] = []
    inspected = 0
    for root in roots:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if _is_test(p) or _is_generated(p):
                continue
            inspected += 1
            hits.extend(scan_file(p))
    return hits, inspected


def violations(hits: list[dict]) -> list[dict]:
    out = []
    for h in hits:
        if h["file"] in SANCTIONED:
            continue
        if (h["file"], h["literal"]) in LITERAL_EXEMPT:
            continue
        if h.get("gated"):
            continue
        if h["file"] in UNREACHABLE_EXEMPT:
            continue
        out.append(h)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ci", action="store_true", help="exit non-zero on a violation")
    args = ap.parse_args(argv)

    hits, inspected = scan()
    if inspected == 0:
        print(f"dispatch-contract: ERROR -- inspected 0 files under "
              f"{SEARCH_ROOTS} in {REPO_ROOT}", file=sys.stderr)
        return 2

    # The detector must still recognise the shape it hunts for. If agent.py's
    # own dispatch stops matching, this gate would report a clean tree because
    # it had gone blind, not because the tree is clean.
    if not any(h["file"] == "packages/maverick-core/maverick/agent.py" for h in hits):
        print("dispatch-contract: ERROR -- the agent's own registry dispatch was "
              "not found. The detector no longer recognises a dispatch call, so "
              "a clean result here would be meaningless.", file=sys.stderr)
        return 2

    # An exemption whose premise has rotted is worse than no exemption: it
    # reads as reviewed while protecting nothing.
    if stale := unreachable_exemption_broken():
        print("dispatch-contract: an unreachable-exemption premise no longer holds:",
              file=sys.stderr)
        for s in stale:
            print(f"  {s}", file=sys.stderr)
        return 1 if args.ci else 0

    bad = violations(hits)
    print(f"dispatch-contract: {inspected} files inspected, {len(hits)} "
          f"dispatch site(s), {len(bad)} unsanctioned, "
          f"{len(UNREACHABLE_EXEMPT)} exempt-while-unreachable (premise checked)")
    if not bad:
        return 0

    print("\ndispatch-contract: tool dispatch outside an authorization gate:",
          file=sys.stderr)
    for h in bad:
        print(f"  {h['file']}:{h['line']}  {h['recv']}.run(...)", file=sys.stderr)
    print("\nRoute it through maverick.tool_authz.authorize(tool, params, "
          "origin=...) first, which applies the agent-independent gate subset "
          "AND records the dispatch on the signed chain. Without that record "
          "the attestation's policy_envelope claim is unfalsifiable for this "
          "path. If the tool name is a fixed literal that cannot be steered, "
          "add it to LITERAL_EXEMPT with the literal.", file=sys.stderr)
    return 1 if args.ci else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
