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
``.run(`` matches hundreds of unrelated calls. A direct ``<tool>.fn(...)`` call
skips the registry altogether, so it counts as a dispatch too; the reviewed
ones are listed in ``DIRECT_FN_REVIEWED`` with the calls each review covered. A handler taken into a variable and called later is not seen, and
neither is a call written inside source text that runs in a child process (the
two known ones are on record in the same list).

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


#: Direct ``<tool>.fn(...)`` calls, reviewed one by one and keyed by file and
#: enclosing function, so a new direct call elsewhere in the same file still
#: fails. Each entry is ``(expected, reason)``. ``expected`` lists the calls
#: the review covered in that function, each as its receiver expression
#: (``tool.fn``), in sorted order: one more, one fewer or a different one
#: fails the gate until it is reviewed. The reason says why the call may skip
#: ``ToolRegistry.run``.
#:
#: Two calls sit inside source text that is run in a child process, where this
#: scan cannot see them. They are on record under the function name
#: ``<source text>`` with ``expected`` set to the line itself (a string); the
#: gate fails if the file no longer contains it, so the entry cannot go stale.
_QUALIFICATION = ("plugin qualification: runs the candidate's handler once with the "
                  "reviewed practice input, inside the reviewed container")
DIRECT_FN_REVIEWED: dict[tuple[str, str], tuple[tuple[str, ...] | str, str]] = {
    ("packages/maverick-core/maverick/governed_tools.py", "_fn"): (
        ("tool.fn", "tool.fn"), "the governed connector wrapper: it is the registered handler and "
           "calls the wrapped handler after its own preview, approval and "
           "receipt steps"),
    ("packages/maverick-core/maverick/tools/_lazy.py", "__call__"): (
        ("self.resolve().fn",), "the lazy tool's own handler: the registry calls it, and it forwards "
           "to the tool it builds on first use"),
    ("packages/maverick-core/maverick/sandbox/plugin_contracts.py", "execute"): (("tool.fn",), _QUALIFICATION),
    ("packages/maverick-core/maverick/sandbox/plugin_contracts.py", "execute_node"): (("tool.fn",), _QUALIFICATION),
    ("packages/maverick-core/maverick/sandbox/plugin_contracts.py", "execute_grpc"): (("tool.fn",), _QUALIFICATION),
    ("packages/maverick-core/maverick/proof_guarantees.py",
     "claim_fleet_can_read_but_not_write"): (
        ("tools['billdotcom_read'].fn",), "a self-check with fixed arguments: it asks a read-only seat to "
           "write and requires the refusal"),
    # Not gated like a real call. ToolRegistry.speculate_reads applies the
    # access list, the MCP binding and the ambient-credential check, and the
    # agent skips speculation under a capability, but there is no Shield scan,
    # stop check, replay check or audit row. Opt-in, side-effect-free reads
    # only. Listed so the gap is on record here, not so it reads as closed.
    ("packages/maverick-core/maverick/speculative_tools.py", "_call_tool"): (
        ("tool.fn",), "KNOWN GAP: opt-in pre-run of repeat reads outside the governed "
           "dispatch; partial checks only (see the comment above)"),
    ("packages/maverick-core/maverick/self_learning.py", "<source text>"): (
        "_result = _tool.fn(_args)",
        "not scanned: source text run in a child process. It is the generated "
        "tool's own handler; the registered tool starts that child in the sandbox"),
    ("packages/maverick-core/maverick/plugin_isolation.py", "<source text>"): (
        "result = fn().fn(args)",
        "not scanned: source text run in a child process. It is the isolated "
        "plugin's own handler; the registered proxy tool starts that child"),
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
    # Keep lexical function ownership separate from source order: ast.walk
    # includes nested definitions, whose authorize calls do not gate their
    # parent's dispatch. A later call cannot authorize an earlier effect.
    owners: dict[ast.AST, ast.AST | None] = {}
    gates: dict[ast.AST, list[tuple[int, int]]] = {}

    def index(node: ast.AST, owner: ast.AST | None = None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            owner = node
        elif isinstance(node, ast.ClassDef):
            owner = None
        owners[node] = owner
        if isinstance(node, ast.Call) and owner is not None:
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            if name == "authorize":
                gates.setdefault(owner, []).append((node.end_lineno or node.lineno,
                                                   node.end_col_offset or node.col_offset))
        for child in ast.iter_child_nodes(node):
            index(child, owner)

    index(tree)

    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if not (isinstance(f, ast.Attribute) and f.attr in ("run", "fn")):
            continue
        recv = f.value
        name = recv.id if isinstance(recv, ast.Name) else (
            recv.attr if isinstance(recv, ast.Attribute) else "")
        # ``.run`` is a common method name, so it counts only on a registry.
        # ``.fn`` is the tool handler itself: calling it on any receiver skips
        # the registry and every gate in it, so every such call is a dispatch.
        if f.attr == "run" and name not in REGISTRY_NAMES:
            continue
        literal = None
        if f.attr == "run" and n.args and isinstance(n.args[0], ast.Constant):
            literal = n.args[0].value
        owner = owners[n]
        gated = any(position < (n.lineno, n.col_offset) for position in gates.get(owner, ()))
        out.append({"file": rel, "line": n.lineno, "recv": name or "<expression>",
                    "kind": f.attr, "call": ast.unparse(f),
                    "function": getattr(owner, "name", "<lambda>") if owner else "<module>",
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


def _fn_calls(hits: list[dict]) -> dict[tuple[str, str], tuple[str, ...]]:
    """The direct ``.fn(`` calls each (file, function) holds, as sorted
    receiver expressions."""
    calls: dict[tuple[str, str], list[str]] = {}
    for h in hits:
        if h.get("kind") == "fn":
            calls.setdefault((h["file"], h["function"]), []).append(h["call"])
    return {key: tuple(sorted(found)) for key, found in calls.items()}


def stale_fn_reviews(hits: list[dict]) -> list[str]:
    """Reviewed direct-handler exceptions that no longer match a call."""
    seen = _fn_calls(hits)
    stale = []
    for (rel, function), (expected, _reason) in sorted(DIRECT_FN_REVIEWED.items()):
        if isinstance(expected, str):  # a call inside child-process source text
            try:
                present = expected in (REPO_ROOT / rel).read_text(encoding="utf-8")
            except OSError:
                present = False
        else:
            present = (rel, function) in seen
        if not present:
            stale.append(f"{rel}: {function}")
    return stale


def violations(hits: list[dict]) -> list[dict]:
    out = []
    calls = _fn_calls(hits)
    for h in hits:
        if h["file"] in SANCTIONED:
            continue
        key = (h["file"], h.get("function"))
        # A review covers the calls it lists, not every later or different
        # one in the same function.
        if h.get("kind") == "fn" and DIRECT_FN_REVIEWED.get(key, (None, ""))[0] == calls.get(key):
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

    if stale_reviews := stale_fn_reviews(hits):
        print("dispatch-contract: a reviewed direct handler call no longer "
              "exists; remove it from DIRECT_FN_REVIEWED:", file=sys.stderr)
        for s in stale_reviews:
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
        print(f"  {h['file']}:{h['line']}  {h['recv']}.{h.get('kind', 'run')}(...)",
              file=sys.stderr)
    print("\nRoute it through maverick.tool_authz.authorize(tool, params, "
          "origin=...) first, which applies the agent-independent gate subset "
          "AND records the dispatch on the signed chain. Without that record "
          "the attestation's policy_envelope claim is unfalsifiable for this "
          "path. If the tool name is a fixed literal that cannot be steered, "
          "add it to LITERAL_EXEMPT with the literal. A direct handler call "
          "(.fn) that has been reviewed goes in DIRECT_FN_REVIEWED with its "
          "reason and the calls it covers in that function; a function "
          "already listed there is reported again when those calls change.",
          file=sys.stderr)
    return 1 if args.ci else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
