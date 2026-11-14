"""Every outbound HTTP path must go through a library the egress guard wraps.

``egress_guard`` moved the enterprise boundary from 11 hand-written per-tool
checks to the per-request methods of ``httpx``, ``httpx2`` and ``requests``,
which covers direct application calls plus provider SDK traffic. That is a real
fix, and it has exactly one way to silently stop being true: someone adds a
connector using a client library the guard does not wrap.

That is not hypothetical -- it is the history of this subsystem. The per-tool
convention was undermined by sixty connectors that simply did not call it, and
nothing failed, because the tests validated the policy *function* and a
handful of hand-picked wrappers. A guarantee that depends on authors
remembering an unenforced convention decays to whatever the least careful
commit did.

So this gate enumerates every production module that issues outbound HTTP and
classifies the library it uses:

``COVERED``    httpx / httpx2 / requests / urllib -- guard wrappers apply
``UNCOVERED``  another known HTTP entry point (aiohttp, http.client)

Only calls to the known HTTP entry points are seen. Network access through
other libraries (SMTP, cloud SDKs, database and cache clients, raw sockets,
``asyncio.open_connection``) is not in the census at all, so the covered and
uncovered counts describe HTTP only.

An UNCOVERED module is not automatically a build failure -- one exists today
and is recorded below. It is a failure to add a *new* one, or to leave a
recorded one in the list after it has been migrated. The number is a debt
register, not an exemption list.

CLI: ``python -m maverick.egress_contract`` prints the census;
``--ci`` fails on drift; ``--list`` shows every call site.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

from .source_fingerprint import ScanMemo

REPO_ROOT = Path(__file__).resolve().parents[3]

SEARCH_ROOTS = ("packages", "apps")

#: Fully-qualified calls that ISSUE an outbound request (or build the object
#: that does), mapped to the library root the guard reasons about.
#:
#: Matched on the exact dotted path, not a trailing attribute name. An earlier
#: version matched any ``urllib.request.*`` call and flagged
#: ``urllib.request.Request(...)`` -- which constructs a request and sends
#: nothing. A gate that reports things that are not true gets muted, and a
#: muted gate is worse than no gate.
_HTTP_CALLS = {
    "httpx.Client": "httpx", "httpx.AsyncClient": "httpx",
    "httpx.get": "httpx", "httpx.post": "httpx", "httpx.put": "httpx",
    "httpx.patch": "httpx", "httpx.delete": "httpx", "httpx.head": "httpx",
    "httpx.options": "httpx", "httpx.request": "httpx", "httpx.stream": "httpx",
    "httpx2.Client": "httpx2", "httpx2.AsyncClient": "httpx2",
    "httpx2.get": "httpx2", "httpx2.post": "httpx2", "httpx2.put": "httpx2",
    "httpx2.patch": "httpx2", "httpx2.delete": "httpx2",
    "httpx2.head": "httpx2", "httpx2.options": "httpx2",
    "httpx2.request": "httpx2", "httpx2.stream": "httpx2",
    "requests.Session": "requests", "requests.get": "requests",
    "requests.post": "requests", "requests.put": "requests",
    "requests.patch": "requests", "requests.delete": "requests",
    "requests.head": "requests", "requests.options": "requests",
    "requests.request": "requests",
    "aiohttp.ClientSession": "aiohttp", "aiohttp.request": "aiohttp",
    "urllib.request.urlopen": "urllib",
    "urllib.request.build_opener": "urllib",
    "urllib.request.install_opener": "urllib",
    "http.client.HTTPConnection": "http.client",
    "http.client.HTTPSConnection": "http.client",
    "websockets.connect": "websockets",
}

#: Modules known to reach the network through a library the guard does not
#: wrap. Each one is a live hole in the enterprise boundary: a request from
#: here is NOT checked against [enterprise] allowed_hosts. Shrink this list by
#: migrating the module to httpx; do not grow it.
KNOWN_UNCOVERED: dict[str, str] = {
    "packages/maverick-channels/maverick_channels/slack.py":
        "aiohttp ClientSession in the Socket Mode listener; migrating it means "
        "reworking the websocket loop, so it is recorded rather than rushed",
}


def _rel(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _is_test(path: Path) -> bool:
    return (
        "tests" in path.parts
        or path.name.startswith("test_")
        or path.name == "conftest.py"
        or "benchmarks" in path.parts
    )


def _is_generated(path: Path) -> bool:
    """Exclude ignored build outputs that duplicate already-scanned sources."""
    return any(part in {"build", "dist", ".tox", ".venv"} for part in path.parts)


def _dotted(node: ast.AST) -> str:
    """Full dotted path of an attribute chain, or "" if it is not a plain one."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(node.id)
    return ".".join(reversed(parts))


def _alias_map(tree: ast.AST) -> dict[str, str]:
    """Local name -> real dotted name, for every import in the module.

    Without this the gate is trivially evaded by ``import aiohttp as ah``,
    which is not an attack so much as ordinary style -- and it was found the
    embarrassing way, by a stray probe file sitting in the package that the
    gate reported as clean. Covers ``import x as y``, ``import x.y as z``, and
    ``from x import y as z``.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                # Only an explicit `as` rebinds. Plain `import x.y` binds the
                # TOP-LEVEL `x`, which already resolves correctly -- mapping it
                # to "x.y" produced "urllib.request.request.urlopen" and made
                # eight real modules invisible.
                if a.asname:
                    out[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _resolve(dotted: str, aliases: dict[str, str]) -> str:
    """Rewrite a call's dotted name through the module's import aliases."""
    if not dotted:
        return ""
    head, _, rest = dotted.partition(".")
    real = aliases.get(head)
    if real is None:
        return dotted
    return f"{real}.{rest}" if rest else real


def _libraries_used(tree: ast.AST) -> set[str]:
    """Libraries this module issues outbound HTTP through."""
    aliases = _alias_map(tree)
    used: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lib = _HTTP_CALLS.get(_resolve(_dotted(node.func), aliases))
        if lib:
            used.add(lib)
    return used


_MEMO: ScanMemo[dict[str, set[str]]] = ScanMemo()


def scan(roots: tuple[str, ...] | None = None) -> dict[str, set[str]]:
    """Map production module -> outbound HTTP libraries it calls directly.

    Memoised on the tree's content (see ``source_fingerprint``): the tests
    call this four times per process and the tree does not change between.
    """
    chosen = tuple(roots or SEARCH_ROOTS)
    return _MEMO.get(
        REPO_ROOT, chosen, lambda: _scan_uncached(chosen),
        lambda census: {module: set(libs) for module, libs in census.items()},
    )


def _scan_uncached(roots: tuple[str, ...]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for root in roots:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if _is_test(path) or _is_generated(path):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            libs = _libraries_used(tree)
            if libs:
                out[_rel(path)] = libs
    return out


def classify(census: dict[str, set[str]]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Split the census into (covered, uncovered)."""
    from .egress_guard import COVERED_LIBRARIES

    covered: dict[str, set[str]] = {}
    uncovered: dict[str, set[str]] = {}
    for module, libs in census.items():
        outside = {lib for lib in libs if lib not in COVERED_LIBRARIES}
        if outside:
            uncovered[module] = outside
        else:
            covered[module] = libs
    return covered, uncovered


def problems(uncovered: dict[str, set[str]]) -> list[str]:
    out = []
    for module, libs in sorted(uncovered.items()):
        if module not in KNOWN_UNCOVERED:
            out.append(
                f"{module}: reaches the network via {sorted(libs)}, which the "
                "egress guard does not wrap. Requests from here bypass "
                "[enterprise] allowed_hosts entirely. Use httpx, or record it "
                "in egress_contract.KNOWN_UNCOVERED with the reason.")
    for module in sorted(KNOWN_UNCOVERED):
        if module not in uncovered:
            out.append(
                f"{module} is recorded as uncovered but no longer reaches the "
                "network outside the guarded libraries. Remove it from "
                "KNOWN_UNCOVERED.")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ci", action="store_true", help="exit non-zero on drift")
    ap.add_argument("--list", action="store_true", help="print every module")
    args = ap.parse_args(argv)

    census = scan()
    if not census:
        print("egress_contract: ERROR -- found 0 modules making outbound HTTP. "
              f"The scan roots are wrong or missing under {REPO_ROOT}.",
              file=sys.stderr)
        return 2
    covered, uncovered = classify(census)

    print(f"egress_contract: {len(census)} modules make direct outbound HTTP "
          f"-- {len(covered)} covered by the guard, {len(uncovered)} not "
          f"({len(KNOWN_UNCOVERED)} recorded).")
    if args.list:
        for module, libs in sorted(census.items()):
            mark = "  " if module in covered else "!!"
            print(f"{mark} {module}: {','.join(sorted(libs))}")

    found = problems(uncovered)
    if not found:
        return 0
    print(f"\negress_contract: {len(found)} problem(s):", file=sys.stderr)
    for p in found:
        print(f"  {p}", file=sys.stderr)
    return 1 if args.ci else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
