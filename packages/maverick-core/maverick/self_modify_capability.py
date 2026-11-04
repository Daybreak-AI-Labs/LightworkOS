"""Capability-algebra non-escalation EVIDENCE for a code patch (Gap 5).

This computes a machine screen for capability escalation using the real
capability algebra (:mod:`maverick.capability`) instead of a boolean guess. It is
deliberately called **evidence, not a proof**: detection is syntactic (regex over
source lines), so a determined obfuscation (``getattr(os,'sy'+'stem')``, a
base64/``codecs`` payload) can still evade it. It is one layer of a
defence-in-depth stack — the editable-surface boundary, this screen, and a
**human Ed25519 signature at the code rung** — not a standalone guarantee. The
screen's job is to reliably CATCH the common escalations and make the gate
stricter; the human signer is the backstop for what a regex cannot.

The idea is **differential**: a patch widens authority only if it introduces a
capability *class* the edited baseline did not already use. Editing a module that
already opens sockets to tweak one of its network calls does not widen the
envelope; adding the first socket to a module that had none does. We map both the
baseline source and the patch's added lines to a set of capability classes
(process spawn, network, dynamic code, filesystem write, dynamic import, native
FFI, deserialization, explicit authority grant), express each as a
:class:`~maverick.capability.Capability` over that class universe, and let
``Capability.permits`` decide — so the answer routes through the same
least-privilege algebra the runtime enforces on tools, not an ad-hoc check.

The result plugs into the governed gate: :func:`capability_delta` returns
``(before, after, probe_tools)`` for a candidate's ``capability_before`` /
``capability_after`` / ``probe_tools`` fields, and
:func:`maverick.self_improvement._capability_widens` computes escalation as
"some probed class the *after* grant permits that the *before* grant did not."

Fail-closed: with no real baseline source the baseline class set is **empty**, so
every capability construct the added lines introduce counts as new (maximally
strict). A baseline derived from the patch's own context lines was rejected as
unsafe — an unchanged context word could seed a class into ``before`` and mask a
genuinely-added grant.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from .capability import Capability

# Capability classes and the constructs that evidence each. This is the SINGLE
# construct taxonomy — the syntactic screen (self_modify.capability_diff) reports
# *classes* so the before/after comparison is over a small, stable universe.
_CLASS_PATTERNS: dict[str, tuple[str, ...]] = {
    "process": (
        r"\bshell\s*=\s*True\b", r"\bsubprocess\b",
        r"\bos\.(system|popen|exec[lv]\w*|spawn\w*)\s*\(",
        r"\bpty\.spawn\b", r"\bmultiprocessing\b",
    ),
    "network": (
        r"\b(socket|asyncio\.open_connection|http\.client|urllib|requests|"
        r"httpx|aiohttp|smtplib|ftplib|paramiko|websockets)\b",
    ),
    "dynamic_code": (
        # Bare builtin dynamic-exec calls, DOT-guarded so an unrelated METHOD of
        # the same name is not a false positive: `compiler.compile(...)` (a query
        # compiler), `frame.eval(...)`/`df.eval(...)` are attribute calls, not the
        # builtins. This matches the AST pass, which already flags eval/exec/
        # compile only as bare Names -- the regex now says the same thing.
        r"(?<![\w.])(eval|exec)\s*\(", r"(?<![\w.])compile\s*\(",
        r"\bbuiltins\.(eval|exec|compile)\s*\(",
        # Obfuscation constructs that reach the same primitives past a literal
        # regex (getattr(os,'sy'+'stem'), __builtins__[...], base64/codecs
        # payloads). A regex screen can't catch every spelling, so a change that
        # even *uses* dynamic-attribute/decoded-payload machinery is itself
        # treated as a dynamic-code capability -- fail toward flagging. getattr is
        # flagged UNLESS its attribute-name argument is a single string LITERAL:
        # `getattr(x, "CONST")` is static attribute access (== x.CONST), not
        # obfuscation. A non-literal name (`getattr(x, var)`), a concatenated one
        # (`getattr(os, 'sy'+'stem')`), or a call split across lines we cannot
        # verify all still flag -- every ambiguous form fails toward flagging.
        r"(?<![\w.])getattr\s*\([^,]+,(?!\s*['\"][^'\"]*['\"]\s*[,)])",
        r"(?<![\w.])getattr\s*\([^)]*$",
        r"\b__builtins__\b", r"\bcodecs\.decode\b",
        r"\bbase64\b", r"\bglobals\s*\(\s*\)\s*\[", r"\bvars\s*\(\s*\)\s*\[",
    ),
    "fs_write": (
        r"\bos\.(remove|unlink|rmdir|chmod|chown|rename|replace)\s*\(",
        r"\bshutil\.(rmtree|move|copy\w*)\s*\(",
        r"\bopen\s*\([^)]*['\"][rwax+bt]*[wax+][rwax+bt]*['\"]",
        r"\.write_(text|bytes)\s*\(",
    ),
    "dynamic_import": (
        r"\b__import__\s*\(", r"\bimportlib\b",
    ),
    "native_ffi": (
        r"\bctypes\b", r"\bcffi\b",
    ),
    "deserialize": (
        r"\bpickle\.(load|loads)\b", r"\bmarshal\.(load|loads)\b",
    ),
    "authority_grant": (
        r"\b(grant|entitlement|allow_?list|allowlist|editable_paths|"
        r"probe_tools|capability_before|capability_after|max_risk|deny_tools)\b",
    ),
}
_CLASS_COMPILED: dict[str, tuple[re.Pattern, ...]] = {
    cls: tuple(re.compile(p) for p in pats) for cls, pats in _CLASS_PATTERNS.items()
}

# The full class universe probed for escalation. Fixed so `before`/`after` are
# compared over the same axes every time.
CAPABILITY_CLASSES: tuple[str, ...] = tuple(sorted(_CLASS_PATTERNS))

# A token that is never a capability class and never probed. Included in every
# grant's allow-list so it is never EMPTY -- an empty ``allow_tools`` means "all"
# in the capability algebra, which would invert the intended "permits nothing".
_ANCHOR = "\x00cap-anchor"


def classes_in(lines: Iterable[str]) -> frozenset[str]:
    """The capability classes evidenced by a block of source lines via the regex
    screen. A pure comment line contributes nothing (a ``# subprocess`` note is
    not a spawn); string literals can still match, deliberately (a string can be
    an exec payload, and a false positive only over-reports widening). For a
    coherent source string prefer :func:`classes_in_source`, which adds a
    structural AST pass that catches import-aliasing / getattr obfuscation."""
    found: set[str] = set()
    for raw in lines:
        stripped = str(raw).lstrip()
        if stripped.startswith("#"):
            continue
        for cls, patterns in _CLASS_COMPILED.items():
            if cls in found:
                continue
            if any(rx.search(raw) for rx in patterns):
                found.add(cls)
    return frozenset(found)


# --- structural (AST) detection: robust to obfuscation the regex misses -------

# Root module -> capability class it grants merely by being imported (matches the
# regex's bareword flags: `import socket` etc. is itself the signal).
_IMPORT_MODULE_CLASS: dict[str, str] = {
    "subprocess": "process", "multiprocessing": "process", "pty": "process",
    "socket": "network", "urllib": "network", "http": "network",
    "requests": "network", "httpx": "network", "aiohttp": "network",
    "smtplib": "network", "ftplib": "network", "paramiko": "network",
    "websockets": "network",
    "ctypes": "native_ffi", "cffi": "native_ffi",
    "importlib": "dynamic_import", "base64": "dynamic_code",
}
_NETWORK_ROOTS = frozenset({
    "socket", "urllib", "requests", "httpx", "aiohttp", "smtplib", "ftplib",
    "paramiko", "websockets", "http",
})
_OS_FS_ATTRS = frozenset({
    "remove", "unlink", "rmdir", "chmod", "chown", "rename", "replace"})
_AUTHORITY_NAMES = frozenset({
    "grant", "entitlement", "allowlist", "allow_list", "editable_paths",
    "probe_tools", "capability_before", "capability_after", "max_risk",
    "deny_tools"})


class _CapVisitor(ast.NodeVisitor):
    """Walk an AST accumulating capability classes. Catches what the line regex
    can't: ``from os import system as s; s(...)`` (aliasing), ``getattr(os,
    'sy'+'stem')`` (dynamic attribute), attribute calls on known-dangerous
    modules, and a subprocess ``shell`` keyword set true as a real kwarg node."""

    def __init__(self) -> None:
        self.found: set[str] = set()
        self.aliases: dict[str, str] = {}  # local name -> class (aliased funcs)

    def _add(self, cls: str | None) -> None:
        if cls:
            self.found.add(cls)

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self._add(_IMPORT_MODULE_CLASS.get(a.name.split(".")[0]))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".")[0]
        self._add(_IMPORT_MODULE_CLASS.get(root))
        for a in node.names:  # dangerous from-imports (incl. aliases)
            local, cls = a.asname or a.name, None
            if root == "os" and (a.name in ("system", "popen")
                                 or a.name.startswith(("exec", "spawn"))):
                cls = "process"
            elif root == "os" and a.name in _OS_FS_ATTRS:
                cls = "fs_write"
            elif root == "subprocess":
                cls = "process"
            elif root in ("pickle", "marshal") and a.name in ("load", "loads"):
                cls = "deserialize"
            if cls:
                # Importing the dangerous name IS acquiring the capability; also
                # track the local alias so a later bare call is attributed too.
                self._add(cls)
                self.aliases[local] = cls
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        if isinstance(f, ast.Name):
            nm = f.id
            if nm in ("eval", "exec", "compile"):
                self._add("dynamic_code")
            elif nm == "getattr":
                # getattr(x, "CONST") is static attribute access (== x.CONST); a
                # single string-literal name is not dynamic. Flag any other form
                # (variable/expression/concatenated name, or too few args to
                # verify) -- fail toward flagging. Literal names are resolved
                # through the same attribute taxonomy as x.CONST, so dangerous
                # static equivalents like getattr(os, "system") still classify.
                name_arg = node.args[1] if len(node.args) >= 2 else None
                if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                    self._add(self._literal_getattr_class(node.args[0], name_arg.value))
                else:
                    self._add("dynamic_code")
            elif nm == "__import__":
                self._add("dynamic_import")
            elif nm == "open" and self._open_is_write(node):
                self._add("fs_write")
            elif nm in self.aliases:
                self._add(self.aliases[nm])
        elif isinstance(f, ast.Attribute):
            self._add(self._attr_class(f))
        for kw in node.keywords:
            if (kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                self._add("process")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _AUTHORITY_NAMES:
            self._add("authority_grant")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in _AUTHORITY_NAMES:
            self._add("authority_grant")
        elif node.id == "__builtins__":
            self._add("dynamic_code")
        self.generic_visit(node)

    @staticmethod
    def _literal_getattr_class(value: ast.expr, attr: str) -> str | None:
        return _CapVisitor._attr_class(ast.Attribute(value=value, attr=attr))

    @staticmethod
    def _attr_class(f: ast.Attribute) -> str | None:
        attr = f.attr
        if attr in ("write_text", "write_bytes"):
            return "fs_write"
        root = f.value.id if isinstance(f.value, ast.Name) else None
        if root is None:
            return None
        if root == "os":
            if attr in ("system", "popen") or attr.startswith(("exec", "spawn")):
                return "process"
            if attr in _OS_FS_ATTRS:
                return "fs_write"
        if root in ("subprocess", "multiprocessing"):
            return "process"
        if root == "pty" and attr == "spawn":
            return "process"
        if root == "shutil" and (attr in ("rmtree", "move") or attr.startswith("copy")):
            return "fs_write"
        if root in ("pickle", "marshal") and attr in ("load", "loads"):
            return "deserialize"
        if root == "codecs" and attr == "decode":
            return "dynamic_code"
        if root == "base64":
            return "dynamic_code"
        if root in ("builtins", "__builtins__") and attr in ("eval", "exec", "compile"):
            return "dynamic_code"
        if root in _NETWORK_ROOTS:
            return "network"
        return None

    @staticmethod
    def _open_is_write(node: ast.Call) -> bool:
        mode = None
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        return isinstance(mode, str) and any(c in mode for c in "wax+")


def _ast_classes(source: str) -> set[str]:
    """AST-detected classes for a source string; ``set()`` if it doesn't parse
    (a partial diff fragment) — the regex screen still covers that case."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    v = _CapVisitor()
    v.visit(tree)
    return v.found


def classes_in_source(source: str) -> frozenset[str]:
    """Capability classes in a (whole or partial) source string — the UNION of a
    structural AST walk (robust to import-aliasing / ``getattr`` obfuscation /
    attribute calls) and the regex line scan. Union, so detection only ever gets
    STRICTER; the AST pass no-ops on an unparseable fragment and the regex covers
    it. This is what the differential and the screen should use when they have a
    source string rather than a bare line list."""
    return frozenset(_ast_classes(source) | set(classes_in((source or "").splitlines())))


def _added_lines(patch: str) -> list[str]:
    return [ln[1:] for ln in (patch or "").splitlines()
            if ln.startswith("+") and not ln.startswith("+++")]


def _grant(principal: str, classes: Iterable[str]) -> Capability:
    """A capability whose allow-list is exactly ``classes`` (plus the anchor so
    it is never the empty 'all' set). ``permits(cls)`` is then True iff the grant
    'has' that class."""
    return Capability(principal=principal,
                      allow_tools=frozenset(set(classes) | {_ANCHOR}))


def capability_delta(
    patch: str,
    *,
    baseline_files: dict[str, str] | None = None,
    principal: str = "self_modify",
) -> tuple[Capability, Capability, tuple[str, ...]]:
    """Compute ``(before, after, probe_tools)`` for a patch's non-escalation
    EVIDENCE (not a proof — see the module docstring on the regex limitation).

    ``before`` permits the capability classes the baseline already uses;
    ``after`` permits those plus any class the patch's added lines introduce.
    Probing every class in :data:`CAPABILITY_CLASSES`, the governed gate reports
    escalation iff ``after`` permits a class ``before`` did not — i.e. the patch
    introduces a *new* capability class.

    ``baseline_files`` maps repo-relative path -> full current source for the
    touched files (from the Phase-2 materialized baseline tree); when given, the
    differential is real (a class already used elsewhere in the file is not a new
    grant). WITHOUT it the baseline is **empty** — every capability class the
    added lines introduce counts as new. Deriving the baseline from the patch's
    own context lines was unsafe: an unchanged context line mentioning e.g.
    ``allowlist``/``grant`` would seed that class into ``before`` and NEUTRALISE
    detection of a genuinely-added grant. Empty-baseline is fail-closed (any
    added construct widens); pass ``baseline_files`` to earn the differential."""
    # AST-aware detection on coherent source (the joined added block often parses;
    # baseline files always do), falling back to the regex within classes_in_source.
    added = classes_in_source("\n".join(_added_lines(patch)))
    base = classes_in_source(
        "\n".join(str(src) for src in (baseline_files or {}).values()))
    after = base | added
    return _grant(principal, base), _grant(principal, after), CAPABILITY_CLASSES


def widens(patch: str, *, baseline_files: dict[str, str] | None = None) -> tuple[bool, list[str]]:
    """Convenience: ``(widened, new_classes)`` computed via the algebra. True iff
    the patch introduces a capability class absent from the baseline."""
    before, after, probe = capability_delta(patch, baseline_files=baseline_files)
    new = sorted(c for c in probe if after.permits(c) and not before.permits(c))
    return bool(new), new


# Human-readable label per capability class — the single source the syntactic
# screen (self_modify.capability_diff) also reports from, so the two detectors
# can never drift apart.
_CLASS_DESC: dict[str, str] = {
    "process": "process spawn",
    "network": "network client",
    "dynamic_code": "dynamic code execution",
    "fs_write": "filesystem write",
    "dynamic_import": "dynamic import",
    "native_ffi": "native FFI",
    "deserialize": "deserialization",
    "authority_grant": "authority / tool grant",
}


def describe_classes(classes: Iterable[str]) -> list[str]:
    """Sorted human labels for a set of capability classes."""
    return [_CLASS_DESC.get(c, c) for c in sorted(set(classes))]


__all__ = [
    "CAPABILITY_CLASSES", "classes_in", "classes_in_source",
    "capability_delta", "widens", "describe_classes",
]
