from __future__ import annotations

import ast
import contextlib
import gc
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest


def _closing_connect(path: Path) -> sqlite3.Connection:
    from maverick.sqlite_closing import ClosingConnection

    return sqlite3.connect(path, timeout=5.0, factory=ClosingConnection)


def _create_table(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE t(a INTEGER)")
        connection.commit()
    finally:
        connection.close()


def _values(path: Path) -> list[tuple]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute("SELECT a FROM t ORDER BY a").fetchall()
    finally:
        connection.close()


def test_with_block_commits_on_success_and_leaves_connection_closed(tmp_path: Path) -> None:
    path = tmp_path / "store.sqlite3"
    _create_table(path)
    with _closing_connect(path) as connection:
        connection.execute("INSERT INTO t VALUES (1)")
    assert _values(path) == [(1,)]
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_with_block_rolls_back_propagates_exception_and_leaves_connection_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "store.sqlite3"
    _create_table(path)
    with pytest.raises(ValueError, match="boom"):
        with _closing_connect(path) as connection:
            connection.execute("INSERT INTO t VALUES (2)")
            raise ValueError("boom")
    assert _values(path) == []
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


@contextlib.contextmanager
def _gc_disabled() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _record_connections(store: object, monkeypatch: pytest.MonkeyPatch) -> list[sqlite3.Connection]:
    opened: list[sqlite3.Connection] = []
    original = store._connect

    def connect() -> sqlite3.Connection:
        connection = original()
        opened.append(connection)
        return connection

    monkeypatch.setattr(store, "_connect", connect)
    return opened


def test_third_party_intelligence_connection_closes_when_its_block_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maverick import third_party_intelligence

    store = third_party_intelligence.ThirdPartyIntelligenceStore(
        tmp_path / "third-party.sqlite3", config_gate=lambda: None
    )
    opened = _record_connections(store, monkeypatch)
    with _gc_disabled():
        assert store.list_sources("tenant-a") == ()
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")


def test_governance_agents_connection_closes_when_its_block_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maverick import governance_agents

    store = governance_agents.GovernanceAgentStore(
        tmp_path / "governance-agents.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: "operator-a",
    )
    opened = _record_connections(store, monkeypatch)
    with _gc_disabled():
        assert store.list_policies("tenant-a") == ()
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")


# Ratchet scope, by design: helpers named _connect, _conn or _connection, in packages/*/maverick*/
# (apps/ and tests are not scanned). Followed: sqlite3 imported under an alias, sqlite3.connect
# imported under any name, lambda helpers, and one level of same-class self.method() delegation.
# Not followed, so not checked: helpers with other names (_open_store, _sqlite_conn,
# _connect_index), delegation deeper than one call, connections returned by module-level
# functions, and dynamic imports or getattr on sqlite3.
CONNECT_HELPERS = frozenset({"_connect", "_conn", "_connection"})
REPO_ROOT = Path(__file__).resolve().parents[3]

# Ratchet exemptions. Each key is "path::Scope.helper" and carries the exact count of unclosed
# sqlite3.connect calls in that helper, so a second leaking connection in an exempt helper fails
# too. An entry is deleted when its helper stops leaking. A new leaking helper anywhere fails.

# Rule 1: close-on-exit would break a use the module already makes. Nothing else goes here.
RULE_1_UNCHANGED = {
    "packages/maverick-core/maverick/federation.py::_FederationState._connect": (
        1,
        "one thread-local connection is cached and returned to every later call, so closing it "
        "on with-exit would hand the next caller a closed connection; close_cached_connections() "
        "and hold_state_file_closed() are the explicit releases, used at exit for the calling "
        "thread and around every restore, purge and erasure that replaces the file",
    ),
    "packages/maverick-core/maverick/entity_graph.py::_connect": (
        1,
        "every caller closes the connection in a finally block; rebuild() runs `with conn:` and "
        "then reads conn again after that block, so closing on with-exit would make those reads "
        "fail",
    ),
}

# Pre-existing, outside the 42-module factory group of this change. These leaks are out of scope
# here and are not rule-1 exemptions. They are pinned only so they cannot grow, and each entry is
# deleted when its owner converts or removes the helper.
_CLOSED_AT_EVERY_WITH_SITE = (
    "every with-site closes the connection through contextlib.closing (or the module's sqlite-only "
    "closing helper), so nothing leaks; the helper itself is not converted"
)
OUT_OF_SCOPE_BASELINE = {
    "packages/maverick-core/maverick/administration_document_access.py::DocumentAccessStore._connect": (
        1, _CLOSED_AT_EVERY_WITH_SITE,
    ),
    "packages/maverick-core/maverick/ai_discovery_sensor_agents.py::DiscoverySensorSpool._connect": (
        1,
        "its one caller closes the connection in a finally block, so nothing leaks; not converted "
        "here",
    ),
    "packages/maverick-core/maverick/comments.py::_connect": (
        1,
        "all seven call sites wrap the connection in contextlib.closing, so nothing leaks; not "
        "converted here",
    ),
    "packages/maverick-core/maverick/consent_web_publish_settings.py::WebPublishSettingsStore._connect": (
        1, _CLOSED_AT_EVERY_WITH_SITE,
    ),
    "packages/maverick-core/maverick/customer_sandbox_lifecycle.py::CustomerSandboxLifecycleStore._connect": (
        2,
        "its only caller, _connection, closes the connection in a finally block, so nothing leaks; "
        "not converted here",
    ),
    "packages/maverick-core/maverick/finance/regulatory_change.py::RegulatoryChangeEngine._connect": (
        1,
        "all eleven call sites wrap the connection in contextlib.closing, so nothing leaks; not "
        "converted here",
    ),
    "packages/maverick-core/maverick/governed_document_vault.py::GovernedDocumentVault._connect": (
        1, _CLOSED_AT_EVERY_WITH_SITE,
    ),
    "packages/maverick-core/maverick/insight_exchange.py::_InsightReplayLedger._connect": (
        1,
        "both call sites close the connection in a finally block, so nothing leaks; not converted "
        "here",
    ),
    "packages/maverick-core/maverick/policy_suggestions.py::_connect": (
        1,
        "all six call sites wrap the connection in contextlib.closing, so nothing leaks; not "
        "converted here",
    ),
    "packages/maverick-core/maverick/provider_spend_sqlite.py::_connect": (
        1,
        "all seven call sites close the connection in a finally block, so nothing leaks; not "
        "converted here",
    ),
    "packages/maverick-core/maverick/self_harness_holdout.py::HoldoutQueryLedger._connect": (
        1,
        "each call site closes the connection in a finally block or closing(), so nothing leaks; "
        "not converted here",
    ),
    "packages/maverick-core/maverick/trust_center_branding.py::TrustCenterBrandingStore._connect": (
        1, _CLOSED_AT_EVERY_WITH_SITE,
    ),
    "packages/maverick-dashboard/maverick_dashboard/ai_evidence_analysis_composition.py::EvidenceAuthorityRegistry._connect": (
        1, _CLOSED_AT_EVERY_WITH_SITE,
    ),
}


def _sqlite_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Names this module binds to the sqlite3 module and to sqlite3.connect (aliases included)."""
    modules: set[str] = set()
    connects: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names if alias.name == "sqlite3")
        elif isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
            connects.update(alias.asname or alias.name for alias in node.names if alias.name == "connect")
    return modules, connects


def _is_sqlite_connect(call: ast.Call, modules: set[str], connects: set[str]) -> bool:
    callee = call.func
    if isinstance(callee, ast.Attribute):
        return callee.attr == "connect" and isinstance(callee.value, ast.Name) and callee.value.id in modules
    return isinstance(callee, ast.Name) and callee.id in connects


def _is_self_attribute(callee: ast.expr) -> bool:
    return isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name) and callee.value.id == "self"


def _is_managed(function: ast.AST) -> bool:
    return isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        "contextmanager" in ast.unparse(decorator) for decorator in function.decorator_list
    )


def _has_closing_factory(call: ast.Call) -> bool:
    return any(
        keyword.arg == "factory" and ast.unparse(keyword.value) == "ClosingConnection"
        for keyword in call.keywords
    )


def _connection_names(
    function: ast.AST, methods: dict[str, ast.AST], modules: set[str], connects: set[str]
) -> set[str]:
    """Names the helper assigns from sqlite3.connect or from a call to a same-class method."""
    names: set[str] = set()
    for node in ast.walk(function):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        call = node.value
        opened = _is_sqlite_connect(call, modules, connects) or (
            _is_self_attribute(call.func) and call.func.attr in methods
        )
        if opened:
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
    return names


def _closes_names(function: ast.AST, names: set[str]) -> bool:
    """True when a finally block closes one of the names, or closing() wraps one.

    A close on any other object, such as a lock file, does not count.
    """
    if not names:
        return False
    for node in ast.walk(function):
        if isinstance(node, ast.Try):
            for statement in node.finalbody:
                for call in ast.walk(statement):
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "close"
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id in names
                    ):
                        return True
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Name):
            callee = node.func
            name = callee.attr if isinstance(callee, ast.Attribute) else getattr(callee, "id", "")
            if name == "closing" and node.args[0].id in names:
                return True
    return False


def _direct_sites(function: ast.AST, modules: set[str], connects: set[str]) -> list[int]:
    return [
        call.lineno
        for call in ast.walk(function)
        if isinstance(call, ast.Call)
        and _is_sqlite_connect(call, modules, connects)
        and not _has_closing_factory(call)
    ]


def _delegates(function: ast.AST, methods: dict[str, ast.AST]) -> list[ast.AST]:
    """Same-class methods the helper calls as self.name(), excluding the helpers themselves."""
    names = {
        call.func.attr
        for call in ast.walk(function)
        if isinstance(call, ast.Call) and _is_self_attribute(call.func)
    }
    return [
        methods[name]
        for name in sorted(names)
        if name in methods and name not in CONNECT_HELPERS and methods[name] is not function
    ]


def _helper_sites(
    function: ast.AST, methods: dict[str, ast.AST], modules: set[str], connects: set[str]
) -> list[int]:
    """Lines of unclosed connect calls that the helper can hand out or leave open.

    A contextmanager helper that closes a connection it opened, directly or through a same-class
    method, is clean. Otherwise the helper's own connect calls count, plus those of each method it
    calls. Those methods are followed one level only.
    """
    names = _connection_names(function, methods, modules, connects)
    if _is_managed(function) and _closes_names(function, names):
        return []
    sites = _direct_sites(function, modules, connects)
    for delegate in _delegates(function, methods):
        sites += _helper_sites(delegate, {}, modules, connects)
    return sites


def _helpers(tree: ast.AST) -> Iterator[tuple[str, ast.AST, dict[str, ast.AST]]]:
    """Yield each connection helper as (scope name, node, methods of its class).

    A helper is a def, or a lambda assignment, named _connect, _conn or _connection. The scope
    name is dotted, such as "Store._connect".
    """

    def visit(scope: ast.AST, prefix: str, methods: dict[str, ast.AST]):
        for child in ast.iter_child_nodes(scope):
            if isinstance(child, ast.ClassDef):
                class_methods = {
                    item.name: item
                    for item in child.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                yield from visit(child, f"{prefix}{child.name}.", class_methods)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name in CONNECT_HELPERS:
                    yield f"{prefix}{child.name}", child, methods
                yield from visit(child, f"{prefix}{child.name}.", {})
            elif isinstance(child, ast.Assign) and isinstance(child.value, ast.Lambda):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id in CONNECT_HELPERS:
                        yield f"{prefix}{target.id}", child.value, methods
            else:
                yield from visit(child, prefix, methods)

    yield from visit(tree, "", {})


def _unclosed_connects(source: str) -> list[tuple[str, int]]:
    """Helpers that call sqlite3.connect without ClosingConnection and never close what they open.

    Each helper is named by its scope, so two helpers called _connect in one module are counted
    apart. A plain helper returns a connection to a with-block, so it must use the factory. A
    contextmanager helper may close in its own body instead.
    """
    tree = ast.parse(source)
    modules, connects = _sqlite_names(tree)
    found: list[tuple[str, int]] = []
    for qualified, node, methods in _helpers(tree):
        for line in sorted(set(_helper_sites(node, methods, modules, connects))):
            found.append((qualified, line))
    return found


def _repo_violations() -> dict[str, list[int]]:
    violations: dict[str, list[int]] = {}
    for path in sorted(REPO_ROOT.glob("packages/*/maverick*/**/*.py")):
        relative = path.relative_to(REPO_ROOT)
        if "tests" in relative.parts or path.name.startswith("test_"):
            continue
        for name, line in _unclosed_connects(path.read_text(encoding="utf-8")):
            violations.setdefault(f"{relative.as_posix()}::{name}", []).append(line)
    return violations


def test_ratchet_detector_flags_only_helpers_that_open_without_closing() -> None:
    leaky = "import sqlite3\nclass S:\n    def _connect(self):\n        return sqlite3.connect(self.p)\n"
    closed = leaky.replace("sqlite3.connect(self.p)", "sqlite3.connect(self.p, factory=ClosingConnection)")
    wrong_factory = leaky.replace(
        "sqlite3.connect(self.p)", "sqlite3.connect(self.p, factory=OtherClosingConnection)"
    )
    managed_closes = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        connection = sqlite3.connect(self.p)\n"
        "        try:\n            yield connection\n        finally:\n            connection.close()\n"
    )
    managed_leaks = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        yield sqlite3.connect(self.p)\n"
    )
    other_object_closed = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        connection = sqlite3.connect(self.p)\n"
        "        try:\n            yield connection\n        finally:\n            self.lock_file.close()\n"
    )
    closed_outside_finally = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        connection = sqlite3.connect(self.p)\n"
        "        yield connection\n        connection.close()\n"
    )
    closing_wrapper = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        connection = sqlite3.connect(self.p)\n"
        "        with contextlib.closing(connection):\n            yield connection\n"
    )
    plain_function = "import sqlite3\ndef open_it(p):\n    return sqlite3.connect(p)\n"
    two_classes = (
        "import sqlite3\nclass A:\n    def _connect(self):\n        return sqlite3.connect(self.p)\n"
        "class B:\n    def _connect(self):\n        return sqlite3.connect(self.p)\n"
    )
    assert _unclosed_connects(leaky) == [("S._connect", 4)]
    assert _unclosed_connects(closed) == []
    assert _unclosed_connects(wrong_factory) == [("S._connect", 4)]
    assert _unclosed_connects(managed_closes) == []
    assert _unclosed_connects(managed_leaks) == [("S._connect", 6)]
    assert _unclosed_connects(other_object_closed) == [("S._connect", 6)]
    assert _unclosed_connects(closed_outside_finally) == [("S._connect", 6)]
    assert _unclosed_connects(closing_wrapper) == []
    assert _unclosed_connects(plain_function) == []
    assert _unclosed_connects(two_classes) == [("A._connect", 4), ("B._connect", 7)]
    two_calls = (
        "import sqlite3\nclass S:\n    def _connect(self):\n        first = sqlite3.connect(self.p)\n"
        "        return sqlite3.connect(self.q)\n"
    )
    assert _unclosed_connects(two_calls) == [("S._connect", 4), ("S._connect", 5)]
    alias_module = "import sqlite3 as sq\nclass S:\n    def _connect(self):\n        return sq.connect(self.p)\n"
    from_import = (
        "from sqlite3 import connect as open_db\nclass S:\n    def _connect(self):\n"
        "        return open_db(self.p)\n"
    )
    lambda_helper = "import sqlite3\nclass S:\n    _connect = lambda self: sqlite3.connect(self.p)\n"
    delegated = (
        "import sqlite3\nclass S:\n    def _connect(self):\n        return self._open()\n"
        "    def _open(self):\n        return sqlite3.connect(self.p)\n"
    )
    delegated_closed_by_helper = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        connection = self._open()\n"
        "        try:\n            yield connection\n        finally:\n            connection.close()\n"
        "    def _open(self):\n        return sqlite3.connect(self.p)\n"
    )
    delegated_yielded = (
        "import contextlib\nimport sqlite3\nclass S:\n    @contextlib.contextmanager\n"
        "    def _connect(self):\n        yield self._open()\n"
        "    def _open(self):\n        return sqlite3.connect(self.p)\n"
    )
    helper_calls_helper = (
        "import contextlib\nimport sqlite3\nclass S:\n    def _connect(self):\n"
        "        return sqlite3.connect(self.p)\n    @contextlib.contextmanager\n"
        "    def _connection(self):\n        connection = self._connect()\n"
        "        try:\n            yield connection\n        finally:\n            connection.close()\n"
    )
    assert _unclosed_connects(alias_module) == [("S._connect", 4)]
    assert _unclosed_connects(from_import) == [("S._connect", 4)]
    assert _unclosed_connects(from_import.replace("open_db(self.p)", "open_db(self.p, factory=ClosingConnection)")) == []
    assert _unclosed_connects(lambda_helper) == [("S._connect", 3)]
    assert _unclosed_connects(delegated) == [("S._connect", 6)]
    assert _unclosed_connects(delegated_closed_by_helper) == []
    assert _unclosed_connects(delegated_yielded) == [("S._connect", 8)]
    assert _unclosed_connects(helper_calls_helper) == [("S._connect", 5)]


def test_every_connection_helper_in_the_repo_closes_its_connections() -> None:
    groups = [RULE_1_UNCHANGED, OUT_OF_SCOPE_BASELINE]
    allowed = {key: value for group in groups for key, value in group.items()}
    assert len(allowed) == sum(len(group) for group in groups), "a helper is listed twice"
    for key, (count, reason) in allowed.items():
        assert count >= 1 and reason.strip() and "\n" not in reason, key
    violations = _repo_violations()
    unexpected = {key: lines for key, lines in violations.items() if key not in allowed}
    assert not unexpected, f"connection helpers without factory=ClosingConnection: {unexpected}"
    counts = {
        key: (allowed[key][0], len(violations.get(key, [])))
        for key in allowed
        if allowed[key][0] != len(violations.get(key, []))
    }
    assert not counts, f"allowlisted helpers whose unclosed connect count changed (expected, actual): {counts}"
