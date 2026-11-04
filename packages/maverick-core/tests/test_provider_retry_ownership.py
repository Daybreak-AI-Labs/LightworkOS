"""Every provider SDK transport has one explicit Lightwork attempt policy."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from maverick.providers.azure_openai_provider import AzureOpenAIClient
from maverick.providers.openai_provider import OpenAIClient

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CLIENT_CONSTRUCTORS = frozenset({
    "Anthropic",
    "AsyncAnthropic",
    "OpenAI",
    "AsyncOpenAI",
    "AzureOpenAI",
    "AsyncAzureOpenAI",
})
_SOURCE_ROOTS = (
    "apps",
    "benchmarks",
    "demo",
    "examples",
    "packages",
    "proof",
    "scripts",
)

_OUTER_BOUNDED_RETRY = "outer_bounded_retry"
_INTENTIONAL_ONE_SHOT = "intentional_one_shot"

# Every production SDK client belongs to exactly one reviewed attempt policy.
# Provider implementations delegate retryable non-streaming completions to
# maverick.retry. Direct SDK operations deliberately make one transport attempt
# per declared model/turn/backend: key validation and health checks must report
# current reachability, benchmark baselines must preserve exact treatment/cost,
# token metering is caller-repeatable, and voice already falls through to the
# next configured backend.
_RETRY_OWNERSHIP = {
    (
        "packages/maverick-core/maverick/providers/anthropic_provider.py",
        "AnthropicClient.__init__",
        "Anthropic",
    ): _OUTER_BOUNDED_RETRY,
    (
        "packages/maverick-core/maverick/providers/anthropic_provider.py",
        "AnthropicClient.__init__",
        "AsyncAnthropic",
    ): _OUTER_BOUNDED_RETRY,
    (
        "packages/maverick-core/maverick/providers/openai_provider.py",
        "OpenAIClient.__init__",
        "OpenAI",
    ): _OUTER_BOUNDED_RETRY,
    (
        "packages/maverick-core/maverick/providers/openai_provider.py",
        "OpenAIClient.__init__",
        "AsyncOpenAI",
    ): _OUTER_BOUNDED_RETRY,
    (
        "packages/maverick-core/maverick/providers/azure_openai_provider.py",
        "AzureOpenAIClient.__init__",
        "AzureOpenAI",
    ): _OUTER_BOUNDED_RETRY,
    (
        "packages/maverick-core/maverick/providers/azure_openai_provider.py",
        "AzureOpenAIClient.__init__",
        "AsyncAzureOpenAI",
    ): _OUTER_BOUNDED_RETRY,
    (
        "apps/installer-cli/maverick_installer/wizard/__init__.py",
        "_validate_anthropic_key",
        "Anthropic",
    ): _INTENTIONAL_ONE_SHOT,
    (
        "apps/installer-cli/maverick_installer/wizard/__init__.py",
        "_validate_openai_key",
        "OpenAI",
    ): _INTENTIONAL_ONE_SHOT,
    (
        "apps/installer-cli/maverick_installer/wizard/__init__.py",
        "_validate_openai_compat_key",
        "OpenAI",
    ): _INTENTIONAL_ONE_SHOT,
    # codec_probe.anthropic_counter now counts through the LLM's configured
    # dispatch client (417d9da9) instead of constructing its own Anthropic().
    (
        "packages/maverick-core/maverick/health.py",
        "_check_anthropic",
        "Anthropic",
    ): _INTENTIONAL_ONE_SHOT,
    (
        "packages/maverick-core/maverick/health.py",
        "_check_openai",
        "OpenAI",
    ): _INTENTIONAL_ONE_SHOT,
    (
        "packages/maverick-core/maverick/tools/voice.py",
        "_whisper_openai",
        "OpenAI",
    ): _INTENTIONAL_ONE_SHOT,
    (
        "packages/maverick-core/maverick/tools/voice.py",
        "_whisper_groq",
        "OpenAI",
    ): _INTENTIONAL_ONE_SHOT,
    (
        "packages/maverick-core/maverick/tools/voice.py",
        "_tts_openai",
        "OpenAI",
    ): _INTENTIONAL_ONE_SHOT,
}


class _CaptureClient:
    calls: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


class _ProviderClientVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.scope: list[str] = []
        self.calls: list[tuple[Path, str, str, ast.Call]] = []

    def _visit_scope(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._visit_scope(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_scope(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        function = node.func
        name = (
            function.id if isinstance(function, ast.Name)
            else function.attr if isinstance(function, ast.Attribute)
            else ""
        )
        if name in _CLIENT_CONSTRUCTORS:
            self.calls.append((self.path, ".".join(self.scope), name, node))
        self.generic_visit(node)


def _provider_client_calls() -> list[tuple[Path, str, str, ast.Call]]:
    calls: list[tuple[Path, str, str, ast.Call]] = []
    for relative_root in _SOURCE_ROOTS:
        source_root = _REPO_ROOT / relative_root
        if not source_root.exists():
            continue
        for path in source_root.rglob("*.py"):
            relative = path.relative_to(_REPO_ROOT)
            if "tests" in relative.parts or path.name.startswith("test_"):
                continue
            # Wheel builds leave copies of package modules under build/lib.
            # They are generated artifacts, not additional provider transports.
            if (relative.parts[0] in {"apps", "packages"}
                    and relative.parts[2:4] == ("build", "lib")):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(relative))
            visitor = _ProviderClientVisitor(relative)
            visitor.visit(tree)
            calls.extend(visitor.calls)
    return calls


def test_provider_scan_keeps_source_and_ignores_generated_wheel_copy(tmp_path, monkeypatch):
    source = tmp_path / "packages" / "example" / "example" / "provider.py"
    generated = tmp_path / "packages" / "example" / "build" / "lib" / "example" / "provider.py"
    for path in (source, generated):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("client = OpenAI(max_retries=0)\n", encoding="utf-8")
    monkeypatch.setattr(f"{__name__}._REPO_ROOT", tmp_path)
    calls = _provider_client_calls()
    assert [(path.as_posix(), constructor) for path, _, constructor, _ in calls] == [
        ("packages/example/example/provider.py", "OpenAI")
    ]


def _call_names_in_scope(relative: str, scope: str) -> set[str]:
    path = _REPO_ROOT / relative
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    found: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.scope: list[str] = []

        def _visit_scope(
            self,
            node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
        ) -> None:
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
            self._visit_scope(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            self._visit_scope(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
            self._visit_scope(node)

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            if ".".join(self.scope) == scope:
                function = node.func
                name = (
                    function.id if isinstance(function, ast.Name)
                    else function.attr if isinstance(function, ast.Attribute)
                    else ""
                )
                if name:
                    found.add(name)
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def test_all_provider_clients_have_a_reviewed_attempt_policy() -> None:
    actual = {
        (path.as_posix(), scope, constructor)
        for path, scope, constructor, _call in _provider_client_calls()
    }
    expected = set(_RETRY_OWNERSHIP)

    assert actual == expected, (
        "provider-client retry ownership changed without review; "
        f"unclassified={sorted(actual - expected)}, stale={sorted(expected - actual)}"
    )
    assert set(_RETRY_OWNERSHIP.values()) == {
        _OUTER_BOUNDED_RETRY,
        _INTENTIONAL_ONE_SHOT,
    }


@pytest.mark.parametrize(
    ("relative", "scope", "retry_call"),
    [
        (
            "packages/maverick-core/maverick/providers/openai_provider.py",
            "OpenAIClient.complete",
            "sync_retry",
        ),
        (
            "packages/maverick-core/maverick/providers/openai_provider.py",
            "OpenAIClient.complete_async",
            "async_retry",
        ),
        (
            "packages/maverick-core/maverick/providers/anthropic_provider.py",
            "AnthropicClient.complete",
            "sync_retry",
        ),
        (
            "packages/maverick-core/maverick/providers/anthropic_provider.py",
            "AnthropicClient.complete_async",
            "async_retry",
        ),
    ],
)
def test_outer_bounded_retry_entrypoints_remain_wrapped(
    relative: str,
    scope: str,
    retry_call: str,
) -> None:
    assert retry_call in _call_names_in_scope(relative, scope)


def test_azure_clients_inherit_the_openai_bounded_retry_entrypoints() -> None:
    relative = "packages/maverick-core/maverick/providers/azure_openai_provider.py"
    tree = ast.parse((_REPO_ROOT / relative).read_text(encoding="utf-8"))
    azure = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "AzureOpenAIClient"
    )
    base_names = {
        base.id for base in azure.bases if isinstance(base, ast.Name)
    }
    overridden = {
        node.name
        for node in azure.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "OpenAIClient" in base_names
    assert overridden.isdisjoint({"complete", "complete_async"})


def test_all_lightwork_created_provider_clients_disable_sdk_retries() -> None:
    missing: list[str] = []
    calls = _provider_client_calls()
    for path, scope, constructor, call in calls:
        retry_keyword = next(
            (keyword for keyword in call.keywords if keyword.arg == "max_retries"),
            None,
        )
        if (
            retry_keyword is None
            or not isinstance(retry_keyword.value, ast.Constant)
            or retry_keyword.value.value != 0
        ):
            key = (path.as_posix(), scope, constructor)
            ownership = _RETRY_OWNERSHIP.get(key, "unclassified")
            missing.append(f"{path}:{call.lineno} ({ownership})")

    assert calls, "provider-client source scan unexpectedly found no constructors"
    assert missing == [], (
        "provider SDK retries must be disabled: provider wrappers use the "
        "outer_bounded_retry policy, while direct diagnostics/baselines use "
        "the intentional_one_shot policy; missing max_retries=0 at "
        f"{missing}"
    )


def test_openai_clients_use_sdk_timeout_and_disable_sdk_retries(monkeypatch) -> None:
    openai = pytest.importorskip("openai")
    _CaptureClient.calls.clear()
    monkeypatch.setenv("MAVERICK_LLM_CONNECT_TIMEOUT", "7")
    monkeypatch.setenv("MAVERICK_LLM_READ_TIMEOUT", "31")
    monkeypatch.setattr(openai, "OpenAI", _CaptureClient)
    monkeypatch.setattr(openai, "AsyncOpenAI", _CaptureClient)

    OpenAIClient(api_key="test-key")  # pragma: allowlist secret

    assert len(_CaptureClient.calls) == 2
    for kwargs in _CaptureClient.calls:
        assert kwargs["max_retries"] == 0
        timeout = kwargs["timeout"]
        assert isinstance(timeout, openai.Timeout)
        assert timeout.connect == 7.0
        assert timeout.read == 31.0
        assert timeout.write == 31.0
        assert timeout.pool == 31.0


def test_azure_clients_use_sdk_timeout_and_disable_sdk_retries(monkeypatch) -> None:
    openai = pytest.importorskip("openai")
    _CaptureClient.calls.clear()
    monkeypatch.setenv("MAVERICK_LLM_CONNECT_TIMEOUT", "5")
    monkeypatch.setenv("MAVERICK_LLM_READ_TIMEOUT", "29")
    monkeypatch.setattr(openai, "AzureOpenAI", _CaptureClient)
    monkeypatch.setattr(openai, "AsyncAzureOpenAI", _CaptureClient)
    environment = {
        "AZURE_OPENAI_AUTH": "api_key",
        "AZURE_OPENAI_DEPLOYMENT": "governed-deployment",
        "AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com",
        "MAVERICK_LLM_CONNECT_TIMEOUT": "5",
        "MAVERICK_LLM_READ_TIMEOUT": "29",
    }
    monkeypatch.setenv("MAVERICK_LLM_CONNECT_TIMEOUT", "91")
    monkeypatch.setenv("MAVERICK_LLM_READ_TIMEOUT", "92")

    AzureOpenAIClient(
        api_key="test-key",  # pragma: allowlist secret
        environment=environment,
    )

    assert len(_CaptureClient.calls) == 2
    for kwargs in _CaptureClient.calls:
        assert kwargs["max_retries"] == 0
        timeout = kwargs["timeout"]
        assert isinstance(timeout, openai.Timeout)
        assert timeout.connect == 5.0
        assert timeout.read == 29.0
        assert timeout.write == 29.0
        assert timeout.pool == 29.0
