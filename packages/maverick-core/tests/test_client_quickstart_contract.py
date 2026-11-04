"""Client quickstarts must match the MCP server's real tool surface.

docs/clients/{typescript,go,rust}-quickstart.md are the cross-language examples
for driving Lightwork over MCP. They're only "runnable" if the tools they call
actually exist with the documented names/args. If anyone renames, removes, or
adds a tool in maverick_mcp.server.TOOLS, these fail so the docs get updated
instead of silently shipping a copy-paste example that calls a missing tool.

This is the language-agnostic "tested" half of the client bindings: it runs in
the Python CI (introspecting the server) without needing Node/Go/Rust toolchains.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from maverick_mcp.server import TOOLS

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TOOL_NAMES = {t["name"] for t in TOOLS}
_QUICKSTARTS = ("typescript", "go", "rust", "java", "csharp")
_CLIENT_SOURCE_SUFFIXES = {
    ".cs",
    ".csproj",
    ".go",
    ".java",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".mod",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".xml",
    ".yaml",
    ".yml",
}
_CLIENT_IGNORED_DIRS = {"bin", "node_modules", "obj", "target"}
_TOOL_COUNT_CLAIM = re.compile(
    r"(?<![\w])(?P<count>\d+)\+?\s+"
    r"(?:(?:[`*_]*[A-Za-z][\w*-]*[`*_]*)\s+){0,3}"
    r"tools?\b",
    flags=re.IGNORECASE,
)


def _doc(lang: str) -> str:
    p = _REPO_ROOT / "docs" / "clients" / f"{lang}-quickstart.md"
    assert p.exists(), f"missing docs/clients/{lang}-quickstart.md"
    return p.read_text(encoding="utf-8")


def test_quickstarts_only_reference_real_tools():
    """No quickstart may reference a maverick_* tool the server doesn't expose."""
    for lang in _QUICKSTARTS:
        referenced = set(re.findall(r"\bmaverick_[a-z_]+\b", _doc(lang)))
        missing = referenced - _TOOL_NAMES
        assert not missing, f"{lang}-quickstart.md calls unknown MCP tools: {sorted(missing)}"


def test_typescript_quickstart_documents_every_tool():
    """The TS quickstart is the canonical surface doc -> it must name every
    tool, so adding one to the server forces a doc update."""
    text = _doc("typescript")
    undocumented = sorted(n for n in _TOOL_NAMES if n not in text)
    assert not undocumented, f"typescript-quickstart.md omits MCP tools: {undocumented}"


def _client_contract_sources():
    for root in (
        _REPO_ROOT / "docs" / "clients",
        _REPO_ROOT / "examples" / "clients",
    ):
        for path in sorted(root.rglob("*")):
            if (
                path.is_file()
                and path.suffix.lower() in _CLIENT_SOURCE_SUFFIXES
                and _CLIENT_IGNORED_DIRS.isdisjoint(
                    part.lower() for part in path.parts
                )
            ):
                yield path


def test_every_numeric_client_tool_count_matches_registry():
    """Find every literal client tool-count claim, not just one blessed line."""
    claims: list[tuple[Path, int, int, str]] = []
    for path in _client_contract_sources():
        text = path.read_text(encoding="utf-8")
        for match in _TOOL_COUNT_CLAIM.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            claims.append((
                path.relative_to(_REPO_ROOT),
                line,
                int(match.group("count")),
                " ".join(match.group(0).split()),
            ))

    assert claims, "no numeric MCP tool-count claim was found in client docs/examples"
    drift = [
        f"{path}:{line}: {claim!r} says {count}; registry has {len(TOOLS)}"
        for path, line, count, claim in claims
        if count != len(TOOLS)
    ]
    assert not drift, "client tool-count drift:\n" + "\n".join(drift)


def _documented_structured_shapes(text: str) -> dict[str, tuple[str, ...]]:
    marker = "## Typed results (`structuredContent`)"
    assert marker in text
    section = text.split(marker, 1)[1].split("\n## ", 1)[0]
    documented: dict[str, tuple[str, ...]] = {}
    for line in section.splitlines():
        if not line.startswith("|") or "`maverick_" not in line:
            continue
        cells = line.split("|")
        assert len(cells) >= 4, f"malformed structuredContent table row: {line}"
        names = re.findall(r"`(maverick_[a-z_]+)`", cells[1])
        fields = tuple(
            re.findall(r"\b([a-z][a-z0-9_]*\??)(?=[,\s}])", cells[2])
        )
        assert names and fields, f"malformed structuredContent table row: {line}"
        for name in names:
            assert name not in documented, f"duplicate structuredContent row for {name}"
            documented[name] = fields
    return documented


def test_typescript_structured_content_table_matches_registry():
    """The canonical table must be an exact projection of each outputSchema."""
    documented = _documented_structured_shapes(_doc("typescript"))
    expected: dict[str, tuple[str, ...]] = {}
    for tool in TOOLS:
        schema = tool["outputSchema"]
        required = set(schema.get("required", ()))
        expected[tool["name"]] = tuple(
            name if name in required else f"{name}?"
            for name in schema.get("properties", {})
        )
    assert documented == expected


def test_maverick_start_documented_args_are_real():
    """The TS example calls maverick_start with title/description/max_dollars;
    those must be real input properties or the example won't work."""
    start = next(t for t in TOOLS if t["name"] == "maverick_start")
    props = set((start.get("inputSchema") or {}).get("properties", {}))
    for arg in ("title", "description", "max_dollars"):
        assert arg in props, f"maverick_start schema is missing documented arg '{arg}'"


def _typescript_allowlist(source: str) -> tuple[str, ...]:
    match = re.search(
        r"(?:export\s+)?const\s+LIGHTWORK_MCP_ENV_ALLOWLIST\s*=\s*"
        r"\[(.*?)\]\s+as const;",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    names = tuple(re.findall(r'"([A-Za-z0-9_()]+)"', match.group(1)))
    assert names
    assert len(names) == len(set(names))
    return names


def test_typescript_client_forwards_only_reviewed_lightwork_environment():
    """Docs and executable code share one exact provider/runtime contract."""
    client_root = _REPO_ROOT / "examples" / "clients" / "typescript"
    helper = (client_root / "environment.ts").read_text(encoding="utf-8")
    client = (client_root / "client.ts").read_text(encoding="utf-8")
    docs = _doc("typescript")
    allowlist = set(_typescript_allowlist(helper))

    assert 'reviewedName.startsWith("MAVERICK_")' in helper
    assert 'reviewedName.startsWith("LIGHTWORK_")' in helper
    assert "platform: string = process.platform" in helper
    assert 'platform === "win32"' in helper
    assert "name.toUpperCase()" in helper
    assert 'name.endsWith("_API_KEY")' not in helper
    assert "selectLightworkMcpEnvironment(process.env)" in client
    assert "env: serverEnv" in client
    assert "env: process.env" not in client
    assert "../../examples/clients/typescript/environment.ts" in docs
    assert 'from "./environment.js"' in docs
    assert "selectLightworkMcpEnvironment(process.env)" in docs
    assert "env: serverEnv" in docs
    assert "env: process.env" not in docs
    assert "const LIGHTWORK_MCP_ENV_ALLOWLIST" not in docs

    from maverick.config import (
        PROVIDER_BASE_URL_ENV_VARS,
        PROVIDER_CREDENTIAL_ENV_VARS,
    )

    assert set(PROVIDER_CREDENTIAL_ENV_VARS) <= allowlist
    assert set(PROVIDER_BASE_URL_ENV_VARS) <= allowlist

    provider_env_reads: set[str] = set()
    for provider in (
        _REPO_ROOT / "packages" / "maverick-core" / "maverick" / "providers"
    ).glob("*.py"):
        provider_env_reads.update(
            re.findall(
                r'os\.environ\.get\(\s*"([A-Za-z0-9_]+)"',
                provider.read_text(encoding="utf-8"),
            )
        )
    assert {
        name for name in provider_env_reads if not name.startswith("MAVERICK_")
    } <= allowlist

    azure_identity_inputs = {
        "AZURE_AUTHORITY_HOST",
        "AZURE_CLIENT_CERTIFICATE_PASSWORD",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN",
        "AZURE_FEDERATED_TOKEN_FILE",
        "AZURE_IDENTITY_DISABLE_MULTITENANTAUTH",
        "AZURE_KUBERNETES_CA_DATA",
        "AZURE_KUBERNETES_CA_FILE",
        "AZURE_KUBERNETES_SNI_NAME",
        "AZURE_KUBERNETES_TOKEN_PROXY",
        "AZURE_PASSWORD",
        "AZURE_POD_IDENTITY_AUTHORITY_HOST",
        "AZURE_REGIONAL_AUTHORITY_NAME",
        "AZURE_TENANT_ID",
        "AZURE_TOKEN_CREDENTIALS",
        "AZURE_USERNAME",
        "IDENTITY_ENDPOINT",
        "IDENTITY_HEADER",
        "IDENTITY_SERVER_THUMBPRINT",
        "IMDS_ENDPOINT",
        "MSI_ENDPOINT",
        "MSI_SECRET",
    }
    provider_endpoints_and_auth = {
        "ANTHROPIC_BASE_URL",
        "AZURE_OPENAI_AUTH",
        "AZURE_OPENAI_DEPLOYMENT",
        "AZURE_OPENAI_ENDPOINT",
        "BEDROCK_MODEL_ID",
        "CODEX_ACCESS_TOKEN",
        "CODEX_HOME",
        "DEEPSEEK_BASE_URL",
        "MOONSHOT_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_COMPATIBLE_BASE_URL",
        "TGI_BASE_URL",
        "VLLM_BASE_URL",
        "XAI_BASE_URL",
    }
    proxy_and_ca = {
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
    safe_runtime = {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LOCALAPPDATA",
        "PATH",
        "SHELL",
        "SYSTEMROOT",
        "TEMP",
        "TMPDIR",
        "USER",
        "USERNAME",
        "USERPROFILE",
    }
    assert (
        azure_identity_inputs
        | provider_endpoints_and_auth
        | proxy_and_ca
        | safe_runtime
    ) <= allowlist
    assert {
        "GITHUB_TOKEN",
        "LD_PRELOAD",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "STRIPE_API_KEY",
    }.isdisjoint(allowlist)


def test_typescript_client_dependency_and_ci_security_gates():
    """Keep the reviewed SDK floor/overrides and audit gate from regressing."""
    client_root = _REPO_ROOT / "examples" / "clients" / "typescript"
    package = json.loads((client_root / "package.json").read_text(encoding="utf-8"))
    # 1.31.0 fixes GHSA-6qxp-vccf-f47h (OAuth client credentials sent to an
    # unvalidated authorization server); the lock resolves 1.32.1.
    assert package["dependencies"]["@modelcontextprotocol/sdk"] == "^1.32.1"
    assert package["devDependencies"]["@types/node"] == "22.20.1"
    assert "environment.test.ts" in package["scripts"]["test:environment"]
    assert "tsc --noEmit --strict" in package["scripts"]["typecheck"]
    # Reviewed patched versions of vulnerable transitive dependencies.
    assert package["overrides"] == {
        "@hono/node-server": "2.1.3",
        "body-parser": "2.4.0",
        "fast-uri": "3.1.9",
        "qs": "6.16.1",
        "hono": "4.13.11",
        "ip-address": "10.7.4",
        "zod": "4.6.6",
    }

    lock = json.loads((client_root / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["packages"]["node_modules/@modelcontextprotocol/sdk"]["version"] == "1.32.1"

    workflow = (
        _REPO_ROOT / ".github" / "workflows" / "mcp-clients.yml"
    ).read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "runs-on: ubuntu-latest" not in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 2
    assert "cancel-in-progress: true" in workflow
    assert "npm audit --audit-level=low" in workflow
    assert workflow.count("persist-credentials: false") == 2
    for packaging_tool in (
        "'pip==26.2.2'",
        "'setuptools==84.2.1'",
        "'wheel==0.48.0'",
        "'packaging==26.3'",
    ):
        assert workflow.count(packaging_tool) == 2
    assert 'go-version: "1.26.10"' in workflow
    assert "go-version-file:" not in workflow
    assert "go run -mod=readonly ." in workflow

    for client_language in ("rust", "java", "csharp"):
        client_workflow = (
            _REPO_ROOT
            / ".github"
            / "workflows"
            / f"mcp-client-{client_language}.yml"
        ).read_text(encoding="utf-8")
        assert "permissions:\n  contents: read" in client_workflow
        assert "runs-on: ubuntu-24.04" in client_workflow
        assert "ubuntu-latest" not in client_workflow
        assert "cancel-in-progress: true" in client_workflow
        assert "persist-credentials: false" in client_workflow
        assert "PIP_CONSTRAINT:" in client_workflow
        assert "scripts/verify_constraint_closure.py" in client_workflow
        for packaging_tool in (
            "'pip==26.2.2'",
            "'setuptools==84.2.1'",
            "'wheel==0.48.0'",
            "'packaging==26.3'",
        ):
            assert packaging_tool in client_workflow
    assert "cargo run --locked" in (
        _REPO_ROOT / ".github" / "workflows" / "mcp-client-rust.yml"
    ).read_text(encoding="utf-8")
    rust_lock = (
        _REPO_ROOT / "examples" / "clients" / "rust" / "Cargo.lock"
    ).read_text(encoding="utf-8")
    assert 'name = "anyhow"\nversion = "1.0.103"' in rust_lock

    csharp_root = _REPO_ROOT / "examples" / "clients" / "csharp"
    csharp_project = (
        csharp_root / "Lightwork.McpClient.Example.csproj"
    ).read_text(encoding="utf-8")
    assert "RestorePackagesWithLockFile>true" in csharp_project
    assert 'Version="[1.3.0]"' in csharp_project
    for audit_control in (
        "NuGetAudit>true",
        "NuGetAuditMode>all",
        "NuGetAuditLevel>low",
        "NU1901;NU1902;NU1903;NU1904",
    ):
        assert audit_control in csharp_project
    csharp_lock = json.loads(
        (csharp_root / "packages.lock.json").read_text(encoding="utf-8")
    )
    sdk_lock = csharp_lock["dependencies"]["net8.0"]["ModelContextProtocol"]
    assert sdk_lock["requested"] == "[1.3.0, 1.3.0]"
    assert sdk_lock["resolved"] == "1.3.0"

    csharp_workflow = (
        _REPO_ROOT / ".github" / "workflows" / "mcp-client-csharp.yml"
    ).read_text(encoding="utf-8")
    assert 'dotnet-version: "8.0.423"' in csharp_workflow
    assert "dotnet restore --locked-mode" in csharp_workflow
    assert "dotnet run --no-restore" in csharp_workflow
