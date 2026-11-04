"""Security contract for the public Lightwork composite GitHub Action."""

from __future__ import annotations

import ast
import base64
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
ACTION = REPO_ROOT / "deploy" / "github-action" / "action.yml"
SANITIZER = REPO_ROOT / "deploy" / "github-action" / "sanitize_output.py"
SECRET_REGISTRY = (
    REPO_ROOT / "deploy" / "github-action" / "secret_env_registry.py"
)
README = REPO_ROOT / "deploy" / "github-action" / "README.md"


def test_action_defaults_to_a_locked_down_container() -> None:
    text = ACTION.read_text(encoding="utf-8")

    sandbox_input = text.split("\n  sandbox:", 1)[1].split(
        "\n  allow-unsafe-local:", 1
    )[0]
    unsafe_input = text.split("\n  allow-unsafe-local:", 1)[1].split(
        "\n  anthropic-api-key:", 1
    )[0]

    assert 'default: "docker"' in sandbox_input
    assert 'default: "false"' in unsafe_input
    assert "require_container = true" in text
    assert "allow_network = false" in text
    assert "allow_root = false" in text
    assert "MAVERICK_REQUIRE_CONTAINER_BACKEND=1" in text
    assert "MAVERICK_SANDBOX_ALLOW_ROOT=0" in text
    assert "unset MAVERICK_CONFIG_OVERLAY MAVERICK_TENANT" in text

    assert 'if [ "$IN_SANDBOX" = "local" ]' in text
    assert 'IN_ALLOW_UNSAFE_LOCAL: ${{ inputs.allow-unsafe-local }}' in text
    assert "Set allow-unsafe-local=true to acknowledge this risk." in text


def test_action_never_streams_raw_agent_output_to_github() -> None:
    text = ACTION.read_text(encoding="utf-8")
    run = text.split("    - name: Run the swarm", 1)[1]

    assert "2>&1 | tee" not in run
    assert '>"$raw_file" 2>&1' in run
    assert 'sanitize_output.py" \\' in run
    assert 'rm -f -- "$raw_file"' in run
    assert '--write-secret-file-snapshot "$secret_snapshot"' in run
    assert '--secret-file-snapshot "$secret_snapshot"' in run
    # The raw capture, the native signed result, its key and the secret
    # snapshot are all discarded right after sanitization, before exposure.
    discard = 'rm -f -- "$raw_file" "$native_result" "$result_key" "$secret_snapshot"'
    assert discard in run
    assert '--run-result "$native_result"' in run and '--result-key "$result_key"' in run
    assert "::stop-commands::%s" in run
    assert 'cat -- "$out_file"' in run
    assert 'cat -- "$summary_file"' in run
    assert "--max-chars 50000" in run

    snapshot = run.index('--write-secret-file-snapshot "$secret_snapshot"')
    capture = run.index('>"$raw_file" 2>&1')
    sanitize = run.index('--input "$raw_file"')
    exposed_log = run.index('cat -- "$out_file"')
    exposed_output = run.index('result<<$result_delimiter')
    assert snapshot < capture < sanitize < run.index(discard) < exposed_log < exposed_output


def test_action_uses_the_reviewed_setup_python_release() -> None:
    text = ACTION.read_text(encoding="utf-8")
    assert (
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 "
        "# v7.0.0"
    ) in text


def test_sanitizer_tracks_every_lightwork_provider_credential() -> None:
    from maverick.config import (
        PROVIDER_CREDENTIAL_ENV_MAP,
        PROVIDER_CREDENTIAL_ENV_VARS,
    )
    from maverick.providers import KNOWN_PROVIDERS

    namespace = runpy.run_path(str(SANITIZER))
    sanitizer_names = set(namespace["SECRET_ENV_NAMES"])
    assert set(PROVIDER_CREDENTIAL_ENV_VARS) <= sanitizer_names
    # Every provider that can authenticate through an environment variable is
    # represented in the canonical map. Ollama is intentionally keyless.
    assert set(KNOWN_PROVIDERS) - {"ollama"} <= set(PROVIDER_CREDENTIAL_ENV_MAP)


def test_sanitizer_tracks_secret_bearing_azure_identity_inputs_only() -> None:
    namespace = runpy.run_path(str(SANITIZER))
    sanitizer_names = set(namespace["SECRET_ENV_NAMES"])

    assert {
        "AZURE_CLIENT_CERTIFICATE_PASSWORD",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_CLIENT_SECRET",
        "AZURE_FEDERATED_TOKEN_FILE",
        "AZURE_PASSWORD",
        "IDENTITY_HEADER",
        "MSI_SECRET",
    } <= sanitizer_names
    assert {
        "AZURE_AUTHORITY_HOST",
        "AZURE_CLIENT_ID",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_TOKEN_SCOPE",
        "AZURE_TENANT_ID",
        "AZURE_TOKEN_CREDENTIALS",
    }.isdisjoint(sanitizer_names)
    assert {
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_FEDERATED_TOKEN_FILE",
    } <= set(namespace["SECRET_FILE_ENV_NAMES"])


def test_provider_source_cannot_add_an_untracked_environment_credential() -> None:
    from maverick.config import PROVIDER_CREDENTIAL_ENV_VARS

    provider_dir = REPO_ROOT / "packages" / "maverick-core" / "maverick" / "providers"
    reads: set[str] = set()
    for source in provider_dir.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                continue
            owner = node.func.value
            if (
                isinstance(owner, ast.Attribute)
                and owner.attr == "environ"
                and isinstance(owner.value, ast.Name)
                and owner.value.id == "os"
            ):
                name = node.args[0].value
                if any(
                    marker in name
                    for marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
                ):
                    reads.add(name)

    # This is a public Azure audience/scope URI, not a bearer credential.
    non_credentials = {"AZURE_OPENAI_TOKEN_SCOPE"}
    assert reads - non_credentials <= set(PROVIDER_CREDENTIAL_ENV_VARS)


def _static_string(
    node: ast.AST,
    constants: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _environment_scan_metadata(
    tree: ast.AST,
) -> tuple[dict[str, str], set[str], set[str], set[str]]:
    constant_candidates: dict[str, set[str]] = {}
    os_aliases = {"os"}
    environ_aliases: set[str] = set()
    getenv_aliases: set[str] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "os":
                    os_aliases.add(alias.asname or alias.name)
        elif isinstance(statement, ast.ImportFrom) and statement.module == "os":
            for alias in statement.names:
                imported_as = alias.asname or alias.name
                if alias.name == "environ":
                    environ_aliases.add(imported_as)
                elif alias.name == "getenv":
                    getenv_aliases.add(imported_as)

        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(statement, ast.Assign):
            targets = statement.targets
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
            value = statement.value
        if value is None:
            continue
        resolved = _static_string(value, {})
        if resolved is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constant_candidates.setdefault(target.id, set()).add(resolved)
    constants = {
        name: next(iter(values))
        for name, values in constant_candidates.items()
        if len(values) == 1
    }
    return constants, os_aliases, environ_aliases, getenv_aliases


def _is_name(node: ast.AST, names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in names


def _is_os_environ(node: ast.AST, os_aliases: set[str]) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and _is_name(node.value, os_aliases)
    )


def _environment_argument(
    node: ast.AST,
    *,
    os_aliases: set[str],
    environ_aliases: set[str],
    getenv_aliases: set[str],
) -> ast.AST | None:
    if isinstance(node, ast.Call) and node.args:
        function = node.func
        if isinstance(function, ast.Name):
            if function.id in getenv_aliases or function.id == "get_secret":
                return node.args[0]
            return None
        if not isinstance(function, ast.Attribute):
            return None
        if function.attr == "get_secret":
            return node.args[0]
        if function.attr == "getenv" and _is_name(
            function.value, os_aliases
        ):
            return node.args[0]
        if function.attr in {"get", "pop", "setdefault"} and (
            _is_os_environ(function.value, os_aliases)
            or _is_name(function.value, environ_aliases)
        ):
            return node.args[0]
        return None
    if not isinstance(node, ast.Subscript):
        return None
    if _is_os_environ(node.value, os_aliases) or _is_name(
        node.value, environ_aliases
    ):
        return node.slice
    return None


def _declared_environment_reads(source: Path) -> set[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    (
        constants,
        os_aliases,
        environ_aliases,
        getenv_aliases,
    ) = _environment_scan_metadata(tree)
    names: set[str] = set()
    for node in ast.walk(tree):
        argument = _environment_argument(
            node,
            os_aliases=os_aliases,
            environ_aliases=environ_aliases,
            getenv_aliases=getenv_aliases,
        )
        if argument is None:
            continue
        name = _static_string(argument, constants)
        if (
            name
            and name.upper() == name
            and all(character.isalnum() or character == "_" for character in name)
        ):
            names.add(name)
    return names


_SECURITY_ADJACENT_SEGMENTS = frozenset(
    {
        "AUTH",
        "COOKIE",
        "CREDENTIAL",
        "CREDENTIALS",
        "DSN",
        "JWT",
        "KEY",
        "KEYFILE",
        "KEYS",
        "NETRC",
        "PASSPHRASE",
        "PASSWD",
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "WEBHOOK",
    }
)


def _looks_secret_bearing(name: str) -> bool:
    segments = set(name.split("_"))
    if segments & _SECURITY_ADJACENT_SEGMENTS:
        return True
    if name.endswith(("_API_KEY", "_API_SECRET", "_APP_PASSWORD")):
        return True
    if name.endswith(("_URL", "_URI")) and segments & {
        "DATABASE",
        "MONGO",
        "MONGODB",
        "POSTGRES",
        "REDIS",
        "SENTRY",
    }:
        return True
    return name.endswith("_SERVICE_ACCOUNT_JSON")


def _runtime_python_sources() -> list[Path]:
    sources: list[Path] = []
    for source_root in (
        REPO_ROOT / "packages",
        REPO_ROOT / "deploy",
        REPO_ROOT / "scripts",
    ):
        for source in source_root.rglob("*.py"):
            if "tests" not in source.parts and "__pycache__" not in source.parts:
                sources.append(source)
    return sources


def test_secret_registry_covers_declared_runtime_environment_consumers() -> None:
    registry = runpy.run_path(str(SECRET_REGISTRY))
    secret_names = set(registry["SECRET_ENV_NAMES"])
    secret_file_names = set(registry["SECRET_FILE_ENV_NAMES"])
    reviewed_non_secrets = set(registry["REVIEWED_NON_SECRET_ENV_NAMES"])
    classified = registry["is_secret_env_name"]

    consumers: dict[str, set[str]] = {}
    for source in _runtime_python_sources():
        for name in _declared_environment_reads(source):
            if _looks_secret_bearing(name):
                consumers.setdefault(name, set()).add(
                    source.relative_to(REPO_ROOT).as_posix()
                )

    registered = secret_names | secret_file_names
    assert len(registry["SECRET_ENV_NAMES"]) == len(secret_names)
    assert len(registry["SECRET_FILE_ENV_NAMES"]) == len(secret_file_names)
    assert registered.isdisjoint(reviewed_non_secrets)
    missing = {
        name: sorted(paths)
        for name, paths in consumers.items()
        if name not in registered and name not in reviewed_non_secrets
    }
    assert not missing, (
        "Declare each new secret-bearing environment consumer in "
        f"{SECRET_REGISTRY.relative_to(REPO_ROOT)} or explicitly review it as "
        f"non-secret: {missing}"
    )
    assert all(classified(name) for name in consumers if name in registered)
    assert all(not classified(name) for name in reviewed_non_secrets)


def _generated_connector_secret_names() -> tuple[set[str], set[str]]:
    specs_path = (
        REPO_ROOT
        / "packages"
        / "maverick-core"
        / "maverick"
        / "tools"
        / "_connector_specs.py"
    )
    tree = ast.parse(
        specs_path.read_text(encoding="utf-8"),
        filename=str(specs_path),
    )
    names: set[str] = set()
    concrete_names: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "dict"
        ):
            continue
        keywords = {
            keyword.arg: keyword.value
            for keyword in node.keywords
            if keyword.arg is not None
        }
        name_node = keywords.get("name")
        connector = (
            None if name_node is None else _static_string(name_node, {})
        )
        if connector is None:
            continue
        token_node = keywords.get("token_env")
        token_env = (
            None if token_node is None else _static_string(token_node, {})
        )
        names.add(token_env or f"{connector.upper()}_TOKEN")
        if token_env is not None:
            concrete_names.add(token_env)
        extra_headers = keywords.get("extra_headers_env")
        if isinstance(extra_headers, ast.Dict):
            for value_node in extra_headers.values:
                value = _static_string(value_node, {})
                if value is not None:
                    names.add(value)
                    concrete_names.add(value)

    public_path = (
        REPO_ROOT
        / "packages"
        / "maverick-core"
        / "maverick"
        / "tools"
        / "enterprise_connectors.py"
    )
    tree = ast.parse(
        public_path.read_text(encoding="utf-8"),
        filename=str(public_path),
    )
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_pub"
            and node.args
        ):
            connector = _static_string(node.args[0], {})
            if connector is not None:
                names.add(f"{connector.upper()}_API_KEY")
        elif (
            isinstance(node, ast.keyword)
            and node.arg == "token_env"
        ):
            token_env = _static_string(node.value, {})
            if token_env is not None:
                names.add(token_env)
                concrete_names.add(token_env)
        elif (
            isinstance(node, ast.Tuple)
            and len(node.elts) == 2
            and isinstance(node.elts[1], ast.Constant)
            and node.elts[1].value is True
        ):
            name = _static_string(node.elts[0], {})
            if name is not None:
                names.add(name)
                concrete_names.add(name)
    return names, concrete_names


def test_secret_registry_covers_generated_connector_credentials() -> None:
    registry = runpy.run_path(str(SECRET_REGISTRY))
    classified = registry["is_secret_env_name"]
    generated, concrete = _generated_connector_secret_names()
    missing = sorted(
        name for name in generated if not classified(name)
    )
    assert not missing
    assert concrete <= set(registry["SECRET_ENV_NAMES"])


def test_secret_registry_includes_platform_dsns_and_connector_tokens() -> None:
    registry = runpy.run_path(str(SECRET_REGISTRY))
    names = set(registry["SECRET_ENV_NAMES"])
    classified = registry["is_secret_env_name"]

    assert {
        "MAVERICK_A2A_TOKEN",
        "MAVERICK_AUDIT_SIGNING_KEY",
        "MAVERICK_DASHBOARD_SESSION_SECRET",
        "MAVERICK_ENCRYPTION_KEY",
        "MAVERICK_KNOWLEDGE_DSN",
        "MAVERICK_OIDC_CLIENT_SECRET",
        "MAVERICK_PG_DSN",
        "MAVERICK_QUEUE_REDIS_DSN",
        "MAVERICK_RELAY_TOKEN",
        "MAVERICK_SENTRY_DSN",
        "MAVERICK_WEBHOOK_SECRET",
    } <= names
    assert classified("ZENDESK_TOKEN")
    assert classified("REGULATIONS_GOV_API_KEY")
    assert classified("ACME_CONNECTOR_CLIENT_SECRET")


def test_secret_registry_lists_the_vendor_siem_credentials() -> None:
    # audit/forwarder.py passes these names to a parameter (_audit_secret), so the
    # environment-read scan above cannot see them; they are listed by name instead.
    registry = runpy.run_path(str(SECRET_REGISTRY))
    names = set(registry["SECRET_ENV_NAMES"])
    classified = registry["is_secret_env_name"]

    assert {
        "MAVERICK_DATADOG_API_KEY",
        "MAVERICK_SENTINEL_CLIENT_SECRET",
        "MAVERICK_SIEM_TOKEN",
    } <= names
    assert classified("MAVERICK_DATADOG_API_KEY")
    assert classified("MAVERICK_SENTINEL_CLIENT_SECRET")


def _sanitize(
    tmp_path: Path,
    raw: bytes,
    *,
    max_chars: int = 50_000,
    extra_env: dict[str, str] | None = None,
    secret_file_snapshot: Path | None = None,
) -> tuple[str, str]:
    input_path = tmp_path / "raw.log"
    output_path = tmp_path / "result.log"
    summary_path = tmp_path / "summary.html"
    input_path.write_bytes(raw)
    env = os.environ.copy()
    env.update(extra_env or {})

    args = [
        sys.executable,
        "-I",
        "-S",
        str(SANITIZER),
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--summary",
        str(summary_path),
        "--max-chars",
        str(max_chars),
    ]
    if secret_file_snapshot is not None:
        args.extend(["--secret-file-snapshot", str(secret_file_snapshot)])
    subprocess.run(
        args,
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    return (
        output_path.read_text(encoding="utf-8"),
        summary_path.read_text(encoding="utf-8"),
    )


def _snapshot_secret_files(
    tmp_path: Path,
    *,
    extra_env: dict[str, str],
) -> Path:
    snapshot_path = tmp_path / "secret-files.snapshot"
    env = os.environ.copy()
    env.update(extra_env)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(SANITIZER),
            "--write-secret-file-snapshot",
            str(snapshot_path),
        ],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert snapshot_path.is_file()
    return snapshot_path


def _compact_jwt(label: str) -> str:
    def encode(value: dict[str, str]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = encode({"alg": "RS256", "typ": "JWT"})
    payload = encode({"sub": "workload", "nonce": label})
    signature = base64.urlsafe_b64encode(
        (f"signature-{label}-" * 6).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.{signature}"


def test_sanitizer_redacts_secrets_mentions_markup_and_controls(
    tmp_path: Path,
) -> None:
    exact_secret = "secret-value-from-the-job-environment"  # pragma: allowlist secret
    raw = (
        "::error::this must stay inert\n"
        "@octocat please notify @security-team\n"
        f"environment secret: {exact_secret}\n"
        "provider key: sk-ant-abcdefghijklmnopqrstuvwxyz012345\n"
        "Authorization: Bearer bearer-credential-value\n"
        "password=hunter2-secret\n"
        "</pre><script>alert(1)</script>\n"
        "\x1b[31mred\x1b[0m\x00\u202eevil-bidi\n"
    ).encode()

    result, summary = _sanitize(
        tmp_path,
        raw,
        extra_env={"ANTHROPIC_API_KEY": exact_secret},
    )

    for leaked in (
        exact_secret,
        "sk-ant-abcdefghijklmnopqrstuvwxyz012345",  # pragma: allowlist secret
        "bearer-credential-value",
        "hunter2-secret",
    ):
        assert leaked not in result
        assert leaked not in summary
    assert "[REDACTED_SECRET]" in result
    assert "[REDACTED_CREDENTIAL]" in result
    assert "@octocat" not in result
    assert "＠octocat" in result
    assert "\x1b" not in result
    assert "\x00" not in result
    assert "\u202e" not in result
    assert "::error::this must stay inert" not in result
    assert "：:error::this must stay inert" in result
    assert "&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in summary
    assert re.fullmatch(r"<pre>\n.*</pre>\n", summary, flags=re.DOTALL)


def test_sanitizer_exact_redacts_generated_connector_environment_value(
    tmp_path: Path,
) -> None:
    connector_token = "zendesk-connector-token-without-a-provider-prefix"
    result, summary = _sanitize(
        tmp_path,
        f"connector credential: {connector_token}\n".encode(),
        extra_env={"ZENDESK_TOKEN": connector_token},
    )

    assert connector_token not in result
    assert connector_token not in summary
    assert "[REDACTED_SECRET]" in result


def test_sanitizer_canonicalizes_controls_before_credential_matching(
    tmp_path: Path,
) -> None:
    exact_secret = "exact-environment-secret-value-for-control-test"  # pragma: allowlist secret
    anthropic_key = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"  # pragma: allowlist secret
    jwt = _compact_jwt("control-split-jwt")
    header, _, signature = jwt.split(".")
    detached_jws = f"{header}..{signature}"

    def obfuscate(value: str) -> str:
        quarter = len(value) // 4
        midpoint = len(value) // 2
        three_quarters = (len(value) * 3) // 4
        return (
            value[:quarter]
            + "\u202e"
            + value[quarter:midpoint]
            + "\x00"
            + value[midpoint:three_quarters]
            + "\x1b[31m"
            + value[three_quarters:]
            + "\x1b[0m"
        )

    raw = "\n".join(
        (
            f"exact: {obfuscate(exact_secret)}",
            f"anthropic: {obfuscate(anthropic_key)}",
            f"jwt: {obfuscate(jwt)}.",
            f"jws: {obfuscate(detached_jws)},",
        )
    ).encode()
    result, summary = _sanitize(
        tmp_path,
        raw,
        extra_env={"ANTHROPIC_API_KEY": exact_secret},
    )

    for leaked in (
        exact_secret,
        anthropic_key,
        jwt,
        detached_jws,
        "exact-environment-secret",
        "sk-ant-",
        header[:20],
        signature[:20],
    ):
        assert leaked not in result
        assert leaked not in summary
    assert result.count("[REDACTED_SECRET]") == 1
    assert result.count("[REDACTED_CREDENTIAL]") >= 3
    assert "\x1b" not in result
    assert "\u202e" not in result
    assert "\x00" not in result


def test_sanitizer_canonicalizes_multiline_environment_secret(
    tmp_path: Path,
) -> None:
    crlf_secret = "azure-secret-line-one\r\nline-two\r\nline-three"  # pragma: allowlist secret
    normalized_secret = crlf_secret.replace("\r\n", "\n")
    result, summary = _sanitize(
        tmp_path,
        f"multiline credential follows\n{normalized_secret}\n".encode(),
        extra_env={"AZURE_CLIENT_SECRET": crlf_secret},
    )

    for leaked in (normalized_secret, "azure-secret-line-one", "line-three"):
        assert leaked not in result
        assert leaked not in summary
    assert "[REDACTED_SECRET]" in result


def test_sanitizer_redacts_exact_azure_identity_environment_values(
    tmp_path: Path,
) -> None:
    secrets = {
        "AZURE_CLIENT_CERTIFICATE_PASSWORD": "azure-env-value-certificate-password",  # pragma: allowlist secret
        "AZURE_CLIENT_SECRET": "azure-env-value-client-secret",  # pragma: allowlist secret
        "AZURE_PASSWORD": "azure-env-value-user-password",  # pragma: allowlist secret
        "IDENTITY_HEADER": "azure-env-value-identity-header",
        "MSI_SECRET": "azure-env-value-msi-secret",  # pragma: allowlist secret
    }
    raw = "".join(
        f"{name} leaked as {value}\n"
        for name, value in secrets.items()
    ).encode()

    result, summary = _sanitize(tmp_path, raw, extra_env=secrets)

    for secret in secrets.values():
        assert secret not in result
        assert secret not in summary
    assert result.count("[REDACTED_SECRET]") == len(secrets)


def test_sanitizer_redacts_federated_token_file_path_and_contents(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "workload-identity-token"
    token = "federated-assertion-exact-value"
    token_file.write_text(f"{token}\n", encoding="utf-8")
    raw = f"path leaked as {token_file}\nassertion leaked as {token}\n".encode()

    result, summary = _sanitize(
        tmp_path,
        raw,
        extra_env={"AZURE_FEDERATED_TOKEN_FILE": str(token_file)},
    )

    for leaked in (str(token_file), token):
        assert leaked not in result
        assert leaked not in summary
    assert result.count("[REDACTED_SECRET]") == 2


def test_sanitizer_unions_pre_run_and_rotated_secret_file_values(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "rotating-workload-identity-token"
    old_token = "old-azure-workload-jwt-value-before-rotation"
    new_token = "new-azure-workload-jwt-value-after-rotation"
    token_file.write_text(old_token, encoding="utf-8")
    env = {"AZURE_FEDERATED_TOKEN_FILE": str(token_file)}
    snapshot = _snapshot_secret_files(tmp_path, extra_env=env)

    token_file.write_text(new_token, encoding="utf-8")
    raw = f"old observed: {old_token}\nnew observed: {new_token}\n".encode()
    result, summary = _sanitize(
        tmp_path,
        raw,
        extra_env=env,
        secret_file_snapshot=snapshot,
    )

    for leaked in (old_token, new_token):
        assert leaked not in result
        assert leaked not in summary
    assert result.count("[REDACTED_SECRET]") == 2


def test_sanitizer_unions_pre_run_and_post_run_environment_values(
    tmp_path: Path,
) -> None:
    old_token = "relay-token-value-before-environment-rotation"
    new_token = "relay-token-value-after-environment-rotation"
    snapshot = _snapshot_secret_files(
        tmp_path,
        extra_env={"MAVERICK_RELAY_TOKEN": old_token},
    )

    result, summary = _sanitize(
        tmp_path,
        f"old observed: {old_token}\nnew observed: {new_token}\n".encode(),
        extra_env={"MAVERICK_RELAY_TOKEN": new_token},
        secret_file_snapshot=snapshot,
    )

    for leaked in (old_token, new_token):
        assert leaked not in result
        assert leaked not in summary
    assert result.count("[REDACTED_SECRET]") == 2


def test_sanitizer_retains_pre_run_environment_value_after_deletion(
    tmp_path: Path,
) -> None:
    old_token = "relay-token-value-before-environment-deletion"
    snapshot = _snapshot_secret_files(
        tmp_path,
        extra_env={"MAVERICK_RELAY_TOKEN": old_token},
    )

    result, summary = _sanitize(
        tmp_path,
        f"deleted environment value observed: {old_token}\n".encode(),
        extra_env={"MAVERICK_RELAY_TOKEN": ""},
        secret_file_snapshot=snapshot,
    )

    assert old_token not in result
    assert old_token not in summary
    assert "[REDACTED_SECRET]" in result


def test_sanitizer_redacts_bare_jwt_from_intermediate_file_rotation(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "multi-rotation-workload-identity-token"
    old_token = _compact_jwt("before-run")
    intermediate_token = _compact_jwt("during-run")
    new_token = _compact_jwt("after-run")
    token_file.write_text(old_token, encoding="utf-8")
    env = {"AZURE_FEDERATED_TOKEN_FILE": str(token_file)}
    snapshot = _snapshot_secret_files(tmp_path, extra_env=env)

    # The intermediate value is neither in the pre-run snapshot nor the fresh
    # post-run file. Generic compact JWT/JWS matching must still cover it.
    token_file.write_text(new_token, encoding="utf-8")
    raw = (
        f"pre: {old_token}\n"
        f"intermediate: {intermediate_token}\n"
        f"post: {new_token}\n"
    ).encode()
    result, summary = _sanitize(
        tmp_path,
        raw,
        extra_env=env,
        secret_file_snapshot=snapshot,
    )

    for token in (old_token, intermediate_token, new_token):
        assert token not in result
        assert token not in summary
    assert result.count("[REDACTED_SECRET]") == 2
    assert result.count("[REDACTED_CREDENTIAL]") == 1


def test_sanitizer_uses_pre_run_value_after_secret_file_deletion(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "deleted-workload-identity-token"
    deleted_token = "azure-workload-jwt-value-before-file-deletion"
    token_file.write_text(deleted_token, encoding="utf-8")
    env = {"AZURE_FEDERATED_TOKEN_FILE": str(token_file)}
    snapshot = _snapshot_secret_files(tmp_path, extra_env=env)

    token_file.unlink()
    result, summary = _sanitize(
        tmp_path,
        f"deleted file value observed: {deleted_token}\n".encode(),
        extra_env=env,
        secret_file_snapshot=snapshot,
    )

    assert deleted_token not in result
    assert deleted_token not in summary
    assert "[REDACTED_SECRET]" in result


def test_sanitizer_fails_closed_if_required_snapshot_is_missing(
    tmp_path: Path,
) -> None:
    with pytest.raises(subprocess.CalledProcessError):
        _sanitize(
            tmp_path,
            b"untrusted output must not be exposed\n",
            secret_file_snapshot=tmp_path / "deleted-secret-files.snapshot",
        )
    assert not (tmp_path / "result.log").exists()
    assert not (tmp_path / "summary.html").exists()


def test_sanitizer_redacts_client_certificate_path_and_partial_pem_contents(
    tmp_path: Path,
) -> None:
    certificate_file = tmp_path / "azure-client-certificate.pem"
    # Deliberately omit the PEM footer: the generic complete-private-key regex
    # cannot catch this fragment, so the exact secret-file redaction must.
    partial_pem = (
        "-----BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
        "partial-client-certificate-key-material-without-a-footer"
    )
    certificate_file.write_text(partial_pem, encoding="utf-8")
    raw = (
        f"certificate path leaked as {certificate_file}\n"
        f"certificate bytes leaked as {partial_pem}\n"
    ).encode()

    result, summary = _sanitize(
        tmp_path,
        raw,
        extra_env={"AZURE_CLIENT_CERTIFICATE_PATH": str(certificate_file)},
    )

    for leaked in (str(certificate_file), partial_pem):
        assert leaked not in result
        assert leaked not in summary
    assert result.count("[REDACTED_SECRET]") == 2


def test_sanitizer_preserves_public_azure_identity_configuration(
    tmp_path: Path,
) -> None:
    public = {
        "AZURE_AUTHORITY_HOST": "https://login.microsoftonline.us",
        "AZURE_CLIENT_ID": "11111111-2222-3333-4444-555555555555",
        "AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com",
        "AZURE_OPENAI_TOKEN_SCOPE": "https://cognitiveservices.azure.com/.default",
        "AZURE_TENANT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "AZURE_TOKEN_CREDENTIALS": "ManagedIdentityCredential",
    }
    raw = "".join(
        f"{name} configured as {value}\n"
        for name, value in public.items()
    ).encode()

    result, summary = _sanitize(tmp_path, raw, extra_env=public)

    for value in public.values():
        assert value in result
        assert value in summary


def test_generic_jwt_redaction_preserves_ordinary_dotted_versions(
    tmp_path: Path,
) -> None:
    ordinary = (
        "versions: 1.2.3, v1.2.3, release.2026.07, "
        "alpha.beta.gamma, com.example.tool"
    )
    result, summary = _sanitize(tmp_path, ordinary.encode())

    for value in ("1.2.3", "v1.2.3", "release.2026.07", "alpha.beta.gamma"):
        assert value in result
        assert value in summary
    assert "[REDACTED_CREDENTIAL]" not in result


def test_sanitizer_bounds_the_exposed_result(tmp_path: Path) -> None:
    result, summary = _sanitize(
        tmp_path,
        ("untrusted-output-" * 100).encode(),
        max_chars=256,
    )

    assert len(result) <= 256
    assert "Lightwork output truncated" in result
    assert "Lightwork output truncated" in summary


def test_sanitizer_redacts_secret_crossing_cap_and_unterminated_key(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "large-workload-identity-token"
    secret_prefix = "azure-token-boundary-key-prefix-"  # pragma: allowlist secret
    boundary_secret = secret_prefix + ("K" * 900)
    assert len(boundary_secret.encode()) > 824
    token_file.write_text(boundary_secret, encoding="utf-8")

    benign_prefix = "B" * 130
    unterminated_key = (
        "-----BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
        "PEM-KEY-PREFIX-" + ("Z" * 900)
    )
    raw = f"{benign_prefix}{boundary_secret}\n{unterminated_key}".encode()

    result, summary = _sanitize(
        tmp_path,
        raw,
        max_chars=256,
        extra_env={"AZURE_FEDERATED_TOKEN_FILE": str(token_file)},
    )

    for leaked_prefix in (
        secret_prefix,
        "K" * 32,
        "-----BEGIN PRIVATE KEY-----",  # pragma: allowlist secret
        "PEM-KEY-PREFIX-",
        "Z" * 32,
    ):
        assert leaked_prefix not in result
        assert leaked_prefix not in summary
    assert "[REDACTED_SECRET]" in result
    assert "[REDACTED_PRIVATE_KEY]" in result
    assert len(result) <= 256


def test_action_docs_make_local_execution_an_explicit_exception() -> None:
    docs = README.read_text(encoding="utf-8")

    assert "| `sandbox` | `docker` |" in docs
    assert "`allow-unsafe-local`" in docs
    assert "Azure Identity environment secrets" in docs
    assert "workload-token file contents" in docs
    assert re.search(r"client\s+certificate file contents", docs)
    assert re.search(r"bare compact\s+JWT/JWS credentials", docs)
    assert "control characters are neutralized before matching" in docs
    assert "privately snapshotted before the" in docs
    assert "pre-rotation and post-rotation" in docs
    assert "trusted disposable" in docs
    assert "no network" in docs
    assert "non-root" in docs
