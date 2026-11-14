"""`maverick doctor`: end-to-end health check with remediation.

Every red/yellow row ends with an actionable verb so users aren't told
"something's wrong" without knowing what to do.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys

import click

from .sandbox.gvisor import (
    GVisorRuntimeValidationError,
    validate_docker_gvisor_runtime,
)
from .sandbox_names import BUILTIN_SANDBOX_BACKENDS

GREEN = click.style("✓", fg="green")
YELLOW = click.style("!", fg="yellow")
RED = click.style("✗", fg="red")

# diagnose() accumulates the labels of failed (✗) checks here so the CLI can
# exit nonzero when the install is actually broken, so `maverick doctor &&
# deploy` and CI health gates can tell a broken deployment from a healthy one.
_FAILURES: list[str] = []


def _is_outage(exc: BaseException) -> bool:
    """True if ``exc`` signals the provider is actually unreachable/down --
    a connection error, a timeout, or a 5xx server response -- as opposed to
    a local reason the probe couldn't run (SDK quirk, unexpected shape).

    Matched by class name so this works for both the anthropic and openai
    SDKs (and their httpx-level timeouts) without importing either eagerly.
    Both SDKs share these exception names (APIConnectionError / APITimeoutError
    / APIStatusError, with the 5xx InternalServerError as an APIStatusError
    subclass).
    """
    names = {c.__name__ for c in type(exc).__mro__}
    if names & {"APIConnectionError", "APITimeoutError", "ConnectError",
                "ConnectTimeout", "ReadTimeout", "TimeoutException"}:
        return True
    # 5xx server-side outage. InternalServerError subclasses APIStatusError and
    # carries a status_code; treat any >=500 status as a real outage.
    if "APIStatusError" in names:
        code = getattr(exc, "status_code", None)
        return isinstance(code, int) and code >= 500
    return "InternalServerError" in names


def _console_text(value: str) -> str:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        value.encode(encoding)
        return value
    except UnicodeEncodeError:
        return value.translate(str.maketrans({"✓": "OK", "✗": "FAIL", "→": "->"})).encode(
            encoding, errors="replace").decode(encoding)


def _row(marker: str, label: str, detail: str = "", fix: str = "") -> None:
    if marker == RED:
        _FAILURES.append(label)
    line = f"  {marker} {label}"
    if detail:
        line += click.style(f"  ({detail})", fg="bright_black")
    click.echo(_console_text(line))
    if fix:
        click.echo(_console_text(click.style(f"      → {fix}", fg="cyan")))


def _check_config() -> dict:
    from .operator_preflight import _config_state

    check, cfg = _config_state()
    if check.status == "blocked":
        _row(RED, "config", check.detail,
             fix="Open Settings > Installation health. Ask an administrator to repair unavailable settings or restore a known-good copy.")
        return {}
    _row(GREEN, "config", check.detail)
    return cfg or {}


def _check_config_lint(cfg: dict) -> None:
    """Schema-lint the loaded config so a mistyped section/key -- e.g. a budget
    cap typo (`[budget] max_dollarss`) that would otherwise silently run
    UNCAPPED -- surfaces in `maverick doctor`, not only in the dedicated
    `maverick config-lint`. Advisory: findings are warnings, never failures."""
    if not cfg:
        return  # no config / corrupt -- _check_config already reported it
    try:
        from .config_lint import lint_config
        findings = lint_config(cfg)
    except Exception:  # pragma: no cover -- linting must never break the doctor
        return
    if not findings:
        _row(GREEN, "config-lint", "no unknown or mistyped keys")
        return
    for i, f in enumerate(findings[:8]):
        _row(YELLOW, "config-lint", getattr(f, "message", str(f)),
             fix="run `maverick config-lint` for the full report" if i == 0 else "")


def _sdk_import_failure(
    name: str, exc: ImportError, install_fix: str
) -> tuple[str, str]:
    """Message + fix for a provider SDK whose import raised.

    A missing package and a CORRUPT install both land here as ImportError,
    but the fixes differ -- and "SDK not installed" while pip lists the
    package sent a user chasing the wrong problem (field finding: a broken
    anthropic install needed --force-reinstall, not install). Only a
    ModuleNotFoundError for the package itself means "not installed";
    anything else (a broken submodule, a missing compiled dep) reports the
    real error.
    """
    if isinstance(exc, ModuleNotFoundError) and exc.name == name:
        return "SDK not installed", install_fix
    return (
        f"SDK is installed but failed to import: {exc}",
        f"pip install --force-reinstall {name}",
    )


def _check_anthropic() -> None:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        # Not a failure when some OTHER provider is configured (env key,
        # base-url env, or a [providers.<name>] table): a self-hosted
        # Ollama/vLLM deployment is healthy with no Anthropic key at all.
        try:
            from .config import any_provider_configured
            other = any_provider_configured()
        except Exception:
            other = False
        if other:
            _row(YELLOW, "anthropic",
                 "ANTHROPIC_API_KEY not set (another provider is configured)",
                 fix="fine unless a [models] role routes to an anthropic model")
        else:
            _row(RED, "anthropic", "ANTHROPIC_API_KEY not set",
                 fix="open Lightwork Settings > Models to connect an AI service")
        return
    if not key.startswith("sk-ant-"):
        _row(YELLOW, "anthropic", "key doesn't start with sk-ant-",
             fix="re-check the key at https://console.anthropic.com/settings/keys")
        return
    try:
        import anthropic
    except ImportError as e:
        msg, fix = _sdk_import_failure("anthropic", e, "pip install anthropic")
        _row(YELLOW, "anthropic", msg, fix=fix)
        return
    try:
        # A health probe is a one-shot observation of current reachability.
        client = anthropic.Anthropic(api_key=key, max_retries=0)
        list(client.models.list(limit=1))
        _row(GREEN, "anthropic", "key validated")
    except anthropic.AuthenticationError:
        _row(RED, "anthropic", "API rejected the key",
             fix="generate a new key at https://console.anthropic.com/settings/keys, then update it in Lightwork Settings > Models")
    except Exception as e:
        # A real outage (no connection / timeout / 5xx) is RED -- the agent
        # cannot reach the API, so reporting it as a benign YELLOW "skipped"
        # hid genuine downtime. Anything else (unexpected SDK shape) stays
        # YELLOW: we just couldn't run the probe.
        if _is_outage(e):
            _row(RED, "anthropic", f"API unreachable: {type(e).__name__}",
                 fix="check network / proxy / api.anthropic.com status; key format looks right")
        else:
            _row(YELLOW, "anthropic", f"validation skipped: {type(e).__name__}",
                 fix="check network / proxy; key format looks right")


def _check_openai() -> None:
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return
    try:
        from openai import AuthenticationError, OpenAI
    except ImportError as e:
        msg, fix = _sdk_import_failure(
            "openai",
            e,
            "install the OpenAI extra from the same reviewed Lightwork "
            "checkout; public-index lookup is disabled",
        )
        _row(YELLOW, "openai", msg, fix=fix)
        return
    try:
        # A health probe is a one-shot observation of current reachability.
        client = OpenAI(api_key=key, max_retries=0)
        list(client.models.list().data[:1])
        _row(GREEN, "openai", "key validated")
    except AuthenticationError:
        _row(RED, "openai", "API rejected the key",
             fix="regenerate at https://platform.openai.com/api-keys, then update it in Lightwork Settings > Models")
    except Exception as e:
        # Real outage (no connection / timeout / 5xx) is RED; everything else
        # stays YELLOW "skipped" -- see _check_anthropic.
        if _is_outage(e):
            _row(RED, "openai", f"API unreachable: {type(e).__name__}",
                 fix="check network / proxy / status.openai.com")
        else:
            _row(YELLOW, "openai", f"validation skipped: {type(e).__name__}")


def _check_sandbox_docker() -> None:
    if not shutil.which("docker"):
        _row(RED, "sandbox", "docker not on PATH",
             fix="install Docker Desktop (https://docker.com/products/docker-desktop) or change [sandbox] backend to 'local' in ~/.maverick/config.toml")
        return
    try:
        subprocess.run(
            ["docker", "version"],
            capture_output=True, timeout=5, check=True,
        )
        _row(GREEN, "sandbox", "docker daemon responding")
    except subprocess.CalledProcessError:
        _row(RED, "sandbox", "docker daemon not running",
             fix="start Docker Desktop, or `sudo systemctl start docker` on Linux")
    except subprocess.TimeoutExpired:
        _row(RED, "sandbox", "docker version timed out",
             fix="docker is installed but unresponsive -- restart Docker Desktop")


def _check_sandbox_podman() -> None:
    if not shutil.which("podman"):
        _row(RED, "sandbox", "podman not on PATH",
             fix="install podman, or change [sandbox] backend to 'docker'/'local' in ~/.maverick/config.toml")
        return
    try:
        subprocess.run(
            ["podman", "version"],
            capture_output=True, timeout=5, check=True,
        )
        _row(GREEN, "sandbox", "podman responding")
    except subprocess.CalledProcessError:
        _row(RED, "sandbox", "podman present but not responding",
             fix="check `podman version`; on Linux/macOS you may need `podman machine start`")
    except subprocess.TimeoutExpired:
        _row(RED, "sandbox", "podman version timed out",
             fix="podman is installed but unresponsive")


def _check_sandbox_gvisor(cfg: dict) -> None:
    """Verify Docker reports an approved runsc runtime registration."""
    if not shutil.which("docker"):
        _row(
            RED,
            "sandbox",
            "gvisor needs Docker, but docker is not on PATH",
            fix="install Docker and gVisor/runsc, then register runsc with Docker",
        )
        return
    configured = cfg.get("sandbox", {}).get("runtime", "runsc")
    try:
        runtime = validate_docker_gvisor_runtime(configured)
    except GVisorRuntimeValidationError as exc:
        _row(
            RED,
            "sandbox",
            str(exc),
            fix=(
                "register an approved runsc runtime with an exact runsc path "
                "or io.containerd.runsc.v1 runtimeType"
            ),
        )
        return
    except (OSError, subprocess.CalledProcessError):
        _row(
            RED,
            "sandbox",
            "gvisor Docker daemon/runtime probe failed",
            fix="start Docker and confirm `docker info` succeeds",
        )
        return
    except subprocess.TimeoutExpired:
        _row(
            RED,
            "sandbox",
            "gvisor Docker daemon/runtime probe timed out",
            fix="restart Docker and confirm `docker info` succeeds",
        )
        return
    _row(
        GREEN,
        "sandbox",
        f"gvisor runtime {runtime!r} registration metadata validated; "
        "Docker responding",
    )


def _check_sandbox_modal(cfg: dict) -> None:
    allow_network = cfg.get("sandbox", {}).get("allow_network", False)
    acknowledged = allow_network is True or (
        isinstance(allow_network, str)
        and allow_network.strip().lower() in {"1", "true", "yes", "on"}
    )
    if not acknowledged:
        _row(
            RED,
            "sandbox",
            "modal selected with allow_network=false; execution will fail closed",
            fix="set [sandbox] allow_network = true to acknowledge Modal networking",
        )
        return
    try:
        modal_present = importlib.util.find_spec("modal") is not None
    except (ImportError, ValueError):
        modal_present = False
    if not modal_present:
        _row(
            RED,
            "sandbox",
            "modal package is not installed",
            fix="install the reviewed `packages/maverick-core[modal]` extra",
        )
        return
    _row(
        GREEN,
        "sandbox",
        "modal package present (authentication is verified on first execution)",
    )


def _check_sandbox_kubernetes(cfg: dict) -> None:
    if not shutil.which("kubectl"):
        _row(RED, "sandbox", "kubectl not on PATH",
             fix="install kubectl and configure a kubeconfig context")
        return
    ctx = cfg.get("sandbox", {}).get("context")
    try:
        subprocess.run(
            ["kubectl", "version", "--client"],
            capture_output=True, timeout=5, check=True,
        )
        detail = "kubectl present" + (f", context={ctx}" if ctx else "")
        _row(GREEN, "sandbox", f"{detail} (cluster reachability not checked)")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        _row(RED, "sandbox", "kubectl present but `kubectl version --client` failed",
             fix="check your kubectl install")


def _check_sandbox_firecracker(cfg: dict) -> None:
    provider = str(cfg.get("sandbox", {}).get("provider", "local") or "local").strip().lower()
    if provider == "e2b":
        if os.environ.get("E2B_API_KEY"):
            _row(GREEN, "sandbox", "firecracker via E2B (E2B_API_KEY set)")
        else:
            _row(RED, "sandbox", "firecracker provider=e2b but E2B_API_KEY unset",
                 fix='export E2B_API_KEY=..., or set [sandbox] provider = "local"')
    elif provider == "local":
        if shutil.which("firecracker"):
            _row(GREEN, "sandbox", "firecracker binary present")
        else:
            _row(RED, "sandbox", "firecracker binary not on PATH",
                 fix='install firecracker, or set [sandbox] provider = "e2b"')
    else:
        _row(YELLOW, "sandbox", f"firecracker provider={provider!r} unknown",
             fix='[sandbox] provider must be "local" or "e2b"')


def _check_sandbox(cfg: dict) -> None:
    # Match build_sandbox(): the backend is user-typed config and is compared
    # case-sensitively below, so normalize or a valid "Docker" misreports as
    # the "unsupported" catch-all while build_sandbox actually runs it.
    backend = str(cfg.get("sandbox", {}).get("backend", "local") or "local").strip().lower()
    if backend == "local":
        _row(YELLOW, "sandbox", "work runs directly on this computer, without isolation",
             fix="start Docker or Podman, then select its container in Lightwork > Permissions > Where work runs")
        return
    if backend == "docker":
        _check_sandbox_docker()
        return
    if backend == "gvisor":
        _check_sandbox_gvisor(cfg)
        return
    if backend == "podman":
        _check_sandbox_podman()
        return
    if backend == "devcontainer":
        # The devcontainer backend builds/runs through Docker under the hood.
        if not shutil.which("docker"):
            _row(RED, "sandbox", "devcontainer needs Docker, not on PATH",
                 fix="install Docker -- the devcontainer backend builds/runs via docker")
            return
        _row(YELLOW, "sandbox",
             "devcontainer (Docker present; also needs a .devcontainer/devcontainer.json with an image)")
        return
    if backend == "kubernetes":
        _check_sandbox_kubernetes(cfg)
        return
    if backend == "firecracker":
        _check_sandbox_firecracker(cfg)
        return
    if backend == "modal":
        _check_sandbox_modal(cfg)
        return
    if backend == "ssh":
        host = cfg.get("sandbox", {}).get("host", "")
        if not host:
            _row(RED, "sandbox", "backend=ssh but no [sandbox] host=",
                 fix='edit ~/.maverick/config.toml and add: host = "user@example.com"')
            return
        _row(YELLOW, "sandbox", f"ssh -> {host} (live check not performed)")
        return
    if backend.startswith("ep:"):
        name = backend[3:].strip()
        try:
            from .sandbox.sdk import installed_entry_point_names

            installed = installed_entry_point_names()
        except Exception:
            installed = ()
        if name and name in installed:
            _row(
                GREEN,
                "sandbox",
                f"external sandbox entry point {name!r} is installed",
            )
        else:
            _row(
                RED,
                "sandbox",
                f"external sandbox entry point {name or '(empty)'!r} is not installed",
                fix=(
                    "install the backend package or select one of: "
                    + (", ".join(installed) if installed else "no installed entry points")
                ),
            )
        return
    _row(
        YELLOW,
        "sandbox",
        f"backend={backend} not recognized",
        fix=f"supported: {', '.join(BUILTIN_SANDBOX_BACKENDS)}, or ep:<name>",
    )


_FILE_WORK_TOOLS = ("shell", "write_file", "apply_patch", "str_replace_editor", "ast_edit")


def file_work_limits(cfg: dict) -> tuple[list[str], list[str]]:
    """Configured first-run blocks and higher-priority effective tool blocks."""
    from .runtime_overrides import denied_tools as runtime_denied_tools

    security = cfg.get("security") or {}
    if not isinstance(security, dict):
        security = {}
    denied = {name for name in (security.get("denied_tools") or [])
              if isinstance(name, str)}
    allowed = {name for name in (security.get("allowed_tools") or [])
               if isinstance(name, str)}
    runtime_denied = runtime_denied_tools()
    setup = [name for name in _FILE_WORK_TOOLS if name in denied]
    other = [name for name in _FILE_WORK_TOOLS
             if (allowed and name not in allowed) or name in runtime_denied]
    return setup, other


def file_work_notice(cfg: dict, *, backend: str | None = None) -> str:
    """Plain, pre-task explanation of missing file/program authority."""
    setup, other = file_work_limits(cfg)
    chosen = str(backend or (cfg.get("sandbox") or {}).get("backend") or "local").lower()
    if not setup and not other:
        return ""
    if other and not setup:
        return (
            "An additional organization rule limits file changes or program "
            "execution. Review Permissions or ask an administrator before "
            "starting a task that needs those actions."
        )
    if chosen == "local":
        message = (
            "File changes or program execution are off in this setup. "
            "Lightwork can still answer questions. Start Docker or Podman, "
            "then open Lightwork > Permissions > Where work runs, choose its "
            "container and select Allow file work before asking for files or programs."
        )
    else:
        message = (
            "File changes or program execution are still off. Open Lightwork > "
            "Permissions > Where work runs and select Allow file work after the "
            "container is running."
        )
    if other:
        message += " Another organization rule may still block those actions."
    return message


def _check_file_work(cfg: dict) -> None:
    if not cfg:
        return  # the missing/corrupt config row already explains the blocker
    from .runtime_overrides import RuntimeOverridesSecurityError

    try:
        setup, other = file_work_limits(cfg)
    except (RuntimeOverridesSecurityError, OSError, TypeError, ValueError):
        _row(RED, "file work", "the effective tool rules could not be verified",
             fix="repair the saved policy, then run lightwork doctor again")
        return
    if not setup and not other:
        _row(GREEN, "file work", "file and program actions are allowed by tool rules")
        return
    _row(YELLOW, "file work", "file changes or program execution are limited",
         fix=file_work_notice(cfg))


CHANNEL_DEPS = {
    "telegram": ("telegram", "python-telegram-bot"),
    "discord":  ("discord", "discord.py"),
    "slack":    ("slack_sdk", "slack_sdk"),
    "matrix":   ("nio", "matrix-nio"),
    "whatsapp": ("twilio", "twilio + fastapi"),
    "sms":      ("twilio", "twilio + fastapi"),
}


def _check_channels(cfg: dict) -> None:
    channels = cfg.get("channels", {})
    if not channels:
        return
    if not isinstance(channels, dict):
        return
    for name, ch_cfg in channels.items():
        if not isinstance(ch_cfg, dict) or not ch_cfg.get("enabled"):
            continue
        dep = CHANNEL_DEPS.get(name)
        if dep:
            mod, friendly = dep
            try:
                __import__(mod)
                _row(GREEN, f"channel:{name}", f"{friendly} installed")
            except ImportError:
                _row(
                    YELLOW,
                    f"channel:{name}",
                    f"{friendly} not installed",
                    fix=("install this channel extra from the same reviewed "
                         "Lightwork checkout; public-index lookup is disabled"),
                )
                continue
        elif name == "signal":
            if not shutil.which("signal-cli"):
                _row(YELLOW, "channel:signal", "signal-cli not on PATH",
                     fix="install signal-cli per https://github.com/AsamK/signal-cli, then register your number")
                continue
            _row(GREEN, "channel:signal", "signal-cli present")
        elif name == "imessage":
            if sys.platform != "darwin":
                _row(RED, "channel:imessage", f"requires macOS (you're on {sys.platform})",
                     fix="disable in config or run Lightwork from a Mac")
                continue
            _row(GREEN, "channel:imessage", "macOS")
        elif name == "email":
            _row(GREEN, "channel:email", "stdlib only")


def _check_world_db() -> None:
    # Open the SAME configured backend as the runtime. A local workspace path
    # can hold a healthy SQLite mirror while the deployment's authoritative
    # world is Postgres, so inspecting that path would report the wrong store.
    from .workspace import Workspace
    from .world_model import close_world_if_owned, open_world
    from .world_model_backends import is_postgres_configured

    label = "Postgres" if is_postgres_configured() else str(Workspace.current().db_path)
    try:
        w = open_world()
        try:
            _row(GREEN, "world-db", f"{label} (schema v{w.schema_version})")
        finally:
            close_world_if_owned(w)
    except Exception as e:
        _row(RED, "world-db", f"open failed: {e}",
             fix="check world-model backend credentials, connectivity, and storage permissions")


def _check_shield() -> None:
    try:
        from maverick_shield import Shield
    except ImportError:
        from .shield_policy import shield_required
        if shield_required():
            _row(RED, "shield",
                 "shield REQUIRED (enterprise / [safety] require_shield) but "
                 "maverick-shield is not installed — external traffic is refused",
                 fix=("install Shield from the same reviewed Lightwork checkout; "
                      "public-index lookup is disabled"))
            return
        _row(
            YELLOW,
            "shield",
            "maverick-shield not installed",
            fix=("install Shield from the same reviewed Lightwork checkout; "
                 "public-index lookup is disabled"),
        )
        return
    # warn_if_missing=False: doctor renders the shield row (with remediation)
    # itself, so the raw "SDK not installed" log line would just bleed into the
    # health-check output mid-table.
    s = Shield.from_config(warn_if_missing=False)
    from maverick_shield.builtin_rules import RULES
    backend_label = {
        "agent-shield": "agent-shield SDK",
        "builtin": f"builtin rules ({len(RULES)} bundled patterns)",
        "none": "DISABLED -- [safety] profile=off in config",
    }.get(s.backend, s.backend)
    if s.backend == "agent-shield":
        _row(GREEN, "shield", backend_label)
    elif s.backend == "builtin":
        _row(YELLOW, "shield", backend_label,
             fix="Use the built-in layer; the full SDK is not on public PyPI")
    else:
        _row(RED, "shield", backend_label,
             fix="set [safety] profile = \"balanced\" in ~/.maverick/config.toml to re-enable")


def _check_profile() -> None:
    """Surface the active deployment profile + security posture so an operator
    can confirm which posture is live (the single ``MAVERICK_PROFILE`` /
    ``[profile] name`` switch). Informational; a misconfigured enterprise
    boundary is reported in depth by ``maverick enterprise verify``."""
    try:
        from .enterprise import enterprise_enabled
        from .profile import active_profile
        from .security_defaults import secure_by_default
    except Exception:  # pragma: no cover - never break doctor
        return
    prof = active_profile()
    ent = enterprise_enabled()
    sec = secure_by_default()
    posture = []
    posture.append("egress lock ON" if ent else "egress lock off (cloud-capable)")
    posture.append("hardened defaults ON" if sec else "hardened defaults OFF")
    if prof == "enterprise":
        _row(GREEN, "profile",
             f"deployment profile = enterprise ({', '.join(posture)})")
    else:
        _row(GREEN, "profile",
             f"deployment profile = standard ({', '.join(posture)})",
             fix="set MAVERICK_PROFILE=enterprise (or [profile] name) for the "
                 "regulated, data-boundary posture")


def _check_data_residency(cfg: dict) -> None:
    """When the deployment DECLARES a data-residency requirement
    (``[residency] region`` / ``MAVERICK_RESIDENCY_REGION``), warn about any
    residency-sensitive feature still defaulting to a US region — silently
    routing a sovereign client's data through us-east-1/us-central1 is a real
    compliance hit. No declared requirement -> no-op (no noise)."""
    region = (os.environ.get("MAVERICK_RESIDENCY_REGION")
              or str((cfg.get("residency") or {}).get("region") or "")).strip()
    if not region:
        return
    if not os.environ.get("AWS_REGION") and not (cfg.get("s3") or {}).get("region"):
        _row(YELLOW, "residency",
             f"residency={region!r} but AWS_REGION is unset — S3 attachments "
             "default to us-east-1",
             fix="set AWS_REGION to an in-region value")
    if not os.environ.get("VERTEX_LOCATION") and not (cfg.get("vertex") or {}).get("location"):
        _row(YELLOW, "residency",
             f"residency={region!r} but VERTEX_LOCATION is unset — Vertex "
             "defaults to us-central1",
             fix="set VERTEX_LOCATION to an in-region value (if Vertex is used)")


def _check_config_perms() -> None:
    """Config may hold tokens/secrets — warn if it's group/world-accessible."""
    try:
        from .config import config_path
        p = config_path()
        if not p.exists():
            return
        mode = p.stat().st_mode & 0o777
    except Exception:  # pragma: no cover - never break doctor
        return
    if mode & 0o077:
        _row(YELLOW, "config-perms",
             f"{p} is group/world-accessible (mode {oct(mode)})",
             fix=f"chmod 600 {p} — it may hold tokens/secrets")
    else:
        _row(GREEN, "config-perms", "config.toml is owner-only (0600)")


def _check_client_binding() -> None:
    """One Lightwork per enterprise client — surface the binding and fail loudly
    when it's enforced but unset (the deployment would otherwise serve from the
    shared root)."""
    try:
        from .client import status as client_status
        st = client_status()
    except Exception as e:  # pragma: no cover - never break doctor
        _row(YELLOW, "client", f"binding status unavailable: {e}")
        return
    cid = st.get("client_id")
    if cid:
        _row(GREEN, "client", f"bound to {cid!r} — data root {st['data_root']}")
    elif st.get("enforced"):
        _row(RED, "client",
             "client binding ENFORCED but no client id set — refusing to serve "
             "unbound",
             fix="set MAVERICK_CLIENT_ID (service unit) or [client] id in config")
    else:
        _row(YELLOW, "client",
             "no client binding (shared root) — single-tenant/legacy mode",
             fix="for an enterprise deployment set [client] id + enforce = true")


def _check_agent_trust() -> None:
    """Surface the Agent Trust Plane state — especially the silent footgun
    where the plane is ENGAGED (e.g. via enterprise mode) but the registry is
    empty, so every external agent is denied with no other signal."""
    try:
        from .agent_trust import status as trust_status
        st = trust_status()
    except Exception as e:  # pragma: no cover - never break doctor
        _row(YELLOW, "agent-trust", f"status unavailable: {e}")
        return
    if not st.get("enforced"):
        _row(GREEN, "agent-trust", "disengaged (external agents ungoverned — default)")
        return
    count = int(st.get("count") or 0)
    if count == 0:
        _row(RED, "agent-trust",
             "ENGAGED but the [agent_trust] registry is EMPTY — every external "
             "agent (federation/A2A/fleet) is denied",
             fix="add [agent_trust] agents = [...] entries, or unset enforce")
        return
    inactive = sum(1 for a in st.get("agents", []) if not a.get("active", True))
    detail = f"engaged — {count} agent(s) registered"
    if inactive:
        _row(YELLOW, "agent-trust", detail + f"; {inactive} expired/revoked",
             fix="rotate or remove expired/revoked entries")
    else:
        _row(GREEN, "agent-trust", detail)
    # Proactive expiry horizon: warn BEFORE a credential lapses (federation/mTLS
    # then starts failing with no prior signal), not just after.
    import time as _time
    now = _time.time()
    soon = [a for a in st.get("agents", [])
            if a.get("active", True) and isinstance(a.get("expires_at"), (int, float))
            and 0 < (a["expires_at"] - now) <= _EXPIRY_HORIZON_S]
    for a in sorted(soon, key=lambda a: a["expires_at"]):
        days = (a["expires_at"] - now) / 86400.0
        _row(YELLOW, "agent-trust",
             f"agent {a['id']!r} expires in {days:.1f} day(s)",
             fix="rotate the credential before it lapses (maverick trust ...)")


def _check_governed_execution() -> None:
    """Surface the two execution planes an operator can arm by accident.

    The kernel runs model-written code, so an operator needs to see that it
    is ON and — more importantly — whether it is running against a real
    container sandbox or the local host backend. Refinement is flagged when
    its approval gate is disarmed (the agent can then rewrite its own
    standing instructions with no human in the loop) and when proposals are
    piling up unread."""
    try:
        from .config import get_harness_refine, get_repl
        repl_cfg = get_repl()
        refine_cfg = get_harness_refine()
    except Exception as e:  # pragma: no cover - never break doctor
        _row(YELLOW, "governed-execution", f"config unavailable: {e}")
        return
    if not repl_cfg.get("enable"):
        _row(GREEN, "session-kernel", "disabled (default)")
    else:
        contained = False
        try:
            from .sandbox import container_backend_required
            contained = bool(container_backend_required())
        except Exception:  # pragma: no cover
            contained = False
        if contained:
            _row(GREEN, "session-kernel",
                 "enabled — statements run in a container sandbox")
        else:
            _row(YELLOW, "session-kernel",
                 "enabled WITHOUT a container backend — model-written code "
                 "runs on this host with a scrubbed environment",
                 fix="set [sandbox] backend to a container runtime, or "
                     "unset [repl] enable")
    if not refine_cfg.get("enable"):
        _row(GREEN, "self-refinement", "disabled (default)")
        return
    if not refine_cfg.get("require_approval"):
        _row(RED, "self-refinement",
             "ENABLED with require_approval OFF — the agent can rewrite its "
             "own standing instructions with no human decision",
             fix="set [harness_refine] require_approval = true")
        return
    try:
        from .harness_refine import list_proposals
        pending = len(list_proposals(status="pending"))
    except Exception as exc:
        _row(YELLOW, "self-refinement",
             f"enabled, but the proposal ledger is unreadable ({type(exc).__name__})",
             fix="inspect the harness-refine proposals.json")
        return
    detail = "enabled — every change needs a human approval"
    if pending:
        _row(YELLOW, "self-refinement",
             f"{detail}; {pending} proposal(s) awaiting a decision",
             fix="review them in the approvals queue")
    else:
        _row(GREEN, "self-refinement", detail)


def _check_external_agents() -> None:
    """Surface the bring-your-own-agent gateway state: an enabled plane with
    zero enrollments, contained agents nobody released, and over-budget
    cutoffs — each otherwise visible only when a foreign agent starts
    getting refused."""
    try:
        from .external_agents import roster
        from .external_agents import status as xa_status
        st = xa_status()
    except Exception as e:  # pragma: no cover - never break doctor
        _row(YELLOW, "external-agents", f"status unavailable: {e}")
        return
    if not st.get("enabled"):
        _row(GREEN, "external-agents", "disabled (default)")
        return
    enrolled = int(st.get("enrolled") or 0)
    if enrolled == 0:
        _row(RED, "external-agents",
             "ENABLED but no agents are enrolled — the gateway answers 401 "
             "to everyone",
             fix="enroll an agent on /external-agents, or unset "
                 "[external_agents] enable")
        return
    contained = int(st.get("contained") or 0)
    over_budget = int(st.get("over_budget") or 0)
    detail = f"enabled — {enrolled} agent(s) enrolled"
    if contained or over_budget:
        _row(YELLOW, "external-agents",
             detail + f"; {contained} contained, {over_budget} over budget",
             fix="review and release/reset from /external-agents")
    else:
        _row(GREEN, "external-agents", detail)
    # Same proactive expiry horizon as the trust plane: these are minted
    # credentials that lapse silently.
    import time as _time
    now = _time.time()
    try:
        rows = roster()
    except Exception:  # pragma: no cover - never break doctor
        return
    from .agent_trust import lookup
    for r in rows:
        agent = lookup(r["id"])
        exp = agent.expires_at if agent else None
        if (r.get("active") and isinstance(exp, (int, float))
                and 0 < (exp - now) <= _EXPIRY_HORIZON_S):
            _row(YELLOW, "external-agents",
                 f"agent {r['id']!r} enrollment expires in "
                 f"{(exp - now) / 86400.0:.1f} day(s)",
                 fix="re-enroll before it lapses (/external-agents)")


_EXPIRY_HORIZON_S = 14 * 86400  # warn when a credential expires within 14 days
_TLS_CERT_HORIZON_S = 30 * 86400  # warn when a TLS cert expires within 30 days


def _check_tls_cert_expiry() -> None:
    """Warn before a configured gRPC/federation TLS server cert expires — there
    is no other signal until clients suddenly fail to connect."""
    try:
        from .config import load_config
        from .grpc_tls import tls_enabled
        cfg = load_config() or {}
    except Exception:  # pragma: no cover - never break doctor
        return
    try:
        from cryptography import x509
    except Exception:
        return  # cert parsing needs cryptography; at-rest check already flags it
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    for section in ("grpc", "federation"):
        try:
            section_cfg = cfg.get(section)
            if not isinstance(section_cfg, dict) or not tls_enabled(section, section_cfg):
                continue
            path = section_cfg.get("tls_cert")
            if not path:
                continue
            from pathlib import Path as _P
            data = _P(str(path)).expanduser().read_bytes()
            cert = x509.load_pem_x509_certificate(data)
            try:
                not_after = cert.not_valid_after_utc  # cryptography >= 42
            except AttributeError:  # pragma: no cover - older cryptography
                not_after = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
            remaining = (not_after - now).total_seconds()
            if remaining <= 0:
                _row(RED, f"tls:{section}",
                     f"server cert EXPIRED ({not_after:%Y-%m-%d})",
                     fix=f"renew [{section}] tls_cert")
            elif remaining <= _TLS_CERT_HORIZON_S:
                _row(YELLOW, f"tls:{section}",
                     f"server cert expires in {remaining / 86400:.1f} day(s) "
                     f"({not_after:%Y-%m-%d})",
                     fix=f"renew [{section}] tls_cert before it lapses")
            else:
                _row(GREEN, f"tls:{section}",
                     f"server cert valid until {not_after:%Y-%m-%d}")
        except Exception as e:  # pragma: no cover - a misconfigured cert path
            _row(YELLOW, f"tls:{section}", f"cert unreadable: {type(e).__name__}")


def _check_proxy_auth() -> None:
    """Flag an insecure reverse-proxy-SSO config: proxy auth enabled, but no
    `trusted_proxies` pin and the loopback fallback still active -- any
    co-located loopback process (a sidecar, a pod-netns neighbour, an SSRF pivot
    to 127.0.0.1) could then spoof the forwarded identity header. Advisory only;
    off-by-default proxy auth and a pinned/enterprise config are silent."""
    try:
        from .proxy_auth import (
            _section,
            _trust_loopback_fallback,
            proxy_auth_enabled,
        )
    except Exception:  # pragma: no cover -- never break the doctor
        return
    if not proxy_auth_enabled():
        return  # off by default -> nothing to flag
    trusted = _section().get("trusted_proxies")
    if isinstance(trusted, (list, tuple)) and trusted:
        _row(GREEN, "proxy-auth", "trusted_proxies pinned")
    elif _trust_loopback_fallback():
        _row(YELLOW, "proxy-auth",
             "enabled with no trusted_proxies pin; any loopback process can spoof "
             "the identity header",
             fix="pin [auth.proxy] trusted_proxies, or set trust_loopback = false "
                 "(enterprise mode disables the fallback automatically)")
    else:
        _row(GREEN, "proxy-auth", "loopback fallback disabled")


def diagnose() -> int:
    """Run every health check, print the report, and return the number of
    failed (✗) checks. 0 == healthy. The CLI exits nonzero when this is
    nonzero so a deploy gate or CI can detect a broken install."""
    _FAILURES.clear()
    click.echo(click.style("Lightwork health check\n", bold=True))
    cfg = _check_config()
    _check_config_lint(cfg)
    _check_config_perms()
    _check_profile()
    _check_data_residency(cfg)
    _check_client_binding()
    _check_proxy_auth()
    _check_anthropic()
    _check_openai()
    _check_sandbox(cfg)
    _check_file_work(cfg)
    _check_channels(cfg)
    _check_world_db()
    _check_shield()
    _check_agent_trust()
    _check_external_agents()
    _check_governed_execution()
    _check_tls_cert_expiry()
    click.echo("")
    if _FAILURES:
        click.echo(click.style(
            f"{len(_FAILURES)} check(s) need attention: " + ", ".join(_FAILURES),
            fg="red") + "   Re-run after fixing:  maverick doctor")
        return len(_FAILURES)
    click.echo(click.style("Done.", fg="bright_black") + "  Re-run any time:  maverick doctor")
    return 0


# ---- go-live readiness (maverick launch-check) -----------------------------
#
# diagnose() answers "does this install WORK?"; run_launch_check() answers "are
# the deliberate PRODUCTION switches on?". They are distinct: a box can be
# perfectly healthy (doctor all-green) yet wide open for go-live -- no cost
# caps, plaintext at rest, one shared world for every user, no license trust
# anchor. Each switch reads the same config/env the runtime enforces and NEVER
# raises: an unreadable policy is itself a FAIL, because a go-live gate that
# errors out is worse than one that plainly says "not ready".

_PASS = click.style("PASS", fg="green")
_FAIL = click.style("FAIL", fg="red")


def _launch_row(ok: bool, label: str, detail: str = "", fix: str = "") -> bool:
    line = f"  [{_PASS if ok else _FAIL}] {label}"
    if detail:
        line += click.style(f"  ({detail})", fg="bright_black")
    click.echo(line)
    if not ok and fix:
        click.echo(click.style(f"      → {fix}", fg="cyan"))
    return ok


def _launch_check_cost_caps() -> bool:
    """A workspace or everyone spending limit (Admin > Spending limits), or
    [quotas] enforce = true with at least one non-zero cap."""
    try:
        from . import spending_limits
        limits = spending_limits.load()
    except Exception as e:  # noqa: BLE001 - a go-live gate never aborts
        return _launch_row(False, "cost caps", f"spending limits unreadable: {e}",
                           "save the limits again in Admin > Spending limits")
    set_limits = [f"{name} ${limit['amount']:g} {spending_limits.PERIOD_LABELS[limit['period']]}"
                  for name, limit in (("workspace", limits["workspace"]),
                                      ("everyone", limits["default"])) if limit]
    if set_limits:
        return _launch_row(True, "cost caps", "spending limits: " + ", ".join(set_limits))
    try:
        from .quotas import _quota_config
        cfg = _quota_config()
    except Exception as e:  # noqa: BLE001 - a go-live gate never aborts
        return _launch_row(False, "cost caps", f"quota policy unreadable: {e}",
                           "fix [quotas] config so enforcement is resolvable")
    dollars = float(cfg.get("max_dollars_per_day", 0) or 0)
    tokens = float(cfg.get("max_tokens_per_day", 0) or 0)
    if not cfg.get("enforce"):
        return _launch_row(False, "cost caps", "no spending limit is set",
                           "set a workspace or everyone limit in Admin > Spending limits "
                           "(or [quotas] enforce = true)")
    if dollars <= 0 and tokens <= 0:
        return _launch_row(False, "cost caps",
                           "enforcement on but every cap is 0 (unlimited)",
                           "set [quotas] max_dollars_per_day and/or max_tokens_per_day")
    return _launch_row(True, "cost caps",
                       f"enforced (${dollars:g}/day, {int(tokens)} tok/day)")


def _launch_check_per_user_tenancy() -> bool:
    """Per-user tenant isolation is on (paths.tenant_by_user_enabled)."""
    try:
        from .paths import tenant_by_user_enabled
        on = tenant_by_user_enabled()
    except Exception as e:  # noqa: BLE001
        return _launch_row(False, "per-user tenancy", f"policy unreadable: {e}",
                           "fix [tenancy] by_user (must be a boolean)")
    if on:
        return _launch_row(True, "per-user tenancy",
                           "each user isolated into their own tenant")
    return _launch_row(False, "per-user tenancy",
                       "[tenancy] by_user is off (one shared world for all users)",
                       "set [tenancy] by_user = true (or MAVERICK_TENANT_BY_USER=1)")


def _launch_check_at_rest() -> bool:
    """Encryption at rest is on (MAVERICK_ENCRYPT_AT_REST / [encryption] at_rest)."""
    try:
        from .crypto_at_rest import at_rest_enabled
        on = at_rest_enabled()
    except Exception as e:  # noqa: BLE001
        return _launch_row(False, "encryption at rest", f"policy unreadable: {e}",
                           "fix [encryption] at_rest (must be a boolean)")
    if on:
        try:
            from .crypto_at_rest import strict_at_rest
            from .world_model import DEFAULT_DB, migrated_marker_path
            strict = strict_at_rest() or migrated_marker_path(DEFAULT_DB).exists()
        except Exception:  # noqa: BLE001 -- the posture detail never fails the row
            strict = False
        if strict:
            return _launch_row(True, "encryption at rest", "on (strict)")
        return _launch_row(True, "encryption at rest",
                           "on; unsealed legacy values are still accepted",
                           "run 'maverick encryption migrate' to seal and bind them")
    return _launch_row(False, "encryption at rest", "disabled",
                       "unset MAVERICK_ENCRYPT_AT_REST=0 or set [encryption] at_rest = true")


def _launch_check_provider() -> bool:
    """A provider API key / endpoint is resolvable (config.any_provider_configured)."""
    try:
        from .config import any_provider_configured
        ok = any_provider_configured()
    except Exception as e:  # noqa: BLE001
        return _launch_row(False, "provider credential", f"probe failed: {e}",
                           "set a provider key (e.g. ANTHROPIC_API_KEY)")
    if ok:
        return _launch_row(True, "provider credential",
                           "a provider key/endpoint is resolvable")
    return _launch_row(False, "provider credential",
                       "no provider credential resolvable",
                       "set a provider key (e.g. ANTHROPIC_API_KEY) or a "
                       "[providers.<name>] api_key/base_url")


#: The go-live switches, in report order. Each returns True (PASS) / False (FAIL)
#: and prints its own row; all are self-guarding so one failure can't abort the
#: gate.
_LAUNCH_CHECKS = (
    _launch_check_cost_caps,
    _launch_check_per_user_tenancy,
    _launch_check_at_rest,
    _launch_check_provider,
)


def run_launch_check() -> int:
    """Print PASS/FAIL for each go-live switch; return the number of FAILs (0 ==
    ready). The CLI exits nonzero on any FAIL so a deploy gate can block."""
    click.echo(click.style("Lightwork go-live check\n", bold=True))
    failed = sum(1 for check in _LAUNCH_CHECKS if not check())
    click.echo("")
    if failed:
        click.echo(click.style(
            f"{failed} switch(es) not ready for go-live.", fg="red")
            + "   Re-run after fixing:  maverick launch-check")
        return failed
    click.echo(click.style("All go-live switches are on.", fg="green")
               + "  You're clear for go-live.")
    return 0
