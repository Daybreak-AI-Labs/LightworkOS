"""Lightwork CLI."""
from __future__ import annotations

import asyncio
import functools
import logging
import math
import os
import re
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

import click

from ..sandbox_names import BUILTIN_SANDBOX_BACKENDS

# Keep the top-level import surface
# minimal so `maverick --help` and `maverick version` don't pay for
# heavy submodules (orchestrator, agent, swarm, skills, sandbox) they
# never use. Submodules import lazily inside the command bodies that
# actually need them. ``world_model`` must be lazy too: importing it performs
# storage admission for its compatibility ``DEFAULT_DB`` hook, while diagnostic
# commands such as ``config-lint`` must be able to report a corrupt client
# configuration before any storage path is admitted.


def open_world(*args, **kwargs):
    """Lazy compatibility facade for the CLI's many world-model commands."""
    from ..world_model import open_world as _open_world

    return _open_world(*args, **kwargs)

_TERMINAL_CONTROL_RE = re.compile(
    r"(?:\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$))"
    r"|(?:\x1b\[[0-?]*[ -/]*[@-~])"
    r"|(?:\x1b[@-Z\\-_])"
    r"|[\x00-\x1f\x7f-\x9f]"
)


def _strip_terminal_control(text: str) -> str:
    """Remove terminal control bytes before rendering untrusted text."""
    return _TERMINAL_CONTROL_RE.sub("", text)


def _strip_result_terminal_control(text: str) -> str:
    """Remove escape sequences and unsafe controls, keeping answer layout."""
    return _TERMINAL_CONTROL_RE.sub(
        lambda match: match.group() if match.group() in {"\n", "\t"} else "", text,
    )


def _default_model(role: str = "orchestrator") -> str:
    """The configured model for ``role`` (kernel rule 2: never a hard-coded
    model). Resolves through ``model_for_role`` -- per-role overrides, the
    ``[models]`` config, dashboard pins and the admin allow-list -- the same
    way the dashboard and the channel server pick the model for the same
    action. Lazy so importing the CLI doesn't pull ``.llm`` (and the anthropic
    SDK)."""
    from ..llm import model_for_role
    return model_for_role(role)


def _cli_model(ctx: click.Context, role: str) -> str:
    """An explicit ``--model`` wins; otherwise the configured ``role`` model."""
    return (ctx.obj or {}).get("model") or _default_model(role)


def _cli_task_budget(title: str, max_dollars: float | None, default_dollars: float):
    """Apply task budget precedence with a command's historical dollar fallback."""
    import types

    from ..budget import budget_from_config
    from ..orchestrator import _budget_task_class
    return budget_from_config(
        defaults={"max_dollars": default_dollars},
        task_class=_budget_task_class(types.SimpleNamespace(title=title)),
        max_dollars=max_dollars,
    )


def _fact_subject_token(channel: str, user: str) -> str:
    """Stable, delimiter-safe token for explicitly user-scoped facts."""
    return f"{quote(channel, safe='')}:{quote(user, safe='')}"


def _model_route_configuration_missing(
    model_spec: str | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Return the selected model provider and its missing prerequisites.

    A global "some credential exists" probe cannot answer whether the route
    this command will actually instantiate is usable. It also rejects valid
    keyless routes such as Ollama/vLLM/TGI localhost defaults and authenticated
    Codex CLI installs. Delegate to the operator preflight's provider contract
    so the CLI and preflight cannot drift.
    """
    from ..config import load_config
    from ..operator_preflight import _route_configuration_missing
    from ..providers import _canonical

    spec = str(model_spec or _default_model("orchestrator")).strip()
    provider = _canonical(spec.split(":", 1)[0] if ":" in spec else "anthropic")
    return provider, _route_configuration_missing(provider, load_config())


def _require_llm_key(model_spec: str | None = None) -> str:
    """Refuse cleanly when a selected route (or any swarm route) is incomplete."""
    try:
        if model_spec is None:
            from ..config import load_config
            from ..operator_preflight import _routed_configuration_missing

            routed = _routed_configuration_missing(load_config())
            missing_routes = {
                provider: fields
                for provider, fields in routed.items()
                if fields
            }
        else:
            provider, missing = _model_route_configuration_missing(model_spec)
            missing_routes = {provider: missing} if missing else {}
    except Exception:
        missing_routes = {"selected": ("configuration",)}
    if not missing_routes:
        return "config"
    from ..operator_preflight import _format_route_missing

    detail = _format_route_missing(missing_routes)
    click.echo(
        "Lightwork can't reach an LLM through every selected model route. "
        f"Missing: {detail}.\n"
        "\n"
        "Add its key in Lightwork > Settings (on a computer with no Lightwork\n"
        "setup yet, run:  maverick init)\n"
        "Then verify it with:  maverick preflight",
        err=True,
    )
    sys.exit(2)


def _warn_file_work_before_start(config: dict, backend: str | None) -> None:
    """Explain first-run file limits before a task can incur provider cost."""
    from ..health import file_work_notice

    notice = file_work_notice(config, backend=backend)
    if notice:
        click.echo(f"Before starting: {notice}\n  Check again with: lightwork doctor", err=True)


def _humanize_run_error(e: Exception) -> str:
    """Map an operational run failure to a one-line, actionable message.

    Sandbox/provider errors must not reach the user as a raw traceback. The
    failures a consumer actually hits -- no Docker daemon, a rejected or
    typo'd key, a dropped connection, exhausted credits -- each get a plain
    sentence and a next step instead.
    """
    name = type(e).__name__.lower()
    msg = str(e).strip()
    low = msg.lower()
    from ..runtime_overrides import RuntimeOverridesSecurityError

    if isinstance(e, RuntimeOverridesSecurityError):
        return (
            "Lightwork stopped because the operator policy is unavailable.\n"
            "  Restore or repair runtime-overrides.toml, then run "
            "`maverick doctor` before retrying."
        )
    from ..budget import UsageAccountingError

    if isinstance(e, UsageAccountingError):
        # A gateway fault, not a cap breach: say so, and don't send
        # the user off to raise max_dollars.
        return (
            "The model provider returned invalid usage accounting, so Lightwork "
            "stopped rather than run uncounted against your spending cap.\n"
            f"  {msg}\n"
            "  This is a provider/gateway fault, not a budget problem: fix or "
            "route around the gateway, then retry."
        )
    # Sandbox backends already raise an actionable RuntimeError, e.g.
    # "Docker not available. ... change [sandbox] backend to 'local'".
    if isinstance(e, RuntimeError) and (
        "not available" in low or "docker" in low or "podman" in low
        or "sandbox" in low
    ):
        return f"Couldn't start the sandbox.\n  {msg}"
    if "authentication" in name or "invalid x-api-key" in low or "401" in msg:
        return (
            "Your LLM API key was rejected (401).\n"
            "  Check the key in ~/.maverick/.env or your shell, then retry.\n"
            "  Diagnose with:  maverick doctor"
        )
    # A typo'd / unavailable model id surfaces as a provider 404 (Anthropic/
    # OpenAI raise NotFoundError). Point at `maverick config`, where [models]
    # are set -- NOT `maverick doctor`, which only validates the API key and
    # would send the user chasing a non-existent auth problem.
    if "notfound" in name or "404" in msg or ("model" in low and "not found" in low):
        return (
            "The model id wasn't found by the provider (404).\n"
            "  This usually means a typo'd or unavailable model id.\n"
            "  Check the model in [models]:  maverick config"
        )
    if "ratelimit" in name or "429" in msg:
        return ("The LLM provider rate-limited this run (429). "
                "Wait a moment and retry.")
    if ("connection" in name or "timeout" in name
            or "connect" in low or "network" in low):
        return ("Couldn't reach the LLM provider. Check your network "
                "connection, then retry.")
    if "quota" in low or "credit" in low or "insufficient" in low or "billing" in low:
        return (f"The LLM provider refused the request: {msg}\n"
                "  Check your plan / billing, then retry.")
    # Anything unanticipated: a short line, not a 20-frame stack trace.
    return (
        "The run stopped on an unexpected error.\n"
        f"  {type(e).__name__}: {msg}\n"
        "  Re-run with MAVERICK_DEBUG=1 for the full traceback, "
        "or check `maverick doctor`."
    )


def _humane_errors(fn):
    """Wrap a run-driving command so operational failures print a friendly
    message and exit non-zero instead of dumping a traceback (and exiting 0).

    Set ``MAVERICK_DEBUG=1`` to bypass and re-raise the original exception.
    Use as the innermost decorator (closest to ``def``).
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (SystemExit, click.ClickException, click.Abort):
            raise
        except KeyboardInterrupt:
            click.echo("\nInterrupted.", err=True)
            sys.exit(130)
        except Exception as e:  # noqa: BLE001 -- top-level humane boundary
            if os.environ.get("MAVERICK_DEBUG"):
                raise
            click.echo(_humanize_run_error(e), err=True)
            sys.exit(1)
    return wrapper


def _kernel():
    """Lazy-import the agent-runtime modules into a single namespace.

    Importing ``.orchestrator`` transitively pulls agent + swarm +
    blackboard + sandbox + skills + tools (~30 ms). Commands that
    don't drive the agent (``version``, ``doctor``, ``config``,
    ``audit``, ``cache``, ``retention``, ``skill *``, ``template *``)
    never need any of it. Call this at the top of any command that does.
    """
    import types

    from ..budget import Budget
    from ..llm import LLM
    from ..orchestrator import run_goal_sync
    from ..sandbox import build_sandbox
    from ..secrets import scrub
    return types.SimpleNamespace(
        Budget=Budget, LLM=LLM,
        run_goal_sync=run_goal_sync, build_sandbox=build_sandbox, scrub=scrub,
    )


def _run_outcome_blocked(world, goal_id: int) -> bool:
    """Report blocked or unsuccessful terminal outcomes to CLI automation."""
    try:
        goal = world.get_goal(goal_id)
    except Exception:
        # An unreadable verdict cannot certify a successful run.
        return True
    return bool(goal and goal.status in {"blocked", "failed", "cancelled"})


@contextmanager
def _cli_sandbox(kernel, **kwargs):
    """Release the CLI-owned work area on success, refusal and exceptions."""
    sandbox = kernel.build_sandbox(**kwargs)
    try:
        yield sandbox
    finally:
        close = getattr(sandbox, "close", None)
        if close is not None:
            close()


def _write_cli_result(write, *args, **kwargs) -> None:
    """Do not replace an active run exception with an export failure."""
    run_error = sys.exc_info()[1]
    try:
        write(*args, **kwargs)
    except Exception as exc:
        if run_error is None:
            raise
        click.echo(f"Could not write the run result: {exc}", err=True)


def _require_cli_execution_allowed() -> None:
    from .. import killswitch
    from ..paths import current_tenant_id_strict
    from ..tenant.registry import TenantSuspended, assert_tenant_active

    try:
        killswitch.check()
    except killswitch.Halted:
        click.echo(
            "Stopped: Lightwork is halted (a HALT file is present).\n"
            "Run `maverick unhalt` to clear it, then try again.", err=True,
        )
        raise SystemExit(3) from None
    try:
        assert_tenant_active(current_tenant_id_strict())
    except TenantSuspended as exc:
        click.echo(f"Stopped: {exc}", err=True)
        raise SystemExit(3) from None


def _require_known_cli_tenant(tenant: str | None) -> None:
    from ..tenant.registry import get_tenant, list_tenants

    if tenant and list_tenants() and get_tenant(tenant) is None:
        click.echo(f"ERROR: no such tenant {tenant!r}. Check the tenant id.", err=True)
        raise SystemExit(2)


def _maybe_start_progress_poller(world_path, goal_id, stop_poll):
    """Start the background goal-events poller, or return None when it should
    stay quiet: output isn't a TTY (don't litter piped logs), MAVERICK_NO_PROGRESS
    is set (runtime override), or [features] streaming is off (persistent opt-out)."""
    import threading

    from ..config import get_features
    # No pollable local DB file (e.g. the Postgres backend, whose .path is None):
    # file-based progress streaming does not apply. Skip rather than crash.
    if world_path is None:
        return None
    try:
        streaming_on = get_features()["streaming"]
    except Exception:
        streaming_on = True
    if (not click.get_text_stream("stderr").isatty()
            or os.environ.get("MAVERICK_NO_PROGRESS")
            or not streaming_on):
        return None
    poller = threading.Thread(
        target=_stream_progress, args=(world_path, goal_id, stop_poll), daemon=True,
    )
    poller.start()
    return poller


_CLI_SECURITY_WARNING_LOGGERS = ("maverick.sandbox", "maverick.orchestrator")


class _CliDefaultWarningFilter(logging.Filter):
    """Keep routine WARNING noise quiet while surfacing safety warnings."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.ERROR:
            return True
        return any(
            record.name == name or record.name.startswith(f"{name}.")
            for name in _CLI_SECURITY_WARNING_LOGGERS
        )


def _configure_cli_logging() -> None:
    """Keep routine library log lines off the consumer's terminal by default.

    The CLI installs no log handler, so Python's last-resort handler dumps any
    library WARNING/ERROR (e.g. "ignoring unreadable config.toml
    (TOMLDecodeError...)") straight to stderr mid-run. Install a root handler
    so routine warnings are suppressed by default while security-posture
    warnings still surface:

      - ``MAVERICK_DEBUG`` set  -> verbose: DEBUG-level logs to stderr.
      - ``MAVERICK_LOG_LEVEL``  -> honored as-is (operators who want logs).
      - otherwise               -> ERROR+ reaches the terminal, plus WARNING
        diagnostics from the sandbox / Shield safety path.

    Delegates to ``logging_config.configure_logging`` (idempotent) so the
    JSON-format / context-filter wiring stays in one place.
    """
    from ..logging_config import configure_logging
    default_warning_filter = False
    if os.environ.get("MAVERICK_DEBUG"):
        level = "DEBUG"
    elif os.environ.get("MAVERICK_LOG_LEVEL"):
        # Explicit operator logging preference wins as-is.
        level = os.environ["MAVERICK_LOG_LEVEL"]
    else:
        # Root must admit WARNING records so the filter below can pass through
        # sandbox / Shield safety warnings while dropping routine library noise.
        level = "WARNING"
        default_warning_filter = True
    try:
        configure_logging(level=level)
        if default_warning_filter:
            safety_filter = _CliDefaultWarningFilter()
            for handler in logging.getLogger().handlers:
                handler.addFilter(safety_filter)
    except Exception:  # pragma: no cover -- logging setup must never break the CLI
        pass


def _configure_cli_text_streams() -> None:
    """Keep redirected/frozen Windows consoles from crashing on Unicode.

    PyInstaller can freeze ``sys.stdout``/``stderr`` with the active Windows
    code page (often cp1252) and ``errors='strict'``.  Lightwork's human-facing
    CLI intentionally uses a few status glyphs, so one unrepresentable glyph
    must degrade to ``?`` rather than aborting an otherwise healthy command.
    Preserve the selected encoding and only relax the error policy.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            # Click's test streams and embedded hosts may not be reconfigurable.
            # Their existing encoding policy remains authoritative.
            continue


@click.group(epilog=(
    "New here? Start with these four:\n"
    "\n"
    "\b\n"
    "  maverick init            set up (API key, sandbox, budget)\n"
    "  maverick start \"...\"      run a task\n"
    "  maverick chat            talk to it interactively\n"
    "  maverick doctor          check your setup\n"
    "\n"
    "The other commands are for power users; most people never need them."
))
@click.option("--db", default=None,
              help="World model database path (default: the active tenant's world.db).")
@click.option("--model", default=None, help="LLM model id (default: from config).")
@click.pass_context
def main(ctx: click.Context, db: str | None, model: str | None) -> None:
    """Lightwork: multi-agent swarm for long-horizon work."""
    _configure_cli_text_streams()
    _configure_cli_logging()
    ctx.ensure_object(dict)
    # Diagnostic commands must keep running on a broken installation so they
    # can report it; everything else stays behind the recovery gate.
    if ctx.invoked_subcommand not in {
        "dashboard", "installation-maintenance", "version", "doctor",
        "config-lint", "preflight",
    }:
        from ..installation_recovery import MaintenanceError, assert_normal_start_allowed
        try:
            assert_normal_start_allowed()
        except MaintenanceError as exc:
            raise click.ClickException(str(exc)) from exc
    if ctx.invoked_subcommand == "mcp":
        from .._mcp_parent_guard import ParentGuardError, arm_from_environment

        try:
            arm_from_environment()
        except ParentGuardError as exc:
            raise click.ClickException(
                f"refusing unsafe tagged MCP launch: {exc}"
            ) from exc
    if ctx.invoked_subcommand not in {
        "tenant", "config-lint", "doctor", "gen-stubs", "init",
        "installation-maintenance", "launch-check", "preflight", "version",
    }:
        from ..paths import current_tenant_id_strict

        _require_known_cli_tenant(current_tenant_id_strict())
    # Default the world DB to the ACTIVE TENANT's world.db (selected via
    # MAVERICK_TENANT) so one business's run history / goals / facts never pool
    # into another's -- the same isolation the channel server already gets via
    # world_for_tenant(). With no tenant this resolves to the legacy
    # ~/.maverick/world.db, so single-tenant installs are unchanged. An explicit
    # --db always wins.
    if db is None:
        if ctx.invoked_subcommand in {
            "config-lint",
            "doctor",
            "gen-stubs",
            "init",
            "installation-maintenance",
            "launch-check",
            "preflight",
            "version",
        }:
            # These setup/diagnostic commands never need the world DB. A
            # corrupt config can make the strict client floor unknowable, so
            # resolving the ordinary Workspace path here would abort before
            # the command can report or repair the problem. `init` belongs in
            # this set because it is the recovery path for a broken config.
            from ..paths import diagnostic_data_dir

            db = str(diagnostic_data_dir("world.db"))
        else:
            from ..workspace import Workspace

            db = str(Workspace.current().db_path)
    ctx.obj["db"] = Path(db)
    if model:
        from ..llm import ModelNotAllowedError, require_model_allowed

        try:
            model = require_model_allowed(model)
        except (ModelNotAllowedError, ValueError) as exc:
            raise click.BadParameter(str(exc), param_hint="'--model'") from exc
    ctx.obj["model"] = model  # resolved lazily on first use
    # `--model` is a run-wide override. The agents resolve their model via
    # model_for_role(), not the LLM facade's default, so threading it through
    # the env is what actually makes the flag apply to every agent (it was
    # silently ignored before -- the LLM default got overridden per call).
    if model:
        os.environ["MAVERICK_MODEL_OVERRIDE"] = model


@main.command("installation-maintenance", hidden=True)
@click.argument(
    "step",
    type=click.Choice([
        "status", "repair-capability", "authorize-repair", "inspect", "prepare",
        "execute", "resume", "logs",
        "save-native-review", "inspect-handoff", "offline-review", "offline-authorize", "recovery-plan",
    ]),
)
def installation_maintenance_cmd(step: str) -> None:
    """Fixed native maintenance protocol; authorization travels over stdin."""
    import json

    from .. import installation_recovery as recovery
    try:
        raw = sys.stdin.read(65537) if step != "status" else "{}"
        if len(raw) > 65536:
            raise recovery.MaintenanceError("The maintenance request exceeds its size limit.")
        request = json.loads(raw)
        if step == "status":
            result = recovery.status()
        elif step == "save-native-review":
            from ..installation_handoff import save_review
            result = save_review(request.get("release"))
        elif step == "inspect-handoff":
            from ..installation_handoff import inspect_handoff
            result = inspect_handoff()
        elif step == "offline-review":
            from ..installation_offline import review
            result = review(request.get("folder"), public_key=request.get("public_key", ""))
        elif step == "offline-authorize":
            from ..installation_offline import authorize
            result = authorize(request.get("review"), confirm=request.get("confirm") is True)
        elif step == "recovery-plan":
            from ..installation_planner import plan
            result = plan(request.get("id"), offset=request.get("offset", 0))
        elif step == "repair-capability":
            result = recovery.repair_capability(
                expected_runtime_sha256=request.get("runtime_sha256"),
                expected_installer_sha256=request.get("installer_sha256"),
                expected_public_key=request.get("public_key"),
                expected_version=request.get("version"),
            )
        elif step == "authorize-repair":
            expected = {
                "expected_runtime_sha256": request.get("runtime_sha256"),
                "expected_installer_sha256": request.get("installer_sha256"),
                "expected_public_key": request.get("public_key"),
                "expected_version": request.get("version"),
            }
            result = recovery.authorize_repair(
                actor="native-desktop-repair",
                confirm_all_workspaces=request.get("confirm") is True,
                **({} if all(value is None for value in expected.values()) else expected),
            )
        elif step == "logs":
            result = recovery.logs(request.get("id"))
        elif step == "inspect":
            result = recovery.inspect_grant(request.get("authorization"))
        elif step == "prepare":
            result = recovery.prepare(request.get("authorization"))
        elif step == "resume":
            identifier = request.get("id")
            token = recovery.resume(identifier)
            result = recovery.inspect_grant(token) | {"authorization": token}
        else:
            # The retained helper must outlive the installed desktop executable.
            # Wait only for the native parent supplied by our fixed local IPC.
            import ctypes
            parent_pid = request.get("parent_pid")
            if os.name != "nt" or not isinstance(parent_pid, int) or parent_pid <= 0:
                raise recovery.MaintenanceError("The native maintenance parent is unavailable.")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.restype = ctypes.c_void_p
            kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            handle = kernel.OpenProcess(0x00100000, False, parent_pid)
            if handle:
                try:
                    if kernel.WaitForSingleObject(handle, 60000) != 0:
                        raise recovery.MaintenanceError("Close the previous desktop maintenance window before retrying.")
                finally:
                    kernel.CloseHandle(handle)
            authorization = request.get("authorization")
            details = recovery.inspect_grant(authorization)
            directory = recovery._directory(details["id"])
            try:
                result = recovery.execute(authorization)
            finally:
                record = recovery._read(directory / "record.json")
                installed = Path(record["installed_runtime"]).parent / "maverick-desktop.exe"
                desktop = installed if installed.is_file() and record.get("status") in {
                    "upgraded", "upgrade_recovered", "rolled_back", "repaired", "repair_recovered",
                } else directory / "maverick-desktop.exe"
                import subprocess
                # Native production calls always open their result window.
                # The disposable CI protocol harness may suppress the window;
                # this changes no maintenance authority or verification gate.
                if request.get("open_result") is not False:
                    # This desktop outlives the onefile helper. Its later
                    # rollback must unpack a fresh helper, not reuse this
                    # process's temporary runtime after bootloader cleanup.
                    subprocess.Popen([str(desktop), "--maintenance-result", details["id"]],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"},
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        click.echo(json.dumps(result))
    except Exception as exc:
        # No request bodies, grant tokens, signing keys or workspace payloads.
        raise click.ClickException(str(exc)) from exc


@main.command("gen-stubs")
def gen_stubs_cmd() -> None:
    """Pre-generate gRPC stubs (for immutable/locked-down images).

    Run at image/VM build time, then set MAVERICK_NO_RUNTIME_PROTOC=1 so the
    runtime never invokes protoc (read-only FS / SBOM integrity)."""
    from ..grpc_stubs import generate_all
    try:
        done = generate_all()
    except Exception as e:
        raise click.ClickException(f"stub generation failed: {e}") from e
    click.echo(click.style("generated: " + ", ".join(done), fg="green"))


def _install_config_from_file(src: str) -> None:
    """Headless provisioning: validate SRC and install it as config.toml (0600)."""
    from pathlib import Path as _P

    from ..config_install import (
        ConfigInstallError,
        blocking_config_findings,
        config_findings,
        install_config_bytes,
        parse_config_bytes,
    )
    src_path = _P(src).expanduser()
    if not src_path.is_file():
        raise click.ClickException(f"no such config file: {src}")
    try:
        data = src_path.read_bytes()
        cfg = parse_config_bytes(data)
    except (ConfigInstallError, OSError) as e:
        raise click.ClickException(f"invalid TOML in {src}: {e}") from e
    try:
        findings = config_findings(cfg)
    except Exception as exc:  # noqa: BLE001 -- never install when validation is unavailable
        raise click.ClickException(f"could not check settings; no changes made: {exc}") from exc
    blocking = blocking_config_findings(findings)
    for finding in findings:
        click.echo(click.style(f"  ! {finding.section}: {finding.message}",
                               fg="red" if finding in blocking else "yellow"), err=True)
    if blocking:
        raise click.ClickException(
            f"{len(blocking)} setting(s) cannot be used by this version of Lightwork. "
            "Correct them and try again; no changes were made."
        )
    try:
        result = install_config_bytes(data, backup=True)
    except OSError as exc:
        raise click.ClickException(f"could not install settings; the previous file remains: {exc}") from exc
    dst = result["path"]
    if result["unchanged"]:
        click.echo(click.style(f"config unchanged -> {dst} (0600)", fg="green"))
        return
    click.echo(click.style(f"installed config -> {dst} (0600)", fg="green"))
    if result["backup"]:
        click.echo(f"previous settings saved -> {result['backup']}")


@main.command()
@click.option("--fast", is_flag=True,
              help="Skip every prompt; use recommended defaults.")
@click.option("--resume", is_flag=True,
              help="Resume from the last unanswered wizard question.")
@click.option("--from-file", "from_file", default=None,
              help="Headless: install this config.toml (validated) — no prompts.")
def init(fast: bool, resume: bool, from_file: str | None) -> None:
    """Run the interactive setup wizard (or --from-file for headless provisioning)."""
    if from_file:
        _install_config_from_file(from_file)
        return
    try:
        from maverick_installer.wizard import run as run_wizard
    except ImportError as exc:
        if isinstance(exc, ModuleNotFoundError) and exc.name == "maverick_installer":
            # First-party public namespaces are not yet reserved; never send
            # an operator to an unreviewed package index for the installer.
            click.echo(
                "Install the installer component from the same reviewed Lightwork "
                "checkout; public-index lookup is disabled. See "
                "docs/getting-started.md.",
                err=True,
            )
        else:
            click.echo(
                f"Lightwork setup could not load: {_strip_terminal_control(str(exc))}. "
                "Run `maverick doctor` "
                "to check the installation before retrying.",
                err=True,
            )
        sys.exit(2)
    sys.exit(run_wizard(fast=fast, resume=resume))


@main.command()
def doctor() -> None:
    """Diagnose your Lightwork installation."""
    from ..health import diagnose
    if diagnose():
        # At least one ✗ check: exit nonzero so `maverick doctor && ...` and CI
        # health gates can detect a broken install (it always exited 0 before).
        sys.exit(1)


@main.command("shared-key-digest", hidden=True)
def shared_key_digest() -> None:
    """Print sha256:<hex> of the injected at-rest key.

    This is the value to set as MAVERICK_ENCRYPTION_KEY_DIGEST -- the operator
    trust anchor a Postgres (shared-authority) deployment requires for governed
    records. Output is a one-way hash of the key, never the key itself, so it
    is safe to store in IaC. Reads the key from the process environment exactly
    as crypto_at_rest does; run it wherever MAVERICK_ENCRYPTION_KEY is injected.
    """
    from ..installation_info import KeyDigestError, encryption_key_digest

    try:
        digest = encryption_key_digest()
    except KeyDigestError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    click.echo(digest)


@main.command("launch-check")
def launch_check() -> None:
    """Verify the platform is configured for go-live (PASS/FAIL, exits nonzero
    on any FAIL).

    Distinct from ``maverick doctor`` (which diagnoses whether the install
    *works*): this asserts the deliberate production switches are ON --
    cost-cap enforcement, per-user tenant isolation, at-rest encryption, and a
    resolvable provider key. Each row reads real config/env, so
    ``maverick launch-check`` is safe to gate a deploy on."""
    from ..health import run_launch_check
    if run_launch_check():
        sys.exit(1)


@main.command()
def version() -> None:
    """Show installed package versions + runtime info."""
    from ..installation_info import package_versions, runtime_facts

    click.echo(click.style("Lightwork installed packages", bold=True))
    for display, version in package_versions():
        if version:
            click.echo(f"  {display:22s} {version}")
        else:
            click.echo(f"  {display:22s} " + click.style("not installed", fg="yellow"))
    click.echo("")
    click.echo(click.style("Runtime", bold=True))
    facts = runtime_facts()
    if facts["schema"] is not None:
        click.echo(f"  schema:                v{facts['schema']}")
    if facts["shield_backend"] is not None:
        click.echo(f"  shield backend:        {facts['shield_backend']}")
    else:
        click.echo("  shield backend:        (maverick-shield not installed)")
    native = facts.get("native_acceleration")
    if native:
        click.echo(f"  unicode scanner:       {native['unicode']}")
        click.echo(f"  image hash:            {native['image_hash']}")
    if facts["providers"] is not None:
        click.echo(f"  providers:             {', '.join(facts['providers'])}")
    p = facts["persona"]
    if p is not None:
        if p.get("name") or p.get("style"):
            ident = p.get("name") or "(unnamed)"
            style = p.get("style") or "(default)"
            click.echo(f"  persona:               {ident} ({style})")
        else:
            click.echo("  persona:               (none)")
    click.echo(f"  python:                {facts['python']}")
    click.echo(f"  platform:              {facts['platform']}")


@main.command("release-runtime-check")
def release_runtime_check() -> None:
    """Verify packaged providers, parsers, SQL, MathML and metrics offline."""
    from ..release_runtime import libpq_label, verify_full_release_runtime

    try:
        libpq_version = verify_full_release_runtime()
    except Exception as exc:
        raise click.ClickException(
            f"full release runtime is unavailable: {exc}"
        ) from exc
    click.echo(
        "release runtime ready: Anthropic and OpenAI-compatible provider "
        "SDKs, document parsers and document worker source are available; "
        "offline SQL, bundled PostgreSQL driver "
        f"(libpq {libpq_label(libpq_version)}), "
        "MathML and metrics checks passed"
    )


def _reporting_world(ctx: click.Context):
    from ..world_model import open_world

    if ctx.parent is not None and ctx.parent.params.get("db") is not None:
        from ..world_model_backends import is_postgres_configured

        if is_postgres_configured():
            raise click.UsageError(
                "--db selects a local database file and cannot select a Postgres database. "
                "Omit --db to report on the configured Postgres workspace."
            )
    return open_world(ctx.obj["db"])


@main.command()
@click.option("--json", "as_json", is_flag=True,
              help="Machine-readable output for FinOps/BI scripts.")
@click.option("--tag-field", "tag_field", default="tag", show_default=True,
              help="Episode/goal field to attribute spend by (team / project / cost-center).")
@click.option("--limit", default=500, show_default=True,
              help="Max recent priced episodes to scan.")
@click.option("--top", default=15, show_default=True,
              help="Show the top N goals by cost.")
@click.pass_context
def spend(ctx: click.Context, as_json: bool, tag_field: str, limit: int, top: int) -> None:
    """Print spend — total, per-goal, and per-tag run costs.

    The CLI face of the /spend dashboard: pull FinOps data into scripts and
    chargeback exports without the dashboard. Use --json for a stable shape.
    """
    import json as _json

    from ..cost.by_tag import gather, render, split_by_tag
    from ..world_model import close_world_if_owned
    w = _reporting_world(ctx)
    total = w.total_spend()

    by_goal: dict[int, dict] = {}
    for e in w.list_episodes(limit=max(limit, top * 8)):
        b = by_goal.setdefault(e.goal_id, {
            "goal_id": e.goal_id, "cost": 0.0,
            "input_tokens": 0, "output_tokens": 0, "runs": 0,
            "cache_read_tokens": 0, "cache_write_tokens": 0})
        b["cost"] += e.cost_dollars
        b["input_tokens"] += e.input_tokens
        b["output_tokens"] += e.output_tokens
        b["cache_read_tokens"] += getattr(e, "cache_read_tokens", 0)
        b["cache_write_tokens"] += getattr(e, "cache_write_tokens", 0)
        b["runs"] += 1
    goals = sorted(by_goal.values(), key=lambda x: x["cost"], reverse=True)[:top]
    for g in goals:
        try:
            go = w.get_goal(g["goal_id"])
        except Exception:
            go = None
        g["cost"] = round(g["cost"], 6)
        g["title"] = (go.title if go else "") or ""
        # Token-efficiency baseline: work bought per dollar, and how much of
        # the input bill the prompt cache absorbed. billable input = fresh
        # input tokens; cache reads are the 0.1x-priced remainder.
        toks = g["input_tokens"] + g["output_tokens"]
        g["tokens_per_dollar"] = round(toks / g["cost"]) if g["cost"] > 0 else None
        denom = g["input_tokens"] + g["cache_read_tokens"]
        g["cache_hit_rate"] = (
            round(g["cache_read_tokens"] / denom, 4) if denom else None)

    tags = split_by_tag(gather(w, tag_field=tag_field, limit=limit))
    close_world_if_owned(w)

    if as_json:
        click.echo(_json.dumps(
            {"total": total, "by_goal": goals, "by_tag": tags,
             "tag_field": tag_field}, indent=2))
        return

    click.echo(click.style("Total spend", bold=True))
    click.echo(
        f"  ${total['dollars']:.4f}   "
        f"{int(total['input_tokens']):,} in / {int(total['output_tokens']):,} out tok   "
        f"{int(total['runs'])} runs")
    click.echo("")
    click.echo(click.style(f"Top {len(goals)} goals by cost", bold=True))
    if not goals:
        click.echo("  (no priced episodes yet)")
    for g in goals:
        title = g["title"]
        if len(title) > 44:
            title = title[:43] + "…"
        eff = ""
        if g.get("tokens_per_dollar"):
            eff = f"  {g['tokens_per_dollar']:,} tok/$"
        if g.get("cache_hit_rate") is not None:
            eff += f"  cache {g['cache_hit_rate'] * 100:.0f}%"
        click.echo(f"  ${g['cost']:>9.4f}  #{g['goal_id']:<5} {title}  "
                   f"({g['runs']} runs){eff}")
    click.echo("")
    click.echo(click.style(f"Spend by {tag_field}", bold=True))
    click.echo("  " + render(tags).replace("\n", "\n  "))


@main.command()
@click.option("--json", "as_json", is_flag=True,
              help="Machine-readable posture for CI assertions.")
def safety(as_json: bool) -> None:
    """Print the safety posture — shield, sandbox backend, egress policy.

    Assert deployment safety in CI without the dashboard (e.g. fail a pipeline
    if the sandbox is unisolated). Exits 0; gate on the --json fields.
    """
    import json as _json

    from ..config import get_sandbox, load_config
    try:
        from maverick_shield import Shield
        shield = {"installed": True,
                  "backend": Shield.from_config(warn_if_missing=False).backend}
    except ImportError:
        shield = {"installed": False, "backend": None}
    except Exception:
        shield = {"installed": True, "backend": None}

    sb = get_sandbox()
    backend = str(sb.get("backend", "local") or "local").strip().lower()
    from ..sandbox import (
        SandboxPolicyError,
        _container_backend_required,
        _deployment_policy,
        _offline_policy,
        _resolve_local_under_policy,
    )
    try:
        full = load_config().get("sandbox", {})
        resolved, full = _deployment_policy(sb, full, None, None)
        backend = str(resolved.get("backend") or "local").strip().lower()
        full = _offline_policy(full, backend)
        backend = _resolve_local_under_policy(backend, full)
        if backend not in BUILTIN_SANDBOX_BACKENDS and not backend.startswith("ep:"):
            if _container_backend_required(full):
                raise SandboxPolicyError("Unknown sandbox backend cannot satisfy the container policy")
            backend = "local"
        isolated = backend in BUILTIN_SANDBOX_BACKENDS and backend != "local"
    except (SandboxPolicyError, ValueError):
        isolated = False

    try:
        from ..enterprise import enterprise_enabled
        locked = bool(enterprise_enabled())
    except Exception:
        locked = False
    try:
        from ..enterprise import _allowed_egress_hosts
        hosts = sorted(_allowed_egress_hosts())
    except Exception:
        hosts = []
    try:
        from ..profile import active_profile
        profile = active_profile()
    except Exception:
        profile = "standard"

    posture = {
        "profile": profile,
        "shield": shield,
        "sandbox": {"backend": backend, "isolated": isolated,
                    "workdir": sb.get("workdir")},
        "egress": {"locked": locked, "allowed_hosts": hosts},
    }
    if as_json:
        click.echo(_json.dumps(posture, indent=2))
        return

    def mark(ok: bool) -> str:
        return click.style("✔", fg="green") if ok else click.style("•", fg="yellow")

    click.echo(click.style(f"Safety posture  (profile = {profile})", bold=True))
    if shield["installed"]:
        click.echo(f"  {mark(True)} shield   installed (backend = {shield['backend']})")
    else:
        click.echo(f"  {mark(False)} shield   not installed — kernel fails open "
                   "(built-in fallback rules screen tool calls)")
    if isolated:
        isolation = {
            "ssh": "remote host", "modal": "cloud sandbox",
            "firecracker": "microVM-isolated",
        }.get(backend, "container-isolated")
        click.echo(f"  {mark(True)} sandbox  {backend} ({isolation})")
    else:
        click.echo(f"  {mark(False)} sandbox  {backend} — model-generated shell runs "
                   "on this host with NO container isolation")
    if locked:
        click.echo(f"  {mark(True)} egress   LOCKED (enterprise boundary)"
                   + (f" — allowed hosts: {', '.join(hosts)}" if hosts else ""))
    else:
        click.echo(f"  {mark(False)} egress   open (cloud-capable; not locked)")


@main.command()
@click.option("--output", "-o", "output", default=None,
              help="Write the bundle to this file (chmod 600) instead of stdout.")
def support(output: str | None) -> None:
    """Print a redacted diagnostics bundle for a support ticket.

    Versions, runtime, client binding, readiness checks, the shape of the
    config (hashed key names, values removed), and a recent-failures
    summary — one JSON document to attach to a
    ticket instead of hand-running version/doctor/diag and redacting by hand.
    """
    import json as _json

    from ..support_bundle import collect
    bundle = collect()
    text = _json.dumps(bundle, indent=2, sort_keys=True, default=str)
    if output:
        from pathlib import Path as _P

        from ..file_lock import atomic_write_text as _atomic_write_text

        path = _P(output).expanduser()
        _atomic_write_text(path, text + "\n", mode=0o600)
        click.echo(f"support bundle written: {path}")
        # Record the export on the signed audit trail — redacted METADATA only
        # (correlation_id / basename; never bundle contents), so a CISO can see
        # every support touch on their own log. A write error is logged and
        # does not break the export; a refusal by the audit subsystem fails it.
        from ..audit import AuditRefused, audit_event
        try:
            audit_event(
                "support_bundle_exported", agent="cli",
                correlation_id=bundle.get("correlation_id"),
                filename=path.name)
        except AuditRefused as exc:
            raise click.ClickException(
                f"the audit trail refused to record this export: {exc}") from exc
    else:
        click.echo(text)


def _show_capability_plan(profile):
    """Analyse a draft pack for capability gaps and print them. Read-only;
    returns the plan (or None if analysis was unavailable) for later apply."""
    from ..provision import analyze_profile
    try:
        from ..tools import base_tool_names
        plan = analyze_profile(profile, known_tools=base_tool_names())
    except Exception as e:  # analysis must never block onboarding
        click.echo(f"(capability analysis skipped: {e})", err=True)
        return None
    if plan.is_empty():
        return plan
    click.echo(click.style("\nCapability gaps the factory can close:", bold=True))
    for g in plan.gaps:
        click.echo(f"  - {g.describe()}")
    from .. import self_learning
    if not self_learning.enabled():
        click.echo("  (enable [self_learning] to auto-provision these on approval)")
    return plan


def _apply_capability_plan(profile, plan, llm) -> None:
    """Equip an approved pack: install catalog skills + synthesize declared
    tools through the governed paths. No-op unless self-learning is enabled.
    Records the gaps as factory-learning signals (no-op unless that's on)."""
    if plan is None or plan.is_empty():
        return
    from ..provision import apply_approved_plan
    result = apply_approved_plan(profile, plan, llm=llm)
    if result.acquired or result.generated or result.failed:
        click.echo(click.style(f"Provisioning: {result.summary()}", fg="cyan"))


@main.command()
@click.option("--name", default=None, help="Business name (otherwise prompted).")
@click.option("--doc", "docs", multiple=True,
              help="Path to a document to ingest (repeatable).")
@click.option("--no-llm", is_flag=True,
              help="Use deterministic generation instead of the configured LLM.")
@click.option("--description", default=None,
              help="What the business does (skips the prompt; for non-interactive use).")
@click.option("--industry", default=None,
              help="Industry (skips the prompt; for non-interactive use).")
@click.option("--yes", is_flag=True, help="Skip the approval prompt.")
@click.pass_context
def onboard(ctx: click.Context, name, docs, no_llm, description, industry, yes) -> None:
    """Onboard a business: describe it + attach docs -> a sealed domain agent.

    Generates a domain pack (clamped to a safe envelope), shows it for your
    approval, and on approval saves it so the sealed, knowledge-loaded agent
    goes live. Nothing is activated without your yes.
    """
    from ..agent_tests_policy import NewSpecialistNeedsTests
    from ..intake import IntakeSpec, attach_docs_to_profile, run_intake, save_profile

    # Only prompt when a human is attached (a TTY). In non-interactive use (CI,
    # piped stdin) the intake prompts would fire and then abort even with
    # --name/--no-llm/--yes supplied, so onboarding could not be automated.
    # Pass --name/--description/--industry/--doc instead.
    interactive = sys.stdin.isatty()
    if not name:
        if not interactive:
            click.echo("ERROR: --name is required for non-interactive onboarding.", err=True)
            sys.exit(2)
        name = click.prompt("Business name")
    if description is None:
        description = (click.prompt("What does the business do?", default="", show_default=False)
                      if interactive else "")
    if industry is None:
        industry = (click.prompt("Industry (optional)", default="", show_default=False)
                    if interactive else "")
    doc_paths = list(docs)
    if not doc_paths and interactive:
        click.echo("Attach documents (blank line to finish):")
        while True:
            p = click.prompt("  document path", default="", show_default=False)
            if not p.strip():
                break
            doc_paths.append(p.strip())

    spec = IntakeSpec(name=name, description=description, industry=industry,
                      doc_paths=doc_paths)

    llm = None
    if not no_llm:
        try:
            from ..llm import LLM

            # Same role the dashboard's agent drafting uses (intake proposer).
            llm = LLM(model=_cli_model(ctx, "writer"))
        except Exception as e:  # no provider/key -> deterministic generation
            click.echo(f"(LLM unavailable; using deterministic generation: {e})", err=True)
    from ..intake import onboarding_knowledge_base
    kb, kb_problem = onboarding_knowledge_base()
    if kb is None and doc_paths:
        if kb_problem == "disabled":
            # The client explicitly attached docs AND the generated persona
            # tells the agent to answer from them -- so a quiet "skipping"
            # aside under-sells that the domain agent ends up with NO document
            # memory. Make it a clear, actionable warning: name the count
            # and the exact remediation.
            click.echo(
                f"WARNING: knowledge is disabled, so the {len(doc_paths)} "
                "document(s) you attached were NOT loaded; this domain agent "
                "will have no document memory. Turn on \"Document search for "
                "agents\" in Lightwork > Settings > All settings, or set "
                "[knowledge] enable = true in ~/.maverick/config.toml, then "
                "re-run onboard.",
                err=True,
            )
        elif kb_problem is not None:
            click.echo(f"(knowledge unavailable; skipping doc ingestion: {kb_problem})", err=True)

    click.echo("Generating a draft domain agent...")
    profile = run_intake(spec, llm=llm, kb=None)

    click.echo(click.style("\nDraft domain pack (review before it goes live):", bold=True))
    click.echo(f"  name:        {profile.name}")
    click.echo(f"  compartment: {profile.compartment}")
    click.echo(f"  max_risk:    {profile.max_risk}")
    click.echo(f"  allow_tools: {', '.join(profile.allow_tools) or '(none)'}")
    click.echo(f"  deny_tools:  {', '.join(profile.deny_tools) or '(none)'}")
    click.echo(f"  knowledge:   {', '.join(profile.knowledge_sources) or '(none)'}")
    if profile.refuse:
        preview = "; ".join(profile.refuse)[:400]
        click.echo(f"  refusals:    {preview}")
    click.echo(f"  persona:     {profile.persona[:400]}")

    # Capability provisioning: surface (and, on approval, close) the skills/
    # tools this pack needs but doesn't have yet. Analysis is always safe.
    plan = _show_capability_plan(profile)

    if not yes and not click.confirm("\nApprove and activate this agent?", default=False):
        click.echo("Discarded. Nothing was saved.")
        return
    if kb is not None and doc_paths:
        attach_docs_to_profile(spec, profile, kb)
    try:
        path = save_profile(profile, approved=True)
    except NewSpecialistNeedsTests as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(click.style(f"\nActivated. Pack saved to {path}", fg="green"))
    click.echo(f"Domain '{profile.name}' is now available to the swarm.")

    _apply_capability_plan(profile, plan, llm)


@main.command("learn-demo")
@click.argument("demo_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--name", default=None, help="Task title (otherwise the file name).")
@click.option("--industry", default="", help="Industry context (optional).")
@click.option("--source", default="log",
              help="Where the demonstration came from: screen | narration | log.")
@click.option("--no-llm", is_flag=True,
              help="Derive the pack deterministically from the steps (no LLM).")
@click.option("--yes", is_flag=True, help="Skip the approval prompt.")
@click.pass_context
def learn_demo(ctx: click.Context, demo_file, name, industry, source, no_llm, yes) -> None:
    """Synthesize a specialist agent from a watched task (programming by demo).

    Reads a demonstration -- an ordered log of what a person did (JSONL, or
    prefixed text like ``ACTION[email]: send the weekly digest -> ops@``) --
    induces a domain pack from it (clamped to a safe envelope), shows it for
    your approval, and on approval saves it and provisions its skills/tools.
    Nothing is activated without your yes.
    """
    from ..agent_tests_policy import NewSpecialistNeedsTests
    from ..demonstration import induce_profile, load_demonstration
    from ..intake import save_profile

    demonstration = load_demonstration(demo_file, title=name or "", source=source,
                                       industry=industry)
    if not demonstration.steps:
        click.echo("ERROR: no usable steps parsed from the demonstration file.", err=True)
        sys.exit(2)
    click.echo(f"Parsed {len(demonstration.steps)} step(s) from the demonstration.")

    llm = None
    if not no_llm:
        try:
            from ..llm import LLM

            # Same role the dashboard's agent drafting uses (intake proposer).
            llm = LLM(model=_cli_model(ctx, "writer"))
        except Exception as e:  # no provider/key -> deterministic derivation
            click.echo(f"(LLM unavailable; deriving pack from steps: {e})", err=True)

    click.echo("Inducing a draft domain agent from the demonstration...")
    profile = induce_profile(demonstration, llm=llm)

    click.echo(click.style("\nDraft domain pack (review before it goes live):", bold=True))
    click.echo(f"  name:        {profile.name}")
    click.echo(f"  max_risk:    {profile.max_risk}")
    click.echo(f"  allow_tools: {', '.join(profile.allow_tools) or '(none)'}")
    click.echo(f"  workflow:    {len(profile.workflow)} step(s)")
    for step in profile.workflow:
        gate = f" [gate: {step.gate}]" if step.gate else ""
        click.echo(f"    - {step.name}{gate}")
    click.echo(f"  persona:     {profile.persona[:400]}")

    plan = _show_capability_plan(profile)

    if not yes and not click.confirm("\nApprove and activate this agent?", default=False):
        click.echo("Discarded. Nothing was saved.")
        return
    try:
        path = save_profile(profile, approved=True)
    except NewSpecialistNeedsTests as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(1)
    click.echo(click.style(f"\nActivated. Pack saved to {path}", fg="green"))
    click.echo(f"Domain '{profile.name}' is now available to the swarm.")

    _apply_capability_plan(profile, plan, llm)


def _learning_cli_preflight(job: str, phase: str = "cli-start") -> None:
    """Translate the strict learning stop into a stable automation failure."""
    from ..learning_guard import Halted, check_learning_halt

    try:
        check_learning_halt(job, phase)
    except Halted as exc:
        raise click.ClickException(
            f"{job} refused: global learning HALT is active") from exc


def _run_learning_cli(job: str, operation):
    """Run a learning operation without exposing HALT-file contents."""
    from ..learning_guard import Halted

    try:
        return operation()
    except Halted as exc:
        raise click.ClickException(
            f"{job} refused: global learning HALT is active") from exc


@main.command("factory-learn")
@click.option("--min-support", default=3, show_default=True,
              help="Distinct packs that must exhibit a gap before it's a correction.")
@click.option("--dry-run", is_flag=True,
              help="Show mined corrections without promoting any.")
@click.option(
    "--evidence",
    "evidence_path",
    type=click.Path(exists=True, dir_okay=False),
    help=("Strict version-2 JSON with unique paired case IDs, dataset/split/"
          "evaluator/model/prompt hashes, run provenance, and a canonical "
          "evidence digest. Required for live promotion; v1 is dry-run only."),
)
def factory_learn(min_support, dry_run, evidence_path) -> None:
    """Improve the agent factory from what its packs got wrong.

    Mines recurring provisioning/approval gaps into proposer corrections and
    promotes those the self-improvement gate accepts; promoted guidance is then
    folded into future pack generation. Default-on with governed
    self-improvement; set factory_learning=false or MAVERICK_FACTORY_LEARNING=0
    to opt out. Live promotion requires strict v2
    evidence with unique paired case IDs, immutable evaluator/data/model/prompt
    hashes, provenance, and a verified canonical digest; v1 is inspection-only.
    """
    from .. import factory_learning

    _learning_cli_preflight("factory-learning")
    if not factory_learning.enabled():
        click.echo("Factory learning is OFF. Enable [self_improvement] or set "
                   "MAVERICK_FACTORY_LEARNING=1 to mine and promote corrections.")
        return
    corrections = _run_learning_cli(
        "factory-learning",
        lambda: factory_learning.mine_corrections(min_support=min_support),
    )
    if not corrections:
        click.echo("No recurring factory gaps meet the support threshold yet.")
        return
    click.echo(click.style(f"{len(corrections)} candidate correction(s):", bold=True))
    for c in corrections:
        click.echo(f"  - [{c.scope}/{c.signal}] support={c.support}: {c.guidance}")
    if dry_run:
        click.echo("\n(dry run: nothing promoted)")
        return
    if not evidence_path:
        raise click.ClickException(
            "promotion requires --evidence with strict version-2 paired-case "
            "provenance and a canonical evidence digest; recurrence alone is not "
            "proof that guidance improves drafts"
        )
    try:
        scorer = factory_learning.load_measured_evidence(evidence_path)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    promoted = _run_learning_cli(
        "factory-learning",
        lambda: factory_learning.review_and_promote(
            min_support=min_support, scorer=scorer),
    )
    if promoted:
        click.echo(click.style(f"\nPromoted {len(promoted)} correction(s) through "
                               "the self-improvement gate.", fg="green"))
    else:
        click.echo("\nNothing cleared the gate this pass "
                   "(insufficient evidence, or calibration frozen).")


@main.command()
@click.option("--principal", default=None,
              help="Principal to inspect (default: user:local). Match your "
                   "[role_assignments] key, e.g. user:<oidc-sub>.")
@click.option("--channel", default=None, help="Channel for ACL resolution.")
@click.option("--user", "user_id", default=None, help="Channel user id for ACL resolution.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
def whoami(principal: str | None, channel: str | None, user_id: str | None,
           as_json: bool) -> None:
    """Show the effective capability (and role) for a principal.

    Resolves the grant exactly as the agent would -- the [security] ACL narrowed
    by any assigned role ([role_assignments] / [roles]) -- so you can verify what
    a principal is allowed to do before you deploy. Read-only.
    """
    import json as _json

    from ..capability import capability_enforced, capability_from_config

    p = principal or "user:local"
    cap = capability_from_config(p, channel=channel, user_id=user_id)
    role = None
    try:  # role_for_principal ships with RBAC; tolerate older kernels.
        from ..capability import role_for_principal
        role = role_for_principal(p)
    except Exception:
        pass

    info = {
        "principal": cap.principal,
        "role": role,
        "enforcement": capability_enforced(),
        "allow_tools": sorted(cap.allow_tools) or "all",
        "deny_tools": sorted(cap.deny_tools),
        "max_risk": cap.max_risk or "none",
        "allow_paths": sorted(cap.allow_paths) or "all",
        "allow_hosts": sorted(cap.allow_hosts) or "all",
        "expires_at": cap.expires_at,
    }
    if as_json:
        click.echo(_json.dumps(info, default=str))
        return
    click.echo(click.style(f"principal: {info['principal']}", bold=True))
    click.echo(f"  role:         {role or '(none)'}")
    click.echo(f"  enforcement:  {'ON' if info['enforcement'] else 'off (advisory)'}")
    click.echo(f"  allow_tools:  {info['allow_tools']}")
    click.echo(f"  deny_tools:   {info['deny_tools'] or '(none)'}")
    click.echo(f"  max_risk:     {info['max_risk']}")
    click.echo(f"  allow_paths:  {info['allow_paths']}")
    click.echo(f"  allow_hosts:  {info['allow_hosts']}")
    if info["expires_at"]:
        click.echo(f"  expires_at:   {info['expires_at']}")




@main.group("overrides")
def overrides_group() -> None:
    """Export / load this workspace's agent customizations as a portable bundle.

    A bundle is a plain directory carrying the workspace's domain-pack overrides
    (``domains/*.toml``) and per-role system-prompt addendums (``roles.toml``).
    Commit it to a repo and ``maverick overrides load`` it in CI so the
    ``agent-on-pr`` review runs as your customized workforce."""


@overrides_group.command("export")
@click.argument("dest", type=click.Path(file_okay=False))
def overrides_export_cmd(dest: str) -> None:
    """Write this workspace's overrides (domain packs + role addendums) into DEST."""
    from ..overrides_bundle import export_overrides
    n = export_overrides(dest)
    click.echo(f"exported {n['domains']} domain override(s), "
               f"{n['roles']} role addendum(s) to {dest}")


@overrides_group.command("load")
@click.argument("src", type=click.Path(exists=True, file_okay=False))
def overrides_load_cmd(src: str) -> None:
    """Apply a bundle from SRC into this workspace (each item re-validated)."""
    from ..overrides_bundle import load_overrides
    n = load_overrides(src)
    click.echo(f"loaded {n['domains']} domain override(s), "
               f"{n['roles']} role addendum(s)")
    for s in n["skipped"]:
        click.echo(click.style(f"  skipped {s}", fg="yellow"))


@main.group()
def governance() -> None:
    """Inspect the oversight control-plane policy (enterprise)."""


@governance.command("show")
def governance_show() -> None:
    """Show the active org policy from [governance] (default-allow if unset)."""
    from ..governance import Policy
    pol = Policy.from_config()
    if pol.is_empty():
        click.echo("no [governance] policy configured (default-allow)")
        return
    click.echo(f"deny_actions:           {sorted(pol.deny_actions) or '(none)'}")
    click.echo(f"require_human_actions:  {sorted(pol.require_human_actions) or '(none)'}")
    click.echo(f"deny_min_risk:          {pol.deny_min_risk or '(none)'}")
    click.echo(f"require_human_min_risk: {pol.require_human_min_risk or '(none)'}")


@governance.command("check")
@click.argument("action")
@click.option("--risk", type=click.Choice(["low", "medium", "high"]), default=None,
              help="Override the action's classified risk.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def governance_check(action: str, risk: str | None, as_json: bool) -> None:
    """Show the control-plane verdict for ACTION under the active policy.

    Returns ALLOW / DENY / REQUIRE_HUMAN so you can verify a policy before
    deploying. Read-only.
    """
    import json as _json

    from ..governance import evaluate
    v = evaluate(action, risk=risk)
    if as_json:
        click.echo(_json.dumps({
            "action": action, "decision": v.decision.value,
            "rule": v.rule, "reason": v.reason,
        }))
        return
    click.echo(f"{action}: {v.decision.value.upper()}  ({v.rule}) — {v.reason}")


def _governance_denied_counts(principals: set[str], *, limit: int = 500) -> dict[str, int]:
    """Count recent policy-denial audit events per principal (fail-soft).

    The oversight signal is a tool the control plane refused for an agent. On
    this kernel that lands as ``capability_denied``; ``governance_denied`` is
    matched too where a build records it, so the count is forward-compatible.
    """
    counts: dict[str, int] = {}
    try:
        from ..audit import EventKind, default_audit_log
        kinds = {EventKind.CAPABILITY_DENIED,
                 getattr(EventKind, "GOVERNANCE_DENIED", "governance_denied")}
        for ev in default_audit_log().tail(limit):
            if ev.get("kind") not in kinds:
                continue
            p = ev.get("principal")
            if p in principals:
                counts[p] = counts.get(p, 0) + 1
    except Exception:  # pragma: no cover -- the oversight view never blocks on audit
        pass
    return counts


@main.group("self-harness")
def harness() -> None:
    """Inspect and roll back the self-harness learned operating guidance."""


def _holdout_ledger_path(path: Path | None) -> Path:
    if path is not None:
        return path
    from ..config import get_self_harness

    configured = str(get_self_harness().get("holdout_ledger") or "").strip()
    if not configured:
        raise click.ClickException(
            "no holdout ledger path supplied; pass --path or set "
            "[self_harness] holdout_ledger")
    return Path(configured)


@harness.group("holdout")
def harness_holdout() -> None:
    """Provision or verify the risk-limited sealed-holdout query ledger."""


@harness_holdout.command("provision")
@click.option("--path", type=click.Path(path_type=Path, dir_okay=False),
              default=None, help="Ledger path (default: configured holdout_ledger).")
def harness_holdout_provision(path: Path | None) -> None:
    """Create the durable query ledger exactly once; existing paths are refused."""
    from ..self_harness_holdout import HoldoutLedgerError, HoldoutQueryLedger

    target = _holdout_ledger_path(path)
    try:
        ledger = HoldoutQueryLedger.provision(target)
        status = ledger.verify()
    except (HoldoutLedgerError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"provisioned holdout ledger: {target}")
    click.echo(f"ledger id: {status.ledger_id}")
    click.echo("record that ledger id in an independently protected audit system")


@harness_holdout.command("verify")
@click.option("--path", type=click.Path(path_type=Path, dir_okay=False),
              default=None, help="Ledger path (default: configured holdout_ledger).")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def harness_holdout_verify(path: Path | None, as_json: bool) -> None:
    """Verify the complete event chain, transactional tip, and query count."""
    import json as _json

    from ..self_harness_holdout import HoldoutLedgerError, HoldoutQueryLedger

    target = _holdout_ledger_path(path)
    try:
        status = HoldoutQueryLedger(target).verify()
    except (HoldoutLedgerError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    payload = {
        "path": str(target),
        "ledger_id": status.ledger_id,
        "events": status.ledger_events,
        "queries": status.queries,
        "tip_sha256": status.ledger_tip_sha256,
    }
    if as_json:
        click.echo(_json.dumps(payload, sort_keys=True))
        return
    click.echo(f"verified holdout ledger: {target}")
    click.echo(f"ledger id: {status.ledger_id}")
    click.echo(f"events: {status.ledger_events}  queries: {status.queries}")
    click.echo(f"tip sha256: {status.ledger_tip_sha256 or '(empty ledger)'}")


@harness.command("show")
@click.option("--model", default=None, help="Only show this model's guidance.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--verbose", "-v", is_flag=True,
              help="Show each line's provenance: why it was learned, the "
                   "held-out evidence, and when.")
def harness_show(model: str | None, as_json: bool, verbose: bool) -> None:
    """Show the operating-guidance the self-harness loop has learned, per model.

    This reads the RAW stored addenda, not the recall-time result: unlike
    ``recall_addendum()`` (what actually reaches a prompt), this command does
    NOT re-apply the safety screen, deliberately -- an operator investigating
    a stale/tampered store needs to see exactly what's stored, screen-failing
    lines included, to find and `forget` them. Do not treat every line shown
    here as something a model will actually see; a line can be listed here
    and still be dropped at recall. ``--verbose`` adds per-line provenance
    (signature, held-out delta, samples, learned date) so an operator can
    judge whether the evidence behind each line is strong. Read-only.
    """
    import json as _json

    from ..self_harness import enabled, line_provenance, list_learned
    learned = list_learned()
    if model:
        learned = {k: v for k, v in learned.items() if k == model}
    if as_json:
        if verbose:
            click.echo(_json.dumps({m: line_provenance(m) for m in learned},
                                   indent=2, sort_keys=True))
        else:
            click.echo(_json.dumps(learned, indent=2, sort_keys=True))
        return
    if not enabled():
        click.echo("note: self-harness is OFF ([self_harness] enable=false) — "
                   "stored guidance is NOT recalled into prompts until enabled.")
    if not learned:
        click.echo("no learned guidance yet.")
        return
    import datetime as _dt

    def _date(ts):
        if not isinstance(ts, (int, float)):
            return "?"
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d")

    for m, lines in sorted(learned.items()):
        click.echo(f"\n{m}  ({len(lines)} line{'s' if len(lines) != 1 else ''}):")
        if not verbose:
            for ln in lines:
                click.echo(f"  - {ln}")
            continue
        for rec in line_provenance(m):
            _dom = rec.get("domain")
            click.echo(f"  - {rec['text']}" + (f"  [domain={_dom}]" if _dom else ""))
            sig = rec.get("signature") or "(no provenance — learned before tracking)"
            d, n = rec.get("held_out_delta"), rec.get("samples")
            ev = (f"held-out {d:+.3g} over {n} samples"
                  if isinstance(d, (int, float)) and n else "no recorded evidence")
            click.echo(f"      why: {sig}")
            click.echo(f"      evidence: {ev} · learned {_date(rec.get('learned_at'))}"
                       f" · updated {_date(rec.get('updated_at'))}")
            used = rec.get("last_recalled_at")
            if isinstance(used, (int, float)):
                click.echo(f"      used: last recalled {_date(used)}")


@harness.command("log")
@click.option("--limit", default=20, show_default=True, help="Recent events to show.")
def harness_log(limit: int) -> None:
    """Show recent self-harness learning events — what was learned or forgotten,
    for which model, and when (read from the signed audit trail). Read-only."""
    from ..audit import EventKind, default_audit_log
    rows: list[dict] = []
    try:
        for ev in default_audit_log().tail(2000):
            if ev.get("kind") == EventKind.LEARNING_UPDATE and ev.get("agent") == "self_harness":
                rows.append(ev)
    except Exception:  # pragma: no cover -- inspection never blocks on audit
        pass
    rows = rows[-limit:]
    if not rows:
        click.echo("no self-harness learning events recorded.")
        return
    import datetime as _dt

    def _when(ev: dict) -> str:
        # Audit rows store ts as an epoch float; render it as a calendar
        # timestamp so "what was learned and when" is actually readable (a raw
        # 1.78e9 float is not). Leave a non-numeric/absent ts as-is.
        ts = ev.get("ts") or ev.get("time")
        if isinstance(ts, (int, float)):
            return _dt.datetime.fromtimestamp(
                ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return str(ts or "")

    for ev in rows:
        click.echo(f"{_when(ev):19}  {ev.get('phase', 'apply'):7} "
                   f"{ev.get('model_id', '?')}  {ev.get('line', '')}")


@harness.command("forget")
@click.option("--model", required=True, help="Model whose guidance to remove.")
@click.option("--line", default=None,
              help="Remove just this one line (default: all guidance for the model).")
@click.option("--domain", default=None,
              help="Scope the removal to this department's block only.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def harness_forget(model: str, line: str | None, domain: str | None, yes: bool) -> None:
    """Roll back learned guidance for a model — the operator undo handle.

    Removes the whole block for MODEL (all scopes), or a single --line, or one
    department's block with --domain. The removal is atomic and audited.
    """
    from ..self_harness import forget_addendum
    what = f"the line {line!r}" if line else "ALL learned guidance"
    scope = f" (domain={domain})" if domain else ""
    if not yes and not click.confirm(f"Remove {what} for {model}{scope}?"):
        click.echo("aborted.")
        return
    if forget_addendum(model, line=line, domain=domain):
        click.echo("removed.")
    else:
        click.echo("nothing to remove.")


@harness.command("efficacy")
@click.option("--model", required=True, help="Model whose per-line efficacy to show.")
def harness_efficacy(model: str) -> None:
    """Show each learned line's outcome record — how often a run that recalled it
    succeeded vs failed, and the success rate. Populated from real runs (the
    orchestrator records the outcome). Use it to spot dead-weight guidance before
    pruning it with `forget` or letting the efficacy review demote it. Read-only.
    """
    from ..self_harness import line_efficacy
    rows = line_efficacy(model)
    if not rows:
        click.echo(f"no learned guidance for {model!r}.")
        return
    for r in rows:
        tag = f" [domain={r['domain']}]" if r.get("domain") else ""
        rate = "—" if r["rate"] is None else f"{r['rate']:.0%}"
        click.echo(f"  - {r['text']}{tag}")
        click.echo(f"      outcomes: {r['success']}✓ / {r['failure']}✗  ·  rate {rate}")


@harness.command("canary")
@click.option("--model", required=True, help="Model whose canaries to inspect/advance.")
@click.option("--review", is_flag=True,
              help="Advance the lifecycle now: graduate proven canaries, demote failing ones.")
@click.option("--graduate-after", type=click.IntRange(min=1), default=3, show_default=True,
              help="Successes before a canary graduates to permanent.")
@click.option("--demote-after", type=int, default=2, show_default=True,
              help="Failures before a canary is pulled.")
def harness_canary(model: str, review: bool, graduate_after: int, demote_after: int) -> None:
    """Inspect or advance the canary (staged-rollout) lifecycle. A canary line is
    recalled but on probation; `--review` graduates the proven ones and pulls the
    failing ones from the accumulated recall→outcome counters (audited)."""
    from ..self_harness import list_canaries, review_canaries
    if review:
        res = review_canaries(model, graduate_after=graduate_after, demote_after=demote_after)
        click.echo(f"graduated: {', '.join(res['graduated']) or '(none)'}")
        click.echo(f"demoted:   {', '.join(res['demoted']) or '(none)'}")
        return
    cans = list_canaries(model)
    if not cans:
        click.echo(f"no lines on canary probation for {model!r}.")
        return
    click.echo(f"{len(cans)} line(s) on canary probation:")
    for ln in cans:
        click.echo(f"  - {ln}")


@harness.command("retire")
@click.option("--older-than-days", type=click.FloatRange(min=0, min_open=True), required=True,
              help="Retire lines not refreshed (re-promoted) within this many days.")
@click.option("--model", default=None, help="Only retire this model's lines.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def harness_retire(older_than_days: float, model: str | None, yes: bool) -> None:
    """Retire stale learned guidance — lines not refreshed within --older-than-days.

    Prompt guidance goes stale as models, tools, and APIs change. A line that
    keeps proving useful is re-promoted (refreshing its age) and survives; one
    that hasn't been seen in a while is removed. Lines with no provenance record
    (learned before tracking) are left alone — their age is unknown. Atomic and
    audited.
    """
    from ..self_harness import retire_stale
    if not math.isfinite(older_than_days) or older_than_days <= 0:
        raise click.BadParameter("must be finite and greater than zero", param_hint="--older-than-days")
    scope = f"{model!r}" if model else "all models"
    if not yes and not click.confirm(
            f"Retire guidance older than {older_than_days} days for {scope}?"):
        click.echo("aborted.")
        return
    n = retire_stale(older_than_days=older_than_days, model_id=model)
    click.echo(f"retired {n} line{'' if n == 1 else 's'}.")


def _echo_harness_cycle(report, retired: int) -> None:
    """Render one cycle's report + retirement count for the operator."""
    click.echo(f"model: {report.model_id or '(unresolved)'}")
    click.echo(f"  mined={report.mined} proposed={report.proposed} "
               f"validated={report.validated} promoted={report.promoted} retired={retired}")
    # Explain WHY a pass promoted nothing, in priority order, so the operator
    # isn't left guessing whether the loop is broken or just gated.
    if report.frozen:
        click.echo("  ⚠ learning is FROZEN (verifier drift) — promotions are paused "
                   "until calibration recovers")
    elif not report.gate_enabled:
        click.echo("  ⚠ promotion gate is OFF — set [self_improvement] enable = true "
                   "to allow promotions")
    elif report.promoted == 0 and report.proposed > 0:
        click.echo("  (dry pass — inject a live A/B scorer and enable "
                   "[self_improvement] to promote)")
    for s in report.skipped[:10]:
        click.echo(f"  - skipped: {s}")
    if report.applied_lines:
        click.echo("  promoted lines:")
        for ln in report.applied_lines:
            click.echo(f"    + {ln}")
    if getattr(report, "relapsed", None):
        click.echo("  relapsed (back on canary probation — recent outcomes turned bad):")
        for ln in report.relapsed:
            click.echo(f"    ~ {ln}")


@harness.command("run")
@click.option("--model", default=None, help="Model to run for (default: orchestrator).")
@click.option("--all-models", is_flag=True,
              help="Run for every configured role model (the whole fleet), not just one.")
@click.option(
    "--system-prompt-file", type=click.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True, path_type=Path),
    default=None,
    help=("Exact deployed system-prompt snapshot for both A/B arms; required by "
          "risk-limited automatic evaluation."),
)
@click.option("--limit", type=int, default=500,
              help="Max recent reflexions to scan for weaknesses.")
@click.option("--retire/--no-retire", default=True,
              help="Also retire stale lines (per [self_harness] retire_after_days).")
@click.option("--canary", is_flag=True,
              help="Stage this run's promotions as canaries: recalled on probation, "
                   "graduated/demoted from real run outcomes "
                   "(default: [self_harness] promote_as_canary).")
def harness_run(model: str | None, all_models: bool, system_prompt_file: Path | None,
                limit: int, retire: bool, canary: bool) -> None:
    """Run one governed self-harness cycle: mine → propose → validate → gate,
    then retire stale guidance. The on-demand / scheduled entry point.

    With ``eval_corpus`` configured, the cycle builds the live A/B evaluator.
    Risk-limited evaluation additionally requires ``--system-prompt-file`` so
    the baseline is the exact deployed prompt, not a generic helper prompt.
    Without a live evaluator this is a DRY pass that writes no NEW guidance;
    stale-line retirement still runs. Promotion also requires [self_improvement]
    enable (the shared governed gate). Safe to schedule: it never perturbs a run.

    --all-models runs the cycle for EVERY distinct configured role model so worker
    models learn their own harness, not just the orchestrator.
    """
    from .. import self_harness
    from .. import self_improvement_runner as runner
    _learning_cli_preflight("self-harness")
    if not self_harness.enabled():
        raise click.ClickException(
            "self-harness is off. Set [self_harness] enable = true or "
            "MAVERICK_SELF_HARNESS=1.")
    # The flag STAGES; leaving it off defers to [self_harness] promote_as_canary
    # (None = config decides), so a scheduled `run` keeps the operator's default.
    stage = True if canary else None
    evaluation_system = None
    if system_prompt_file is not None:
        try:
            with system_prompt_file.open("rb") as prompt_stream:
                raw = prompt_stream.read(runner.EVALUATION_SYSTEM_LIMIT + 1)
            evaluation_system = runner.read_evaluation_system(raw)
        except (OSError, UnicodeError, ValueError) as exc:
            raise click.ClickException(
                f"cannot read deployed system prompt: {exc}") from exc
    if all_models:
        results = _run_learning_cli(
            "self-harness",
            lambda: runner.run_self_harness_all_models(
                limit=limit, retire=retire, canary=stage,
                evaluation_system=evaluation_system),
        )
        if not results:
            click.echo("no configured role models to run.")
            return
        for _mid, (report, retired) in sorted(results.items()):
            _echo_harness_cycle(report, retired)
        return
    report, retired = _run_learning_cli(
        "self-harness",
        lambda: runner.run_self_harness_cycle(
            model_id=model, limit=limit, retire=retire, canary=stage,
            evaluation_system=evaluation_system),
    )
    _echo_harness_cycle(report, retired)


@harness.command("transfer")
@click.option("--from", "source", required=True,
              help="Source model whose graduated guidance to try elsewhere.")
@click.option("--to", "targets", multiple=True,
              help="Target model(s); default: every other configured role model.")
@click.option("--force", is_flag=True,
              help="Ignore the tried-memory and re-attempt already-judged pairs.")
def harness_transfer(source: str, targets: tuple[str, ...], force: bool) -> None:
    """Try one model's PROVEN guidance on other fleet models — a governed
    experiment, not an assumption.

    Each graduated (non-canary, not-relapsing) model-wide line of the source is
    validated against the target's own eval corpus through the full floors and
    the promotion gate, landing as a CANARY so real run outcomes adjudicate it.
    Attempts are one-shot per (target, line) — re-running spends nothing on
    pairs already judged (--force overrides). Requires [self_harness] enable,
    an eval_corpus, and [self_improvement] enable to actually promote.
    """
    from .. import self_harness
    from .. import self_improvement_runner as runner
    if not self_harness.enabled():
        raise click.ClickException(
            "self-harness is off. Set [self_harness] enable = true or "
            "MAVERICK_SELF_HARNESS=1.")
    if not self_harness.settings().get("eval_corpus"):
        raise click.ClickException(
            "no [self_harness] eval_corpus configured — transfer validates "
            "against the target's corpus cases, so it needs one.")
    # Resolve the target list HERE so an empty report can only mean an empty
    # fleet, never a swallowed runner failure (raise_errors surfaces those).
    resolved = list(targets) or [m for m in runner.harness_fleet_models()
                                 if m != source]
    if not resolved:
        raise click.ClickException(
            "no transfer targets: the fleet has no other configured models.")
    report = runner.run_self_harness_transfer(
        source, targets=resolved, force=force, raise_errors=True)
    for tgt in sorted(report):
        res = report[tgt]
        click.echo(f"{source} -> {tgt}: attempted={len(res['attempted'])} "
                   f"promoted={len(res['promoted'])}")
        for ln in res["promoted"]:
            click.echo(f"    + (canary) {ln}")
        for s in res["skipped"][:10]:
            click.echo(f"    - {s}")


@harness.command("migrate-store")
def harness_migrate_store() -> None:
    """Import this host's FILE learning stores into the shared WORLD database
    — the one-way migration for [self_harness] store = "world". Idempotent and
    fleet-safe: existing world entries win, file-only keys import, and a
    conflicting addenda block merges line-by-line under the normal cap.
    Verifies the routed store serves every imported key, then renames the
    files to *.migrated backups. Run once per host that learned locally.
    """
    from ..learning_store_migration import (
        MigrationRefused,
        migrate_corpus,
        migrate_learning_files,
        require_world_store,
    )
    try:
        require_world_store()
        learned = migrate_learning_files()
    except MigrationRefused as exc:
        raise click.ClickException(str(exc)) from exc
    migrated_any = learned is not None
    if learned is not None:
        merged = learned["merged"]
        click.echo(f"imported {learned['addenda']} addenda key(s), "
                   f"{learned['provenance']} provenance "
                   f"record(s), {learned['tried']} tried pair(s) into the world store"
                   + (f" ({merged} conflicting key(s) merged)" if merged else "")
                   + "; file stores renamed to *.migrated.")
    # The eval-corpus family rides the same migration when configured.
    try:
        counts = migrate_corpus()
    except MigrationRefused as exc:
        raise click.ClickException(str(exc)) from exc
    if counts and any(counts.values()):
        migrated_any = True
        click.echo(f"corpus: merged {counts['live']} live case(s), "
                   f"{counts['pending']} pending, {counts['rejected']} "
                   "rejected goal(s) into the world store.")
    if not migrated_any:
        click.echo("nothing to migrate: no file learning stores on this host.")


@harness.group("corpus")
def harness_corpus() -> None:
    """Bootstrap and review the eval corpus from real run history."""


def _corpus_key_and_path(model: str | None) -> tuple[str, str]:
    from ..self_harness import settings
    corpus_path = settings().get("eval_corpus")
    if not corpus_path:
        raise click.ClickException("no [self_harness] eval_corpus configured.")
    if model:
        return model, corpus_path
    from ..llm import model_for_role
    return model_for_role("orchestrator"), corpus_path


@harness_corpus.command("harvest")
@click.option("--model", default=None,
              help="Corpus key to harvest for (default: the orchestrator model).")
@click.option("--auto", is_flag=True,
              help="Merge straight into the live corpus instead of staging "
                   "for review.")
@click.pass_context
def corpus_harvest_cmd(ctx, model: str | None, auto: bool) -> None:
    """Mine {goal, expected} eval cases from HINDSIGHT PAIRS — goals that
    failed (a reflexion exists) and whose wording later ran to done. The
    succeeded goal's text becomes the case; a fragment of its recorded result
    becomes the expected hint. Staged for `corpus review` unless --auto.
    """
    from .. import self_improvement_runner as runner
    from ..self_harness import settings
    from ..world_model import open_world
    if not settings().get("eval_corpus"):
        raise click.ClickException("no [self_harness] eval_corpus configured.")
    # Key/path defaulting is run_corpus_harvest's job (the one owner of the
    # harvest policy) -- the CLI only supplies the operator's explicit choice.
    _learning_cli_preflight("self_harness", "corpus")
    n = runner.run_corpus_harvest(
        open_world(ctx.obj["db"]), mode=("auto" if auto else "propose"),
        key=model, raise_errors=True)
    if auto:
        click.echo(f"{n} candidate case(s) merged into the corpus.")
    else:
        click.echo(f"{n} candidate case(s) staged; review with "
                   "`maverick self-harness corpus review`.")


@harness_corpus.command("review")
@click.option("--model", default=None,
              help="Corpus key to review (default: the orchestrator model).")
@click.option("--accept", "accepts", multiple=True, type=int,
              help="Accept a listed candidate (1-based; repeatable).")
@click.option("--reject", "rejects", multiple=True, type=int,
              help="Reject a listed candidate (1-based; repeatable).")
@click.option("--accept-all", is_flag=True, help="Accept every pending candidate.")
def corpus_review_cmd(model: str | None, accepts: tuple[int, ...],
                      rejects: tuple[int, ...], accept_all: bool) -> None:
    """List staged corpus candidates, or resolve them: accepted cases merge
    into the LIVE corpus (the loop's ground truth — human-gated by default),
    rejected ones are dropped, the rest stay pending.
    """
    from .. import self_harness_eval as ev
    key, corpus_path = _corpus_key_and_path(model)
    if not (accepts or rejects or accept_all):
        rows = ev.load_pending(corpus_path).get(key, [])
        if not rows:
            click.echo("no pending corpus candidates.")
            return
        click.echo(f"{len(rows)} pending candidate(s) for {key!r}:")
        # Harvested goal text originates in run history -- strip terminal
        # control bytes before echoing untrusted text (same rule as status/
        # history).
        for i, c in enumerate(rows, 1):
            click.echo(f"  {i}. "
                       f"{_strip_terminal_control(c['goal'].splitlines()[0][:70])}")
            click.echo(f"     expected: {_strip_terminal_control(c['expected'])}")
        return
    _learning_cli_preflight("self_harness", "corpus")
    try:
        res = ev.resolve_pending(corpus_path, key, accept=list(accepts),
                                 reject=list(rejects), accept_all=accept_all)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    # Echo WHAT was resolved, not just counts -- indexes rebase between
    # invocations, so a mis-target must be visible immediately.
    for g in res["accepted_goals"]:
        click.echo(f"  + accepted: {_strip_terminal_control(g.splitlines()[0][:70])}")
    for g in res["rejected_goals"]:
        click.echo(f"  - rejected: {_strip_terminal_control(g.splitlines()[0][:70])}")
    dup = (f", {res['duplicates']} already live/unlabeled"
           if res["duplicates"] else "")
    click.echo(f"merged {res['merged']} into the corpus{dup}, "
               f"rejected {res['rejected']} (remembered).")


@harness_corpus.command("export")
@click.option("--out", "out_path", required=True,
              type=click.Path(dir_okay=False),
              help="Destination JSON file for the live corpus.")
def corpus_export_cmd(out_path: str) -> None:
    """Write the LIVE eval corpus to a JSON file — the hand-editing handle
    when the corpus lives in the world store ([self_harness] store =
    "world"): export, edit, then `corpus import`. Works identically in file
    mode. Every operator-authored field is preserved.
    """
    import json as _json

    from .. import self_harness_eval as ev
    from ..self_harness import settings
    cpath = settings().get("eval_corpus")
    if not cpath:
        raise click.ClickException("no [self_harness] eval_corpus configured.")
    raw = ev._load_raw(cpath)
    try:
        streamed = _write_private_export(
            out_path, _json.dumps(raw, indent=2, sort_keys=True), overwrite=False,
        )
    except OSError as exc:
        raise click.ClickException(f"could not write {out_path}: {exc}") from exc
    n = sum(len(v) for v in raw.values() if isinstance(v, list))
    click.echo(f"exported {n} case(s) across "
               f"{sum(1 for v in raw.values() if isinstance(v, list))} key(s) "
               f"to {out_path}", err=streamed)


@harness_corpus.command("import")
@click.argument("src", type=click.Path(exists=True, dir_okay=False))
@click.option("--replace", is_flag=True,
              help="Replace the whole live corpus instead of merging by goal.")
def corpus_import_cmd(src: str, replace: bool) -> None:
    """Import a corpus JSON file into the LIVE eval corpus — the other half
    of the edit round trip. Default merges by goal (new rows append with
    every field kept; existing rows untouched); --replace overwrites, which
    is what a full hand-edit of an export wants.
    """
    import json as _json

    from .. import self_harness_eval as ev
    from ..self_harness import settings
    cpath = settings().get("eval_corpus")
    if not cpath:
        raise click.ClickException("no [self_harness] eval_corpus configured.")
    try:
        data = _json.loads(Path(src).read_text(encoding="utf-8"))
    except ValueError as e:
        raise click.ClickException(f"{src} is not valid JSON: {e}") from e
    _learning_cli_preflight("self_harness", "corpus")
    try:
        n = ev.import_corpus(
            cpath, data, replace=replace,
            before_write=lambda: _learning_cli_preflight("self_harness", "corpus"),
            effect_guard=lambda: _learning_cli_preflight("self_harness", "corpus"),
        )
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"{'replaced the live corpus with' if replace else 'merged'} "
               f"{n} case(s).")


@harness_corpus.command("quality")
@click.option("--model", default=None,
              help="Corpus key to probe (default: the orchestrator model).")
@click.option("--samples", default=2, show_default=True,
              help="Baseline attempts per case.")
@click.option("--retire", is_flag=True,
              help="Remove non-discriminative cases from the live corpus.")
def corpus_quality_cmd(model: str | None, samples: int, retire: bool) -> None:
    """Measure each live corpus case's baseline DISCRIMINATIVENESS — a case
    the baseline model already passes every time cannot show a candidate
    line's lift, so it is dead ground truth diluting every split. Spends
    real evaluation dollars (the [self_harness] eval budget caps it);
    --retire prunes the dead cases, preserving every other row untouched.
    """
    from .. import self_harness_eval as ev
    from .. import self_improvement_runner as runner
    key, corpus_path = _corpus_key_and_path(model)
    if retire:
        _learning_cli_preflight("self_harness", "corpus")
    rows = runner.run_corpus_quality(key=key, corpus_path=corpus_path,
                                     samples=samples, raise_errors=True)
    if not rows:
        click.echo("no live corpus cases for this key.")
        return
    dead = [r for r in rows if not r["discriminative"]]
    for r in rows:
        rate = ("n/a" if r["baseline_rate"] is None
                else f"{r['baseline_rate']:.0%}")
        age = "" if r.get("age_days") is None else f"  age={r['age_days']}d"
        mark = "ok  " if r["discriminative"] else "DEAD"
        click.echo(f"  {mark} baseline={rate}{age}  "
                   f"{_strip_terminal_control(r['goal'].splitlines()[0][:60])}")
    click.echo(f"{len(rows)} case(s); {len(dead)} non-discriminative.")
    if retire and dead:
        _learning_cli_preflight("self_harness", "corpus")
        n = ev.retire_corpus_cases(corpus_path, key, [r["goal"] for r in dead])
        click.echo(f"retired {n} case(s) from the live corpus.")


@harness.command("conflicts")
@click.option("--model", default=None, help="Only check this model's guidance.")
@click.option("--semantic", is_flag=True,
              help="Also judge contradiction by MEANING with the verifier-role "
                   "model (catches reworded conflicts the lexical heuristic "
                   "misses).")
def harness_conflicts(model: str | None, semantic: bool) -> None:
    """Flag learned lines that appear to CONTRADICT each other, per model.

    Addenda are cumulative, so a later lesson can quietly oppose an earlier one
    ("prefer streaming large exports" vs "avoid streaming; batch first"),
    degrading the prompt. This is an advisory heuristic (shared topic, opposite
    polarity) for an operator to review and `forget` the wrong side — it never
    auto-removes anything. Read-only. With --semantic the verifier-role model
    judges each candidate pair by meaning (per-pair fallback to the heuristic
    if the judge fails), catching conflicts that share no wording.
    """
    from ..self_harness import detect_store_conflicts, llm_conflict_classifier
    classifier = None
    if semantic:
        try:
            from ..llm import LLM, model_for_role
            classifier = llm_conflict_classifier(LLM(model_for_role("verifier")))
        except Exception:  # no provider -> the lexical heuristic still works
            click.echo("note: semantic judge unavailable — using the lexical "
                       "heuristic only.")
    pairs = detect_store_conflicts(model_id=model, classifier_fn=classifier)
    if not pairs:
        click.echo("no conflicting guidance detected.")
        return
    click.echo(f"{len(pairs)} possible conflict(s):")
    for m, a, b in pairs:
        click.echo(f"\n  [{m}]")
        click.echo(f"    - {a}")
        click.echo(f"    ⚔ {b}")


@main.group("self-modify")
def self_modify() -> None:
    """Drive and inspect the governed code self-modification (DGM) loop."""


@self_modify.command("status")
def self_modify_status() -> None:
    """Show client control state, readiness, earned surface, and archive size."""
    from .. import self_improvement as si
    from .. import self_modify as sm
    from ..self_modify_loop import earned_surface
    from ..self_modify_runner import build_policy, load_archive
    status = sm.production_status()
    modify_enabled = status["requested"]
    improvement_enabled = si.enabled()
    enabled = status["effective"]
    click.echo(f"self-modify research: {status['state'].upper()}")
    click.echo("  required gates: "
               f"[self_modify] enable={'true' if modify_enabled else 'false'}, "
               "[self_improvement] enable="
               f"{'true' if improvement_enabled else 'false'}")
    if not enabled:
        click.echo("  (OFF: the loop proposes, evaluates, and archives nothing.)")
    click.echo("  production posture: research only; live code adoption disabled")
    for blocker in status["blockers"]:
        click.echo(f"  blocked: {blocker['message']}")
    policy = build_policy()
    archive = load_archive()
    try:
        ledger = getattr(si.shared(), "ledger", None)
    except Exception:
        ledger = None
    tier, surface = earned_surface(archive, policy, ledger=ledger)
    click.echo(f"earned tier: {tier.name!r}")
    click.echo("editable surface: " + (", ".join(surface.editable_globs) or "(none)"))
    click.echo(f"archive: {len(archive.candidates)} candidate(s), "
               f"{sum(1 for c in archive.candidates if c.promoted)} "
               "legacy promotion marker(s)")


@self_modify.command("run")
@click.option("--cycles", type=click.IntRange(min=1, max=100), default=1,
              show_default=True,
              help="Number of governed DGM cycles to run.")
@click.option("--tree", default=None,
              help="Repo tree to evaluate against (default: cwd).")
@click.option("--objective", required=True,
              help="Explicit improvement objective supplied to the grounded proposer.")
@click.option("--max-dollars", type=click.FloatRange(min=0.0), default=None,
              help="Override the configured dollar cap for this DGM run.")
@click.option("--max-wall-seconds", type=click.FloatRange(min=0.001), default=None,
              help="Override the configured wall-clock cap for this DGM run.")
@click.option("--max-tool-calls", type=click.IntRange(min=1), default=None,
              help="Override the configured sandbox/tool-call cap for this DGM run.")
def self_modify_run(cycles: int, tree: str | None, objective: str,
                    max_dollars: float | None,
                    max_wall_seconds: float | None,
                    max_tool_calls: int | None) -> None:
    """Run research DGM cycles: ground, review, isolate, evaluate, and archive.

    This command never adopts code. Live adoption remains disabled until an
    external one-shot evaluator and PREPARE/CAS/COMMIT integration exist.
    """
    from ..budget import budget_from_config
    from ..self_modify_runner import run
    budget = budget_from_config(
        task_class="self_modify", max_dollars=max_dollars,
        max_wall_seconds=max_wall_seconds, max_tool_calls=max_tool_calls)
    summary = run(
        cycles=cycles, tree=Path(tree) if tree else None,
        objective=objective, budget=budget)
    if not summary.ran:
        raise click.ClickException(f"self-modify did not run: {summary.reason}")
    click.echo(f"ran {len(summary.reports)} cycle(s): "
               f"{summary.evaluated} evaluated, "
               f"{summary.promoted} legacy promotion marker(s).")
    click.echo(f"budget used: {budget.summary()}")
    for i, r in enumerate(summary.reports):
        note = r.reason or ("legacy promotion marker" if r.promoted else "")
        click.echo(f"  #{i} tier={r.tier or '-'} proposed={r.proposed} "
                   f"eval={r.evaluated} promoted={r.promoted}"
                   + (f" — {note}" if note else ""))


@self_modify.command("archive")
@click.option("--limit", type=click.IntRange(min=1), default=20, show_default=True,
              help="Most recent candidates to show.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def self_modify_archive(limit: int, as_json: bool) -> None:
    """Show bounded research candidates and lineage metadata. Read-only."""
    import json as _json

    from ..self_modify_runner import load_archive
    archive = load_archive()
    cands = sorted(archive.candidates, key=lambda c: c.created_at, reverse=True)[:limit]
    if as_json:
        click.echo(_json.dumps([c.to_dict() for c in cands], indent=2, sort_keys=True))
        return
    if not cands:
        click.echo("archive is empty.")
        return
    for c in cands:
        flags = []
        if c.promoted:
            flags.append("legacy-promotion-marker")
        if c.rolled_back:
            flags.append("rolled-back")
        if c.capability_widens:
            flags.append("widens")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        click.echo(f"{c.id}  gen{c.generation}  score={c.score:.3f} "
                   f"(baseline {c.baseline_score:.3f})  {c.summary}{tag}")


@main.group()
def fleet() -> None:
    """Manage per-employee agent fleets (enterprise)."""


@fleet.command("create")
@click.argument("name")
@click.option("--owner", required=True, help="Owning principal, e.g. user:alice.")
@click.option("--agent", "agents", multiple=True, metavar="NAME:ROLE",
              help="An agent as NAME:ROLE (repeatable). ROLE is an RBAC role.")
def fleet_create(name: str, owner: str, agents: tuple[str, ...]) -> None:
    """Create a fleet: an owner plus a roster of NAME:ROLE agents."""
    from ..capability import role_exists
    from ..fleet import Fleet, FleetAgent, save_fleet, valid_name
    if not valid_name(name):
        click.echo("ERROR: name must be [A-Za-z0-9_-] (<=64 chars)", err=True)
        sys.exit(2)
    roster = []
    for spec in agents:
        agent_name, _, role = spec.partition(":")
        agent_name = agent_name.strip()
        role = role.strip()
        if not valid_name(agent_name) or not role:
            click.echo(f"ERROR: bad --agent {spec!r}; use NAME:ROLE", err=True)
            sys.exit(2)
        if not role_exists(role):
            click.echo(f"ERROR: undefined RBAC role {role!r} for --agent {spec!r}",
                       err=True)
            sys.exit(2)
        roster.append(FleetAgent(name=agent_name, role=role))
    path = save_fleet(Fleet(name=name, owner=owner, agents=tuple(roster)))
    click.echo(f"created fleet {name!r} ({len(roster)} agent(s)) -> {path}")


@fleet.command("list")
def fleet_list() -> None:
    """List fleets."""
    from ..fleet import list_fleets
    fleets = list_fleets()
    if not fleets:
        click.echo("no fleets. create one with `maverick fleet create`")
        return
    for f in fleets:
        click.echo(f"  {f.name}  (owner {f.owner}, {len(f.agents)} agent(s))")


@fleet.command("show")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def fleet_show(name: str, as_json: bool) -> None:
    """Show a fleet's roster (each agent + its role/principal)."""
    import json as _json

    from ..fleet import load_fleet
    f = load_fleet(name)
    if f is None:
        click.echo(f"no such fleet: {name}", err=True)
        sys.exit(1)
    if as_json:
        click.echo(_json.dumps(f.to_dict()))
        return
    click.echo(click.style(f"fleet {f.name}  (owner {f.owner})", bold=True))
    if not f.agents:
        click.echo("  (no agents)")
    for a in f.agents:
        line = f"  {a.name:16} role={a.role:14} {f.principal_for(a.name)}"
        click.echo(line + (f"  — {a.description}" if a.description else ""))


@fleet.command("rm")
@click.argument("name")
def fleet_rm(name: str) -> None:
    """Remove a fleet."""
    from ..fleet import remove_fleet
    if remove_fleet(name):
        click.echo(f"removed fleet {name!r}")
    else:
        click.echo(f"no such fleet: {name}", err=True)
        sys.exit(1)


@fleet.command("run")
@click.argument("fleet_name")
@click.argument("agent_name")
@click.argument("prompt")
@click.option("--max-dollars", default=None, type=float,
              help="Spend cap for this run (else [budget] / the runner default).")
@click.pass_context
def fleet_run(ctx, fleet_name: str, agent_name: str, prompt: str,
              max_dollars: float | None) -> None:
    """Run a governed goal AS one of a fleet's agents.

    The agent runs least-privileged under its RBAC role's capability and under
    its own audit principal (``agent:<fleet>.<agent>``), so the oversight
    control plane governs the work automatically.
    """
    from ..capability import UnknownRoleError, capability_for_role
    from ..fleet import load_fleet, record_run
    from ..runner import run_goal_in_thread

    f = load_fleet(fleet_name)
    if f is None:
        click.echo(f"no such fleet: {fleet_name}", err=True)
        sys.exit(1)
    agent = next((a for a in f.agents if a.name == agent_name), None)
    if agent is None:
        click.echo(f"no such agent {agent_name!r} in fleet {fleet_name!r}", err=True)
        sys.exit(1)

    principal = f.principal_for(agent.name)
    try:
        cap = capability_for_role(agent.role, principal=principal)
    except UnknownRoleError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(2)
    world = open_world(ctx.obj["db"])
    try:
        goal_id = world.create_goal(
            prompt,
            owner=f.owner,
            execution_principal=principal,
        )
    finally:
        world.close()
    record_run(fleet_name, agent.name, goal_id)
    click.echo(f"goal #{goal_id} created for {principal} (role {agent.role})")
    status = run_goal_in_thread(goal_id, max_dollars=max_dollars,
                                capability=cap, user_id=principal, db_path=ctx.obj["db"])
    click.echo(f"goal #{goal_id}: {status or 'did not start'}")
    if status != "done":
        raise SystemExit(2 if status == "blocked" else 1)


@fleet.command("status")
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def fleet_status(ctx, name: str, as_json: bool) -> None:
    """Supervisor oversight: each agent's recent runs + governance denials."""
    import json as _json

    from ..fleet import load_fleet, load_runs
    f = load_fleet(name)
    if f is None:
        click.echo(f"no such fleet: {name}", err=True)
        sys.exit(1)

    runs = load_runs(name)
    by_agent: dict[str, list[dict]] = {a.name: [] for a in f.agents}
    for r in runs:
        by_agent.setdefault(str(r.get("agent")), []).append(r)
    denied = _governance_denied_counts({f.principal_for(a.name) for a in f.agents})

    world = open_world(ctx.obj["db"])
    try:
        def _row(r: dict) -> dict:
            gid = r.get("goal_id")
            g = world.get_goal(gid) if isinstance(gid, int) else None
            return {"goal_id": gid, "status": g.status if g else "missing",
                    "ts": r.get("ts")}
        report = []
        for a in f.agents:
            recent = sorted(by_agent.get(a.name, []),
                            key=lambda r: r.get("ts") or 0.0)[-10:]
            report.append({
                "agent": a.name, "role": a.role,
                "principal": f.principal_for(a.name),
                "runs": [_row(r) for r in recent],
                "governance_denied": denied.get(f.principal_for(a.name), 0),
            })
    finally:
        world.close()

    if as_json:
        click.echo(_json.dumps({"fleet": f.name, "agents": report}))
        return
    click.echo(click.style(f"fleet {f.name}  (owner {f.owner})", bold=True))
    for a in report:
        click.echo(f"  {a['agent']:16} role={a['role']:14} {a['principal']}  "
                   f"denied={a['governance_denied']}")
        if not a["runs"]:
            click.echo("      (no runs)")
        for r in a["runs"]:
            click.echo(f"      goal #{r['goal_id']}: {r['status']}")


@main.command()
@click.argument("action", type=click.Choice(["show", "path", "edit"]), default="show")
def config(action: str) -> None:
    """Show, locate, or edit ~/.maverick/config.toml."""
    from ..config import config_path
    p = config_path()
    if action == "path":
        click.echo(str(p))
        return
    if action == "edit":
        import shlex
        # EDITOR is commonly set with args (e.g. "code --wait"); execvp treats
        # the whole string as one binary name and fails. Split it.
        parts = shlex.split(os.environ.get("EDITOR", "nano")) or ["nano"]
        try:
            os.execvp(parts[0], parts + [str(p)])
        except OSError as e:
            raise click.ClickException(f"could not launch editor {parts[0]!r}: {e}") from e
        return
    if not p.exists():
        click.echo(f"No config at {p}. Run:  maverick init", err=True)
        sys.exit(1)
    click.echo(p.read_text(encoding="utf-8"))


@main.command()
@click.pass_context
def budget(ctx) -> None:
    """Show total spend + per-run cost history."""
    world = open_world(ctx.obj["db"])
    total = world.total_spend()
    click.echo(click.style("Total spend", bold=True))
    click.echo(f"  ${total['dollars']:.4f}  across {total['runs']} run(s)")
    click.echo(
        f"  {total['input_tokens']:,} input tokens  /  "
        f"{total['output_tokens']:,} output tokens"
    )
    click.echo("")
    eps = world.list_episodes(limit=15)
    if not eps:
        click.echo("no completed runs yet.")
        return
    click.echo(click.style("Recent runs", bold=True))
    for e in eps:
        outcome = e.outcome or "running"
        click.echo(
            f"  ep #{e.id} (goal {e.goal_id}) [{outcome}]  "
            f"${e.cost_dollars:.4f}  "
            f"in={e.input_tokens:,} out={e.output_tokens:,} tools={e.tool_calls}"
        )


@main.command("budget-tune")
@click.option("--percentile", type=float, default=90.0,
              help="Percentile of historical goal cost to size the cap to.")
@click.option("--min-samples", type=int, default=5,
              help="Minimum priced goals before a recommendation is made.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def budget_tune(ctx, percentile: float, min_samples: int, as_json: bool) -> None:
    """Recommend a max_dollars cap learned from historical goal spend.

    Sizes the default to the percentile of what goals actually cost plus a
    margin, so the common case fits while a runaway still trips it. Read-only —
    set the value yourself in config.
    """
    import json as _json

    from ..budget_tuner import recommend_for_world
    world = open_world(ctx.obj["db"])
    recs = recommend_for_world(world, pct=percentile, min_samples=min_samples)
    if as_json:
        click.echo(_json.dumps(recs))
        return
    if not recs:
        click.echo(f"not enough priced goals yet (need >= {min_samples}).")
        return
    click.echo(click.style("Recommended max_dollars (learned):", bold=True))
    for cls, info in sorted(recs.items()):
        click.echo(f"  {cls}: ${info['recommended_max_dollars']:.2f}  "
                   f"(p{int(percentile)}=${info[f'p{int(percentile)}']:.2f}, "
                   f"{info['samples']} goal(s))")


@main.command("confidential-compute")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def confidential_compute_cmd(as_json: bool) -> None:
    """Detect whether this runs inside a confidential VM (SEV-SNP / TDX).

    For a regulated deployment to verify its memory is hardware-encrypted.
    Exits non-zero when NOT confidential, so it can gate a deployment.
    """
    import json as _json

    from ..confidential_compute import detect
    rep = detect()
    if as_json:
        click.echo(_json.dumps(rep))
    elif rep["confidential"]:
        kind = "Intel TDX" if rep["tdx"] else "AMD SEV-SNP"
        click.echo(click.style(f"CONFIDENTIAL VM ({kind})", fg="green")
                   + f" — {', '.join(rep['indicators'])}")
    else:
        click.echo(click.style(
            "NOT a confidential VM (no SEV-SNP / TDX indicators)", fg="yellow"))
    if not rep["confidential"]:
        raise SystemExit(1)


@main.command("airgap")
@click.argument("action", type=click.Choice(["check"]), default="check")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def airgap_cmd(action: str, as_json: bool) -> None:
    """Verify the deployment is configured with no outbound path.

    Audits for a remote model provider, a non-deny-all egress policy, and
    sandbox network access. Exits non-zero on any finding so it can gate a
    deployment. (OS-level air-gapping is the operator's job; this checks
    Lightwork's own config.)
    """
    import json as _json

    from ..air_gap import audit
    rep = audit()
    if as_json:
        click.echo(_json.dumps(rep))
    elif rep["clean"]:
        click.echo(click.style("AIR-GAPPED: no outbound path in config", fg="green"))
    else:
        click.echo(click.style("NOT air-gapped — findings:", fg="red"))
        for v in rep["violations"]:
            click.echo(f"  • {v}")
    if not rep["clean"]:
        raise SystemExit(1)


@main.command("failures")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def failures_cmd(as_json: bool) -> None:
    """Show the default-on local failure-mode distribution.

    When the telemetry is on, failed runs record a canonical mode (budget /
    auth / timeout / shield / sandbox / network / error); this reads them back.
    """
    import json as _json

    from ..failure_telemetry import enabled, summarize
    s = summarize()
    if as_json:
        click.echo(_json.dumps(s))
        return
    if not s["total"]:
        hint = "" if enabled() else " (telemetry is off — set [telemetry] failure_modes)"
        click.echo(f"no recorded failures{hint}.")
        return
    click.echo(click.style(f"Failure modes ({s['total']} recorded)", bold=True))
    for mode, n in s["by_mode"].items():
        click.echo(f"  {mode:<10} {n}")


# Extends the existing `governance` group (oversight policy) with the
# governed-action audit trail: what a run did, and what a skill/source touched.
@governance.command("lineage")
@click.argument("goal_id", type=int)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def governance_lineage(goal_id: int, as_json: bool) -> None:
    """Show + verify the tamper-evident action lineage for a goal."""
    import json as _json

    from .. import governed_actions as _ga
    links = _ga.load_lineage(goal_id)
    status = _ga.verify_lineage_file(goal_id)
    if as_json:
        click.echo(_json.dumps({"links": links, "verify": status}))
        return
    if not links:
        click.echo(status)
        if status.startswith(("BROKEN", "UNAVAILABLE")):
            raise SystemExit(1)
        click.echo(f"no recorded actions for goal {goal_id} "
                   "(governed actions off? set [actions] enable).")
        return
    click.echo(click.style(f"Action lineage for goal {goal_id}", bold=True))
    for i, link in enumerate(links):
        click.echo(f"  {i}. {link.get('action')}  skills={link.get('skills') or []}  "
                   f"sources={link.get('sources') or []}  {str(link.get('hash',''))[:12]}")
    click.echo(status)


@governance.command("impact")
@click.argument("identifier")
@click.option("--kind", type=click.Choice(["skill", "source", "any"]), default="any",
              help="Match the identifier as a skill, a source, or either.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def governance_impact(identifier: str, kind: str, as_json: bool) -> None:
    """Impact analysis: which recorded actions depended on a skill/source.

    Use after revoking a skill or flagging a bad source to see exactly what it
    touched across every run.
    """
    import json as _json

    from .. import governed_actions as _ga
    hits = _ga.impact_of(identifier, kind=kind)
    if as_json:
        click.echo(_json.dumps(hits))
        return
    if not hits:
        click.echo(f"no recorded actions depended on {identifier!r}.")
        return
    click.echo(click.style(f"Impact of {identifier!r}: {len(hits)} action(s)", bold=True))
    for h in hits:
        click.echo(f"  goal {h['goal_id']}  {h['action']}  via {h['via']}  {h['hash']}")




@main.group("canary")
def canary_group() -> None:
    """Record / compare cost-perf metric snapshots per release."""


def _parse_metrics(pairs: tuple[str, ...]) -> dict:
    out: dict = {}
    for p in pairs:
        if "=" not in p:
            raise click.ClickException(f"--metric must be name=value, got {p!r}")
        name, _, val = p.partition("=")
        try:
            out[name.strip()] = float(val)
        except ValueError as e:
            raise click.ClickException(f"metric {name!r} value not numeric: {val!r}") from e
    return out


@canary_group.command("record")
@click.argument("release")
@click.option("--metric", "metrics", multiple=True,
              help="name=value (repeatable), e.g. --metric p95_latency_s=3.4")
def canary_record(release: str, metrics: tuple[str, ...]) -> None:
    """Record RELEASE's metric snapshot (cost/latency/success_rate/...)."""
    from ..release_canary import CanaryStore
    parsed = _parse_metrics(metrics)
    if not parsed:
        raise click.ClickException("at least one --metric is required")
    CanaryStore().record(release, parsed)
    click.echo(f"recorded {len(parsed)} metric(s) for release {release!r}")


@canary_group.command("compare")
@click.argument("baseline")
@click.argument("candidate")
@click.option("--tolerance", type=click.FloatRange(min=0), default=0.10,
              help="Relative move allowed before flagging a regression.")
def canary_compare(baseline: str, candidate: str, tolerance: float) -> None:
    """Compare CANDIDATE release metrics against BASELINE; exit 1 on regression."""
    from ..release_canary import CanaryStore, compare, render
    if not math.isfinite(tolerance):
        raise click.BadParameter("must be finite and nonnegative", param_hint="--tolerance")
    store = CanaryStore()
    base, cand = store.get(baseline), store.get(candidate)
    if base is None:
        raise click.ClickException(f"no recorded metrics for baseline {baseline!r}")
    if cand is None:
        raise click.ClickException(f"no recorded metrics for candidate {candidate!r}")
    result = compare(base, cand, tolerance=tolerance)
    click.echo(render(result))
    if not result.passed:
        raise SystemExit(1)


@main.command()
@click.option("--sample", "sample", nargs=2, type=str, default=None,
              metavar="CONFIDENCE CORRECT",
              help="Record one labeled sample: verifier confidence (0-1) and "
                   "whether the answer was actually correct (true/false). "
                   "Build the set across calls, then run with no args to assess.")
@click.option("--json", "as_json", is_flag=True, help="Emit the verdict as JSON.")
def calibrate(sample, as_json) -> None:
    """Assess verifier calibration -- the self-improvement safety interlock.

    The verifier's confidence is the label the trajectory-donation flywheel
    learns from, so a drifted verifier would teach the system its own mistakes.
    With ``--sample`` append one ``(confidence, ground_truth)`` pair to the
    calibration set; with no arguments, assess the set and persist the verdict
    that gates donation. If the verifier no longer separates correct from
    incorrect answers (and ``[calibration] enforce`` is on), learning freezes.
    """
    import json as _json

    from .. import calibration

    if sample is not None:
        conf_s, correct_s = sample
        try:
            conf = float(conf_s)
        except ValueError as e:
            raise click.BadParameter(
                "confidence must be a finite number in [0,1]", param_hint="--sample",
            ) from e
        if not math.isfinite(conf) or not 0 <= conf <= 1:
            raise click.BadParameter(
                "confidence must be a finite number in [0,1]", param_hint="--sample",
            )
        word = correct_s.strip().lower()
        true_words = {"1", "true", "yes", "y", "pass"}
        false_words = {"0", "false", "no", "n", "fail"}
        if word not in true_words | false_words:
            raise click.BadParameter("correct must be an explicit true/false word", param_hint="--sample")
        correct = word in true_words
        ok = calibration.record_sample(conf, correct, source="cli")
        click.echo("recorded calibration sample" if ok else "failed to record sample")
        return

    report = calibration.run_assessment()
    if as_json:
        click.echo(_json.dumps(report.to_dict(), indent=2))
        return
    status = (
        click.style("ADEQUATE", fg="green") if report.adequate
        else click.style("INADEQUATE", fg="red")
    )
    click.echo(click.style("Verifier calibration", bold=True))
    click.echo(f"  status:          {status}")
    click.echo(
        f"  samples:         {report.n} "
        f"({report.n_correct} correct / {report.n_incorrect} incorrect)"
    )
    click.echo(f"  discrimination:  {report.discrimination:.3f}")
    click.echo(f"  brier score:     {report.brier:.3f}")
    click.echo(f"  {report.reason}")
    if not report.adequate:
        from ..config import get_calibration
        if get_calibration()["enforce"]:
            click.echo(click.style(
                "  learning is FROZEN (trajectory donation gated) until this passes.",
                fg="yellow",
            ))
        else:
            click.echo("  note: [calibration] enforce is off, so learning is not frozen.")


@main.command("runs")
@click.option("--json", "as_json", is_flag=True,
              help="Emit machine-readable JSON (array of run objects).")
@click.option("-n", "--limit", default=50, type=int, help="Max runs to show.")
@click.option("--goal", "goal_id", default=None, type=int,
              help="Only runs for this goal id.")
@click.pass_context
def runs(ctx, as_json: bool, limit: int, goal_id) -> None:
    """List recent runs (episodes) with cost, status, and timing.

    A "run" is one episode of the agent loop against a goal. ``--json``
    emits a stable array (one object per run) — this is the contract the
    VS Code extension's runs view consumes, so keep the field names
    stable.
    """
    world = open_world(ctx.obj["db"])
    try:
        episodes = world.list_episodes(limit=limit, goal_id=goal_id)
        goal_cache = {}
        records = []
        for e in episodes:
            if e.goal_id not in goal_cache:
                goal_cache[e.goal_id] = world.get_goal(e.goal_id)
            g = goal_cache[e.goal_id]
            duration = (
                round(e.ended_at - e.started_at, 3)
                if e.ended_at is not None else None
            )
            records.append({
                "episode_id": e.id,
                "goal_id": e.goal_id,
                "goal_title": g.title if g else None,
                "goal_status": g.status if g else None,
                "outcome": e.outcome,            # None while the run is live
                "running": e.ended_at is None,
                "started_at": e.started_at,
                "ended_at": e.ended_at,
                "duration_s": duration,
                "cost_dollars": e.cost_dollars,
                "input_tokens": e.input_tokens,
                "output_tokens": e.output_tokens,
                "tool_calls": e.tool_calls,
            })
    finally:
        world.close()

    if as_json:
        import json as _json
        click.echo(_json.dumps(records, default=str))
        return

    if not records:
        click.echo("no runs yet.")
        return
    click.echo(click.style(f"Recent runs ({len(records)})", bold=True))
    for r in records:
        state = "running" if r["running"] else (r["outcome"] or "done")
        title = _strip_terminal_control(r["goal_title"] or "")[:48]
        click.echo(
            f"  ep #{r['episode_id']:<4} goal {r['goal_id']:<4} "
            f"[{state:<10}] ${r['cost_dollars']:.4f}  "
            f"in={r['input_tokens']:,} out={r['output_tokens']:,} "
            f"tools={r['tool_calls']}  {title}"
        )


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
@click.option("--recovery-mode", is_flag=True, help="Local isolated recovery: no normal jobs or schedulers.")
def dashboard(host: str, port: int, recovery_mode: bool = False) -> None:
    """Start the local web dashboard + REST API."""
    # Mirror the module entrypoint's safety contract (app.main): refuse to bind a
    # non-loopback host without a token, so this CLI path can't expose an
    # unauthenticated admin surface even though the middleware would also 401.
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get(
        "MAVERICK_DASHBOARD_TOKEN"
    ):
        click.echo(
            "Refusing to bind dashboard to a non-loopback host without "
            "MAVERICK_DASHBOARD_TOKEN set in the server environment.",
            err=True,
        )
        sys.exit(2)
    try:
        from maverick_dashboard.app import app as fastapi_app
    except ImportError as exc:
        if isinstance(exc, ModuleNotFoundError) and exc.name == "maverick_dashboard":
            click.echo(
                "Install the dashboard from the same reviewed Lightwork checkout; "
                "public-index lookup is disabled.",
                err=True,
            )
        else:
            click.echo(
                f"Lightwork dashboard could not load: {_strip_terminal_control(str(exc))}. "
                "Run `maverick doctor` "
                "to check the installation before retrying.",
                err=True,
            )
        sys.exit(2)
    if recovery_mode:
        from maverick_dashboard.recovery_mode import configure
        configure(fastapi_app, host=host)
    click.echo(f"Lightwork dashboard: http://{host}:{port}")
    click.echo(f"REST API docs:      http://{host}:{port}/docs")
    try:
        from ..proxy_auth import uvicorn_launch_kwargs
        proxy_kwargs = uvicorn_launch_kwargs()
    except Exception:  # pragma: no cover - never block startup on a config read
        proxy_kwargs = {}
    from maverick_dashboard._server import run_dashboard_server
    run_dashboard_server(fastapi_app, host=host, port=port, log_level="info", **proxy_kwargs)


@main.command()
@click.option("--http", "use_http", is_flag=True,
              help="Serve over Streamable HTTP instead of stdio.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind host (with --http).")
@click.option("--port", default=8771, type=int, show_default=True,
              help="Port (with --http).")
def mcp(use_http: bool, host: str, port: int) -> None:
    """Start the MCP server on stdio (or --http).

    This is Lightwork's official cross-language surface. Any MCP-speaking
    client (TypeScript, Go, Rust, .NET, JVM, plus every IDE-side MCP
    client like Claude Code / Cursor / Continue / Zed) can drive the
    swarm from outside Python via this command. See
    docs/clients/typescript-quickstart.md for a 20-line example.
    """
    try:
        from maverick_mcp.server import MCPServer
    except ImportError:
        click.echo(
            "Install the MCP server from the same reviewed Lightwork checkout; "
            "public-index lookup is disabled.",
            err=True,
        )
        sys.exit(2)
    from ..deployment import require_enterprise_or_die
    require_enterprise_or_die()
    if use_http:
        try:
            from maverick_mcp.http_transport import serve
        except ImportError:
            click.echo(
                "Install the MCP HTTP extra from the same reviewed Lightwork "
                "checkout; public-index lookup is disabled.",
                err=True,
            )
            sys.exit(2)
        serve(host=host, port=port)
    else:
        # Run the stdio server directly. Going through server.main() would
        # re-parse sys.argv and reject the `mcp` subcommand token (the bug
        # that made `maverick mcp` -- the command every quickstart uses --
        # exit before serving).
        MCPServer().run()


@main.group()
def tenant() -> None:
    """Provision and manage tenants (hosted control plane)."""


@tenant.command("create")
@click.argument("tenant_id")
@click.option("--plan", default="free", help="Plan name (free/pro/enterprise/...).")
@click.option("--name", "display_name", default="", help="Human display name.")
@click.option(
    "--max-daily-dollars",
    type=float,
    default=0.0,
    show_default=True,
    help="Per-tenant daily spend cap (USD); 0 (the default) means no cap.",
)
def tenant_create(tenant_id: str, plan: str, display_name: str,
                  max_daily_dollars: float) -> None:
    """Provision a tenant + its isolated workspace."""
    from ..tenant.registry import create_tenant
    try:
        rec = create_tenant(tenant_id, plan=plan, display_name=display_name,
                             max_daily_dollars=max_daily_dollars)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"created tenant {rec.id!r} (plan {rec.plan}, status {rec.status})")
    from ..billing import known_plan_names
    if rec.plan not in known_plan_names():
        click.echo(
            f"  WARNING: plan {rec.plan!r} is not a known billing plan; its "
            f"entitlements fall back to 'free' until defined in [billing.plans]",
            err=True,
        )
    # Tell the operator where to drop this tenant's own provider keys / models /
    # budget so each client can use its own credentials (overlays global config).
    from ..workspace import Workspace
    click.echo(f"  per-tenant config: {Workspace(rec.id).root / 'config.toml'}")


def _dashboard_public_url() -> str:
    """The externally-reachable dashboard base URL for a CLI-built invite link.

    A browser flow reads ``request.base_url``; a CLI has no request, so it reads
    the same operator-configured public URL the flow-approval links use --
    ``MAVERICK_PUBLIC_URL`` env, else ``[dashboard] public_url`` /
    ``[flows] public_url`` in config. Empty when unset (the caller then prints
    the token path and tells the operator to prepend their host)."""
    url = os.environ.get("MAVERICK_PUBLIC_URL", "").strip()
    if url:
        return url
    try:
        from ..config import load_config
        cfg = load_config() or {}
        return str((cfg.get("dashboard") or {}).get("public_url")
                   or (cfg.get("flows") or {}).get("public_url") or "").strip()
    except Exception:
        return ""


def _require_unfinished_onboarding(tenant_id: str) -> None:
    from maverick_dashboard import invites, rbac

    from ..tenant.registry import get_tenant

    record = get_tenant(tenant_id)
    if (record is None or not record.active or rbac.list_tenant_roles(tenant_id)
            or any(inv.tenant == tenant_id for inv in invites.list_invites())):
        raise ValueError("tenant already exists with members or an invitation; use the dashboard to manage access")


@tenant.command("onboard")
@click.argument("tenant_id")
@click.option("--admin-email", "admin_email", required=True,
              help="Email to mint the first-admin dashboard invite for.")
@click.option("--plan", default="free", help="Plan name (free/pro/enterprise/...).")
@click.option("--name", "display_name", default="", help="Human display name.")
@click.option(
    "--max-daily-dollars", type=float, default=0.0, show_default=True,
    help="Per-tenant daily spend cap (USD); 0 (the default) means no cap.")
@click.option("--role", default="admin", show_default=True,
              help="RBAC role granted by the invite (admin/operator/auditor/viewer).")
@click.option("--base-url", "base_url", default=None,
              help="Dashboard base URL for the invite link "
                   "(default: MAVERICK_PUBLIC_URL / [dashboard] public_url).")
def tenant_onboard(tenant_id: str, admin_email: str, plan: str, display_name: str,
                   max_daily_dollars: float, role: str, base_url: str | None) -> None:
    """Provision a tenant AND mint its first-admin invite in one step.

    Wraps ``tenant create`` + the dashboard invite flow: it creates the tenant
    (plan, display name, spend cap) and mints a single-use, expiring invite
    link for ``--admin-email``, printed ONCE. The tenant is created first; a
    failure to mint the invite leaves the (already provisioned) tenant in place
    and exits non-zero so the operator can retry ``maverick tenant onboard``.
    """
    from ..tenant.registry import create_tenant, get_tenant
    try:
        rec = get_tenant(tenant_id)
        if rec is not None:
            _require_unfinished_onboarding(rec.id)
            click.echo(f"continuing unfinished setup for tenant {rec.id!r}")
        else:
            rec = create_tenant(tenant_id, plan=plan, display_name=display_name,
                                 max_daily_dollars=max_daily_dollars)
            click.echo(f"created tenant {rec.id!r} (plan {rec.plan}, status {rec.status})")
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    except PermissionError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    from ..billing import known_plan_names
    if rec.plan not in known_plan_names():
        click.echo(
            f"  WARNING: plan {rec.plan!r} is not a known billing plan; its "
            f"entitlements fall back to 'free' until defined in [billing.plans]",
            err=True,
        )
    try:
        from maverick_dashboard import invites
    except Exception as e:  # pragma: no cover - dashboard extra not installed
        click.echo(
            f"ERROR: tenant created, but the dashboard package is unavailable so "
            f"no invite was minted ({e}). Install maverick-dashboard, then mint "
            f"one from the /users page or re-run `maverick tenant onboard`.",
            err=True,
        )
        sys.exit(2)
    try:
        inv, token = invites.create_invite(admin_email, role, created_by="operator",
                                           tenant=rec.id,
                                           before_effect=lambda: _require_unfinished_onboarding(rec.id))
    except ValueError as e:
        click.echo(f"ERROR: tenant created, but the invite was rejected: {e}",
                   err=True)
        sys.exit(2)
    base = (base_url or _dashboard_public_url()).strip().rstrip("/")
    link = f"{base}/auth/invite/{token}" if base else f"/auth/invite/{token}"
    click.echo(f"first-admin invite for {inv.email} (role={inv.role}) — shown ONCE:")
    click.echo(f"  {link}")
    if not base:
        click.echo(
            "  NOTE: no dashboard public URL configured; prepend your dashboard's "
            "base URL. Set MAVERICK_PUBLIC_URL or [dashboard] public_url.",
            err=True,
        )
    if not invites.invites_enabled():
        click.echo(
            "  NOTE: dashboard invites are disabled; the link 404s until you set "
            "[dashboard] invites = true (or MAVERICK_DASHBOARD_INVITES=1).",
            err=True,
        )


@tenant.command("list")
def tenant_list() -> None:
    """List provisioned tenants."""
    from ..tenant.registry import list_tenants, tenant_spend_today
    rows = list_tenants()
    if not rows:
        click.echo("no tenants. create one with `maverick tenant create`")
        return
    for t in rows:
        cap = f"${t.max_daily_dollars:g}/day" if t.max_daily_dollars else "unlimited"
        # Surface tenants that are at/over today's spend cap -- enforcement
        # happens at serve time, and this is how an operator SEES which tenants
        # are currently over quota from the CLI. Only
        # capped tenants are checked (a ledger read each), so unlimited tenants
        # (the common case) cost nothing extra.
        flag = ""
        if t.max_daily_dollars > 0:
            spent = tenant_spend_today(t.id)
            if spent >= t.max_daily_dollars:
                flag = f"  [OVER QUOTA ${spent:.2f}/${t.max_daily_dollars:g}]"
        click.echo(f"  {t.id}  [{t.status}]  plan={t.plan}  quota={cap}{flag}")


@tenant.command("suspend")
@click.argument("tenant_id")
def tenant_suspend(tenant_id: str) -> None:
    """Suspend a tenant (its requests are refused until resumed)."""
    from ..tenant.registry import UnknownTenant, suspend_tenant
    try:
        suspend_tenant(tenant_id)
    except UnknownTenant:
        click.echo(f"ERROR: no such tenant {tenant_id!r}", err=True)
        sys.exit(2)
    click.echo(f"suspended {tenant_id!r}")


@tenant.command("resume")
@click.argument("tenant_id")
def tenant_resume(tenant_id: str) -> None:
    """Resume a suspended tenant."""
    from ..tenant.registry import UnknownTenant, resume_tenant
    try:
        resume_tenant(tenant_id)
    except UnknownTenant:
        click.echo(f"ERROR: no such tenant {tenant_id!r}", err=True)
        sys.exit(2)
    click.echo(f"resumed {tenant_id!r}")


@tenant.command("quota")
@click.argument("tenant_id")
@click.argument("max_daily_dollars", type=float)
def tenant_quota(tenant_id: str, max_daily_dollars: float) -> None:
    """Set a tenant's daily spend cap (USD; 0 = unlimited)."""
    import math

    from ..tenant.registry import UnknownTenant, set_quota
    # Clamping a negative cap to 0 (= UNLIMITED) would let a typo'd `-5`
    # quietly remove the cap, and nan/inf would slip past as "unlimited" /
    # "$inf/day" -- both disable the cap. Require a finite, non-negative
    # amount; use 0 for unlimited.
    if not math.isfinite(max_daily_dollars) or max_daily_dollars < 0:
        click.echo(f"ERROR: quota must be a finite, non-negative amount "
                   f"(got {max_daily_dollars:g}); use 0 for unlimited.", err=True)
        sys.exit(2)
    try:
        rec = set_quota(tenant_id, max_daily_dollars)
    except UnknownTenant:
        click.echo(f"ERROR: no such tenant {tenant_id!r}", err=True)
        sys.exit(2)
    # Render 0 as "unlimited" to match `tenant list`; printing "$0/day" while the
    # listing said "unlimited" was a contradiction in the same value.
    cap = f"${rec.max_daily_dollars:g}/day" if rec.max_daily_dollars else "unlimited"
    click.echo(f"{rec.id!r} quota -> {cap}")


@tenant.command("delete")
@click.argument("tenant_id")
@click.option("--purge", is_flag=True,
              help="Also delete the tenant's data directory (irreversible).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def tenant_delete(tenant_id: str, purge: bool, yes: bool) -> None:
    """Remove a tenant from the registry (optionally purging its data)."""
    from ..tenant.registry import TenantRegistryError, delete_tenant
    if purge and not yes and not click.confirm(
        f"PURGE all data for tenant {tenant_id!r}? This cannot be undone."
    ):
        click.echo("aborted")
        return
    try:
        deleted = delete_tenant(tenant_id, purge=purge)
    except (ValueError, TenantRegistryError) as e:
        raise click.ClickException(str(e)) from e
    if deleted:
        click.echo(f"deleted {tenant_id!r}" + (" (data purged)" if purge else ""))
    else:
        click.echo(f"ERROR: no such tenant {tenant_id!r}", err=True)
        sys.exit(2)


@tenant.command("rls-preflight")
@click.option("--dsn", default=None,
              help="Postgres DSN (else MAVERICK_PG_DSN / [world_model] dsn).")
def tenant_rls_preflight(dsn: str | None) -> None:
    """Check readiness to enable Postgres Row-Level Security.

    Reports, per tenant-scoped table, whether this DB role owns it (only the
    owner can install the RLS policy) and how many legacy unscoped rows remain
    (which RLS would hide). Assign those rows with `maverick tenant backfill`,
    then set [world_model] rls = true.
    """
    from ..world_model_backends import pg_rls
    resolved = pg_rls.resolve_dsn(dsn)
    if not resolved:
        click.echo("ERROR: no Postgres DSN (set MAVERICK_PG_DSN or "
                   "[world_model] dsn).", err=True)
        sys.exit(2)
    try:
        conn = pg_rls.connect(resolved, autocommit=True)
    except ImportError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    try:
        rep = pg_rls.preflight(conn)
    finally:
        conn.close()
    click.echo(f"role: {rep['role']}")
    for t, info in rep["tables"].items():
        if info.get("missing"):
            click.echo(f"  {t}: MISSING (run the app once to migrate the schema)")
            continue
        own = ("owned" if info["owned_by_current_role"]
               else f"NOT owned (owner={info['owner']})")
        click.echo(f"  {t}: {own}, {info['null_tenant_rows']} legacy "
                   f"NULL-tenant row(s)")
        if info.get("empty_tenant_rows"):
            click.echo(f"    {info['empty_tenant_rows']} legacy empty-tenant event row(s)")
    if rep["ready"]:
        click.echo("READY: set [world_model] rls = true (or MAVERICK_PG_RLS=1) "
                   "to enforce database tenant isolation.")
    else:
        click.echo("NOT READY: assign unscoped rows with `maverick tenant backfill "
                   "--tenant <id>` and ensure this role owns every table above.")


@tenant.command("backfill")
@click.option("--tenant", "tenant_id", required=True,
              help="Tenant id to assign legacy unscoped rows to.")
@click.option("--dsn", default=None,
              help="Postgres DSN (else MAVERICK_PG_DSN / [world_model] dsn).")
@click.option("--dry-run", is_flag=True,
              help="Report how many rows would be assigned without writing.")
def tenant_backfill(tenant_id: str, dsn: str | None, dry_run: bool) -> None:
    """Assign legacy unscoped rows to a tenant before enabling RLS.

    Pre-tenancy rows have a NULL tenant_id (empty for event records) and RLS would hide
    them. This assigns them to --tenant so they stay visible under that tenant.
    Idempotent and safe to re-run. Run `maverick tenant rls-preflight` first.
    """
    from ..world_model_backends import pg_rls
    resolved = pg_rls.resolve_dsn(dsn)
    if not resolved:
        click.echo("ERROR: no Postgres DSN (set MAVERICK_PG_DSN or "
                   "[world_model] dsn).", err=True)
        sys.exit(2)
    # Warn (don't block) if the target tenant isn't in the registry: a typo would
    # otherwise silently assign every legacy row to a non-existent tenant.
    try:
        from ..tenant.registry import get_tenant
        if get_tenant(tenant_id) is None:
            click.echo(f"WARNING: tenant {tenant_id!r} is not in the registry; "
                       "continuing (use `maverick tenant create` if this is a typo).")
    except Exception:
        pass
    try:
        conn = pg_rls.connect(resolved, autocommit=False)
    except ImportError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    try:
        report = pg_rls.backfill(conn, tenant_id, dry_run=dry_run)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    finally:
        conn.close()
    verb = "would assign" if dry_run else "assigned"
    for t in sorted(report):
        click.echo(f"  {t}: {verb} {report[t]}")
    click.echo(f"{verb} {sum(report.values())} row(s) to tenant {tenant_id!r}"
               + (" (dry run)" if dry_run else ""))


@tenant.command("kms-rotate")
@click.option("--old-kek-file", "old_kek_file",
              type=click.Path(exists=True, dir_okay=False, readable=True),
              help="File containing the current KEK (hex/base64, 32 bytes).")
@click.option("--new-kek-file", "new_kek_file",
              type=click.Path(exists=True, dir_okay=False, readable=True),
              help="File containing the new KEK (hex/base64, 32 bytes).")
@click.option("--dry-run", is_flag=True,
              help="Report what each tenant would do; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def tenant_kms_rotate(old_kek_file: str | None, new_kek_file: str | None,
                      dry_run: bool, yes: bool) -> None:
    """Rotate every tenant's wrapped DEK between LocalKMS KEKs.

    Use when rolling the at-rest master key / MAVERICK_KMS_KEK. Re-wrap only --
    no tenant data is re-encrypted. Idempotent and resumable: a tenant already
    on the new KEK is skipped, so a re-run finishes an interrupted rotation. Set
    the new KEK live only AFTER this reports 0 failed. Supply KEKs via protected
    files or the hidden prompts; raw KEKs are never accepted in command argv.
    """
    from ..tenant.kms_fleet import rotate_local_fleet

    def _read_kek(label: str, path: str | None) -> str:
        if path:
            return Path(path).read_text(encoding="utf-8").strip()
        return click.prompt(label, hide_input=True).strip()

    old_kek = _read_kek("Current KEK", old_kek_file)
    new_kek = _read_kek("New KEK", new_kek_file)
    if not dry_run and not yes:
        click.confirm("Re-wrap every tenant's DEK to the new KEK?", abort=True)
    try:
        rep = rotate_local_fleet(old_kek, new_kek, dry_run=dry_run)
    except Exception as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    tag = " (dry run)" if dry_run else ""
    click.echo(f"fleet KEK rotation{tag}: {rep['total']} tenant(s) with a DEK")
    click.echo(f"  rotated: {len(rep['rotated'])}  skipped (already new): "
               f"{len(rep['skipped'])}  failed: {len(rep['failed'])}")
    for tid, reason in sorted(rep["failed"].items()):
        click.echo(f"  FAILED {tid}: {reason}", err=True)
    if rep["failed"]:
        click.echo("Do NOT retire the old KEK: some tenants are still wrapped "
                   "under it. Resolve the failures and re-run.", err=True)
        sys.exit(1)


@main.group()
def billing() -> None:
    """Rate metered usage into invoices and inspect plan entitlements."""


@billing.command("invoice")
@click.argument("tenant_id")
@click.option("--since", default=None, help="Start day (YYYY-MM-DD, inclusive).")
@click.option("--until", default=None, help="End day (YYYY-MM-DD, inclusive).")
@click.option("--markup-pct", type=float, default=0.0, help="Markup on provider cost.")
@click.option("--min-charge", type=float, default=0.0, help="Minimum invoice total.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def billing_invoice(tenant_id: str, since: str | None, until: str | None,
                    markup_pct: float, min_charge: float, as_json: bool) -> None:
    """Generate an invoice for a tenant from its metered usage."""
    import json as _json

    from ..audit.events import is_valid_day
    from ..billing import RateCard, generate_invoice
    from ..tenant.registry import get_tenant, list_tenants
    # Period bounds compare lexically against YYYY-MM-DD ledger keys, so a typo'd
    # --since/--until ("2026-6-1", "june") silently fell out of range and minted
    # a misleading empty invoice. Reject anything that isn't a real calendar day.
    for _label, _val in (("--since", since), ("--until", until)):
        if _val is not None and not is_valid_day(_val):
            click.echo(f"ERROR: {_label} must be a valid YYYY-MM-DD date (got {_val!r}).",
                       err=True)
            sys.exit(2)
    inv = generate_invoice(
        tenant_id, RateCard(markup_pct=markup_pct, minimum_charge=min_charge),
        since=since, until=until,
    )
    # A typo'd tenant id reads an absent ledger and rates to an empty $0 invoice
    # that reads like a real "owes nothing" statement. Flag only the genuinely
    # suspect case -- an EMPTY invoice for a tenant a provisioned roster has
    # never heard of -- as an error. We still invoice (a) any tenant that has
    # usage, so a deleted-but-unpurged tenant's surviving ledger can be billed a
    # final time, and (b) every tenant when no roster exists at all (the opt-in
    # registry is absent in single-tenant deployments), leaving those unchanged.
    if not inv.line_items and list_tenants() and get_tenant(tenant_id) is None:
        click.echo(
            f"ERROR: no such tenant {tenant_id!r}, and no metered usage to bill. "
            "Check the tenant id (or widen --since/--until).", err=True,
        )
        sys.exit(2)
    if as_json:
        click.echo(_json.dumps(inv.to_dict(), indent=2))
        return
    click.echo(f"Invoice for {tenant_id!r}  {inv.period_start or '…'} → {inv.period_end or '…'}")
    if inv.invoice_id:
        click.echo(f"  id: {inv.invoice_id}  (idempotency key — charge this period once)")
    else:
        click.echo("  id: (open-ended period — NOT a safe dedup key; pass --since and "
                   "--until to close the period before charging)")
    for li in inv.line_items:
        click.echo(f"  {li.day}  {li.principal:<24} ${li.charge:.4f} "
                   f"({li.in_tokens}+{li.out_tokens} tok)")
    if not inv.line_items:
        click.echo("  (no metered usage in this period)")
    click.echo(f"  {'-' * 40}")
    click.echo(f"  TOTAL: ${inv.total:.2f} {inv.currency}")


@billing.command("entitlements")
@click.argument("tenant_id")
def billing_entitlements(tenant_id: str) -> None:
    """Show a tenant's plan entitlements (features + limits)."""
    from ..billing import entitlements_for
    from ..tenant.registry import get_tenant
    rec = get_tenant(tenant_id)
    plan = rec.plan if rec else "free"
    ent = entitlements_for(plan)
    click.echo(f"{tenant_id!r}  plan={plan}")
    click.echo(f"  features: {', '.join(sorted(ent.features)) or '(none)'}")
    cap = f"${ent.max_daily_dollars:g}/day" if ent.max_daily_dollars else "unlimited"
    goals = ent.max_concurrent_goals or "unlimited"
    click.echo(f"  max spend/day: {cap}   max concurrent goals: {goals}")


@billing.command("stripe-status")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def billing_stripe_status(as_json: bool) -> None:
    """Show whether Stripe platform billing is enabled and why (never charges)."""
    import json as _json

    from ..billing_stripe import status
    st = status()
    if as_json:
        click.echo(_json.dumps(st.to_dict(), indent=2))
        return
    click.echo(f"Stripe platform billing: {'ENABLED' if st.enabled else 'disabled'}")
    click.echo(f"  reason: {st.reason}")
    click.echo(f"  secret key present: {st.has_secret_key}   "
               f"webhook secret present: {st.has_webhook_secret}")
    click.echo(f"  stripe SDK installed: {st.sdk_available}")
    click.echo(f"  bill metered usage: {st.bill_metered_usage}"
               f"   (off = platform fee only)")
    click.echo(f"  plans priced: {', '.join(st.plans_priced) or '(none)'}   "
               f"currency: {st.currency}")


@billing.command("stripe-preview")
@click.argument("tenant_id")
@click.option("--since", default=None, help="Start day (YYYY-MM-DD, inclusive).")
@click.option("--until", default=None, help="End day (YYYY-MM-DD, inclusive).")
@click.option("--markup-pct", type=float, default=0.0, help="Markup on provider cost.")
@click.option("--min-charge", type=float, default=0.0, help="Minimum invoice total.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def billing_stripe_preview(tenant_id: str, since: str | None, until: str | None,
                           markup_pct: float, min_charge: float,
                           as_json: bool) -> None:
    """Dry-run what a Stripe sync WOULD charge a tenant (no network calls)."""
    import json as _json

    from ..audit.events import is_valid_day
    from ..billing import RateCard
    from ..billing_stripe import preview_charges
    for _label, _val in (("--since", since), ("--until", until)):
        if _val is not None and not is_valid_day(_val):
            click.echo(f"ERROR: {_label} must be a valid YYYY-MM-DD date (got {_val!r}).",
                       err=True)
            sys.exit(2)
    card = RateCard(markup_pct=markup_pct, minimum_charge=min_charge)
    prev = preview_charges(tenant_id, card, since=since, until=until)
    if as_json:
        click.echo(_json.dumps(prev, indent=2))
        return
    click.echo(f"Stripe charge preview for {tenant_id!r}  (plan {prev['plan']})")
    fee = prev["platform_fee_price"] or "(no price configured for this plan)"
    click.echo(f"  platform fee (recurring): {fee}")
    if not prev["billing_enabled"]:
        click.echo("  NOTE: Stripe billing is currently disabled; this is a preview only.")
    if prev["metered_billing_enabled"]:
        click.echo(f"  metered model usage WOULD be billed: "
                   f"{len(prev['usage_items_that_would_bill'])} item(s), "
                   f"${prev['metered_total']:.2f} {prev['currency'].upper()}")
    else:
        click.echo(f"  metered model usage: computed (${prev['metered_total']:.2f} "
                   f"{prev['currency'].upper()}) but NOT billed "
                   "(bill_metered_usage is off; platform fee only)")


@billing.command("stripe-sync")
@click.argument("tenant_id")
@click.option("--since", default=None, help="Usage start day (YYYY-MM-DD).")
@click.option("--until", default=None, help="Usage end day (YYYY-MM-DD).")
@click.option("--markup-pct", type=float, default=0.0, help="Markup on provider cost.")
@click.option("--min-charge", type=float, default=0.0, help="Minimum invoice total.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def billing_stripe_sync(tenant_id: str, since: str | None, until: str | None,
                        markup_pct: float, min_charge: float, as_json: bool) -> None:
    """Sync a tenant to Stripe: ensure customer + platform-fee subscription (and
    push metered usage only when metered billing is enabled)."""
    import json as _json

    from ..audit.events import is_valid_day
    from ..billing import RateCard
    from ..billing_stripe import StripeError, sync_tenant_for_period
    from ..tenant.registry import UnknownTenant
    for _label, _val in (("--since", since), ("--until", until)):
        if _val is not None and not is_valid_day(_val):
            click.echo(f"ERROR: {_label} must be a valid YYYY-MM-DD date (got {_val!r}).",
                       err=True)
            sys.exit(2)
    try:
        result = sync_tenant_for_period(
            tenant_id, RateCard(markup_pct=markup_pct, minimum_charge=min_charge),
            since=since, until=until,
        )
    except UnknownTenant:
        click.echo(f"ERROR: no such tenant {tenant_id!r}.", err=True)
        sys.exit(2)
    except StripeError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    if as_json:
        click.echo(_json.dumps(result, indent=2, default=str))
        return
    sub = result["subscription"]
    click.echo(f"synced tenant {tenant_id!r} to Stripe")
    click.echo(f"  customer: {result['customer']}")
    click.echo(f"  subscription: {sub.get('status')} (plan {sub.get('plan')}"
               f"{', price ' + sub['price'] if sub.get('price') else ''})")
    items = result.get("usage_items")
    if items is not None:
        click.echo(f"  metered usage items pushed: {len(items)}")
    else:
        click.echo("  metered usage: not billed (bill_metered_usage is off; "
                   "platform fee only)")


@main.group()
def diag() -> None:
    """Diagnostics: circuit breakers, rate-limit predictions, run health, cost-by-tag."""


@diag.command("circuits")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def diag_circuits(as_json: bool) -> None:
    """Show the provider circuit-breaker states (closed/open/half-open)."""
    import json as _json

    from ..circuit_breaker import snapshot
    snaps = snapshot()
    if as_json:
        click.echo(_json.dumps(snaps, indent=2))
        return
    if not snaps:
        click.echo("no circuit breakers tripped this process.")
        return
    for s in snaps:
        click.echo(f"  {s.get('key')}: {s.get('state')} "
                   f"(failures={s.get('consecutive_failures', 0)})")


@diag.command("ratelimits")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def diag_ratelimits(as_json: bool) -> None:
    """Show recent per-provider call rates (feeds the rate-limit predictor)."""
    import json as _json

    from ..rate_limit_predictor import report
    rows = report()
    if as_json:
        click.echo(_json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("no provider calls recorded yet this process.")
        return
    for r in rows:
        click.echo(f"  {r.get('provider')}: {r.get('recorded', 0)} call(s) in window")


@diag.command("health")
@click.argument("goal_id", type=int)
@click.pass_context
def diag_health(ctx, goal_id: int) -> None:
    """Compute a 0-100 health score for a finished goal from its episode."""
    from ..health_score import goal_health, render
    from ..world_model import close_world_if_owned, open_world
    # An explicit --db selects this diagnostic's database; otherwise retain
    # open_world's canonical default/backend and active-tenant resolution.
    path = ctx.obj["db"] if ctx.find_root().params.get("db") is not None else None
    w = open_world(path)
    try:
        found = goal_health(w, goal_id)
    finally:
        close_world_if_owned(w)
    if found is None:
        click.echo(f"ERROR: no such goal {goal_id}", err=True)
        sys.exit(2)
    g, h = found
    click.echo(f"goal #{goal_id} ({g.status}):")
    click.echo(render(h))


@diag.command("replay")
@click.argument("trace_file", type=click.Path(exists=True))
@click.option("--kind", default=None, help="Only show events of this kind.")
def diag_replay(trace_file: str, kind: str | None) -> None:
    """Read a replayable run trace (written when MAVERICK_TRACE_DIR or [replay] record is set)."""
    from ..replay.trace import read_trace
    events = read_trace(trace_file)
    shown = 0
    for e in events:
        if kind and e.get("kind") != kind:
            continue
        shown += 1
        click.echo(f"  [{e.get('seq')}] {e.get('kind')}  "
                   f"{e.get('agent', '')}: {str(e.get('content', ''))[:100]}")
    click.echo(f"  ({shown} of {len(events)} event(s))")


@diag.command("cost-by-tag")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def diag_cost_by_tag(ctx, as_json: bool) -> None:
    """Split run cost across tags (from priced episodes)."""
    import json as _json

    from ..cost.by_tag import gather, render
    from ..world_model import close_world_if_owned, open_world
    path = ctx.obj["db"] if ctx.find_root().params.get("db") is not None else None
    world = open_world(path)
    try:
        buckets = gather(world)
    finally:
        close_world_if_owned(world)
    if as_json:
        click.echo(_json.dumps(buckets, indent=2))
        return
    click.echo(render(buckets))


@main.group("mcp-registry")
def mcp_registry_group() -> None:
    """Discover external MCP servers from a registry.

    A registry is a self-hostable `<base>/mcp/index.json` (point
    `[mcp_registries] indexes` at your own). Registry installation is disabled
    until publisher authentication is available. (`maverick mcp` — without
    `-registry` — starts Lightwork's own MCP
    server; this group manages the servers Lightwork *consumes*.)
    """


@mcp_registry_group.command("browse")
def mcp_registry_browse() -> None:
    """List MCP servers available in the registry."""
    from ..mcp_registry import load_mcp_registry
    entries = load_mcp_registry()
    if not entries:
        click.echo("no registry entries (index empty or unreachable).")
        return
    for e in entries:
        mark = " [verified]" if e.verified else ""
        transport = "http" if (e.spec or {}).get("url") else "stdio"
        click.echo(f"  {e.name}{mark}  v{e.version}  ({transport})")
        if e.summary:
            click.echo(f"    {e.summary}")
    click.echo("")
    click.echo("Registry installation is unavailable; independently review and configure servers.")


@mcp_registry_group.command("add")
@click.argument("name")
def mcp_registry_add(name: str) -> None:
    """Explain why registry-supplied servers cannot currently be installed."""
    from ..mcp_registry import add_mcp_server_to_config, install_mcp_from_registry
    try:
        spec = install_mcp_from_registry(name)
        add_mcp_server_to_config(spec.name, spec.to_dict())
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    transport = "http" if spec.is_http else "stdio"
    click.echo(f"added: {spec.name} ({transport}) -> [mcp_servers.{spec.name}]")
    click.echo("it loads on your next `maverick start` / `maverick chat`.")


@mcp_registry_group.command("remove")
@click.argument("name")
def mcp_registry_remove(name: str) -> None:
    """Remove a configured MCP server from config."""
    from ..mcp_registry import remove_mcp_server_from_config
    try:
        removed = remove_mcp_server_from_config(name)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    if removed:
        click.echo(f"removed: {name}")
    else:
        click.echo(f"no MCP server {name!r} in config.", err=True)
        sys.exit(2)


@mcp_registry_group.command("list")
@click.pass_context
def mcp_registry_list(ctx) -> None:
    """List MCP servers currently configured in ~/.maverick/config.toml."""
    from ..mcp_client import load_mcp_specs_from_config
    specs = load_mcp_specs_from_config()
    if not specs:
        click.echo("no MCP servers configured. add one with "
                   "`maverick mcp-registry add <name>`.")
        return
    for s in specs:
        if s.is_http:
            click.echo(f"  {s.name}  (http)  {s.url}")
        else:
            argstr = " ".join([s.command, *s.args])
            click.echo(f"  {s.name}  (stdio)  {argstr}")


def _apply_director(profile: str, outcome: str, description: str,
                    max_dollars: float | None) -> tuple[str, str, float | None]:
    """Director mode for this process's one run (:mod:`maverick.director_mode`).

    The profile's consent mode and review checkpoints apply to this process
    only (it runs this one goal); its budget multiple is applied to the
    requested or configured cap and then clamped to the configured cap, so a
    profile can never raise spending past what the deployment allows.
    """
    from ..director_mode import UnknownProfileError, direct
    from ..runner import requested_goal_dollars

    try:
        run = direct(outcome, profile=profile, base_max_dollars=max_dollars)
    except (UnknownProfileError, ValueError) as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(2)
    for name, value in run.env_overrides.items():
        if value:
            os.environ[name] = value
    extra = f"\n\n{description}" if description else ""
    capped = requested_goal_dollars(run.max_dollars)
    click.echo(f"[director {profile}] consent={run.consent_mode} "
               f"checkpoint={run.checkpoint} max_dollars={capped}")
    return run.goal_title, run.goal_description + extra, capped


def _sample_task(value, template_name, title, description, domain):
    """``start --sample``: the dashboard's first-outcome title, brief and
    specialist, so the run knows which sample files to read and the sample rule
    (a title alone did not). Returns the inputs unchanged without ``--sample``."""
    if not value:
        return title, description, domain, None
    from .. import sample_outcomes

    department = sample_outcomes.resolve_department(value, default=None)
    if department is None:
        names = ", ".join(row["department"] for row in sample_outcomes.departments())
        click.echo(f"ERROR: unknown sample department {value!r}; choose one of: {names}", err=True)
        sys.exit(2)
    if template_name or title or description or domain:
        click.echo("ERROR: --sample sets the task, its brief and its specialist; "
                   "drop TITLE, --template, --description and --domain", err=True)
        sys.exit(2)
    outcome = sample_outcomes.get(department)
    return outcome.title, sample_outcomes.goal_description(department), outcome.pack, department


def _validate_sample_backend(department, backend) -> None:
    """Refuse sample runs when the backend cannot read fixtures from the host."""
    if department is None:
        return
    from ..config import get_sandbox

    chosen = str(backend or get_sandbox().get("backend") or "local").strip().lower()
    # These backends mount the host workdir or copy it into the execution
    # environment. SSH, Modal, Firecracker and third-party backends do not
    # guarantee that host files are visible to the run.
    if chosen not in {"local", "docker", "podman", "gvisor", "devcontainer", "kubernetes"}:
        click.echo(
            f"ERROR: --sample is not supported with the {chosen!r} sandbox because "
            "its work folder is not shared with this computer. "
            "Choose --sandbox docker, podman, gvisor, devcontainer, kubernetes or local "
            "to run the bundled sample. No task was started.",
            err=True,
        )
        sys.exit(2)


def _place_sample(department, sandbox) -> None:
    """Copy the sample files into the work folder the run reads (no-op without ``--sample``)."""
    if department is None:
        return
    from .. import sample_outcomes

    try:
        sample_outcomes.create_sample_workspace(department, sandbox.workdir)
    except OSError as exc:
        click.echo(f"ERROR: the sample files could not be placed in the work folder ({exc}).", err=True)
        sys.exit(2)


def _mark_sample(world, goal_id, department) -> None:
    """Record the sample-data event on the goal (no-op without ``--sample``)."""
    if department is not None:
        from .. import sample_outcomes

        sample_outcomes.mark_goal_as_sample(world, goal_id, department)


def _propagate_coding_flags(coding_mode: bool, best_of_n: int) -> None:
    """Export the coding-mode / best-of-N env flags that ``coding_mode.from_env()``
    reads everywhere. ``--best-of-n`` only takes effect under ``--coding-mode``,
    so warn (rather than silently single-run) if it's set without it."""
    if coding_mode:
        os.environ["MAVERICK_CODING_MODE"] = "1"
    if best_of_n > 1:
        os.environ["MAVERICK_BEST_OF_N"] = str(best_of_n)
        if not coding_mode:
            click.echo(
                "WARNING: --best-of-n only takes effect with --coding-mode; "
                "without it the swarm does a single run.",
                err=True,
            )


@main.command()
@click.argument("title", required=False)
@click.option("--description", default="")
@click.option("--template", "template_name", default=None)
@click.option("--sample", "sample_department", default=None,
              help="Run a department's first task on sample data: the same brief, files "
                   "and sample record as the dashboard's first outcome (e.g. finance).")
@click.option("--param", "-p", "params", multiple=True)
@click.option("--max-dollars", default=None, type=float)
@click.option("--max-wall-seconds", default=None, type=float)
@click.option("--max-depth", default=3, type=int)
@click.option("--workdir", default=None)
@click.option("--sandbox", "sandbox_backend", default=None,
              type=click.Choice(BUILTIN_SANDBOX_BACKENDS))
@click.option("--domain", default=None,
              help="Run as a specific domain agent's specialist (see "
                   "`maverick domains-audit` for available domains).")
@click.option("--coding-mode", is_flag=True,
              help="Strict diff-only worker prompts + git apply --check "
                   "self-validation. Use for SWE-bench-style runs.")
@click.option("--best-of-n", default=1, type=int,
              help="In coding mode, generate N candidate patches and "
                   "pick the one whose tests pass (or applies smallest).")
@click.option("--fail-to-pass", default=None,
              help="||-separated pytest node IDs that must pass after fix "
                   "(SWE-bench FAIL_TO_PASS). Enables test-driven verifier.")
@click.option("--pass-to-pass", default=None,
              help="||-separated pytest node IDs that must KEEP passing.")
@click.option("--dry-cost", is_flag=True,
              help="Estimate cost from similar past runs and exit "
                   "(no LLM key needed, no swarm run, no goal created).")
@click.option("--repeat", default=1, type=int,
              help="Run the SAME goal N times. Repeated attempts at one task "
                   "share a task_family, so their better-vs-worse outcomes form "
                   "the preference pairs DPO needs (pair with [telemetry] "
                   "donate_min_entropy = 0 to capture them). Non-clean runs are "
                   "kept, not fatal, in repeat mode.")
@click.option("--director", "director_profile", default=None,
              type=click.Choice(["supervised", "semi", "autonomous"]),
              help="Director mode: TITLE is an outcome, run plan-first under this "
                   "autonomy profile (consent, review checkpoints and budget from "
                   "[director.profiles], clamped to the configured spend cap).")
@click.option("--result-file", type=click.Path(dir_okay=False, path_type=Path), default=None,
              help="Write a private native single-run result for automation to a new file. Existing files are never replaced.")
@click.option("--result-key-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None,
              help="Bind --result-file to an automation-owned private 32-byte key. The key is never emitted.")
@click.pass_context
@_humane_errors
def start(
    ctx, title, description, template_name, params,
    max_dollars, max_wall_seconds, max_depth, workdir, sandbox_backend,
    domain, coding_mode, best_of_n, fail_to_pass, pass_to_pass, dry_cost,
    repeat, director_profile, result_file=None, result_key_file=None, sample_department=None,
) -> None:
    """Start a new goal and run the swarm."""
    from .run_result import prepare_result_target, read_result_key, write_if_requested
    result_file = prepare_result_target(result_file, repeat=repeat, dry_cost=dry_cost, key_file=result_key_file)
    result_key = read_result_key(result_key_file)
    # Coding-mode flags propagate via env so coding_mode.from_env()
    # picks them up everywhere (agent prompt, patch validator,
    # test-driven verifier, best-of-N candidate eval).
    _propagate_coding_flags(coding_mode, best_of_n)
    if fail_to_pass:
        os.environ["MAVERICK_FAIL_TO_PASS"] = fail_to_pass
    if pass_to_pass:
        os.environ["MAVERICK_PASS_TO_PASS"] = pass_to_pass
    # A --dry-cost estimate needs no LLM (it never runs the swarm), so don't
    # gate it on a provider key.
    if not dry_cost:
        _require_llm_key()
    title, description, domain, sample = _sample_task(
        sample_department, template_name, title, description, domain)
    if template_name:
        from ..templates import load_template
        try:
            tpl = load_template(template_name)
        except (FileNotFoundError, ValueError) as e:
            click.echo(f"ERROR: {e}", err=True)
            sys.exit(2)
        param_dict = {}
        for raw in params:
            if "=" not in raw:
                click.echo(f"ERROR: --param must be key=value, got {raw!r}", err=True)
                sys.exit(2)
            k, v = raw.split("=", 1)
            param_dict[k.strip()] = v.strip()
        try:
            title, description = tpl.render(**param_dict)
        except ValueError as e:
            click.echo(f"ERROR: {e}", err=True)
            sys.exit(2)
        from ..runner import requested_goal_dollars, requested_goal_wall_seconds

        if max_dollars is None:
            max_dollars = requested_goal_dollars(tpl.budget_dollars)
        if max_wall_seconds is None:
            max_wall_seconds = requested_goal_wall_seconds(tpl.budget_wall_seconds)
        click.echo(f"[template {tpl.name}] {title}")
    elif not title:
        click.echo("ERROR: pass TITLE or --template <name>", err=True)
        sys.exit(2)
    if director_profile:
        title, description, max_dollars = _apply_director(
            director_profile, title, description, max_dollars)

    if dry_cost:
        # Forecast from past priced runs and exit — no goal created, no run.
        from ..cost.forecast import forecast, gather_samples, render
        world = open_world(ctx.obj["db"])
        try:
            fc = forecast(gather_samples(world), f"{title} {description}".strip())
        finally:
            world.close()
        click.echo(render(fc))
        return

    # Refuse BEFORE creating the goal row, so neither refusal leaves an
    # orphan blocked/failed row per attempt after `goal #N created`.
    _require_cli_execution_allowed()
    from .. import providers as _providers
    from ..config import load_config as _load_config
    from ..operator_preflight import _model_specs

    # Check the same effective offline routes the agents will resolve. Raw
    # config values plus DEFAULT_MODEL ignored tenant role edits, dashboard
    # pins, the admin allow-list, and could demand an Anthropic SDK even when
    # every executable route was local.
    _start_config = _load_config()
    _specs = _model_specs(_start_config)
    _sdk_msgs = _providers.missing_sdks(sorted(_specs))
    if _sdk_msgs:
        for m in _sdk_msgs:
            click.echo(f"ERROR: {m}", err=True)
        sys.exit(2)

    # A default first-run install without a container allows answer work, but
    # cannot write files or run programs. Say so before creating a paid task.
    _warn_file_work_before_start(_start_config, sandbox_backend)

    _validate_sample_backend(sample, sandbox_backend)
    k = _kernel()
    with _cli_sandbox(k, workdir=workdir, backend=sandbox_backend) as sandbox:
        # Containment and devcontainer settings can change the actual work folder.
        # Use the constructed backend's directory, not the CLI/config input.
        _place_sample(sample, sandbox)
        llm = k.LLM(model=_cli_model(ctx, "orchestrator"))
        import threading
        import types as _types

        from ..budget import budget_from_config
        from ..orchestrator import _budget_task_class
        from ..runner import goal_budget_defaults

        # --repeat N runs the SAME task N times so its attempts share a task_family
        # and form DPO preference pairs. A fresh goal row + budget per run.
        n_runs = max(1, repeat)
        for _run_i in range(n_runs):
            world = open_world(ctx.obj["db"])
            goal_id = world.create_goal(title, description)
            _mark_sample(world, goal_id, sample)
            _label = f" [{_run_i + 1}/{n_runs}]" if n_runs > 1 else ""
            click.echo(f"goal #{goal_id} created{_label}: {title}")
            # Honor [budget] in config.toml (building Budget() directly would
            # silently ignore config caps). Precedence: built-in defaults
            # < config < explicit CLI flags. A None flag passes through as "unset".
            bud = budget_from_config(
                defaults=goal_budget_defaults(),
                # Learned per-class default cap (default-on, lowest precedence; via
                # [budget] self_tuning). Department runs use their own class so
                # finance runs are sized by finance history.
                task_class=_budget_task_class(
                    _types.SimpleNamespace(title=title), domain,
                ),
                max_dollars=max_dollars,
                max_wall_seconds=max_wall_seconds,
            )

            # So that `maverick start "..."` does not look hung between "goal
            # created" and the final printout, a background poller
            # streams goal_events to stderr so the user sees the swarm thinking
            # in real time. Non-tty output (e.g. piped to a file) skips the
            # poller so logs aren't littered with progress lines.
            stop_poll = threading.Event()
            poller = _maybe_start_progress_poller(world.path, goal_id, stop_poll)

            try:
                if coding_mode and best_of_n > 1:
                    import asyncio as _asyncio

                    from ..orchestrator import run_goal_best_of_n
                    result = _asyncio.run(run_goal_best_of_n(
                        llm, world, bud, goal_id,
                        sandbox=sandbox, max_depth=max_depth, n=best_of_n,
                    ))
                else:
                    result = k.run_goal_sync(
                        llm, world, bud, goal_id,
                        sandbox=sandbox, max_depth=max_depth, domain=domain,
                    )
                # Capture the kernel's final verdict before the DB is closed so the
                # exit code can reflect it (see _run_outcome_blocked).
                _blocked = _run_outcome_blocked(world, goal_id)
            finally:
                stop_poll.set()
                if poller is not None:
                    poller.join(timeout=2.0)
                # Close so WorldModel.close()'s WAL TRUNCATE checkpoint runs; the
                # poller thread (already joined) used its own connection.
                try:
                    _write_cli_result(
                        write_if_requested, result_file, world, goal_id, bud,
                        domain=domain, key=result_key,
                    )
                finally:
                    world.close()
            click.echo("")
            click.echo(_strip_result_terminal_control(str(result)))
            # Single-run keeps the exit-2-on-blocked contract (scripts/CI rely on
            # it). In repeat mode a non-clean run is EXPECTED (it's what produces
            # the worse-attempt half of a preference pair), so keep going.
            if _blocked and n_runs == 1:
                sys.exit(2)


@main.command("report-issue")
@click.argument("goal_id", type=int)
@click.option("--repo", default=None,
              help="GitHub repo owner/name to file against (default: Lightwork).")
@click.pass_context
def report_issue(ctx, goal_id: int, repo: str | None) -> None:
    """Build a pre-filled GitHub bug-report URL from a failed goal run.

    Gathers the goal's error events, scrubs secrets, and prints a
    github.com/.../issues/new link with the context filled in. No network
    call -- open the URL yourself to file the report.
    """
    from ..issue_report import DEFAULT_REPO, build_report
    world = open_world(ctx.obj["db"])
    g = world.get_goal(goal_id)
    if g is None:
        click.echo(f"No goal #{goal_id}.", err=True)
        sys.exit(1)
    errors = [e for e in world.goal_events(goal_id, limit=10_000) if e.kind == "error"]
    url = build_report(g, errors, repo=repo or DEFAULT_REPO)
    click.echo("Open this URL to file a pre-filled bug report:\n")
    click.echo(url)


@main.command("share")
@click.argument("goal_id", type=int)
def share(goal_id: int) -> None:
    """Share a run as a sanitized, private GitHub gist.

    Exports the run's trajectory (secrets scrubbed) and uploads it as a
    secret gist. Needs a GitHub token in GITHUB_TOKEN (or GH_TOKEN).
    """
    from ..run_share import share_run
    try:
        url = share_run(goal_id)
    except RuntimeError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)
    click.echo(f"Shared run #{goal_id}: {url}")


def _sanitize_progress_content(text: str, limit: int = 200) -> str:
    """Sanitize untrusted event content before printing to a TTY.

    - Scrub secret-looking values.
    - Remove terminal control bytes / ANSI escape sequences.
    - Collapse CR/LF to spaces for one-line progress output.
    """
    from ..secrets import scrub  # lazy: only used by the streaming helper
    cleaned = scrub(text or "")
    # Strip common ANSI/OSC escape sequences.
    cleaned = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", cleaned)
    cleaned = re.sub(r"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)", "", cleaned)
    # Replace newlines / carriage returns, then drop remaining control chars.
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", cleaned)
    return cleaned[:limit]


def _stream_progress(db_path, goal_id: int, stop) -> None:
    """Poll goal_events and print one line per new entry to stderr.

    Uses a fresh WorldModel so we don't share the connection with the
    main thread (SQLite WAL handles concurrent reads + one writer).
    """
    try:
        wm = open_world(db_path)
    except Exception:
        return
    seen = 0
    labels = {
        "plan": "thinking", "finding": "answer", "observation": "result",
        "error": "error", "verify": "checking", "artifact": "produced",
    }
    while not stop.is_set():
        try:
            evs = wm.goal_events(goal_id, since_id=seen, limit=200)
            for e in evs:
                label = labels.get(e.kind, e.kind)
                # Strip the hex suffix from agent names for readability.
                agent = e.agent.split("-")[0] if e.agent else "agent"
                content = _sanitize_progress_content(e.content, limit=200)
                click.echo(
                    click.style(f"  [{agent}] ", fg="bright_black")
                    + click.style(f"{label}: ", fg="cyan")
                    + content,
                    err=True,
                )
                seen = e.id
        except Exception:
            pass
        if stop.wait(timeout=1.5):
            break
    wm.close()


@main.command()
@click.option("--max-depth", default=3, type=int)
@click.option("--max-dollars", default=None, type=float)
@click.option("--workdir", default=None)
@click.pass_context
@_humane_errors
def chat(ctx, max_depth: int, max_dollars: float, workdir) -> None:
    """Interactive chat REPL. Each turn becomes a goal.

    Multi-line input: end a line with ``\\`` to continue, or open with
    ``\"\"\"`` to enter a paste block ending with ``\"\"\"`` on its own line.
    """
    _require_llm_key()
    k = _kernel()
    world = open_world(ctx.obj["db"])
    llm = k.LLM(model=_cli_model(ctx, "orchestrator"))
    with _cli_sandbox(k, workdir=workdir) as sandbox:
        # Thread turns through a conversation scoped to this REPL process.
        # Do not use a fixed (channel, user_id) key here: conversations are
        # persistent, so a global CLI key would replay prior chat sessions into
        # unrelated future prompts.
        session_user_id = f"local:{uuid.uuid4().hex}"
        conversation = world.get_or_create_conversation("cli", session_user_id)
        click.echo(click.style("Lightwork chat. Type 'exit' to leave.", fg="cyan"))
        click.echo(click.style(
            "Multi-line: end a line with \\ or wrap a block in \"\"\".",
            fg="bright_black",
        ))
        while True:
            try:
                line = click.prompt("", prompt_suffix="> ", default="", show_default=False)
            except (EOFError, click.exceptions.Abort):
                click.echo("")
                return
            line = line.rstrip()
            if not line:
                continue
            if line in ("exit", "quit", "/exit", "/quit"):
                return

            # Paste-block mode: """ ... """
            if line.startswith('"""'):
                buf = [line[3:]] if len(line) > 3 else []
                while True:
                    try:
                        nxt = click.prompt(
                            "", prompt_suffix="... ", default="", show_default=False,
                        )
                    except (EOFError, click.exceptions.Abort):
                        click.echo("")
                        return  # canceled input is never a submitted task
                    if nxt.rstrip().endswith('"""'):
                        tail = nxt.rstrip()[:-3].rstrip()
                        if tail:
                            buf.append(tail)
                        break
                    buf.append(nxt)
                full = "\n".join(buf).strip()
            # Line-continuation mode: trailing backslash.
            elif line.endswith("\\"):
                buf = [line[:-1].rstrip()]
                while True:
                    try:
                        nxt = click.prompt(
                            "", prompt_suffix="... ", default="", show_default=False,
                        ).rstrip()
                    except (EOFError, click.exceptions.Abort):
                        click.echo("")
                        return  # discard the partial buffer on cancellation
                    if nxt.endswith("\\"):
                        buf.append(nxt[:-1].rstrip())
                    else:
                        buf.append(nxt)
                        break
                full = "\n".join(b for b in buf if b)
            else:
                full = line

            if not full.strip():
                continue

            title = full.splitlines()[0][:80]
            goal_id = world.create_goal(title, full)
            # Record the user's turn so run_goal threads it (and the assistant's
            # reply, which run_goal appends) into the next turn's context.
            world.append_turn(conversation.id, "user", full, goal_id=goal_id)
            click.echo(click.style(f"  ... goal #{goal_id}", fg="bright_black"))
            from ..budget import budget_from_config
            from ..runner import goal_budget_defaults

            bud = budget_from_config(defaults=goal_budget_defaults(), max_dollars=max_dollars)
            try:
                result = k.run_goal_sync(llm, world, bud, goal_id,
                                       sandbox=sandbox, max_depth=max_depth,
                                       conversation_id=conversation.id)
            except Exception as e:
                click.echo(click.style(f"  ✗ {e}", fg="red"))
                continue
            click.echo(result)
            click.echo("")


@main.group()
def template() -> None:
    """Manage goal templates."""


@template.command("list")
def template_list() -> None:
    from ..templates import list_templates
    names = list_templates()
    if not names:
        click.echo("no templates found.")
        return
    for n in names:
        click.echo(f"  {n}")


@template.command("show")
@click.argument("name")
def template_show(name: str) -> None:
    from ..templates import load_template
    try:
        t = load_template(name)
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"template: {t.name}\npath: {t.path}\ntitle: {t.title}")
    click.echo(f"budget: ${t.budget_dollars} / {t.budget_wall_seconds}s")
    click.echo(f"params: {', '.join(t.params) or '(none)'}\n")
    click.echo(t.body)


@template.command("browse")
def template_browse() -> None:
    """List goal templates available in the community registry."""
    from ..templates import browse_templates
    entries = browse_templates()
    if not entries:
        click.echo("no registry templates (index empty or unreachable).")
        return
    from ..marketplace.ratings import RatingsLedger, stars_bar
    ledger = RatingsLedger()
    for e in entries:
        mark = " [verified]" if e.verified else ""
        rating = f"  {stars_bar(e.rating, e.ratings_count)}" if e.ratings_count else ""
        click.echo(f"  {e.name}{mark}  v{e.version}{rating}")
        if e.summary:
            click.echo(f"    {e.summary}")
        mine = ledger.my_rating("templates", e.name)
        if mine:
            click.echo(f"    your rating: {stars_bar(mine['stars'], 0)}")
    click.echo("")
    click.echo("install one with:  maverick template add <name>")
    click.echo("rate one with:     maverick template rate <name> <stars 1-5>")


@template.command("rate")
@click.argument("name")
@click.argument("stars", type=int)
@click.option("--comment", default="", help="Optional short note (kept local).")
def template_rate(name: str, stars: int, comment: str) -> None:
    """Rate a marketplace template 1-5 stars (stored locally).

    Your ratings annotate `browse` output and can be exported for an index
    submission with `maverick template ratings-export`.
    """
    from ..marketplace.ratings import RatingsLedger, stars_bar
    try:
        entry = RatingsLedger().rate("templates", name, stars, comment)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"rated {name}: {stars_bar(entry['stars'], 0)}")


@template.command("ratings-export")
def template_ratings_export() -> None:
    """Print your local ratings as the JSON fragment an index PR expects."""
    from ..marketplace.ratings import RatingsLedger
    click.echo(RatingsLedger().export_for_submission())


@template.command("add")
@click.argument("name")
def template_add(name: str) -> None:
    """Install a registry goal template by name (hash-verified)."""
    from ..templates import install_template_from_catalog
    try:
        t = install_template_from_catalog(name)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"installed: {t.name} -> {t.path}")
    click.echo(f"run it with:  maverick start --template {t.name}")


@main.command()
@click.argument("question")
@click.option("--rounds", default=2, show_default=True, type=int,
              help="Number of debate rounds before the judge decides.")
@click.option("--max-dollars", default=None, type=float,
              help="Override the configured spend cap (fallback: $1 per debate).")
@click.option("--for", "for_stance", default=None,
              help="Stance the proponent defends (default: 'yes / sound').")
@click.option("--against", "against_stance", default=None,
              help="Stance the skeptic defends (default: 'no / flawed').")
@click.pass_context
def debate(ctx, question: str, rounds: int, max_dollars: float | None,
           for_stance: str | None, against_stance: str | None) -> None:
    """Run a two-sided debate on QUESTION and print the judged verdict.

    Two LLM debaters -- a proponent and a skeptic -- argue for ROUNDS rounds,
    then an impartial judge declares a winner. Useful for pressure-testing a
    decision before you commit to it.
    """
    from ..debate import DebateParticipant, run_debate
    from ..llm import model_for_role

    # Friendly preflight (an unconfigured install would otherwise get a raw
    # anthropic-SDK TypeError traceback here), and route
    # through the configured role models instead of hard DEFAULT_MODEL
    # (kernel rule 2) -- debaters argue at the analyst tier.
    _require_cli_execution_allowed()
    selected_model = ctx.obj["model"] or model_for_role("analyst")
    _require_llm_key(selected_model)
    k = _kernel()
    llm = k.LLM(model=selected_model)
    participants = [
        DebateParticipant(
            name="Proponent",
            persona=for_stance or "the answer is YES / the proposal is sound",
            llm_complete=llm.complete,
        ),
        DebateParticipant(
            name="Skeptic",
            persona=against_stance or "the answer is NO / the proposal is flawed",
            llm_complete=llm.complete,
        ),
    ]
    result = run_debate(
        question, participants, judge_complete=llm.complete,
        rounds=rounds, budget=_cli_task_budget(question, max_dollars, 1.0),
    )
    for t in result.transcript:
        click.echo(f"\n[{t.speaker}]\n{t.text}")
    click.echo("\n" + "=" * 48)
    click.echo(f"Winner: {result.winner}")
    click.echo(f"Why: {result.judge_reason}")
    if result.key_argument:
        click.echo(f"Key argument: {result.key_argument}")
    click.echo(f"\n[{result.rounds_completed} round(s), ${result.total_dollars:.4f}]")


@main.command("schema-plan")
def schema_plan_cmd() -> None:
    """Show pending world-model schema migrations + whether they're hot-safe.

    Classifies each pending statement online (non-blocking) vs offline (table
    rewrite / data backfill) so you know before upgrading whether a
    maintenance window is needed. Exits 1 when the migration table fails its
    structural lint.
    """
    from ..schema_migrations import current_plan, render
    try:
        problems, _current, _target, steps = current_plan()
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc
    if problems:
        for pb in problems:
            click.echo(f"LINT: {pb}", err=True)
        sys.exit(1)
    click.echo(render(steps))


@main.command("config-lint")
def config_lint_cmd() -> None:
    """Validate ~/.maverick/config.toml: unknown sections/keys + obvious type
    mistakes, with closest-match suggestions. Exits 1 if any error-level finding."""
    from ..config import config_path, load_config
    from ..config_lint import format_findings, lint_config
    # load_config() is deliberately fail-soft: a corrupt config.toml yields {}
    # with only a warning, so linting it would find nothing and print
    # "config OK" -- the one tool meant to catch a broken config blessing a
    # file in which every setting is being dropped (mirrors
    # health._check_config). Parse the raw file FIRST so a syntax error is a
    # hard lint failure, not invisible.
    p = config_path()
    if not p.exists():
        # No config at all is a legitimate state (Lightwork runs on built-in
        # defaults), but falling through to load_config() == {} would print
        # "config OK" -- as if a real config had been validated. Say plainly
        # there's nothing to lint instead of blessing a non-existent file.
        click.echo(
            f"no config file at {p}; Lightwork is using built-in defaults. "
            "Create one with `maverick init` (nothing to lint yet)."
        )
        return
    try:
        import tomllib
    except ModuleNotFoundError:  # 3.10
        import tomli as tomllib
    try:
        with open(p, "rb") as f:
            tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as e:
        click.echo(
            f"error: {p} is not valid TOML -- every setting in it is being "
            f"IGNORED ({type(e).__name__}: {e})", err=True,
        )
        click.echo("ask an installation administrator to repair the saved settings or restore a known-good backup; setup will not replace them.")
        sys.exit(1)
    try:
        cfg = load_config() or {}
    except Exception as e:
        click.echo(f"could not load config: {e}", err=True)
        sys.exit(1)
    findings = lint_config(cfg)
    click.echo(format_findings(findings))
    if any(getattr(f, "severity", "") == "error" for f in findings):
        sys.exit(1)


@main.command("costs")
@click.option("--limit", default=30, show_default=True, help="Rows to show.")
@click.pass_context
def costs_cmd(ctx: click.Context, limit: int) -> None:
    """Cross-run spend, by day, from recorded episodes (the persisted ledger)."""
    from datetime import datetime, timezone

    from ..cost.report import format_report
    from ..world_model import close_world_if_owned
    w = _reporting_world(ctx)
    rows: list[dict] = []
    try:
        for ep in w.list_episodes(limit=1_000_000):
            if ep.cost_dollars and ep.ended_at:
                day = datetime.fromtimestamp(ep.ended_at, tz=timezone.utc).strftime("%Y-%m-%d")
                rows.append({"dollars": ep.cost_dollars, "day": day})
    finally:
        close_world_if_owned(w)
    click.echo(format_report(rows, by="day", top=limit))


@main.command("migrate")
@click.option("--apply", "do_apply", is_flag=True,
              help="Apply mechanical rewrites (after a timestamped backup). "
                   "Default is a dry run.")
@click.option("--config", "config_path", default=None,
              help="Path to config.toml (default: the active deployment's).")
def migrate_cmd(do_apply: bool, config_path: str | None) -> None:
    """Walk an existing config forward across versions.

    Reports migration advisories (real upgrade paths), lints unknown config
    sections (silent-no-op typos), and -- with --apply -- performs mechanical
    key renames behind a timestamped backup. Dry-run by default.
    """
    from pathlib import Path as _Path

    from ..migrate import migrate, render
    report = migrate(_Path(config_path) if config_path else None, apply=do_apply)
    click.echo(render(report))


@main.command("plan-reflect")
@click.argument("goal")
@click.option("--max-iterations", default=3, show_default=True, type=int,
              help="Max plan->execute->reflect passes before stopping.")
@click.option("--max-dollars", default=None, type=float,
              help="Override the configured spend cap (fallback: $2 per loop).")
@click.pass_context
def plan_reflect(ctx, goal: str, max_iterations: int, max_dollars: float | None) -> None:
    """Run the plan-execute-reflect loop on GOAL and print the trace.

    A planner breaks GOAL into steps, an executor runs each, and a reflector
    decides DONE / REVISE / CONTINUE -- looping until the goal is met, the
    iteration cap is reached, or the budget runs out.
    """
    from ..llm import model_for_role
    from ..plan_execute_reflect import run_plan_execute_reflect

    # Same preflight + role routing as `debate`: planning
    # belongs to the orchestrator tier, and a missing provider must refuse
    # cleanly, not traceback inside the anthropic client constructor.
    _require_cli_execution_allowed()
    selected_model = ctx.obj["model"] or model_for_role("orchestrator")
    _require_llm_key(selected_model)
    k = _kernel()
    llm = k.LLM(model=selected_model)
    result = run_plan_execute_reflect(
        goal,
        planner_complete=llm.complete,
        executor_complete=llm.complete,
        reflector_complete=llm.complete,
        max_iterations=max_iterations,
        budget=_cli_task_budget(goal, max_dollars, 2.0),
    )
    click.echo(f"Plan ({len(result.plan)} steps): {', '.join(result.plan) or '(empty)'}")
    for r in result.results:
        click.echo(f"\n[{r.step}]\n{r.output}")
    click.echo("\n" + "=" * 48)
    for i, refl in enumerate(result.reflections, 1):
        click.echo(f"reflect {i}: {refl.status} -- {refl.notes}")
    click.echo(f"\nStatus: {result.status} "
               f"[{result.iterations} iteration(s), ${result.total_dollars:.4f}]")


@main.command()
@click.option("--idle-sleep", default=2.0, show_default=True,
              help="Seconds to wait when the queue is empty.")
@click.option("--once", is_flag=True,
              help="Drain ready jobs and exit (for cron / systemd timers).")
def worker(idle_sleep: float, once: bool) -> None:
    """Run the background job worker.

    Drains the job queue (``~/.maverick/jobs.db``) and runs jobs armed with
    ``maverick schedule add``. Runs until interrupted (Ctrl-C / SIGTERM).

    With ``--once``, run all currently-ready jobs and exit instead of staying
    resident -- run it from system cron or a systemd timer for scheduling
    without a persistent daemon.
    """
    from ..worker import Worker
    w = Worker(idle_sleep=idle_sleep)
    if once:
        n = w.drain()
        click.echo(f"drained {n} job(s)")
        return
    click.echo(f"worker: draining {w.queue.db_path} (Ctrl-C to stop)")
    w.run_forever()


@main.group()
def queue() -> None:
    """Inspect the background job queue (backlog + dead-letter)."""


@queue.command("status")
def queue_status() -> None:
    """Show job counts by status (pending backlog, running, done, failed)."""
    from ..job_queue import JobQueue
    counts = JobQueue().counts()
    if not counts:
        click.echo("queue is empty.")
        return
    for status in sorted(counts):
        line = f"  {status:10s} {counts[status]}"
        if status == "failed" and counts[status]:
            line += "  <- dead-letter; inspect with `maverick queue failed`"
        click.echo(line)


@queue.command("failed")
@click.option("--limit", default=20, help="Max dead-letter jobs to show.")
def queue_failed(limit: int) -> None:
    """List failed (dead-letter) jobs and their last error.

    Crashed/exhausted jobs land in 'failed' and were otherwise invisible until
    `purge` deleted them — so an operator never saw a worker dropping work."""
    from ..job_queue import JobQueue
    jobs = JobQueue().list(status="failed", limit=limit)
    if not jobs:
        click.echo("no failed jobs.")
        return
    for j in jobs:
        err = (getattr(j, "last_error", "") or "").strip().replace("\n", " ")[:160]
        parked = "  <- recurring: `maverick queue reconcile`" if getattr(
            j, "recurrence_reconcile_required", False) else ""
        click.echo(f"  [{j.id}] kind={j.kind} attempts={getattr(j, 'attempts', '?')} "
                   f"error={err!r}{parked}")


@queue.command("reconcile")
@click.argument("job_id", type=int)
@click.option("--expected-attempts", type=int, required=True,
              help="The attempt count you inspected (`maverick queue failed`); "
                   "refused if the job changed since.")
@click.option("--rearm", is_flag=True, help="Authorize ONE future occurrence.")
@click.option("--successor", "successor_id", type=int, default=None,
              help="Link a reviewed, compatible successor job instead.")
@click.option("--yes", is_flag=True, help="Confirm (required).")
def queue_reconcile(job_id: int, expected_attempts: int, rearm: bool,
                    successor_id: int | None, yes: bool) -> None:
    """Resume a recurring schedule parked for reconciliation.

    A legacy recurring job whose last run cannot be proven to have finished is
    parked as failed (recurrence_reconcile_required) so its business work is
    never replayed blind. After inspecting it, either --rearm one future
    occurrence or link a --successor. The ambiguous run itself stays failed.
    """
    from ..job_queue import JobQueue
    if not yes:
        raise click.UsageError("reconciliation is an operator decision; pass --yes")
    try:
        next_id = JobQueue().reconcile_recurrence(
            job_id, expected_attempts=expected_attempts, successor_id=successor_id,
            rearm=rearm, confirm=True)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"job {job_id} reconciled; schedule continues as job {next_id}")


@main.group()
def schedule() -> None:
    """Schedule recurring jobs via cron (run them with `maverick worker`)."""


@schedule.command("add")
@click.argument("cron_expr")
@click.argument("kind")
@click.option("--payload", default=None,
              help='JSON object for the job handler, e.g. \'{"goal_id": 5}\'.')
def schedule_add(cron_expr: str, kind: str, payload: str | None) -> None:
    """Arm a recurring job: 5-field CRON_EXPR firing job KIND.

    Example: maverick schedule add "0 9 * * *" run_goal --payload '{"goal_id": 5}'
    """
    import json

    from ..job_queue import JobQueue
    from ..scheduler import CronError, next_run, schedule_cron
    try:
        next_run(cron_expr)  # validate up front
    except CronError as e:
        click.echo(f"ERROR: bad cron expression: {e}", err=True)
        sys.exit(2)
    data: dict = {}
    if payload:
        try:
            data = json.loads(payload)
        except ValueError as e:
            click.echo(f"ERROR: --payload must be valid JSON: {e}", err=True)
            sys.exit(2)
        if not isinstance(data, dict):
            click.echo("ERROR: --payload must be a JSON object.", err=True)
            sys.exit(2)
    from ..worker import BUILTIN_JOB_KINDS
    if kind not in BUILTIN_JOB_KINDS:
        click.echo(
            f"WARNING: {kind!r} is not a built-in job kind "
            f"(only {sorted(BUILTIN_JOB_KINDS)} ship by default). "
            "It will fail unless your `maverick worker` registers a handler for it.",
            err=True,
        )
    data["__cron__"] = cron_expr
    job_id, run_at = schedule_cron(JobQueue(), cron_expr, kind, data)
    from datetime import datetime
    when = datetime.fromtimestamp(run_at).strftime("%Y-%m-%d %H:%M:%S")
    click.echo(f"scheduled job {job_id} (kind={kind}); next run {when}")


@schedule.command("list")
def schedule_list() -> None:
    """List armed recurring schedules (pending cron jobs)."""
    from datetime import datetime

    from ..job_queue import JobQueue
    jobs = [j for j in JobQueue().list(status="pending") if j.payload.get("__cron__")]
    if not jobs:
        click.echo("no scheduled jobs.")
        return
    for j in jobs:
        when = datetime.fromtimestamp(j.run_at).strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"  [{j.id}] {j.payload['__cron__']!r} kind={j.kind} next={when}")


@schedule.command("rm")
@click.argument("job_id", type=int)
def schedule_rm(job_id: int) -> None:
    """Cancel a scheduled (pending) job by id."""
    from ..job_queue import JobQueue
    if JobQueue().cancel(job_id):
        click.echo(f"cancelled job {job_id}")
    else:
        click.echo(f"no pending job {job_id} (already running/done, or unknown).",
                   err=True)
        sys.exit(1)


@schedule.command("goal")
@click.argument("cron_expr")
@click.argument("text")
@click.option("--title", default=None,
              help="Short goal title (default: derived from TEXT).")
def schedule_goal(cron_expr: str, text: str, title: str | None) -> None:
    """Arm a recurring autonomous goal: run TEXT as a FRESH goal on CRON_EXPR.

    Unlike `schedule add run_goal` (which re-runs one fixed goal id), every fire
    creates a new goal from TEXT -- a true recurring task. Drain the queue with
    `maverick worker`; manage it with `schedule list` / `schedule rm`.

    Example: maverick schedule goal "0 9 * * 1-5" "Summarize my overnight emails"
    """
    from ..job_queue import JobQueue
    from ..scheduler import CronError, next_run, schedule_cron
    if not text.strip():
        click.echo("ERROR: goal TEXT must not be empty.", err=True)
        sys.exit(2)
    try:
        next_run(cron_expr)  # validate up front
    except CronError as e:
        click.echo(f"ERROR: bad cron expression: {e}", err=True)
        sys.exit(2)
    payload: dict = {"text": text, "__cron__": cron_expr}
    if title:
        payload["title"] = title
    job_id, run_at = schedule_cron(JobQueue(), cron_expr, "start_goal", payload)
    from datetime import datetime
    when = datetime.fromtimestamp(run_at).strftime("%Y-%m-%d %H:%M:%S")
    click.echo(f"scheduled goal job {job_id}; next run {when}")


@main.command()
@click.option("--max-depth", default=3, type=int)
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def serve(ctx: click.Context, max_depth: int, verbose: bool) -> None:
    """Start the channel server."""
    # Use Lightwork's shared logging config (JSON via MAVERICK_LOG_FORMAT=json,
    # correlation-id context filter, secret scrubbing) for parity with the
    # dashboard server entrypoint -- `serve` is the other network-exposed
    # process and otherwise inherited a raw basicConfig with none of that
    # hygiene. Falls back to basicConfig if the config module is unavailable.
    try:
        from ..logging_config import configure_logging
        configure_logging(level="DEBUG" if verbose else "INFO")
    except Exception:
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    # _configure_cli_logging (run by the group) defaults the root level to
    # ERROR so library noise stays off a consumer's terminal -- but `serve`
    # is a long-running server that wants its INFO/DEBUG logs. basicConfig is
    # a no-op once a handler exists, so set the level explicitly here.
    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)
    # Validate config at startup: a typo'd section/key silently uses a default
    # (e.g. an uncapped budget), so surface it now. Warn-only unless
    # MAVERICK_CONFIG_STRICT=1.
    try:
        from ..config_lint import warn_config_at_startup
        warn_config_at_startup()
    except SystemExit:
        raise
    except Exception:  # pragma: no cover - linting never blocks a non-strict start
        pass
    # Enterprise hard-gate: when the operator demands the data-boundary
    # guarantees (MAVERICK_REQUIRE_ENTERPRISE=1 / [enterprise] require=true),
    # refuse to start the channel server unless they hold -- the same preflight
    # the dashboard entrypoint runs. No-op otherwise (kernel stays fail-open).
    try:
        from ..deployment import EnterpriseRequiredError, require_enterprise_or_die
        require_enterprise_or_die()
    except EnterpriseRequiredError as e:
        click.echo(e.summary, err=True)
        sys.exit(3)
    try:
        from ..server import build_from_config
    except ImportError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    try:
        server = (build_from_config(db=ctx.obj["db"])
                  if ctx.parent is not None and ctx.parent.params.get("db") is not None
                  else build_from_config())
    except RuntimeError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    server.max_depth = max_depth
    click.echo("Lightwork serve running. Ctrl-C to stop.")
    _run_until_stopped(server)


def _run_until_stopped(server) -> None:
    """Run the server until Ctrl-C or SIGTERM. After a SIGTERM the process
    ends once the channels are closed, before asyncio waits for threads still
    working (a voice note being transcribed, a send with no timeout)."""
    stopping, restore = _stop_on_sigterm()
    try:
        with asyncio.Runner() as runner:
            try:
                runner.run(server.run())
            except KeyboardInterrupt:
                if not stopping:
                    raise
                try:  # writing fails once nothing reads the output (the dashboard that started it is gone)
                    click.echo("\nshutting down...")
                    runner.run(server.stop())
                finally:
                    _finish_sigterm(stopping)
    except KeyboardInterrupt:
        click.echo("\nshutting down...")
        asyncio.run(server.stop())
    finally:
        restore()  # stopped without one: a later SIGTERM ends the process as before
        _finish_sigterm(stopping)


def _stop_on_sigterm():
    """Stop on SIGTERM as on Ctrl-C, so every channel closes cleanly. The
    dashboard's Stop and Restart, systemd and container runtimes send SIGTERM,
    whose default ends the process before any channel can close. Windows ends
    the process without a signal Python can handle. Returns a list that holds
    True once a SIGTERM has arrived (see _finish_sigterm), and a function that
    puts SIGTERM's earlier handling back.

    Only the first SIGTERM is passed on: the dashboard's shutdown and a
    one-file build's launcher send it again, and asyncio turns a second Ctrl-C
    into an interruption in the middle of closing. Every one of them ends the
    process itself if it does not stop in time. When Ctrl-C is ignored (a
    script's background job), asyncio would not stop on it, so SIGTERM keeps
    its default."""
    import signal

    stopping: list[bool] = []
    if os.name == "nt" or signal.getsignal(signal.SIGINT) is not signal.default_int_handler:
        return stopping, lambda: None

    def stop(_signum, _frame):
        if not stopping:
            stopping.append(True)
            signal.raise_signal(signal.SIGINT)

    try:
        previous = signal.signal(signal.SIGTERM, stop)
    except ValueError:  # not the main thread: the default stays
        return stopping, lambda: None

    def restore():
        # None: the earlier handling was not set from Python, so it cannot be put back.
        if previous is not None and signal.getsignal(signal.SIGTERM) is stop:
            signal.signal(signal.SIGTERM, previous)
    return stopping, restore


def _finish_sigterm(stopping: list[bool]) -> None:
    """After a SIGTERM the channels are closed: end the process as SIGTERM
    always ended it, instead of waiting for local goals or other work still
    running on threads to finish. Never returns once a SIGTERM has arrived."""
    if not stopping:
        return
    import signal

    for stream in (sys.stdout, sys.stderr):  # None when started with its output closed
        try:
            if stream is not None:
                stream.flush()
        except (OSError, ValueError):
            pass
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.raise_signal(signal.SIGTERM)
    # Still here: a container's first process, which its own SIGTERM cannot end.
    os._exit(128 + signal.SIGTERM)


@main.command("history")
@click.option("--limit", default=20, type=int)
@click.pass_context
def history(ctx, limit: int) -> None:
    """Show recent goal + episode history.

    Registered as ``history`` (not ``logs``): a second ``@main.command("logs")``
    for the audit log silently shadowed this one. ``logs`` now unambiguously
    means the audit log; this goal/episode view is ``maverick history``."""
    world = open_world(ctx.obj["db"])
    goals = world.list_goals()
    if not goals:
        click.echo("no goals yet.")
        return
    for g in goals[-limit:]:
        # Goal titles/results are run-history text: strip terminal control
        # bytes (ANSI/OSC injection) before echoing.
        click.echo(f"#{g.id} [{g.status}] {_strip_terminal_control(g.title)}")
        if g.result:
            preview = _strip_terminal_control(
                (g.result or "")[:200].replace("\n", " "))
            click.echo(f"  -> {preview}{'...' if len(g.result) > 200 else ''}")


@main.command()
@click.option("--cost", is_flag=True,
              help="Include persisted spend totals and recent run costs.")
@click.pass_context
def status(ctx, cost: bool) -> None:
    """Show recent goals and open questions."""
    world = open_world(ctx.obj["db"])
    # Self-heal: a CLI run killed mid-flight (or pre-fix crash) leaves goals
    # stranded in 'active'/'pending'. The dashboard reclaims these on startup,
    # but a CLI-only user never triggers that -- so do it here, where the
    # ghosts are seen. Only touches rows older than the reclaim age window.
    try:
        world.reclaim_orphan_goals()
    except Exception:  # pragma: no cover -- never block `status` on cleanup
        pass
    if cost:
        total = world.total_spend()
        click.echo(click.style("Spend", bold=True))
        click.echo(f"  ${total['dollars']:.4f}  across {total['runs']} completed run(s)")
        click.echo(
            f"  {total['input_tokens']:,} input tokens  /  "
            f"{total['output_tokens']:,} output tokens"
        )
        recent = world.list_episodes(limit=5)
        if recent:
            click.echo("  recent:")
            for e in recent:
                outcome = e.outcome or "running"
                click.echo(f"    ep #{e.id} (goal {e.goal_id}) [{outcome}]  ${e.cost_dollars:.4f}")
        click.echo("")
    goals = world.list_goals()
    if not goals:
        click.echo("no goals yet. start one with `maverick start \"...\"`")
        return
    for g in goals[-10:]:
        click.echo(f"  #{g.id} [{g.status}] {_strip_terminal_control(g.title)}")
    qs = world.open_questions()
    if qs:
        click.echo("")
        click.echo("open questions:")
        for q in qs:
            click.echo(f"  #{q.id} (goal {q.goal_id}): "
                       f"{_strip_terminal_control(q.question)}")


@main.command()
@click.option("-n", "--limit", default=10, show_default=True, type=int,
              help="Max recent goals to include.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def ps(ctx, limit: int, as_json: bool) -> None:
    """List the runtime's processes: recent goals + scheduled jobs.

    A unified, read-only view across the two execution surfaces -- the world
    model's goals (last activity) and the cron/job queue (next run) -- so you
    can see what the runtime is doing or about to do in one place. Goals alone:
    `maverick status`; scheduled jobs alone: `maverick schedule list`.
    """
    import datetime as _dt
    import json as _json

    from ..world_model import open_world

    def _when(ts: float | None) -> str:
        if not ts:
            return ""
        return _dt.datetime.fromtimestamp(
            ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M")

    procs: list[dict] = []
    try:
        world = open_world(ctx.obj["db"])
        for g in world.list_goals(limit=limit, order="desc"):
            # Raw title here: --json PRESERVES stored values (pinned by
            # test_ps_json_preserves_raw_values); the table renderer below
            # strips terminal control bytes at display time.
            procs.append({"type": "goal", "id": g.id, "state": g.status,
                          "when": _when(g.updated_at), "what": g.title})
    except Exception:  # fail-soft: a missing/locked world shouldn't crash ps
        pass
    try:
        from ..job_queue import JobQueue
        for j in JobQueue().list(status="pending"):
            cron = j.payload.get("__cron__")
            what = j.kind + (f"  [{cron}]" if cron else "")
            procs.append({"type": "job", "id": j.id, "state": j.status,
                          "when": _when(j.run_at), "what": what})
    except Exception:
        pass

    if as_json:
        click.echo(_json.dumps(procs, default=str))
        return
    if not procs:
        click.echo("no goals or scheduled jobs.")
        return
    click.echo(f"{'TYPE':4}  {'ID':>5}  {'STATE':9}  {'WHEN (UTC)':16}  WHAT")
    for p in procs:
        what = _strip_terminal_control(str(p["what"]))
        click.echo(f"{p['type']:4}  {p['id']!s:>5}  {p['state']:9}  "
                   f"{p['when']:16}  {what}")


@main.command()
@click.argument("question_id", type=int)
@click.argument("answer", nargs=-1, required=True)
@click.pass_context
def answer(ctx, question_id: int, answer: tuple[str, ...]) -> None:
    """Answer a pending question."""
    world = open_world(ctx.obj["db"])
    if not world.answer(question_id, " ".join(answer)):
        click.echo(
            f"no such question #{question_id}. "
            "See open questions with `maverick status`.",
            err=True,
        )
        sys.exit(1)
    click.echo(f"answered #{question_id}")


def _apply_resume_spend(world, goal_id: int, budget) -> None:
    """Reserve earlier non-durable episode costs without charging them twice."""
    from .. import checkpoint

    if checkpoint.enabled() or budget.max_dollars is None:
        return
    limit = 1000
    episodes = world.list_episodes(goal_id=goal_id, limit=limit)
    while len(episodes) == limit:
        limit *= 2
        episodes = world.list_episodes(goal_id=goal_id, limit=limit)
    costs = [episode.cost_dollars for episode in episodes]
    if any(isinstance(cost, bool) or not isinstance(cost, (float, int))
           or not math.isfinite(cost) or cost < 0 for cost in costs):
        raise click.ClickException("Cannot resume: the goal's recorded spend is invalid.")
    spent = math.fsum(costs)
    if not math.isfinite(spent):
        raise click.ClickException("Cannot resume: the goal's recorded spend is invalid.")
    if spent >= budget.max_dollars:
        click.echo(
            f"Cannot resume: this goal has already spent ${spent:.2f} of its "
            f"${budget.max_dollars:.2f} cap. Raise --max-dollars to continue.", err=True,
        )
        raise SystemExit(2)
    # Episode and tenant ledgers record this invocation's counters. Reducing
    # the remaining allowance preserves that accounting while enforcing the
    # full goal cap across non-durable resumes.
    budget.max_dollars -= spent


@main.command()
@click.argument("goal_id_arg", required=False, type=int, metavar="[GOAL_ID]")
@click.option("--goal-id", "goal_id", type=int, default=None,
              help="The goal to resume (alternative to the positional GOAL_ID).")
@click.option("--max-depth", default=3, type=int)
@click.option("--max-dollars", type=float, default=None,
              help="Raise the dollar cap for this resume (e.g. after a budget halt).")
@click.option("--max-wall-seconds", type=float, default=None,
              help="Raise the wall-clock cap for this resume.")
@click.option("--sandbox", "sandbox_backend", default=None,
              type=click.Choice(BUILTIN_SANDBOX_BACKENDS),
              help="Sandbox backend for this resume (default: the [sandbox] config).")
@click.pass_context
@_humane_errors
def resume(ctx, goal_id_arg, goal_id, max_depth: int, max_dollars, max_wall_seconds,
           sandbox_backend) -> None:
    """Resume a blocked goal.

    Pass the goal id positionally (``maverick resume 7``) or via ``--goal-id``;
    omit both to resume the current active/blocked goal.
    """
    world = open_world(ctx.obj["db"])
    # The positional arg and --goal-id are equivalent; the option wins if both
    # are given. The budget-halt / error messages suggest the positional form.
    if goal_id is None:
        goal_id = goal_id_arg
    if goal_id is None:
        g = world.active_goal()
        if not g:
            click.echo("no active or blocked goal to resume.")
            return
        goal_id = g.id
    elif not world.get_goal(goal_id):
        # An explicit --goal-id that doesn't exist is a user error: report it
        # and exit non-zero. Otherwise the run prints run_goal's "no such goal"
        # and still exits 0, which a script can't detect (export exits 2 here).
        click.echo(f"no such goal #{goal_id}. See `maverick status`.", err=True)
        sys.exit(2)
    open_qs = world.open_questions(goal_id)
    if open_qs:
        click.echo(f"cannot resume goal #{goal_id}: {len(open_qs)} open question(s).")
        for q in open_qs:
            click.echo(f"  #{q.id}: {q.question}")
        sys.exit(2)
    # Validate the local resume target before provider readiness. Looking up a
    # goal (including the graceful "nothing to resume" path) needs no LLM and
    # should remain useful while an operator is repairing provider credentials.
    _require_llm_key()
    k = _kernel()
    llm = k.LLM(model=_cli_model(ctx, "orchestrator"))
    # Honor [budget] config, and let --max-dollars/--max-wall-seconds raise
    # the cap on resume (the budget-halt message tells users to do this).
    from ..budget import budget_from_config
    from ..runner import goal_budget_defaults

    bud = budget_from_config(
        defaults=goal_budget_defaults(),
        max_dollars=max_dollars,
        max_wall_seconds=max_wall_seconds,
    )
    _apply_resume_spend(world, goal_id, bud)
    # Honor the configured [sandbox] backend on resume too, rather than
    # falling back to run_goal's default local backend and ignoring a user who
    # configured docker/podman. --sandbox overrides it, so an operator who ran
    # `start --sandbox docker` keeps the same isolation on resume; None = config.
    with _cli_sandbox(k, backend=sandbox_backend) as sandbox:
        result = k.run_goal_sync(llm, world, bud, goal_id,
                                 sandbox=sandbox, max_depth=max_depth,
                                 resume=True)
    click.echo(_strip_result_terminal_control(str(result)))
    if _run_outcome_blocked(world, goal_id):
        sys.exit(2)


@main.command()
@click.argument("goal_id", type=int)
@click.option("--to-step", type=int, default=None,
              help="Rewind to this checkpoint step (the agent re-runs from here).")
@click.option("--fork", is_flag=True,
              help="Restart from the step as a NEW goal, leaving the original intact.")
@click.option("--list", "list_only", is_flag=True,
              help="List the checkpoint steps available to rewind to.")
@click.pass_context
@_humane_errors
def rewind(ctx, goal_id: int, to_step, fork: bool, list_only: bool) -> None:
    """Restart a goal from an earlier checkpoint (durable execution).

    \b
      maverick rewind 7 --list                # which steps can I go back to?
      maverick rewind 7 --to-step 12          # re-run goal 7 from step 12
      maverick rewind 7 --to-step 12 --fork   # try a different branch as a new goal

    Requires durable execution ([durable] enabled) to have checkpointed the run.
    After rewinding, continue the run with `maverick resume`.
    """
    from .. import checkpoint as ckpt_mod
    world = open_world(ctx.obj["db"])
    if not world.get_goal(goal_id):
        click.echo(f"no such goal #{goal_id}. See `maverick status`.", err=True)
        sys.exit(2)
    ck = ckpt_mod.Checkpointer(world)
    found = ck.orchestrator_for(goal_id)
    if found is None:
        click.echo(f"goal #{goal_id} has no checkpoints "
                   "(durable execution off, or it was never run with it on).")
        return
    agent_id, episode_id = found
    if list_only or to_step is None:
        steps = ck.list_steps(goal_id, agent_id, episode_id)
        if not steps:
            click.echo(f"goal #{goal_id}: no checkpoint steps recorded.")
        else:
            click.echo(f"goal #{goal_id} checkpoint steps available: "
                       f"{steps[0]}..{steps[-1]} ({len(steps)} kept)")
            click.echo(f"rewind with `maverick rewind {goal_id} --to-step N [--fork]`")
        return
    res = ckpt_mod.rewind(world, goal_id, to_step, fork=fork)
    click.echo(res.detail)
    if not res.ok:
        sys.exit(1)


@main.command()
@click.argument("key")
@click.argument("value", nargs=-1, required=True)
@click.pass_context
def fact(ctx, key: str, value: tuple[str, ...]) -> None:
    """Set a fact in the world model."""
    if not key.strip():
        click.echo("error: fact key cannot be empty", err=True)
        sys.exit(2)
    world = open_world(ctx.obj["db"])
    world.upsert_fact(key, " ".join(value))
    click.echo(f"set {key}")


@main.command()
@click.pass_context
def facts(ctx) -> None:
    """List known facts."""
    world = open_world(ctx.obj["db"])
    items = world.get_facts()
    if not items:
        click.echo('no facts yet. set one with `maverick fact <key> "<value>"`')
        return
    for k, v in items.items():
        click.echo(_strip_terminal_control(f"  {k}: {v}"))


@main.group(invoke_without_command=True)
@click.pass_context
def skills(ctx: click.Context) -> None:
    """List skills the swarm has distilled or installed.

    With no subcommand, lists skills. Use `skills stats` to see each skill's
    track record and `skills evict` to prune ones that rarely help.
    """
    if ctx.invoked_subcommand is not None:
        return
    from ..skills import available_skills, builtin_skills_dir
    items = available_skills()
    if not items:
        click.echo(f"no skills yet (in {builtin_skills_dir()} or ~/.maverick/skills).")
        return
    for s in items:
        click.echo(f"  {s.name}")
        for t in s.triggers[:3]:
            click.echo(f"    trigger: {t}")


@skills.command("stats")
def skills_stats() -> None:
    """Show each skill's usage track record (uses / win-rate / recall weight)."""
    from ..skill import stats as skill_stats
    from ..skills import load_skills
    items = load_skills()
    if not items:
        click.echo("no skills yet.")
        return
    for row in skill_stats.usage_rows([s.name for s in items]):
        if not row["uses"]:
            click.echo(f"  {row['name']}: no usage recorded")
            continue
        click.echo(
            f"  {row['name']}: uses={row['uses']} wins={row['wins']} losses={row['losses']} "
            f"win_rate={row['win_rate']:.0%} weight={row['weight']:.2f}"
        )


@skills.command("evict")
@click.option("--apply", "do_apply", is_flag=True,
              help="Delete the candidates (default: dry-run, just lists them).")
@click.option("--min-uses", type=int, default=5, show_default=True,
              help="Only consider skills used at least this many times.")
@click.option("--max-win-rate", type=float, default=0.2, show_default=True,
              help="Flag skills whose win rate's 95% CONFIDENCE upper bound "
                   "(not the raw win rate) is at or below this -- so a thin "
                   "sample near the threshold is not flagged on the point "
                   "estimate alone; e.g. 1 win in 5 uses has an upper bound "
                   "near 0.62 and needs a larger sample to clear 0.2.")
def skills_evict(do_apply: bool, min_uses: int, max_win_rate: float) -> None:
    """List (or with --apply, remove) skills that have had a fair trial and rarely help."""
    from ..skill import stats as skill_stats
    from ..skills import remove_skill
    cands = skill_stats.evictable(min_uses=min_uses, max_win_rate=max_win_rate)
    if not cands:
        click.echo("no eviction candidates.")
        return
    for name in cands:
        if do_apply:
            click.echo(f"  {'removed' if remove_skill(name) else 'not found'}: {name}")
        else:
            click.echo(f"  candidate: {name}")
    if not do_apply:
        click.echo("\n(dry-run; re-run with --apply to remove them)")


@main.command()
@click.option("--limit", type=int, default=50, show_default=True,
              help="Max entries to show.")
def learned(limit: int) -> None:
    """List capabilities the swarm acquired via self-learning."""
    import datetime as _dt

    from .. import self_learning
    items = self_learning.history(limit=limit)
    if not items:
        click.echo(
            "no learned capabilities yet "
            f"(ledger: {self_learning.LEARNED_PATH}).\n"
            "Enable self-learning with [self_learning] enable = true "
            "or MAVERICK_SELF_LEARNING=1."
        )
        return
    for e in items:
        when = _dt.datetime.fromtimestamp(e.ts).strftime("%Y-%m-%d %H:%M")
        mark = "" if e.outcome == "acquired" else f" [{e.outcome}]"
        click.echo(f"  {when}  [{e.kind}] {e.name}{mark}")
        if e.need:
            click.echo(f"    for: {e.need}")


@main.group()
def plugin() -> None:
    """Scaffold + manage Lightwork plugins."""


@plugin.command("list")
def plugin_list() -> None:
    """List active plugins (tools, channels, skills, personas) + the allowlist."""
    from ..plugins import _allowed_plugin_names, installed_plugins
    try:
        slots = installed_plugins()
    except Exception as e:  # pragma: no cover -- discovery must never crash the CLI
        click.echo(f"plugin discovery failed: {e}", err=True)
        sys.exit(1)
    if not any(slots.values()):
        click.echo("no active plugins. scaffold one with `maverick plugin new <name>`.")
    else:
        for slot, names in slots.items():
            if names:
                click.echo(f"  {slot}: {', '.join(names)}")
    # Plugins load only when allowlisted (a security default); show it so a
    # user whose installed plugin isn't appearing knows why.
    allow = _allowed_plugin_names()
    if allow is None:
        click.echo('\nallowlist: ALL enabled ([plugins] enabled = ["*"])')
    else:
        listed = ", ".join(sorted(allow)) if allow else "(none)"
        click.echo(
            f"\nallowlist: {listed} "
            "-- enable more via [plugins] enabled in ~/.maverick/config.toml"
        )


@plugin.command("reload")
@click.argument("dist_name")
def plugin_reload(dist_name: str) -> None:
    """Hot-reload a plugin distribution's code (no process restart).

    Drops DIST_NAME's entry-point modules from the import cache so the next
    discovery pass re-imports the current code on disk. Already-instantiated
    tools/channels keep running old code until their owner rebuilds them.
    """
    from ..plugins import reload_plugin
    dropped = reload_plugin(dist_name)
    if not dropped:
        click.echo(f"no maverick entry points found for distribution {dist_name!r} "
                   "(is it installed and allowlisted?)")
        sys.exit(1)
    click.echo(f"reloaded {dist_name}: dropped {len(dropped)} module(s)")
    for m in dropped:
        click.echo(f"  - {m}")


@plugin.command("lock")
def plugin_lock_cmd() -> None:
    """Pin the active plugin distributions' versions to plugins.lock.

    Discovery verifies installed versions against the lock per
    [plugins] lock_policy = "off" | "warn" | "enforce".
    """
    from ..plugin_lock import lock_path, write_lock
    pins = write_lock()
    if not pins:
        click.echo("no plugin distributions found to pin.")
        return
    click.echo(f"pinned {len(pins)} plugin distribution(s) -> {lock_path()}")
    for name, version in sorted(pins.items()):
        click.echo(f"  {name} == {version}")


@plugin.command("verify")
def plugin_verify_cmd() -> None:
    """Verify installed plugin versions against plugins.lock."""
    from ..plugin_lock import verify_lock
    report = verify_lock()
    if report.get("unlocked"):
        click.echo("no plugins.lock (run `maverick plugin lock` to pin). OK")
        return
    for name, pinned, installed in report["drifted"]:
        click.echo(f"  DRIFT {name}: locked {pinned}, installed {installed}")
    for name in report["missing"]:
        click.echo(f"  MISSING {name} (pinned but not installed)")
    for name in report["unpinned"]:
        click.echo(f"  unpinned {name} (installed but not in the lock)")
    if report["ok"]:
        click.echo("plugins.lock OK")
    else:
        click.echo("plugins.lock FAIL")
        sys.exit(1)


@plugin.command("stats")
def plugin_stats_cmd() -> None:
    """Show local plugin-tool usage counts (opt-in [plugins] telemetry)."""
    import time as _time

    from ..plugin_telemetry import enabled as _ptel_enabled
    from ..plugin_telemetry import stats as _ptel_stats
    data = _ptel_stats()
    if not _ptel_enabled():
        click.echo("plugin telemetry is OFF ([plugins] telemetry = true to enable).")
    if not data:
        click.echo("no plugin tool calls recorded.")
        return
    for name, entry in sorted(data.items(), key=lambda kv: -kv[1].get("calls", 0)):
        last = entry.get("last_used")
        ago = f"{(_time.time() - last) / 86400:.0f}d ago" if last else "never"
        dist = f" [{entry['dist']}]" if entry.get("dist") else ""
        click.echo(f"  {name}{dist}: {entry.get('calls', 0)} call(s), last {ago}")


@plugin.command("new")
@click.argument("name")
@click.option(
    "--kind",
    type=click.Choice(("tool", "channel", "persona")),
    default="tool",
    show_default=True,
    help="Plugin kind. Skills install via `maverick skill install`; "
         "MCP servers go in [mcp_servers.<name>] in config.toml.",
)
@click.option(
    "--dest", type=click.Path(file_okay=False), default=".",
    show_default=True, help="Parent directory; a NAME/ subdir is created here.",
)
def plugin_new(name: str, kind: str, dest: str) -> None:
    """Generate a working plugin skeleton at ./<NAME>/.

    Third-party contributors had
    no on-ramp besides hand-writing pyproject.toml + the entry-point
    block + a manifest. This generates all four files with a working
    factory the contributor can ``pip install -e .`` and exercise
    immediately.
    """
    from ..plugin_scaffold import ScaffoldError, scaffold
    try:
        files = scaffold(name, kind, dest=Path(dest))
    except ScaffoldError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"Scaffolded {name} ({kind}) at {Path(dest) / name}:")
    for f in files:
        click.echo(f"  {f.relative_to(Path(dest))}")
    click.echo("")
    click.echo("Next steps:")
    click.echo(f"  cd {name}")
    click.echo("  pip install -e .")
    click.echo("  pytest -v")


@main.group()
def skill() -> None:
    """Manage skills (install, remove, info)."""


@skill.command("install")
@click.argument("source")
def skill_install(source: str) -> None:
    """Install a SKILL.md from a URL, gh:org/repo[:path], or local path."""
    from ..skills import install_skill
    try:
        s = install_skill(source)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"installed: {s.path.stem} -> {s.path}")


@skill.command("browse")
def skill_browse() -> None:
    """List skills available in the federated catalog."""
    from ..catalog import load_catalog
    entries = load_catalog("skills")
    if not entries:
        click.echo("no catalog entries (index empty or unreachable).")
        return
    for e in entries:
        mark = " [verified]" if e.verified else ""
        click.echo(f"  {e.name}{mark}  v{e.version}")
        if e.summary:
            click.echo(f"    {e.summary}")
    click.echo("")
    click.echo("install one with:  maverick skill add <name>")


@skill.command("add")
@click.argument("name")
def skill_add(name: str) -> None:
    """Install a catalog skill by name (hash-verified)."""
    from ..skills import install_from_catalog
    try:
        s = install_from_catalog(name)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    click.echo(f"installed: {s.path.stem} -> {s.path}")


@skill.command("remove")
@click.argument("name")
def skill_remove(name: str) -> None:
    from ..skills import remove_skill
    if remove_skill(name):
        click.echo(f"removed: {name}")
    else:
        click.echo(f"no skill named {name!r}", err=True)
        sys.exit(2)


@skill.command("info")
@click.argument("name")
def skill_info(name: str) -> None:
    from ..skills import load_skills
    for s in load_skills():
        if s.name == name:
            click.echo(s.path)
            for t in s.triggers:
                click.echo(f"trigger: {t}")
            click.echo("")
            click.echo(s.body)
            return
    click.echo(f"no skill named {name!r}", err=True)
    sys.exit(2)


@skill.command("validate")
@click.argument("path", type=click.Path())
def skill_validate(path: str) -> None:
    """Lint a SKILL.md for publish-readiness (offline; does not install)."""
    from ..skills import validate_skill_file
    r = validate_skill_file(Path(path))
    for w in r.warnings:
        click.echo(click.style(f"  warning: {w}", fg="yellow"))
    for e in r.errors:
        click.echo(click.style(f"  error: {e}", fg="red"), err=True)
    if r.ok:
        click.echo(click.style("OK: skill is valid for publishing.", fg="green"))
    else:
        click.echo(f"INVALID: {len(r.errors)} error(s).", err=True)
        sys.exit(1)


@main.command()
@click.option("--goal-id", type=int, default=None, help="Specific goal to watch.")
@click.option("--interval", type=float, default=1.5, help="Refresh seconds.")
@click.pass_context
def monitor(ctx, goal_id, interval) -> None:
    """Watch agent activity in real time (plan tree + recent events)."""
    from ..monitor import monitor_loop
    sys.exit(monitor_loop(
        db_path=ctx.obj["db"],
        goal_id=goal_id,
        interval_seconds=interval,
    ))


def _conversation_user_matches(conv_user_id: str, requested: str, channel: str) -> bool:
    """Match a conversation's user_id for erase/export-user (see ``ediscovery``)."""
    from ..ediscovery import conversation_user_matches

    return conversation_user_matches(conv_user_id, requested, channel)


def _erase_subject_knowledge(channel: str, user: str) -> dict[str, int]:
    """Scrub a subject's document chunks from the knowledge plane (Art. 17).

    Extracted from ``erase`` so the command stays under the complexity cap.
    Fail-soft: knowledge is optional and a KB error must not abort the erase
    already performed on the world model — it only warns and returns ``{}``.
    """
    try:
        from .. import knowledge_admin
        return knowledge_admin.erase_subject(channel, user)
    except Exception as exc:  # pragma: no cover - defensive
        click.echo(
            f"warning: erased the database but could not scrub the knowledge base "
            f"({type(exc).__name__}: {exc}); run `maverick knowledge residual "
            f"--channel {channel} --user {user}` to check.",
            err=True,
        )
        return {}


def _prepare_erasure_proof(world, conversation_ids):
    """Build and best-effort persist the exact pre-delete closure."""
    plan_hook = getattr(world, "plan_conversation_erasure", None)
    if not callable(plan_hook):
        error = "world backend has no pre-delete erasure planning/receipt API"
        click.echo(
            f"warning: {error}; deletion will continue without a complete "
            "post-hoc goal-graph certificate.",
            err=True,
        )
        return None, None, None, False, error

    try:
        plan = plan_hook(conversation_ids)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        click.echo(
            "warning: pre-delete erasure planning failed "
            f"({error}); deletion will continue without a complete "
            "post-hoc goal-graph certificate.",
            err=True,
        )
        return None, None, None, False, error

    try:
        from ..erasure_receipts import build_manifest, persist_receipt
        from ..paths import current_tenant_id

        manifest = build_manifest(
            tenant_id=current_tenant_id() or "shared",
            conversation_ids=plan["conversation_ids"],
            goal_ids=plan["goal_ids"],
            episode_ids=plan["episode_ids"],
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        click.echo(
            "warning: pre-delete erasure manifest could not be created "
            f"({error}); deletion will continue with an in-memory race check, "
            "but verification will remain indeterminate.",
            err=True,
        )
        return plan, None, None, False, error
    try:
        signed = persist_receipt(world, manifest)
    except Exception as exc:
        # Art. 17 deletion is not held hostage by assurance infrastructure.
        # The unsigned in-memory closure still race-checks deletion, but can
        # never support a clean certificate.
        error = f"{type(exc).__name__}: {exc}"
        click.echo(
            "warning: durable signed erasure proof is unavailable "
            f"({error}); deletion will continue, but verification will "
            "remain indeterminate.",
            err=True,
        )
        return plan, manifest, None, False, error
    return plan, manifest, signed, True, ""


def _dispatch_backend_erasure(world, conversation_ids, erasure_plan):
    """Use a backend's atomic erase hook, including closure race checks."""
    backend_erase = getattr(world, "erase_conversations", None)
    if not callable(backend_erase):
        raise click.ClickException(
            "the configured world backend does not implement the atomic "
            "erase_conversations contract; refusing a partial legacy SQL "
            "deletion. Upgrade the backend or export and erase through a "
            "supported SQLite/Postgres deployment."
        )
    if erasure_plan is None:
        return backend_erase(conversation_ids)

    import inspect

    try:
        parameters = inspect.signature(backend_erase).parameters
    except (TypeError, ValueError):
        return backend_erase(conversation_ids)
    if {
        "expected_conversation_ids",
        "expected_goal_ids",
        "expected_episode_ids",
    }.issubset(parameters):
        return backend_erase(
            conversation_ids,
            expected_conversation_ids=erasure_plan["conversation_ids"],
            expected_goal_ids=erasure_plan["goal_ids"],
            expected_episode_ids=erasure_plan["episode_ids"],
        )
    if {
        "expected_conversation_ids",
        "expected_goal_ids",
    }.issubset(parameters):
        return backend_erase(
            conversation_ids,
            expected_conversation_ids=erasure_plan["conversation_ids"],
            expected_goal_ids=erasure_plan["goal_ids"],
        )
    return backend_erase(conversation_ids)


def _refuse_under_legal_hold(ctx, world, conversation_ids) -> None:
    """Stop before any deletion when an active legal matter covers this closure."""
    from ..ediscovery import erasure_refusal

    plan_hook = getattr(world, "plan_conversation_erasure", None)
    goal_ids = plan_hook(conversation_ids)["goal_ids"] if callable(plan_hook) else []
    message = erasure_refusal(world, conversation_ids=conversation_ids, goal_ids=goal_ids, actor="cli")
    if message:
        ctx.obj["erase_refusal"] = message
        click.echo(message, err=True)
        ctx.exit(1)


def _erasure_failure_label(error: BaseException) -> str:
    """Describe an erase failure without echoing subject-bearing paths/data."""
    errno = getattr(error, "errno", None)
    return (
        f"{type(error).__name__} (errno {errno})"
        if isinstance(errno, int)
        else type(error).__name__
    )


def _unlink_erasure_attachments(
    attachment_paths,
) -> tuple[int, list[str]]:
    """Unlink attachment files and report every unverified outcome."""
    removed = 0
    errors: list[str] = []
    for path in attachment_paths:
        try:
            target = Path(path)
            existed = target.exists()
            target.unlink(missing_ok=True)
            if target.exists():
                raise OSError("attachment path remains after unlink")
            if existed:
                removed += 1
        except OSError as error:
            errors.append(_erasure_failure_label(error))
    return removed, errors


def _erase_conversation_user_notes(
    channel,
    conversations,
) -> tuple[int, str | None]:
    """Scrub derived subject notes with an explicit verification outcome."""
    try:
        from .. import user_notes

        return (
            user_notes.erase_notes(
                channel,
                {conv.user_id for conv in conversations if conv.user_id},
                strict=True,
            ),
            None,
        )
    except Exception as exc:  # pragma: no cover - defensive
        error = _erasure_failure_label(exc)
        click.echo(
            "warning: erased the database but could not scrub user notes "
            f"({error}); they may retain prior preferences.",
            err=True,
        )
        return 0, error


def _persist_erasure_auxiliary_closure(
    world,
    signed_receipt,
    failures: list[str],
) -> tuple[bool, str | None]:
    """Create the post-delete proof only when every auxiliary step succeeded."""
    if failures:
        return False, "; ".join(failures)
    if signed_receipt is None:
        return False, "durable pre-delete receipt is unavailable"
    try:
        from ..erasure_receipts import persist_erasure_closure

        persist_erasure_closure(
            world,
            signed_receipt,
            expected_tenant=signed_receipt["tenant_id"],
        )
    except Exception as exc:
        error = _erasure_failure_label(exc)
        click.echo(
            "warning: auxiliary erasure closure could not be durably "
            f"stored ({error}); the clean certificate is withheld.",
            err=True,
        )
        return False, error
    return True, None


def _custodian_holds_subject(custodian: str, channel: str, user: str) -> bool:
    """Whether a matter custodian covers the erase subject ``channel:user``.

    The same identity rules as matter scope: ``user:<channel>:<id>`` is a
    channel user, ``user:<name>`` the dashboard user of that name, and a
    linked account matches by its stored identity. The CLI family rule
    (``local`` and ``local:<uuid>``) applies in both directions.
    """
    from ..ediscovery import (
        account_user_matches,
        conversation_user_matches,
        is_account_custodian,
    )

    if is_account_custodian(custodian):
        return account_user_matches(user, custodian)
    parts = custodian.split(":", 2) if custodian.startswith("user:") else []
    if len(parts) == 3 and parts[1] and parts[2]:
        held_channel, held_user = parts[1], parts[2]
    elif len(parts) == 2 and parts[1]:
        held_channel, held_user = "dashboard", parts[1]
    else:
        return False
    return held_channel == channel and (
        conversation_user_matches(user, held_user, channel)
        or conversation_user_matches(held_user, user, channel)
    )


def _refuse_subject_under_legal_hold(ctx, channel: str, user: str) -> None:
    """Refuse a subject-keyed erase while any active matter names the subject.

    With no conversation row there is no closure for the usual hold check to
    match, so match the subject against each matter's custodians instead: a
    held subject's goals, chats and records are all in scope through them.
    """
    from ..ediscovery import (
        HOLD_UNVERIFIED_MESSAGE,
        LEGAL_HOLD_MESSAGE,
        _audit_refusal,
        active_matters,
    )

    try:
        matters = active_matters()
    except Exception:  # failure-policy: fail_closed -- an unreadable ledger holds everything
        message = HOLD_UNVERIFIED_MESSAGE
    else:
        message = None
        for matter in matters:
            if any(_custodian_holds_subject(str(c), channel, user)
                   for c in matter.get("custodians") or ()):
                _audit_refusal(matter, actor="cli", conversations=0, goals=0)
                message = LEGAL_HOLD_MESSAGE
                break
    if message:
        ctx.obj["erase_refusal"] = message
        click.echo(message, err=True)
        ctx.exit(1)


def _scrub_subject_audit(channel: str, user: str, failures: list[str]) -> int:
    """Scrub the subject's prior audit lines; record a failure instead of raising."""
    from .. import audit

    scrubbed = 0
    try:
        scrubbed, _ = audit.scrub_user(channel, user, strict=True)
    except Exception as exc:
        failures.append(f"audit_scrub: {_erasure_failure_label(exc)}")
    try:
        audit.reanchor_after_erase()
    except Exception as exc:  # pragma: no cover - defensive
        failures.append(f"audit_reanchor: {_erasure_failure_label(exc)}")
    return scrubbed


def _erase_subject_knowledge_strict(channel: str, user: str, failures: list[str]) -> dict[str, int]:
    try:
        from .. import knowledge_admin
        return knowledge_admin.erase_subject(channel, user)
    except Exception as exc:
        failures.append(f"knowledge: {_erasure_failure_label(exc)}")
        return {}


def _subject_residue_verification(world, channel: str, user: str, failures: list[str]) -> None:
    """Fold residual counts and unreadable subject-keyed stores into ``failures``.

    Without a receipt the goal-linked stores are always unchecked, so only the
    stores this path erases count as a verification error.
    """
    from ..erasure_verify import verify_erasure

    try:
        result = verify_erasure(user, channel=channel, world=world)
    except Exception as exc:
        failures.append(f"verification: {_erasure_failure_label(exc)}")
        return
    residual = result.get("residual") or {}
    if residual:
        failures.append("residual data: " + ", ".join(
            f"{store}={count}" for store, count in sorted(residual.items())
        ))
    errors = result.get("errors") or {}
    unread = sorted(s for s in ("facts", "fact_history", "knowledge_chunks") if s in errors)
    if unread:
        failures.append("could not verify: " + ", ".join(unread))


def _erase_subject_residue(ctx, world, channel: str, user: str, yes: bool) -> None:
    """Scrub the subject-keyed stores when no conversation row matches.

    Exits 1 when a scrub fails or residual data remains, so a re-run after a
    partly failed erase can finish the job and a script can tell.
    """
    import secrets
    import types

    from .. import audit

    _refuse_subject_under_legal_hold(ctx, channel, user)
    if not yes:
        click.echo(f"This will erase stored facts, notes, audit lines and "
                   f"knowledge for {channel}:{user}.")
        click.confirm("Proceed?", abort=True)
    scrubbed_fact_keys = world.delete_facts_matching(_fact_subject_token(channel, user))
    removed_notes, notes_error = _erase_conversation_user_notes(
        channel, [types.SimpleNamespace(user_id=user)]
    )
    failures = [f"user_notes: {notes_error}"] if notes_error else []
    audit_scrubbed = _scrub_subject_audit(channel, user, failures)
    knowledge_removed = _erase_subject_knowledge_strict(channel, user, failures)
    knowledge_chunks = sum(knowledge_removed.values())
    if isinstance(ctx.obj, dict):  # for in-process callers (the dashboard)
        # The same list object: failures found below are reported too.
        ctx.obj["erase_residue"] = {
            "removed": (audit_scrubbed + len(scrubbed_fact_keys) + removed_notes
                        + knowledge_chunks),
            "failures": failures,
        }
    # The same record-of-processing marker as a conversation erase, without
    # any identifier derived from the subject.
    try:
        recorded = audit.record(
            "erase", channel=channel, erasure_id=secrets.token_hex(16),
            durable_proof=False, auxiliary_checks_passed=not failures,
            conversations=0, turns=0, goals=0, attachments=0,
            audit_lines_scrubbed=audit_scrubbed,
            facts_scrubbed=len(scrubbed_fact_keys),
            user_notes_scrubbed=removed_notes,
            knowledge_chunks_scrubbed=knowledge_chunks,
        )
        if not recorded:
            failures.append("audit_record: audit sink did not acknowledge the erase marker")
    except audit.AuditRefused:
        # Deletion has already happened; a policy refusal must reach the caller.
        raise
    except Exception as exc:  # pragma: no cover - defensive
        failures.append(f"audit_record: {_erasure_failure_label(exc)}")
    click.echo(
        f"{audit_scrubbed} audit event(s) scrubbed, "
        f"{len(scrubbed_fact_keys)} fact(s) scrubbed, "
        f"{removed_notes} user note(s) scrubbed, "
        f"{knowledge_chunks} knowledge chunk(s) scrubbed"
    )
    _print_erased_extras(knowledge_removed, scrubbed_fact_keys)
    _subject_residue_verification(world, channel, user, failures)
    if failures:
        click.echo("error: erasure incomplete (" + "; ".join(failures) + ")", err=True)
        ctx.exit(1)


@main.command()
@click.option("--channel", required=True, help="Channel name (e.g. telegram, sms).")
@click.option("--user", required=True, help="The channel user_id to erase.")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
@click.pass_context
def erase(ctx, channel: str, user: str, yes: bool) -> None:
    """Erase everything Lightwork knows about a (channel, user_id) pair.

    GDPR Art. 17 right-to-erasure: removes conversations, turns,
    attachments on disk, and the conversation row itself. (First line kept
    abbreviation-free so Click's short help isn't truncated at "Art.".)"""
    world = open_world(ctx.obj["db"])
    convs = [
        c for c in world.list_conversations(channel)
        if _conversation_user_matches(c.user_id, user, channel)
    ]
    if not convs:
        click.echo(f"no conversation found for {channel}:{user}")
        # Facts, notes, audit lines and knowledge are keyed by the subject,
        # not by a conversation row, so they can outlive it (a subject who
        # never chatted, or an earlier erase that failed part-way).
        _erase_subject_residue(ctx, world, channel, user, yes)
        return
    if not yes:
        click.echo(f"This will erase {len(convs)} conversation(s) for {channel}:{user}.")
        click.confirm("Proceed?", abort=True)

    # The previous version left goals, messages,
    # episodes, questions, goal_events, attachments-rows, and
    # processed_messages intact -- a documented Art. 17 violation. Full
    # cascade now wipes every row referencing goals tied to this user's
    # conversations, in one transaction so a partial failure rolls back.
    # Attachment FILE unlinks happen AFTER the DB transaction commits so
    # we don't leave dangling rows pointing at deleted paths if the DB
    # write fails.

    # Step 1: gather every goal_id referenced by any turn in any of
    # these conversations. We use ALL turns (not just recent), so a
    # conversation with >10k turns doesn't leave orphan attachments.
    conv_ids = [c.id for c in convs]
    _refuse_under_legal_hold(ctx, world, conv_ids)
    (
        erasure_plan,
        erasure_manifest,
        signed_erasure_receipt,
        durable_erasure_proof,
        receipt_error,
    ) = _prepare_erasure_proof(world, conv_ids)

    goal_ids, attachment_paths, removed_turns = _dispatch_backend_erasure(
        world,
        conv_ids,
        erasure_plan,
    )

    # Step 4: now that DB rows are gone, unlink files. File bytes remain
    # personal data even when their database metadata is gone, so any unlink
    # failure blocks the clean certificate while leaving deletion completed.
    removed_attachments, attachment_errors = _unlink_erasure_attachments(
        attachment_paths
    )
    for error in attachment_errors:
        click.echo(
            "warning: erased the database but could not remove an attachment "
            f"file ({error}); the clean certificate is withheld.",
            err=True,
        )

    # Step 4b: remove derived per-user preference notes from the dreaming
    # store. These live outside world.db, so the SQL cascade above cannot
    # erase them; use the concrete matched conversation user_ids so CLI
    # family erasure (local -> local:<uuid>) removes every scoped note.
    removed_user_notes, user_notes_error = _erase_conversation_user_notes(
        channel,
        convs,
    )

    # Step 4c: scrub explicitly user-scoped global facts. Facts are global
    # key/value pairs with no per-user attribution, so erase only touches
    # facts deliberately keyed as user:<channel>:<user_id>:<name>. Arbitrary
    # substring matching is unsafe for short/common user ids because it can
    # delete unrelated operator knowledge or other users' data.
    fact_subject = _fact_subject_token(channel, user)
    scrubbed_fact_keys = world.delete_facts_matching(fact_subject)

    # Step 4d: the optional LLM cache (MAVERICK_LLM_CACHE=1) is content-
    # addressed on the full prompt -- system + messages include the user's
    # goal text and the model's replies, so the cache retains exactly the
    # PII we just erased. It can't be purged by subject (the key is a hash of
    # content, not tied to a user), so clear every authority in this tenant's
    # disposable cache. Ordinary cache.clear() is intentionally principal-
    # scoped and would leave other historical authorities behind. Only when
    # the dynamically resolved DB already exists, so a cache-disabled install
    # does not create an empty cache file. Best-effort after the command's
    # irreversible --yes confirmation above.
    llm_cache_error: str | None = None
    try:
        from ..cache.llm import LLMCache, default_db_path
        _llm_cache_db = default_db_path()
        if _llm_cache_db.exists():
            LLMCache().purge_all_authorities_for_erasure(confirmed=True)
    except Exception as exc:  # pragma: no cover - defensive
        llm_cache_error = _erasure_failure_label(exc)
        click.echo(
            f"warning: erased the database but could not clear the LLM cache "
            f"({llm_cache_error}); it may retain prior prompts.",
            err=True,
        )

    # Step 5: scrub the subject from PRIOR audit-log lines. Audit payloads
    # (goal_start / tool_call / channel events) carry channel:user_id, so
    # without this the identity we just erased stayed readable in
    # ~/.maverick/audit/*.ndjson -- an Art.17 gap (scrub_user was dead
    # code, never called). Done BEFORE recording the erase event below so
    # that event (which hashes the subject) isn't itself scrubbed.
    # If [audit] sign is enabled scrub_user verifies the chain before mutating
    # it and re-anchors only the files it changed (leaving PII in place would
    # violate Art.17, but blindly re-signing old tampering would destroy audit
    # evidence).
    audit_scrubbed = 0
    audit_scrub_error: str | None = None
    try:
        from ..audit import scrub_user
        audit_scrubbed, _ = scrub_user(channel, user, strict=True)
    except Exception as exc:
        audit_scrub_error = _erasure_failure_label(exc)
        click.echo(
            f"warning: erased the database but could not scrub the audit log "
            f"({audit_scrub_error}); use the receipt id with `erase-verify` "
            "after repairing audit storage.",
            err=True,
        )

    # Step 5b: erase the subject's document chunks from the knowledge plane.
    # A subject's uploaded documents are ingested with a `subject` provenance
    # stamp; without this, their embedded chunks survived erasure in the vector
    # store (an Art.17 gap for any deployment with knowledge RAG on). Fail-soft:
    # knowledge is optional and a KB error must not abort the erase we've done.
    knowledge_removed = _erase_subject_knowledge(channel, user)

    # Scrubbing may have re-anchored signed audit files, so drop any cached
    # signer before appending the erase marker. The compatibility hook is safe:
    # it refuses to rewrite already-broken chains unless the erase helper
    # verified them before mutation.
    from .. import audit

    audit_reanchor_error: str | None = None
    try:
        audit.reanchor_after_erase()
    except Exception as e:  # pragma: no cover - defensive
        audit_reanchor_error = _erasure_failure_label(e)
        click.echo(
            f"warning: audit re-anchor failed ({audit_reanchor_error})",
            err=True,
        )

    # GDPR Art. 30: record that an erasure happened without deriving a stable
    # identifier from the subject. Low-entropy user IDs (phone numbers, short
    # handles, numeric IDs) are enumerable, so even a truncated hash can
    # re-identify the erased person if audit logs are read.
    import secrets

    knowledge_chunks = sum(knowledge_removed.values())
    erasure_id = (
        erasure_manifest["receipt_id"]
        if isinstance(erasure_manifest, dict)
        else secrets.token_hex(16)
    )
    closure_failures = [
        *attachment_errors,
        *(
            [f"user_notes: {user_notes_error}"]
            if user_notes_error is not None
            else []
        ),
        *(
            [f"llm_cache: {llm_cache_error}"]
            if llm_cache_error is not None
            else []
        ),
        *(
            [f"audit_scrub: {audit_scrub_error}"]
            if audit_scrub_error is not None
            else []
        ),
        *(
            [f"audit_reanchor: {audit_reanchor_error}"]
            if audit_reanchor_error is not None
            else []
        ),
    ]
    audit_record_error: str | None = None
    try:
        audit_recorded = audit.record(
            "erase",
            channel=channel,
            erasure_id=erasure_id,
            durable_proof=durable_erasure_proof,
            auxiliary_checks_passed=not closure_failures,
            conversations=len(convs),
            turns=removed_turns,
            goals=len(goal_ids),
            attachments=removed_attachments,
            audit_lines_scrubbed=audit_scrubbed,
            facts_scrubbed=len(scrubbed_fact_keys),
            user_notes_scrubbed=removed_user_notes,
            knowledge_chunks_scrubbed=knowledge_chunks,
        )
        if not audit_recorded:
            audit_record_error = (
                "audit sink did not acknowledge the erase marker"
            )
    except audit.AuditRefused:
        # Deletion has already committed and cannot honestly be rolled back.
        # A policy-level refusal must still reach the caller, though: returning
        # success would turn "strict audit declined this action marker" into a
        # silently unaudited administrative action.
        raise
    except Exception as exc:  # pragma: no cover - defensive
        audit_record_error = _erasure_failure_label(exc)
    if audit_record_error is not None:
        closure_failures.append(f"audit_record: {audit_record_error}")
        click.echo(
            "warning: the erase marker was not durably recorded "
            f"({audit_record_error}); the clean certificate is withheld.",
            err=True,
        )

    (
        durable_erasure_closure,
        closure_error,
    ) = _persist_erasure_auxiliary_closure(
        world,
        signed_erasure_receipt,
        closure_failures,
    )

    # Automatic same-process proof uses the exact pre-delete closure. When the
    # signed row could not be persisted, the unsigned manifest still checks all
    # database stores but deliberately leaves durable_proof=false and
    # indeterminate=true.
    from ..erasure_verify import verify_erasure

    try:
        verification = verify_erasure(
            user,
            channel=channel,
            receipt=signed_erasure_receipt or erasure_manifest,
            world=world,
        )
    except Exception as exc:  # pragma: no cover - last-resort proof isolation
        verify_error = f"{type(exc).__name__}: {exc}"
        receipt_error = receipt_error or verify_error
        verification = {
            "clean": False,
            "residual": {},
            "errors": {"verification": verify_error},
        }

    if isinstance(ctx.obj, dict):
        # An in-process caller (the dashboard) reads the outcome here rather
        # than parsing this command's output.
        ctx.obj["erase_outcome"] = {
            "receipt_id": erasure_id,
            "durable_proof": bool(durable_erasure_proof),
            "closure_failures": list(closure_failures),
            "clean": bool(verification.get("clean")),
            "residual": dict(verification.get("residual") or {}),
            "indeterminate": bool(verification.get("indeterminate")),
        }
    click.echo(
        f"erased {len(convs)} conversation(s), {removed_turns} turn(s), "
        f"{len(goal_ids)} goal(s) and all linked rows, "
        f"{removed_attachments} attachment file(s), "
        f"{audit_scrubbed} audit event(s) scrubbed, "
        f"{len(scrubbed_fact_keys)} fact(s) scrubbed, "
        f"{removed_user_notes} user note(s) scrubbed, "
        f"{knowledge_chunks} knowledge chunk(s) scrubbed"
    )
    if erasure_manifest is not None:
        click.echo(
            f"  erasure receipt: {erasure_manifest['receipt_id']} "
            f"(durable proof: {'yes' if durable_erasure_proof else 'no'}; "
            "auxiliary closure: "
            f"{'yes' if durable_erasure_closure else 'no'})"
        )
    if verification["clean"]:
        click.echo("  verification: CLEAN (signed receipt closure is zero)")
    elif verification["residual"]:
        click.echo(
            "warning: automatic verification found residual data: "
            + ", ".join(
                f"{store}={count}"
                for store, count in sorted(verification["residual"].items())
            ),
            err=True,
        )
    else:
        detail = (
            closure_error
            or receipt_error
            or "; ".join(verification["errors"].values())
        )
        click.echo(
            "warning: deletion completed without a clean certificate"
            + (f" ({detail})" if detail else ""),
            err=True,
        )
    _print_erased_extras(knowledge_removed, scrubbed_fact_keys)


def _print_erased_extras(knowledge_removed, scrubbed_fact_keys) -> None:
    if knowledge_removed:
        click.echo(
            "  knowledge removed (per collection): "
            + ", ".join(f"{c}={n}" for c, n in sorted(knowledge_removed.items()))
        )
    if scrubbed_fact_keys:
        click.echo(
            "  facts removed (global key/value, scoped with user:<channel>:<user_id>: "
            f"prefix): {', '.join(scrubbed_fact_keys)}"
        )


@main.command("erase-verify")
@click.option("--channel", required=True, help="Channel name (e.g. telegram, sms).")
@click.option("--user", required=True, help="The channel user_id to verify.")
@click.option("--tenant", default=None, help="Tenant data plane (default: active).")
@click.option(
    "--receipt-id",
    default=None,
    help=(
        "Receipt id required for the signed scope + auxiliary completion proof."
    ),
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def erase_verify(
    ctx,
    channel: str,
    user: str,
    tenant: str | None,
    receipt_id: str | None,
    as_json: bool,
) -> None:
    """Verify a (channel, user_id) was fully erased: zero residual records.

    Right-to-erasure proof (GDPR Art. 17): reuses the DSAR export, whose
    subject-matching agrees with the erase path, so any residual count is an
    incomplete erasure. A clean result requires the immutable signed scope
    receipt and its bound signed auxiliary-store completion record. Read-only;
    run it after `maverick erase`.
    """
    import json as _json

    from ..erasure_verify import verify_erasure

    world = open_world(ctx.obj["db"])
    report = verify_erasure(
        user,
        channel=channel,
        tenant=tenant,
        receipt_id=receipt_id,
        world=world,
    )
    if as_json:
        click.echo(_json.dumps(report, default=str))
        if not report["clean"]:
            raise SystemExit(1)
        return
    if report["clean"]:
        click.echo(click.style(
            f"CLEAN: no residual data for {channel}:{user}", fg="green"))
        return
    if not report["residual"]:
        click.echo(click.style(
            f"INDETERMINATE for {channel}:{user} - no clean certificate:",
            fg="yellow",
        ))
        for store, error in sorted(report["errors"].items()):
            click.echo(f"  {store}: {error}")
        if not receipt_id:
            click.echo(
                "  pass --receipt-id from the erase command to verify the "
                "signed scope and auxiliary completion closure"
            )
        raise SystemExit(1)
    click.echo(click.style(
        f"RESIDUAL DATA for {channel}:{user} — erasure incomplete:", fg="red"))
    for store, n in sorted(report["residual"].items()):
        click.echo(f"  {store}: {n}")
    raise SystemExit(1)


@main.command("compliance")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--strict", is_flag=True,
              help="Exit non-zero if any control needs action (gate CI / deploys).")
@click.option("--framework", type=click.Choice(["eu", "us", "all"]), default="all",
              help="Filter to a jurisdiction's frameworks (default: all).")
@click.pass_context
def compliance_cmd(ctx, fmt: str, strict: bool, framework: str) -> None:
    """Report GDPR + EU AI Act + US-framework control coverage for this deployment.

    Maps each active control to the article/framework it supports (EU AI Act,
    GDPR, NIST AI RMF, Colorado AI Act, NYC Local Law 144, EEOC, CCPA) and flags
    opt-in controls that are off. Control coverage only -- not a legal attestation.

    With --strict, exits non-zero if any control is "action needed", so a
    regulated deployment can fail a CI job / release gate when its posture
    regresses (the report still prints first).
    """
    from ..compliance import (
        compliance_report,
        render_report_json,
        render_report_text,
    )
    checks = compliance_report()
    if framework != "all":
        checks = [c for c in checks if c.framework == framework]
    click.echo(
        render_report_json(checks) if fmt == "json" else render_report_text(checks)
    )
    if strict:
        needs_action = [c.control for c in checks if c.status == "action_needed"]
        if needs_action:
            raise click.ClickException(
                f"{len(needs_action)} control(s) need action: "
                + ", ".join(needs_action)
            )


@main.group("record")
def record_grp() -> None:
    """The Operating Record: the firm's decisions as a system of record."""


@record_grp.command("stats")
@click.option("--limit", default=500, show_default=True)
@click.pass_context
def record_stats(ctx, limit: int) -> None:
    """Summarize the Operating Record (decisions, approvals, departments)."""
    from .. import operating_record as orec
    world = open_world(ctx.obj["db"])
    s = orec.stats(orec.assemble(world, limit=limit))
    click.echo(f"records: {s.n_records}  goals: {s.n_goals}  approvals: "
               f"{s.n_approvals}  human decisions: {s.n_human_decisions}")
    for dept, n in sorted(s.departments.items(), key=lambda kv: -kv[1])[:12]:
        click.echo(f"  {dept:<24} {n}")


@record_grp.command("search")
@click.argument("text")
@click.option("--department", default="")
@click.option("--actor", default="")
@click.pass_context
def record_search(ctx, text: str, department: str, actor: str) -> None:
    """Every decision that touched X (subject substring match)."""
    from .. import operating_record as orec
    world = open_world(ctx.obj["db"])
    hits = orec.query(orec.assemble(world), text=text,
                      department=department, actor=actor)
    for r in hits[:50]:
        click.echo(f"[{r.kind}] {r.subject}  -> {r.outcome}  "
                   f"(actor={r.actor}, ${r.cost_dollars:.2f})")
    click.echo(f"{len(hits)} matching record(s)")


@record_grp.command("export")
@click.argument("out", type=click.Path())
@click.option("--limit", default=500, show_default=True)
@click.pass_context
def record_export(ctx, out: str, limit: int) -> None:
    """Export the operating mind as a SIGNED, portable capsule."""
    from .. import operating_record as orec
    world = open_world(ctx.obj["db"])
    try:
        path = orec.export_capsule(world, out, limit=limit)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
    ok, reason = orec.verify_capsule(path)
    click.echo(f"capsule -> {path} (self-check: {reason})")
    if not ok:
        raise click.ClickException("capsule failed its own verification")


@record_grp.command("verify")
@click.argument("capsule", type=click.Path(exists=True))
@click.option("--pubkey", "pubkeys", multiple=True,
              help="Trusted Ed25519 public key (hex) the capsule must be signed "
                   "with, e.g. the firm's published key. Repeatable. Default: "
                   "this installation's own audit keys.")
@click.option("--trusted-keys", "trusted_file", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="File of trusted public keys (hex), one per line; blank "
                   "lines and # comments are ignored.")
def record_verify(capsule: str, pubkeys: tuple[str, ...], trusted_file: str | None) -> None:
    """Verify a capsule's integrity AND that it was signed by a trusted key.

    A capsule carries its own public key, so a signature alone proves only that
    the file is unedited, not who made it. Without --pubkey/--trusted-keys the
    signer must be one of this installation's audit keys; to check a capsule
    from another installation, pass that publisher's key.
    """
    from .. import operating_record as orec
    trusted: list[str] | None = None
    if pubkeys or trusted_file:
        trusted = list(pubkeys)
        if trusted_file:
            try:
                with open(trusted_file, encoding="utf-8") as handle:
                    lines = (ln.split("#", 1)[0].strip() for ln in handle)
                    trusted += [ln for ln in lines if ln]
            except (OSError, UnicodeDecodeError) as e:
                raise click.ClickException(
                    "cannot read the trusted keys file: it must be a text file "
                    "with one public key per line") from e
    ok, reason = orec.verify_capsule(capsule, trusted_pubkeys=trusted)
    click.echo(reason)
    if not ok:
        raise click.ClickException("verification failed")




def _write_private_export(output, text: str, *, overwrite: bool = True) -> bool:
    """Write an export as a new 0600 file, never through a symlink.

    Returns True when the output went to a stream rather than a file, so the
    caller sends its "wrote ..." note to stderr and a redirected export stays
    valid JSON.

    ``-``, ``/dev/stdout`` and ``/dev/stderr`` are written to that stream and
    the path is never opened. Otherwise the parent directory is resolved (a
    symlinked parent such as ``/tmp`` on macOS is fine) and the final
    component is opened without following links: a FIFO or character device
    the caller owns is written in place; a symlink is refused; anything else is
    replaced atomically with a new 0600 file. With ``overwrite=False``, regular
    files are instead created exclusively and an existing pathname is refused.
    """
    import errno as _errno
    import stat as _stat

    from ..file_lock import atomic_create_text, atomic_write_text

    if str(output) in ("-", "/dev/stdout", "/dev/stderr"):
        click.echo(text, nl=False, err=str(output) == "/dev/stderr")
        return True
    given = Path(output)
    target = given.parent.resolve() / given.name
    if target.is_symlink():
        raise OSError(_errno.ELOOP, "refusing to write through a symlink", str(target))
    writer = atomic_write_text if overwrite else atomic_create_text
    if os.name == "nt":  # no FIFOs, O_NOFOLLOW or uids
        writer(target, text, mode=0o600)
        return False
    try:
        # No O_CREAT/O_TRUNC: this open only finds an existing stream. Non-
        # blocking so a FIFO with no reader fails instead of hanging.
        fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno not in (_errno.ENOENT, _errno.EISDIR):
            raise
        fd = -1
    if fd >= 0:
        info = os.fstat(fd)
        if (_stat.S_ISFIFO(info.st_mode) or _stat.S_ISCHR(info.st_mode)) \
                and info.st_uid == os.getuid():
            os.set_blocking(fd, True)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(text)
            return True
        os.close(fd)
        if not _stat.S_ISREG(info.st_mode):
            raise OSError(_errno.EPERM, "not a regular file or a stream you own", str(target))
    writer(target, text, mode=0o600)
    return False


@main.command("export-user")
@click.option("--channel", required=True, help="Channel name.")
@click.option("--user", required=True, help="The channel user_id to export.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write JSON to file (default stdout).")
@click.pass_context
def export_user(ctx, channel: str, user: str, output) -> None:
    """Export everything Lightwork knows about a (channel, user_id) as JSON.

    GDPR Art. 15 right-of-access. Registered as ``export-user`` so it does
    not collide with ``export`` (the goal-trajectory bundle below); a
    duplicate Click command name silently shadowed this one, making the
    data-subject export unreachable from the CLI."""
    import json
    world = open_world(ctx.obj["db"])
    convs = [
        c for c in world.list_conversations(channel)
        if _conversation_user_matches(c.user_id, user, channel)
    ]
    data = {
        "channel": channel,
        "user_id": user,
        "conversations": [],
        # Explicitly user-scoped global facts. Facts have no per-user
        # attribution, so export only includes keys deliberately namespaced as
        # user:<channel>:<user_id>:<name> rather than arbitrary substring
        # matches.
        "facts": world.facts_matching(_fact_subject_token(channel, user)),
        # Art.15 completeness: when [memory] temporal is on, superseded fact
        # values are retained in fact_history and are themselves the subject's
        # personal data, so include them (empty when temporal is off).
        "fact_history": {
            k: [
                {"value": v.value, "valid_from": v.valid_from,
                 "valid_to": v.valid_to, "source": v.source}
                for v in versions
            ]
            for k, versions in world.fact_history_matching(
                _fact_subject_token(channel, user)).items()
        },
    }
    for c in convs:
        limit = 10_000
        turns = world.recent_turns(c.id, limit=limit)
        while len(turns) == limit:
            limit *= 2
            turns = world.recent_turns(c.id, limit=limit)
        conv_data = {
            "id": c.id,
            "created_at": c.created_at,
            "last_seen": c.last_seen,
            "turns": [
                {"role": t.role, "content": t.content, "ts": t.ts,
                 "goal_id": t.goal_id}
                for t in turns
            ],
            "attachments": [],
        }
        for t in turns:
            if t.goal_id is None:
                continue
            for a in world.list_attachments(t.goal_id):
                conv_data["attachments"].append({
                    "filename": a.filename, "mime": a.mime,
                    "size_bytes": a.size_bytes, "sha256": a.sha256,
                    "goal_id": a.goal_id,
                })
        data["conversations"].append(conv_data)

    payload = json.dumps(data, indent=2, default=str)
    if output:
        # A GDPR export carries the subject's full conversation content.
        # Create it 0o600 (not the umask's world-readable 0644) so a
        # co-tenant can't read it, and fail cleanly instead of dumping a
        # traceback on a bad/unwritable path.
        try:
            streamed = _write_private_export(output, payload)
        except OSError as e:
            raise click.ClickException(f"could not write {output}: {e}") from e
        click.echo(f"exported to {output}", err=streamed)
    else:
        click.echo(payload)


@main.command()
@click.option("--days", default=90, type=click.IntRange(min=1),
              help="Delete conversations idle longer than N days.")
@click.option("--events-days", default=30, type=click.IntRange(min=1),
              help="Delete goal_events older than N days.")
@click.option("--yes", is_flag=True)
@click.pass_context
def gc(ctx, days: int, events_days: int, yes: bool) -> None:
    """Garbage-collect old conversations and goal_events.

    Retention was "forever" by default; this
    command (plus the systemd timer in deploy/vps/) enforces a policy.
    """
    if not yes:
        click.echo(
            f"This will prune conversations idle > {days}d and "
            f"goal_events older than {events_days}d."
        )
        click.confirm("Proceed?", abort=True)

    from ..records_gc import prune_world, sweep_workspaces
    from ..world_model import close_world_if_owned
    from ..world_model_backends import is_postgres_configured

    # An unbound Postgres connection is an administrator read view, never
    # implicit delete-all authority. Routine GC fans out through each explicit
    # roster tenant; a true global purge requires a separate purpose-built API.
    if is_postgres_configured():
        from ..paths import current_tenant_id
        if current_tenant_id() is None:
            from ..tenant.registry import list_tenants
            try:
                tenants = list_tenants()
            except Exception as exc:
                raise click.ClickException(
                    f"cannot resolve tenant roster for Postgres GC: {exc}"
                ) from exc
            if not tenants:
                raise click.ClickException(
                    "refusing unbound Postgres GC: bind a tenant or provision "
                    "the tenant roster; global delete is not implicit"
                )
            rows = sweep_workspaces(tenants, days=days, events_days=events_days,
                                    open_world=open_world)
            convs = sum(row["conversations"] for row in rows)
            events = sum(row["activity"] for row in rows)
            dedup = sum(row["duplicate_checks"] for row in rows)
            click.echo(
                f"pruned {convs} conversation(s), {events} goal_event row(s), "
                f"{dedup} processed-message row(s) across {len(tenants)} tenant(s)"
            )
            held = sum(1 for row in rows if row.get("held"))
            if held:
                click.echo(
                    f"{held} workspace(s) were skipped because a legal hold is active there.",
                    err=True,
                )
            return

    from ..ediscovery import LegalHoldApplies

    world = open_world(ctx.obj["db"])
    try:
        convs, events, dedup = prune_world(world, days=days, events_days=events_days)
    except LegalHoldApplies as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        close_world_if_owned(world)
    click.echo(
        f"pruned {convs} conversation(s), {events} goal_event row(s), "
        f"{dedup} processed-message row(s)"
    )


@main.group("donate")
def donate() -> None:
    """Opt-in trajectory donation. Default OFF.

    Enable in ~/.maverick/config.toml:
      [telemetry]
      donate_trajectories = true
      donate_text = false  # set true to include task text (off by default)
    """


@donate.command("status")
def donate_status() -> None:
    """Show pending records in the outbox (NOT yet uploaded)."""
    from ..donation import _donations_enabled, _text_donations_enabled, list_pending
    click.echo(f"donate_trajectories: {_donations_enabled()}")
    click.echo(f"donate_text:         {_text_donations_enabled()}")
    pending = list_pending()
    if not pending:
        click.echo("outbox: empty")
        return
    click.echo(f"outbox: {len(pending)} record(s) pending")
    for p in pending[:10]:
        click.echo(f"  {p.name}  ({p.stat().st_size} bytes)")


@donate.command("clear")
@click.option("--yes", is_flag=True)
def donate_clear(yes: bool) -> None:
    """Delete every pending donation record without uploading."""
    from ..donation import clear_outbox, list_pending
    pending = list_pending()
    if not pending:
        click.echo("outbox: empty (nothing to clear)")
        return
    if not yes:
        click.echo(f"This will delete {len(pending)} pending record(s).")
        click.confirm("Proceed?", abort=True)
    n = clear_outbox()
    click.echo(f"cleared {n} record(s)")




def _watch_goal_allowed(goal_text: str) -> tuple[bool, str | None]:
    """Best-effort Shield scan for watch-mode marker goals."""
    try:
        from maverick_shield import Shield  # type: ignore
    except ImportError:
        return True, None

    try:
        verdict = Shield.from_config().scan_input(goal_text)
    except Exception as exc:  # pragma: no cover
        logging.getLogger(__name__).warning(
            "Shield raised %s during watch --run scan; failing open",
            type(exc).__name__,
        )
        return True, None

    if verdict.allowed:
        return True, None
    return False, f"blocked by Shield ({verdict.severity}): {'; '.join(verdict.reasons)}"

@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--run", is_flag=True, help="Spawn a goal per match (default: print only).")
@click.option("--max-dollars", default=None, type=float,
              help="Override the configured spend cap (fallback: $2 per matched task).")
@click.pass_context
@_humane_errors
def watch(ctx, path: str, run: bool, max_dollars: float | None) -> None:
    """Scan a file or directory for `# AI: <task>` markers and (optionally)
    run each as a goal. One-shot scan; for a long-running watcher use
    `entr` / `watchman` / `fswatch` and pipe to this command."""
    from ..watch_mode import scan_dir, scan_file
    p = Path(path)
    matches = scan_file(p) if p.is_file() else scan_dir(p)

    count = 0
    unsuccessful = False
    for m in matches:
        count += 1
        click.echo(
            click.style(f"[{m.path}:{m.line_number}] ", fg="bright_black")
            + click.style(f"AI{m.marker}", fg="cyan")
            + f" {m.text}"
        )
        if m.follow_lines:
            for fl in m.follow_lines[:4]:
                click.echo(f"    {fl}")

        if run:
            # Don't sys.exit in the watch loop: just skip this marker and continue.
            selected_model = _cli_model(ctx, "orchestrator")
            try:
                from ..config import load_config
                from ..operator_preflight import _routed_configuration_missing

                missing_routes = {
                    provider: fields
                    for provider, fields in _routed_configuration_missing(
                        load_config()
                    ).items()
                    if fields
                }
            except Exception:
                missing_routes = {"selected": ("configuration",)}
            if missing_routes:
                from ..operator_preflight import _format_route_missing

                detail = _format_route_missing(missing_routes)
                click.echo(
                    f"Skipping --run: selected routes are incomplete ({detail}). "
                    "Add the missing key in Lightwork > Settings, then run "
                    "'maverick preflight'.",
                    err=True,
                )
                unsuccessful = True
                continue
            k = _kernel()
            title = (m.text or (m.follow_lines[0] if m.follow_lines else "")).strip()[:80]
            goal_text = m.to_goal()
            allowed, reason = _watch_goal_allowed(goal_text)
            if not allowed:
                click.echo(click.style(f"  skipped: {reason}", fg="yellow"), err=True)
                unsuccessful = True
                continue
            world = open_world(ctx.obj["db"])
            budget = _cli_task_budget(title, max_dollars, 2.0)
            goal_id = world.create_goal(title or "watch-mode goal", goal_text)
            click.echo(click.style(f"  -> goal #{goal_id}", fg="bright_black"))
            try:
                with _cli_sandbox(k, workdir=str(p.parent if p.is_file() else p)) as sandbox:
                    llm = k.LLM(model=selected_model)
                    result = k.run_goal_sync(
                        llm, world, budget,
                        goal_id, sandbox=sandbox, max_depth=2,
                    )
                unsuccessful = _run_outcome_blocked(world, goal_id) or unsuccessful
                click.echo(result)
            except Exception as e:
                unsuccessful = True
                click.echo(click.style(f"  goal #{goal_id} failed: {e}", fg="red"))
            finally:
                world.close()

    if count == 0:
        click.echo(f"no AI markers found in {path}")
    else:
        click.echo(f"\nfound {count} marker(s)")

    if unsuccessful:
        raise SystemExit(1)


# ----- Audit log ---------------------------------------------------------

@main.group()
def audit() -> None:
    """Inspect the audit log (~/.maverick/audit/YYYY-MM-DD.ndjson)."""


def _require_day_opt(day: str | None) -> None:
    """Reject a ``--day`` that isn't a literal YYYY-MM-DD before it becomes a path.

    ``day`` is resolved to ``<audit_dir>/<day>.ndjson``; a value like
    ``../../etc/passwd`` would otherwise escape the audit dir. The writer/export
    layer refuses it too (a backstop for non-CLI callers); this just turns it
    into a friendly CLI error + exit 2, matching ``--since``/``--until``.
    """
    from ..audit.events import is_valid_day
    if day is not None and not is_valid_day(day):
        click.echo("error: --day must be YYYY-MM-DD", err=True)
        sys.exit(2)


@audit.command("tail")
@click.option("-n", "--num", default=50, type=click.IntRange(0, 10000), help="Lines to tail (bounded to 10000).")
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
def audit_tail(num: int, day: str | None) -> None:
    """Print the last N audit events."""
    import json as _json

    _require_day_opt(day)
    from ..audit import default_audit_log
    from ..audit.segments import ReadReport
    report = ReadReport()
    for ev in default_audit_log().tail(num, day=day, report=report):
        click.echo(_json.dumps(ev, default=str))
    if report.failures:
        raise click.ClickException(f"audit tail is {report.state}; this is not complete evidence")


@audit.command("grep")
@click.argument("pattern")
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
def audit_grep(pattern: str, day: str | None) -> None:
    """Regex grep over today's audit log."""
    import json as _json

    _require_day_opt(day)
    from ..audit import default_audit_log
    try:
        events = default_audit_log().grep(pattern, day=day)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(2)
    for ev in events:
        click.echo(_json.dumps(ev, default=str))


@audit.command("verify")
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
@click.option("--all", "all_days", is_flag=True,
              help="Verify every YYYY-MM-DD.ndjson day-file in the audit dir.")
@click.option("--tenant", default=None,
              help="Tenant whose audit dir to verify (default: active/none).")
@click.option("--file", "file_", default=None, type=click.Path(),
              help="A single audit file to verify (overrides --day/--all).")
@click.option(
    "--pubkey", default=None,
    help="Trusted Ed25519 pubkey (hex). Required for real third-party "
         "tamper-evidence; without it a locally-held key is trusted.",
)
def audit_verify(
    day: str | None, all_days: bool, tenant: str | None,
    file_: str | None, pubkey: str | None,
) -> None:
    """Verify the tamper-evident audit log and exit non-zero on any break.

    Walks the Ed25519 hash-chain of the audit day-file(s) and the cross-file
    tip-ledger, printing a concise OK / per-file break report. Exits 1 if any
    break is found and 0 if clean, so CI / cron / SOC 2 evidence checks can gate
    on it. By default it verifies today's day-file; ``--all`` sweeps every
    day-file in the audit dir. Only meaningful when audit signing is enabled
    ([audit] sign = true).

    If ``cryptography`` is unavailable the chain can't be verified at all; that
    is reported as a verification break and exits 1 so automation cannot pass
    unverifiable evidence as clean.
    """
    import datetime as _dt
    from pathlib import Path as _Path

    _require_day_opt(day)
    _require_known_cli_tenant(tenant)
    from ..audit import verify_anchors, verify_chain
    from ..paths import data_dir

    # Resolve the audit dir tenant-aware (matching the writer/signer), unless an
    # explicit --file pins one file in some other location.
    audit_dir = data_dir("audit", tenant=tenant) if tenant else data_dir("audit")

    if file_:
        paths = [_Path(file_)]
        anchor_dir = paths[0].parent
    elif all_days:
        # The anchor ledger is verified separately as the tip-ledger; don't
        # also walk it as if it were a day-file.
        paths = [p for p in sorted(audit_dir.glob("*.ndjson"))
                 if p.name != "anchors.ndjson"]
        anchor_dir = audit_dir
        if not paths:
            click.echo(f"no audit day-files in {audit_dir}")
            if audit_dir.exists() and any(audit_dir.iterdir()):
                # Keys or a ledger without any day-file: as in the default-day
                # branch, verify today's path so a deletion reports
                # missing_file instead of passing.
                today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
                paths = [audit_dir / f"{today}.ndjson"]
    else:
        d = day or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        anchor_dir = audit_dir
        day_file = audit_dir / f"{d}.ndjson"
        from ..audit.signing import _have_crypto
        audit_dir_empty = not audit_dir.exists() or not any(audit_dir.iterdir())
        if not day_file.exists() and _have_crypto() and audit_dir_empty:
            # A completely absent/empty audit directory means no audit events
            # have ever been recorded for this tenant, so the requested day is
            # cleanly empty. If the directory contains any audit artifacts
            # (keys, anchors, other day-files, etc.), keep verifying the
            # requested path so verify_chain() can report a missing_file break
            # instead of allowing deletion of an unanchored day-file to pass.
            click.echo(f"no audit entries for {d} (nothing recorded that day).")
            paths = []
        else:
            paths = [day_file]

    if not pubkey:
        click.echo(
            "warning: no --pubkey given; trusting a locally-held key. For "
            "third-party tamper-evidence, pass the externally-held pubkey.",
            err=True,
        )

    any_break = False
    for path in paths:
        breaks = verify_chain(path, pubkey_hex=pubkey)
        if breaks and all(b.reason == "unsigned" for b in breaks):
            # Default deployment: signing was never on. One actionable line
            # instead of per-row tamper vocabulary -- but still exit 1, so
            # automation cannot pass unverifiable evidence as clean.
            any_break = True
            click.echo(
                f"UNVERIFIABLE: {path} — {len(breaks)} unsigned row(s); audit "
                "signing is off. Set [audit] sign = true in "
                "~/.maverick/config.toml (or MAVERICK_AUDIT_SIGN=1) so future "
                "rows are hash-chained and tamper-evident.",
                err=True,
            )
        elif breaks:
            any_break = True
            click.echo(f"FAIL: {len(breaks)} issue(s) in {path}", err=True)
            for b in breaks:
                click.echo(f"  line {b.line_no}: {b.reason} — {b.detail}", err=True)
        else:
            click.echo(f"OK: chain intact ({path})")

    # Cross-file check: a whole deleted/truncated day-file is invisible to the
    # per-file chain above; the signed tip-ledger catches it.
    anchor_breaks = verify_anchors(anchor_dir, pubkey_hex=pubkey)
    if anchor_breaks:
        any_break = True
        click.echo(
            f"FAIL: {len(anchor_breaks)} cross-file tip-ledger issue(s) in {anchor_dir}",
            err=True,
        )
        for b in anchor_breaks:
            click.echo(f"  anchor: {b.reason} — {b.detail}", err=True)
    else:
        click.echo(f"OK: tip-ledger intact ({anchor_dir})")

    # State the deletions the tip-ledger stopped reporting as breaks. Without
    # this line "OK" would read as "nothing was removed" when the truth is
    # "these days were removed by policy and here is the signed record".
    from ..audit.signing import retention_purged_days
    retired = retention_purged_days(anchor_dir)
    if retired:
        click.echo(
            f"note: {len(retired)} day-file(s) retired by [retention] policy "
            "and recorded in the signed tip-ledger:")
        for entry in retired:
            click.echo(
                f"  {entry.get('day')}: {entry.get('row_count')} row(s), "
                f"tip {str(entry.get('tip_hash'))[:12]}...")

    if any_break:
        raise SystemExit(1)


@audit.group("checkpoint")
def audit_checkpoint() -> None:
    """Publish and verify independently held live audit-tip commitments."""


@audit_checkpoint.command("publish")
@click.option(
    "--checkpoint-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Independent/WORM directory that will hold signed checkpoints.",
)
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
@click.option(
    "--pubkey",
    multiple=True,
    help=(
        "Pinned Ed25519 public key in hex. Repeat during an authorized key "
        "rotation."
    ),
)
@click.option(
    "--supersede-digest",
    default=None,
    help="Exact SHA-256 of the latest checkpoint being superseded.",
)
@click.option(
    "--lifecycle-reason",
    type=click.Choice(["gdpr_reanchor"], case_sensitive=True),
    default=None,
    help="Bounded reason for an authorized changed-prefix supersession.",
)
def audit_checkpoint_publish(
    checkpoint_dir: Path,
    day: str | None,
    pubkey: tuple[str, ...],
    supersede_digest: str | None,
    lifecycle_reason: str | None,
) -> None:
    """Publish the current signed day tip to an independent checkpoint store."""
    from ..audit.checkpoints import AuditCheckpointError, publish_checkpoint
    from ..paths import data_dir

    _require_day_opt(day)
    try:
        path = publish_checkpoint(
            data_dir("audit"),
            checkpoint_dir,
            day=day,
            trusted_pubkeys=pubkey or None,
            supersedes_checkpoint_sha256=supersede_digest,
            lifecycle_reason=lifecycle_reason,
        )
    except (AuditCheckpointError, ImportError, OSError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    import hashlib

    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sequence = int(path.stem.rsplit("-", 1)[-1])
    except (OSError, ValueError) as exc:
        raise click.ClickException(
            f"checkpoint was published but its receipt could not be read: {exc}"
        ) from exc
    click.echo(f"published {path}")
    click.echo(f"retain externally: sequence={sequence} sha256={digest}")


@audit_checkpoint.command("retire")
@click.option(
    "--checkpoint-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Independent/WORM directory containing signed checkpoints.",
)
@click.option(
    "--supersede-digest",
    required=True,
    help="Exact SHA-256 of the latest checkpoint being retired.",
)
@click.option(
    "--lifecycle-reason",
    required=True,
    type=click.Choice(["retention_purge"], case_sensitive=True),
    help="Bounded reason for retirement.",
)
@click.option(
    "--pubkey",
    multiple=True,
    help=(
        "Pinned Ed25519 public key in hex. Repeat during an authorized key "
        "rotation."
    ),
)
def audit_checkpoint_retire(
    checkpoint_dir: Path,
    supersede_digest: str,
    lifecycle_reason: str,
    pubkey: tuple[str, ...],
) -> None:
    """Retire a checkpoint after an exact signed retention purge."""
    from ..audit.checkpoints import AuditCheckpointError, retire_checkpoint
    from ..paths import data_dir

    try:
        path = retire_checkpoint(
            data_dir("audit"),
            checkpoint_dir,
            supersedes_checkpoint_sha256=supersede_digest,
            lifecycle_reason=lifecycle_reason,
            trusted_pubkeys=pubkey or None,
        )
    except (AuditCheckpointError, ImportError, OSError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"retired by signed lifecycle record {path}")


@audit_checkpoint.command("verify")
@click.option(
    "--checkpoint-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help="Independent/WORM directory containing signed checkpoints.",
)
@click.option(
    "--minimum-sequence",
    type=click.IntRange(min=1),
    default=None,
    help="Latest sequence retained by an independent verifier/SIEM.",
)
@click.option(
    "--minimum-digest",
    default=None,
    help="SHA-256 retained externally for --minimum-sequence.",
)
@click.option(
    "--pubkey",
    multiple=True,
    help="Pinned Ed25519 public key in hex; repeat to trust a rotation set.",
)
def audit_checkpoint_verify(
    checkpoint_dir: Path,
    minimum_sequence: int | None,
    minimum_digest: str | None,
    pubkey: tuple[str, ...],
) -> None:
    """Verify published checkpoint history and every committed audit prefix."""
    from ..audit.checkpoints import verify_checkpoints
    from ..paths import data_dir

    try:
        breaks = verify_checkpoints(
            data_dir("audit"),
            checkpoint_dir,
            trusted_pubkeys=pubkey or None,
            minimum_sequence=minimum_sequence,
            minimum_digest=minimum_digest,
        )
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if breaks:
        for item in breaks:
            click.echo(
                f"FAIL checkpoint {item.sequence}: {item.reason} — {item.detail}",
                err=True,
            )
        raise SystemExit(1)
    if pubkey and minimum_sequence is not None and minimum_digest is not None:
        click.echo(
            f"OK: independent audit checkpoints intact and externally pinned "
            f"({checkpoint_dir})"
        )
    else:
        missing = []
        if not pubkey:
            missing.append("--pubkey")
        if minimum_sequence is None:
            missing.append("--minimum-sequence")
        if minimum_digest is None:
            missing.append("--minimum-digest")
        click.echo(
            "OK: independent audit checkpoints intact internally; independent "
            f"assurance incomplete without {', '.join(missing)} "
            f"({checkpoint_dir})"
        )


@audit.command("seal")
@click.option("--dry-run", is_flag=True,
              help="Show which segments would be sealed; write nothing.")
def audit_seal(dry_run: bool) -> None:
    """Encrypt closed audit day-files at rest (confidentiality for the log).

    Seals every day-file dated before today in place with AES-256-GCM. The current
    day-file (live append) and the anchor ledger stay plaintext, and the readers +
    'audit verify' transparently decrypt sealed segments. Requires at-rest
    encryption to be enabled ([encryption] at_rest / MAVERICK_ENCRYPT_AT_REST).
    """
    from ..audit.sealing import seal_closed_segments
    from ..crypto_at_rest import EncryptionUnavailable
    try:
        report = seal_closed_segments(dry_run=dry_run)
    except EncryptionUnavailable as e:
        raise click.ClickException(str(e)) from e
    for name, status in sorted(report.items()):
        click.echo(f"  {name}: {status}")
    done = sum(1 for s in report.values() if s in ("sealed", "would seal"))
    click.echo(f"{'Would seal' if dry_run else 'Sealed'} {done} segment(s).")


@audit.command("rotate-key")
def audit_rotate_key() -> None:
    """Rotate the audit signing key (Ed25519).

    Mints a new keypair and makes it the active signer. Safe and additive: prior
    public keys are retained so 'audit verify' still validates rows signed under
    the old key (each row carries its key_id) -- no audit data is rewritten.
    Takes effect for the next day-file / process restart; restart a running
    'maverick serve' to begin signing with the new key.
    """
    from ..audit.signing import _have_crypto, rotate_audit_keypair
    if not _have_crypto():
        raise click.ClickException(
            "audit signing needs the 'cryptography' package (pip install "
            "'pyjwt[crypto]' or cryptography)."
        )
    key_id = rotate_audit_keypair()
    click.echo(f"rotated audit signing key; new active key_id = {key_id}")
    click.echo("old public keys retained for verification. Restart "
               "'maverick serve' to sign new entries with it.")


def _require_safe_audit_destination(path, tenant):
    from ..audit.export import validate_export_destination

    try:
        validate_export_destination(path, tenant=tenant)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


@audit.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "cef"]), default="json",
              help="Output format for SIEM ingestion (default: json).")
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
@click.option("--all", "all_days", is_flag=True,
              help="Export every YYYY-MM-DD.ndjson day-file in the audit dir.")
@click.option("--since", default=None,
              help="Start of an inclusive YYYY-MM-DD window (e.g. an incident).")
@click.option("--until", default=None,
              help="End of the inclusive YYYY-MM-DD window.")
@click.option("--tenant", default=None,
              help="Tenant whose audit dir to export (default: active/none).")
@click.option("-o", "--output", "output", default=None, type=click.Path(),
              help="Write to FILE (mode 0600; may contain PII). Default: stdout.")
@click.option("--verify", is_flag=True, help="Verify selected segment signatures and chains before export; anchors/checkpoints require audit verify/binder.")
@click.option("--read-report", default=None, type=click.Path(), help="Write a separate JSON read-coverage receipt; raw event rows are unchanged.")
def audit_export(
    fmt: str, day: str | None, all_days: bool, since: str | None,
    until: str | None, tenant: str | None, output: str | None,
    verify: bool = False, read_report: str | None = None,
) -> None:
    """Export the audit log as JSONL or ArcSight CEF for a SIEM.

    Read-only re-emission of the tamper-evident NDJSON log; it never mutates
    the log or the signing chain. By default it exports today's day-file;
    ``--since``/``--until`` export an inclusive date window (for incident
    backfill) and ``--all`` sweeps every day-file. An empty/missing log exits 0
    (a note goes to stderr) so cron/automation never fails on a quiet day.
    """
    import datetime as _dt
    import os as _os
    from pathlib import Path as _Path

    _require_day_opt(day)
    for _label, _val in (("--since", since), ("--until", until)):
        if _val is not None:
            try:
                _parsed = _dt.datetime.strptime(_val, "%Y-%m-%d")
            except ValueError:
                click.echo(f"ERROR: {_label} must be YYYY-MM-DD", err=True)
                sys.exit(2)
            if _parsed.strftime("%Y-%m-%d") != _val:
                click.echo(f"ERROR: {_label} must be YYYY-MM-DD", err=True)
                sys.exit(2)

    # Plan feature gating: SIEM audit export is a plan-gated feature. Deny
    # either an explicit --tenant or the active deployment tenant when it names
    # a provisioned tenant whose plan omits "audit_export"; unscoped/self-host
    # export is unaffected because feature_allowed fails open at the edges.
    from ..billing import feature_allowed
    if not feature_allowed("audit_export", tenant=tenant):
        from ..paths import current_tenant_id
        denied_tenant = tenant or current_tenant_id() or "active tenant"
        click.echo(
            f"ERROR: tenant '{denied_tenant}' plan does not include SIEM audit "
            "export (audit_export entitlement). Upgrade the tenant's plan.",
            err=True,
        )
        sys.exit(2)

    from ..audit.export import audit_event_paths, iter_audit_events, to_cef, to_jsonl
    from ..audit.segments import ReadReport

    coverage = ReadReport()
    source_paths = audit_event_paths(day=day, all_days=all_days, since=since, until=until, tenant=tenant)
    if read_report:
        receipt_path = _Path(read_report)
        _require_safe_audit_destination(receipt_path, tenant)
        for protected in [*source_paths, *([_Path(output)] if output else [])]:
            if (receipt_path.resolve(strict=False) == protected.resolve(strict=False)
                    or (receipt_path.exists() and protected.exists() and _os.path.samefile(receipt_path, protected))):
                raise click.ClickException("read report must not overwrite an audit source or event export")

    def finish_report():
        if read_report:
            import json

            from ..file_lock import atomic_write_text
            atomic_write_text(_Path(read_report), json.dumps(coverage.as_dict(), sort_keys=True) + "\n")
        if coverage.failures:
            click.echo(f"WARNING: audit export is {coverage.state}; {coverage.failures} read/verification failure(s). This is not complete evidence.", err=True)
            raise click.exceptions.Exit(1)
        if verify:
            click.echo(f"audit read: {coverage.state}; segment chains only; anchors/checkpoints not verified", err=True)

    render = to_cef if fmt == "cef" else to_jsonl
    lines = (render(ev) for ev in iter_audit_events(
        day=day, all_days=all_days, since=since, until=until, tenant=tenant,
        report=coverage, verify=verify,
    ))

    if output:
        output_path = _Path(output)
        output_resolved = output_path.resolve(strict=False)
        source_paths = audit_event_paths(
            day=day, all_days=all_days, since=since, until=until, tenant=tenant,
        )
        for source_path in source_paths:
            if (output_resolved == source_path.resolve(strict=False)
                    or (output_path.exists() and source_path.exists()
                        and _os.path.samefile(output_path, source_path))):
                raise click.ClickException(
                    "refusing to write audit export over a source audit log file"
                )
        _require_safe_audit_destination(output_path, tenant)

        # Private from creation on POSIX *and* Windows: os.open(..., 0o600)
        # only adjusts POSIX mode bits and can inherit a broad Windows DACL.
        # Stream through a protected unpublished temp, then atomically publish
        # the complete export so PII is never exposed in a permissive or torn
        # destination file.
        from ..file_lock import atomic_write_text_chunks

        n = atomic_write_text_chunks(
            output_path,
            (line + "\n" for line in lines),
            mode=0o600,
        )
        if n == 0:
            click.echo("no audit events to export", err=True)
        else:
            click.echo(f"exported {n} event(s) to {output}", err=True)
        finish_report()
        return

    n = 0
    for line in lines:
        click.echo(line)
        n += 1
    if n == 0:
        click.echo("no audit events to export", err=True)
    finish_report()


@audit.command("forward")
@click.option("--format", "fmt", type=click.Choice(["json", "cef"]), default="json",
              help="Wire format for the SIEM (default: json).")
@click.option("--to", "dest", default=None,
              help="Destination URI: tcp://host:port, udp://host:port, "
                   "http(s)://host/path, datadog://<site>, or "
                   "sentinel://<dce-host>/<dcr-id>/Custom-<stream>. Default: "
                   "MAVERICK_SIEM_DEST / [audit] siem_dest.")
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
@click.option("--all", "all_days", is_flag=True,
              help="Forward every YYYY-MM-DD.ndjson day-file in the audit dir.")
@click.option("--since", default=None,
              help="Start of an inclusive YYYY-MM-DD window (e.g. an incident).")
@click.option("--until", default=None,
              help="End of the inclusive YYYY-MM-DD window.")
@click.option("--tenant", default=None,
              help="Tenant whose audit dir to forward (default: active/none).")
@click.option("--dry-run", is_flag=True,
              help="Validate the destination and count events; send nothing.")
def audit_forward(
    fmt: str, dest: str | None, day: str | None, all_days: bool,
    since: str | None, until: str | None, tenant: str | None, dry_run: bool,
) -> None:
    """Push the audit log to a SIEM collector over the network.

    The push counterpart of ``audit export``: same read-only re-emission of the
    tamper-evident NDJSON log, but shipped to ``--to`` (a tcp/udp syslog or
    http(s) collector) instead of a file. A transport failure exits non-zero --
    a SIEM gap is a compliance event, not something to swallow. An empty log
    exits 0 with a note (cron never fails on a quiet day).
    """
    import datetime as _dt

    _require_day_opt(day)
    for _label, _val in (("--since", since), ("--until", until)):
        if _val is not None:
            try:
                _parsed = _dt.datetime.strptime(_val, "%Y-%m-%d")
            except ValueError:
                click.echo(f"ERROR: {_label} must be YYYY-MM-DD", err=True)
                sys.exit(2)
            if _parsed.strftime("%Y-%m-%d") != _val:
                click.echo(f"ERROR: {_label} must be YYYY-MM-DD", err=True)
                sys.exit(2)

    if not dest or not dest.strip():
        import os as _os
        dest = _os.environ.get("MAVERICK_SIEM_DEST")
        if not dest:
            try:
                from ..config import load_config
                dest = (load_config() or {}).get("audit", {}).get("siem_dest")
            except Exception:
                dest = None
    if not dest or not str(dest).strip():
        click.echo(
            "ERROR: no SIEM destination (--to, MAVERICK_SIEM_DEST, or "
            "[audit] siem_dest)", err=True,
        )
        sys.exit(2)

    # Same plan gate as export, including active deployment
    # tenants resolved by feature_allowed when --tenant is omitted.
    from ..billing import feature_allowed
    if not feature_allowed("audit_export", tenant=tenant):
        from ..paths import current_tenant_id
        denied_tenant = tenant or current_tenant_id() or "active tenant"
        click.echo(
            f"ERROR: tenant '{denied_tenant}' plan does not include SIEM audit "
            "export (audit_export entitlement). Upgrade the tenant's plan.",
            err=True,
        )
        sys.exit(2)

    from ..audit import forwarder
    from ..audit.export import iter_audit_events, to_cef, to_jsonl
    from ..audit.segments import ReadReport

    coverage = ReadReport()

    # Validate the destination up front so a typo fails before we read the log.
    try:
        forwarder.parse_dest(str(dest))
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)

    render = to_cef if fmt == "cef" else to_jsonl
    lines = (render(ev) for ev in iter_audit_events(
        day=day, all_days=all_days, since=since, until=until, tenant=tenant,
        report=coverage,
    ))

    if dry_run:
        n = sum(1 for _ in lines)
        if coverage.failures:
            raise click.ClickException(f"audit read is {coverage.state}; forwarding would omit unreadable evidence")
        click.echo(f"dry-run: {n} event(s) would ship to {dest}", err=True)
        return

    try:
        sent = forwarder.forward(lines, str(dest))
    except Exception as e:
        click.echo(f"ERROR: SIEM forward failed: {e}", err=True)
        sys.exit(1)
    if coverage.failures:
        raise click.ClickException(f"audit read is {coverage.state}; {sent} event(s) sent, but forwarding is incomplete")
    if sent == 0:
        click.echo("no audit events to forward", err=True)
    else:
        click.echo(f"forwarded {sent} event(s) to {dest}", err=True)


@audit.group("worm")
def audit_worm() -> None:
    """Write-once (WORM) export of closed audit day-files (see docs/security-hardening.md)."""


@audit_worm.command("push")
@click.option("--dry-run", is_flag=True,
              help="Show which day-files would be shipped; write nothing.")
def audit_worm_push(dry_run: bool) -> None:
    """Ship closed audit day-files to the configured write-once target.

    Each day-file dated before today is shipped to an S3 Object-Lock bucket (or a
    local read-only mirror) with a retention lock, so the historical trail can't
    be altered or deleted even by a privileged insider. Idempotent: unchanged
    files are skipped; a file changed by `audit seal` / erase is re-shipped as a
    new locked version. Configure via `[audit.worm]`.
    """
    from ..audit.worm import WormUnavailable, push_closed_dayfiles
    try:
        report = push_closed_dayfiles(dry_run=dry_run)
    except WormUnavailable as e:
        raise click.ClickException(str(e)) from e
    for name, status in sorted(report.items()):
        click.echo(f"  {name}: {status}")
    failed = [
        name for name, status in report.items()
        if status.startswith(("error", "refused"))
    ]
    if failed:
        raise click.ClickException(
            f"{len(failed)} day-file(s) were not safely shipped: {sorted(failed)}"
        )
    shipped = sum(1 for s in report.values()
                  if s.startswith(("pushed", "re-pushed", "would")))
    click.echo(f"{'Would ship' if dry_run else 'Shipped'} {shipped} day-file(s).")


@audit_worm.command("verify")
def audit_worm_verify() -> None:
    """Check closed day-files against the WORM manifest.

    Reports, per closed day-file, whether its current bytes were shipped (`ok`),
    differ from the last shipped version (`changed since push` -- re-run push), or
    were never shipped (`NOT pushed`). Exits non-zero if anything is unshipped or
    diverged, so it can gate a compliance cron.
    """
    from ..audit.worm import verify
    report = verify()
    for name, status in sorted(report.items()):
        click.echo(f"  {name}: {status}")
    bad = [n for n, s in report.items() if s != "ok"]
    if bad:
        click.echo(f"{len(bad)} day-file(s) not durably shipped: {sorted(bad)}",
                   err=True)
        sys.exit(1)
    click.echo(f"all {len(report)} closed day-file(s) verified in WORM store.")


@main.command()
@click.option("--reason", default="manual halt", help="Why you're halting.")
@click.option("--json", "json_output", is_flag=True, help="Return a checked local halt-file acknowledgement.")
def halt(reason: str, json_output: bool = False) -> None:
    """Request a local halt at upcoming execution checkpoints."""
    _local_halt_command("halt", reason, json_output)


@main.command("unhalt")
@click.option("--reason", default="manual clear", help="Why you're clearing the local halt.")
@click.option("--json", "json_output", is_flag=True, help="Return a checked local halt-file acknowledgement.")
def unhalt(reason: str, json_output: bool = False) -> None:
    """Clear the local HALT authority after verifying its generation."""
    _local_halt_command("unhalt", reason, json_output)


def _local_halt_command(command: str, reason: str, json_output: bool) -> None:
    """Share the audited local authority while preserving the CLI wire shape."""
    import json

    from .. import agent_control_plane as acp
    from .. import killswitch
    from ..audit import AuditRefused
    from ._agent_control_plane_groups import _actor

    try:
        result = (
            acp.halt_local(reason, actor=_actor())
            if command == "halt"
            else acp.clear_local_halt(actor=_actor(), reason=reason)
        )
    except AuditRefused as exc:
        raise click.ClickException(
            "Halt audit was refused; local state may have changed. Check status before retrying."
        ) from exc
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if not result.ok:
        raise click.ClickException(
            f"Local halt-file state was not confirmed ({result.detail}); review before retrying."
        )
    p = killswitch._halt_file_path()
    try:
        present = killswitch._halt_file_generation(p) is not None
    except OSError as exc:
        raise click.ClickException("Local halt-file state was not confirmed; review before retrying.") from exc
    if present != (command == "halt"):
        raise click.ClickException("Local halt-file state was not confirmed; review before retrying.")
    if json_output:
        click.echo(json.dumps({"command": command, "acknowledged": True,
                               "halt_file_present": present, "scope": "local", "work_stopped": False,
                               "audit_written": result.audit_written}))
    else:
        click.echo(f"{'halt set' if present else 'local halt cleared'}: {p}")
        if not result.audit_written:
            click.echo("warning: halt audit result was not written", err=True)


# ----- Cost / export / logs --------------------------------------------

@main.command()
@click.option("--month", default=None, help="UTC YYYY-MM within the most recent 10,000 episodes (100,000 with --csv).")
@click.option("--model", default=None, help="Filter to one model id.")
@click.option("--csv", "csv_out", is_flag=True,
              help="Output one row per episode in CSV format.")
@click.pass_context
def cost(ctx, month: str | None, model: str | None, csv_out: bool) -> None:
    """Summarize spend across the world model."""
    world = open_world(ctx.obj["db"])
    try:
        episodes = world.list_episodes(limit=100_000 if csv_out else 10_000)
    finally:
        world.close()
    if month:
        import datetime as _dt
        try:
            m_start = _dt.datetime.strptime(month, "%Y-%m").replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            raise click.ClickException("--month must be YYYY-MM (e.g. 2026-05)") from None
        start = m_start.timestamp()
        # True next-month boundary (a fixed +31 days over-counted short months,
        # e.g. Feb pulled in early March).
        end = _dt.datetime(
            m_start.year + (m_start.month == 12),
            (m_start.month % 12) + 1,
            1, tzinfo=_dt.timezone.utc,
        ).timestamp()
        episodes = [
            e for e in episodes
            if start <= (e.started_at or 0) < end
        ]
    if model:
        # Episode rows don't record a model id (EpisodeSpend has no model column
        # and outcomes don't carry "model=X"), so this filter silently matched
        # nothing. Fail honestly rather than return a misleading empty result.
        raise click.ClickException(
            "--model filtering is not available: episode rows record goal, time, "
            "cost, and tokens, but not a model id. Use per-role cost projection "
            "for model-level spend.")

    click.echo(
        f"Window: most recent {100_000 if csv_out else 10_000:,} episodes"
        + (f"; filtered to {month} UTC" if month else ""), err=csv_out,
    )
    if csv_out:
        import csv as _csv
        writer = _csv.writer(sys.stdout)
        writer.writerow([
            "episode_id", "goal_id", "started_at", "ended_at", "outcome",
            "dollars", "input_tokens", "output_tokens", "tool_calls",
        ])
        for e in episodes:
            writer.writerow([
                e.id, e.goal_id,
                e.started_at, e.ended_at or "",
                e.outcome or "",
                f"{(e.cost_dollars or 0):.6f}",
                e.input_tokens, e.output_tokens, e.tool_calls,
            ])
        return

    total = sum((e.cost_dollars or 0) for e in episodes)
    in_tok = sum((e.input_tokens or 0) for e in episodes)
    out_tok = sum((e.output_tokens or 0) for e in episodes)
    tool_calls = sum((e.tool_calls or 0) for e in episodes)
    click.echo(f"Episodes:    {len(episodes):>10}")
    click.echo(f"Dollars:     ${total:.4f}")
    click.echo(f"Input tok:   {in_tok:>10,}")
    click.echo(f"Output tok:  {out_tok:>10,}")
    click.echo(f"Tool calls:  {tool_calls:>10,}")


@main.command("export")
@click.argument("goal_id", type=int)
@click.option("-o", "--output", type=click.Path(),
              help="Path for the bundle (default: ./goal-<id>.json).")
@click.pass_context
def export_goal(ctx, goal_id: int, output: str | None) -> None:
    """Export a goal's full trajectory as a portable JSON bundle.

    The bundle includes the goal record, all child goals, every event,
    and the episode summaries. No prompt content is included unless it
    was logged to events.
    """
    import json as _json

    from ..goal_bundle import build_goal_bundle
    world = open_world(ctx.obj["db"])
    try:
        bundle = build_goal_bundle(world, goal_id)
        if bundle is None:
            click.echo(f"goal {goal_id} not found", err=True)
            sys.exit(2)
    finally:
        world.close()
    out_path = Path(output) if output else Path(f"goal-{goal_id}.json")
    try:
        streamed = _write_private_export(out_path, _json.dumps(bundle, default=str, indent=2), overwrite=False)
    except OSError as e:
        raise click.ClickException(f"could not write {out_path}: {e}") from e
    click.echo(f"wrote {out_path}", err=streamed)


@main.command("logs")
@click.argument("pattern", required=False)
@click.option("-n", "--num", default=200, type=int, help="Lines to show.")
@click.option("--day", default=None, help="YYYY-MM-DD (default: today).")
def logs_cmd(pattern: str | None, num: int, day: str | None) -> None:
    """Show recent audit log entries (optionally regex-filtered).

    Equivalent to `maverick audit grep <pattern>` or `audit tail -n N`.
    """
    import json as _json

    _require_day_opt(day)
    from ..audit import default_audit_log
    al = default_audit_log()
    try:
        rows = al.grep(pattern, day=day) if pattern else al.tail(num, day=day)
    except ValueError as e:
        click.echo(f"error: {e}", err=True)
        sys.exit(2)
    for r in rows[-num:]:
        click.echo(_json.dumps(r, default=str))


# ----- SOC 2 evidence --------------------------------------------------

_REQUIRED_SOC2_CONTROLS = (
    "capability_enforcement",
    "tenant_isolation",
    "usage_quotas",
    "oidc_auth",
    "encryption_at_rest",
)


def _soc2_posture_ready(evidence) -> bool:
    """Return True only when required SOC 2 controls report a ready posture."""
    controls = evidence.get("controls", {}) if isinstance(evidence, dict) else {}
    if not isinstance(controls, dict):
        return False
    for control in _REQUIRED_SOC2_CONTROLS:
        probe = controls.get(control, {})
        if not isinstance(probe, dict) or probe.get("status") != "enabled":
            return False

    audit_log = evidence.get("audit_log", {}) if isinstance(evidence, dict) else {}
    if not isinstance(audit_log, dict) or audit_log.get("status") != "ok":
        return False

    signing_key = evidence.get("audit_signing_key", {}) if isinstance(evidence, dict) else {}
    return isinstance(signing_key, dict) and signing_key.get("status") == "enabled"


# Register command groups that have been split into submodules. Imported last,
# so every shared helper and `main` is defined before the submodule decorators
# run (@main.group/@main.command register onto `main` on import).
from . import (  # noqa: E402,F401
    _a2a_groups,
    _agent_control_plane_groups,
    _budget_preview,
    _code_groups,
    _codec_groups,
    _compliance_groups,
    _connector_groups,
    _cortex_groups,
    _ekko_groups,
    _external_agent_groups,
    _finance_groups,
    _flow_operator_groups,
    _flow_recipe_groups,
    _governed_execution_groups,
    _immune_groups,
    _import_groups,
    _knowledge_groups,
    _learning_groups,
    _ops_groups,
    _owner_groups,
    _reporting_groups,
    _training_groups,
    _trust_groups,
    _voice_groups,
)

try:
    from maverick_channels.maintenance_cli import channel_maintenance
except ImportError:  # optional channels package
    pass
else:
    main.add_command(channel_maintenance)


if __name__ == "__main__":
    main()
