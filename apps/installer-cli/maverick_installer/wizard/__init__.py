"""Lightwork interactive installer.

Configures Lightwork for a fresh install. Sets up:
  - AI providers and per-role models
  - channels (Telegram, Discord, Slack, Signal, WhatsApp, SMS, Email,
    Matrix, iMessage)
  - safety profile
  - sandbox backend
  - budget caps
  - API keys (stored beside config.toml, referenced from it via ${VAR})

Writes ``$MAVERICK_CONFIG`` (or ``$LIGHTWORK_CONFIG``) when explicitly
selected, otherwise ``$MAVERICK_HOME/config.toml`` (or
``$LIGHTWORK_HOME/config.toml``; default ``~/.maverick/config.toml``), plus a
sibling ``.env``. The agent reads from the same resolution contract.

v0.1.1 additions:
  - Preflight: Python version, write perms, optional docker check
  - API key validation: pings Anthropic with the entered key before save
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from maverick.config_contracts import (
    BOOLEAN_SETTINGS,
    CHOICE_SETTINGS,
    INTEGER_SETTINGS,
    NUMBER_LIST_SETTINGS,
    TEXT_SETTINGS,
)

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.11 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]

from rich.console import Console
from rich.panel import Panel

try:
    import questionary
except ImportError:  # pragma: no cover
    questionary = None  # type: ignore

# Step modules.  Each name is re-exported so ``maverick_installer.wizard.<name>``
# keeps working for callers and tests; the step modules reach the prompt
# primitives, console and CONFIG_* paths through ._seams at call time, so a
# monkeypatch on this facade applies to them too.
from .. import models as catalog
from ._common import _append_nested_product_config as _append_nested_product_config
from ._common import _csv_list as _csv_list
from ._common import _emit_kv as _emit_kv
from ._common import _safe_float as _safe_float
from ._common import _safe_int as _safe_int
from ._common import _toml_str as _toml_str
from .advanced import _FEATURE_LOCKS as _FEATURE_LOCKS
from .advanced import _LOCAL_FIRST_PROVIDERS as _LOCAL_FIRST_PROVIDERS
from .advanced import _ask_chat_and_resource_followups as _ask_chat_and_resource_followups
from .advanced import _ask_dashboard_followups as _ask_dashboard_followups
from .advanced import _ask_external_agent_followups as _ask_external_agent_followups
from .advanced import _ask_flow_followups as _ask_flow_followups
from .advanced import _ask_governed_execution_followups as _ask_governed_execution_followups
from .advanced import _ask_identity_followups as _ask_identity_followups
from .advanced import _ask_insight_exchange as _ask_insight_exchange
from .advanced import _ask_model_followups as _ask_model_followups
from .advanced import _ask_regulated_deployment as _ask_regulated_deployment
from .advanced import _ask_self_harness_evaluation_boundary as _ask_self_harness_evaluation_boundary
from .advanced import _ask_self_harness_followups as _ask_self_harness_followups
from .advanced import _bad_network as _bad_network
from .advanced import _cfg_advanced as _cfg_advanced
from .advanced import _cfg_advanced_autonomy_and_workforce as _cfg_advanced_autonomy_and_workforce
from .advanced import _cfg_advanced_context_and_attachments as _cfg_advanced_context_and_attachments
from .advanced import _cfg_advanced_dashboard as _cfg_advanced_dashboard
from .advanced import _cfg_advanced_dreaming_and_tax as _cfg_advanced_dreaming_and_tax
from .advanced import (
    _cfg_advanced_external_agents_and_memory as _cfg_advanced_external_agents_and_memory,
)
from .advanced import _cfg_advanced_feature_locks as _cfg_advanced_feature_locks
from .advanced import _cfg_advanced_flows_and_extensions as _cfg_advanced_flows_and_extensions
from .advanced import _cfg_advanced_governance_monitors as _cfg_advanced_governance_monitors
from .advanced import _cfg_advanced_learning_governance as _cfg_advanced_learning_governance
from .advanced import _cfg_advanced_learning_opt_outs as _cfg_advanced_learning_opt_outs
from .advanced import _cfg_advanced_memory_and_immune as _cfg_advanced_memory_and_immune
from .advanced import _cfg_advanced_oidc as _cfg_advanced_oidc
from .advanced import _cfg_advanced_products as _cfg_advanced_products
from .advanced import _cfg_advanced_quotas_and_tenancy as _cfg_advanced_quotas_and_tenancy
from .advanced import _cfg_advanced_reflexion as _cfg_advanced_reflexion
from .advanced import _cfg_advanced_routing_and_answers as _cfg_advanced_routing_and_answers
from .advanced import (
    _cfg_advanced_running_tasks_and_images as _cfg_advanced_running_tasks_and_images,
)
from .advanced import _cfg_advanced_runtime_and_tools as _cfg_advanced_runtime_and_tools
from .advanced import _cfg_advanced_saml_and_sign_in as _cfg_advanced_saml_and_sign_in
from .advanced import _cfg_advanced_self_harness as _cfg_advanced_self_harness
from .advanced import _cfg_advanced_self_harness_options as _cfg_advanced_self_harness_options
from .advanced import _cfg_advanced_trust_and_audit as _cfg_advanced_trust_and_audit
from .advanced import (
    _cfg_advanced_verification_and_rewards as _cfg_advanced_verification_and_rewards,
)
from .advanced import _collect_group_pairs as _collect_group_pairs
from .advanced import (
    _drop_self_connect_without_connections as _drop_self_connect_without_connections,
)
from .advanced import _employee_activation_job_choices as _employee_activation_job_choices
from .advanced import _local_first_model as _local_first_model
from .advanced import _pick_action_recipe_lineage as _pick_action_recipe_lineage
from .advanced import _pick_agent_budget_reporting as _pick_agent_budget_reporting
from .advanced import _pick_codebase as _pick_codebase
from .advanced import _pick_data_protection_toggles as _pick_data_protection_toggles
from .advanced import _pick_device_pairing as _pick_device_pairing
from .advanced import _pick_enterprise_toggles as _pick_enterprise_toggles
from .advanced import _pick_feature_allowances as _pick_feature_allowances
from .advanced import _pick_governance_monitor_toggles as _pick_governance_monitor_toggles
from .advanced import _pick_ifc as _pick_ifc
from .advanced import _pick_image_edit_models as _pick_image_edit_models
from .advanced import _pick_learning_lifecycle_toggles as _pick_learning_lifecycle_toggles
from .advanced import _pick_learning_toggles as _pick_learning_toggles
from .advanced import _pick_memory_and_product_toggles as _pick_memory_and_product_toggles
from .advanced import _pick_runtime_toggles as _pick_runtime_toggles
from .advanced import _pick_swarm_scale as _pick_swarm_scale
from .advanced import _pick_workflow_and_extension_toggles as _pick_workflow_and_extension_toggles
from .advanced import _pick_working_toggles as _pick_working_toggles
from .advanced import _prior_consent_salt as _prior_consent_salt
from .advanced import _regulatory_profile_choices as _regulatory_profile_choices
from .advanced import _spending_alert_at as _spending_alert_at
from .advanced import _split_csv as _split_csv
from .advanced import _typical_cost_min_runs as _typical_cost_min_runs
from .advanced import pick_advanced as pick_advanced
from .advanced import pick_department_access as pick_department_access
from .advanced import pick_governed_mcp_sidecar as pick_governed_mcp_sidecar
from .advanced import pick_oidc as pick_oidc
from .advanced import pick_sign_in_security as pick_sign_in_security
from .assessments import _cfg_assessments as _cfg_assessments
from .assessments import _ConsentChoices as _ConsentChoices
from .assessments import _pick_consent_destinations as _pick_consent_destinations
from .assessments import _pick_consent_native_sdk as _pick_consent_native_sdk
from .assessments import _pick_consent_preferences as _pick_consent_preferences
from .assessments import _pick_data_use_governance as _pick_data_use_governance
from .assessments import _pick_notice_publication_binding as _pick_notice_publication_binding
from .assessments import _pick_paper_review_and_graph as _pick_paper_review_and_graph
from .assessments import _pick_privacy_automation as _pick_privacy_automation
from .assessments import _pick_privacy_discovery as _pick_privacy_discovery
from .assessments import (
    _pick_privacy_rights_source_adapters as _pick_privacy_rights_source_adapters,
)
from .assessments import pick_assessments as pick_assessments
from .security_suite import _cfg_governed_records as _cfg_governed_records
from .security_suite import _cfg_security_suite as _cfg_security_suite
from .security_suite import _pick_evidence_local_parsers as _pick_evidence_local_parsers
from .security_suite import _vendor_setup_guidance as _vendor_setup_guidance
from .security_suite import pick_security_suite as pick_security_suite


def _resolve_config_paths() -> tuple[Path, Path, Path]:
    """Resolve exactly the paths used by :mod:`maverick.config`.

    The previous import-time ``Path.home() / '.maverick'`` ignored the
    documented home/config overrides.  The standalone installer imports before
    the core mirrors LIGHTWORK_* to MAVERICK_*, so apply that same precedence
    here rather than writing into an unrelated home.  The wizard
    could therefore overwrite the real user config and then smoke-test a
    different, still-empty location.  Environment is fixed before a CLI
    process imports this module, so resolving once here keeps the existing
    monkeypatchable constants while aligning both sides of the handoff.
    """
    explicit = (
        os.environ["MAVERICK_CONFIG"]
        if "MAVERICK_CONFIG" in os.environ
        else os.environ.get("LIGHTWORK_CONFIG", "")
    ).strip()
    if explicit:
        config_file = Path(explicit).expanduser()
        config_dir = config_file.parent
    else:
        home = (
            os.environ["MAVERICK_HOME"]
            if "MAVERICK_HOME" in os.environ
            else os.environ.get("LIGHTWORK_HOME", "~/.maverick")
        )
        config_dir = Path(home).expanduser()
        config_file = config_dir / "config.toml"
    return config_dir, config_file, config_dir / ".env"


CONFIG_DIR, CONFIG_FILE, ENV_FILE = _resolve_config_paths()


def _pending_setup_path() -> Path:
    return CONFIG_FILE.with_name(f".{CONFIG_FILE.name}.lightwork-pending.json")


def _existing_setup() -> bool:
    """Fail closed when a saved file exists or its absence cannot be verified."""
    for path in (CONFIG_FILE, ENV_FILE, _pending_setup_path()):
        try:
            path.lstat()  # Includes dangling links; never follow one into a key file.
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return False


def _existing_setup_notice() -> None:
    if not CONFIG_FILE.exists() and ENV_FILE.exists():
        console.print(
            Panel.fit(
                "[bold yellow]Lightwork found saved keys but no completed setup.[/bold yellow]\n\n"
                "Your keys were left unchanged. Ask your Lightwork administrator or support "
                "to recover this installation.",
                border_style="yellow",
            )
        )
        return
    console.print(
        Panel.fit(
            "[bold yellow]Lightwork found saved setup files.[/bold yellow]\n\n"
            "This setup left your current choices and saved keys unchanged. "
            "Open Lightwork > Settings to change provider keys or task spending, "
            "or use All settings for other available controls. Some installation "
            "choices cannot be changed there yet.",
            border_style="yellow",
        )
    )


def _pending_setup_bodies() -> tuple[str, str | None] | None:
    """Read only a complete first-install receipt; never follow a link to keys."""
    path = _pending_setup_path()
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4_000_000:
        raise RuntimeError("Interrupted Lightwork setup needs assistance; saved files were not changed.")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(receipt, dict) or set(receipt) != {"version", "config", "env"}:
            raise ValueError("invalid setup receipt")
        config_body, env_body = receipt["config"], receipt["env"]
        if type(receipt["version"]) is not int or receipt["version"] != 1 or not isinstance(config_body, str):
            raise ValueError("invalid setup receipt")
        if env_body is not None and not isinstance(env_body, str):
            raise ValueError("invalid setup receipt")
        if len(config_body) + len(env_body or "") > 4_000_000:
            raise ValueError("oversized setup receipt")
        tomllib.loads(config_body)
        return config_body, env_body
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise RuntimeError("Interrupted Lightwork setup needs assistance; saved files were not changed.") from exc


def _resume_pending_setup_locked() -> bool:
    from maverick.file_lock import atomic_write_text

    bodies = _pending_setup_bodies()
    if bodies is None:
        return False
    config_body, env_body = bodies
    for path, body in ((CONFIG_FILE, config_body), (ENV_FILE, env_body)):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(metadata.st_mode) or body is None
                or not _wizard_file_unchanged(path, body.encode("utf-8"))):
            raise RuntimeError("Interrupted Lightwork setup needs assistance; saved files were not changed.")
    if env_body is not None and not ENV_FILE.exists():
        atomic_write_text(ENV_FILE, env_body, mode=0o600)
    if not CONFIG_FILE.exists():
        atomic_write_text(CONFIG_FILE, config_body, mode=0o600)
    _pending_setup_path().unlink()
    return True


def recover_pending_setup() -> bool:
    """Complete an approved first install after a crash, with no new answers."""
    from maverick.file_lock import cross_process_lock

    with cross_process_lock(CONFIG_FILE, strict=True):
        return _resume_pending_setup_locked()


def _first_setup_guard() -> int | None:
    try:
        if recover_pending_setup():
            console.print("[green]Lightwork finished the interrupted setup.[/green]")
            return 0
    except (OSError, RuntimeError):
        console.print("[red]Interrupted Lightwork setup needs assistance; saved files were not changed.[/red]")
        return 1
    if _existing_setup():
        _existing_setup_notice()
        return 1
    return None


console = Console()


# Channel catalog: (id, label, env_vars_needed)
CHANNELS: list[tuple[str, str, list[str]]] = [
    ("telegram", "Telegram bot (free, easiest)", ["TELEGRAM_BOT_TOKEN"]),
    ("discord", "Discord bot (Gateway WS)", ["DISCORD_BOT_TOKEN"]),
    ("slack", "Slack (Socket Mode)", ["SLACK_APP_TOKEN", "SLACK_BOT_TOKEN"]),
    ("teams", "Microsoft Teams (Azure Bot, needs a public HTTPS address)",
     ["TEAMS_APP_ID", "TEAMS_APP_PASSWORD"]),
    ("signal", "Signal (via signal-cli)", []),
    ("email", "Email (IMAP/SMTP, stdlib only)", ["EMAIL_USER", "EMAIL_APP_PASSWORD"]),
    ("matrix", "Matrix (federated)", ["MATRIX_ACCESS_TOKEN"]),
    ("bluesky", "Bluesky (AT Protocol)", ["BLUESKY_HANDLE", "BLUESKY_PASSWORD"]),
    ("mastodon", "Mastodon (any instance)", ["MASTODON_ACCESS_TOKEN"]),
    ("irc", "IRC (channels + DMs)", []),
    # Voice API key is provider-specific (VAPI/RETELL/BLAND), resolved in the
    # voice block below; only the webhook token is static here.
    ("voice", "Voice (Vapi/Retell/Bland)", ["VAPI_WEBHOOK_TOKEN"]),
    ("whatsapp", "WhatsApp (Twilio, needs webhook)", ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]),
    (
        "whatsapp_cloud",
        "WhatsApp (Meta Cloud API, needs webhook)",
        [
            "WHATSAPP_CLOUD_ACCESS_TOKEN",
            "WHATSAPP_CLOUD_PHONE_NUMBER_ID",
            "WHATSAPP_CLOUD_VERIFY_TOKEN",
            "WHATSAPP_CLOUD_APP_SECRET",
        ],
    ),
    ("sms", "SMS (Twilio, needs webhook)", ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]),
    ("imessage", "iMessage (macOS only)", []),
    ("threads", "Threads (Meta, polling)", ["THREADS_ACCESS_TOKEN", "THREADS_USER_ID"]),
    (
        "rcs",
        "RCS (Google RBM, approved agents only)",
        ["RCS_AGENT_ID", "RCS_SERVICE_ACCOUNT_JSON", "RCS_WEBHOOK_TOKEN"],
    ),
]


# Channels that are scaffolds: they ship runtime code but can't work
# end-to-end from a default install — whatsapp/sms need a Twilio account
# plus a public webhook (maverick_channels documents both as "scaffold"),
# and imessage is macOS-only and needs Full Disk Access. Offering them in
# the default checkbox is dishonest: users pick them, then hit a dead end.
# Gate them behind an explicit opt-in (see pick_channels).
EXPERIMENTAL_CHANNELS: set[str] = {
    "whatsapp",
    "whatsapp_cloud",
    "sms",
    "imessage",
    "threads",
    "rcs",
}


# Ordered advanced-flow steps, mirroring the pick_* sequence in run().
# Purely a progress-bar aid: changing this list never changes the config.
STEPS: list[tuple[str, str]] = [
    ("deployment", "Deployment"),
    ("providers", "Providers"),
    ("role_models", "Models"),
    ("channels", "Channels"),
    ("safety", "Safety"),
    ("signed_skills", "Signed skills"),
    ("budget", "Budget"),
    ("approvals", "Approvals"),
    ("sandbox", "Sandbox"),
    ("research_execution", "Research lab"),
    ("candidate_promotion", "Candidate promotion"),
    ("knowledge_access", "Governed knowledge"),
    ("capabilities", "Capabilities"),
    ("self_learning", "Self-learning"),
    ("ekko", "Ekko work discovery"),
    ("automation_import", "Automation import"),
    ("event_triggers", "Event triggers"),
    ("flows", "Flow engine"),
    ("knowledge", "Knowledge RAG"),
    ("oauth_vault", "OAuth token vault"),
    ("governed_connectors", "Governed connectors"),
    ("durable", "Durable execution"),
    ("journal", "Workspace journal"),
    ("finance", "Finance suite"),
    ("value", "Savings assumptions"),
    ("intent_value", "Intent, work value and opportunities"),
    ("assessments", "Assessment assists"),
    ("security_suite", "Security & GRC"),
    ("monitoring", "Monitoring and key management"),
    ("advanced", "Advanced reasoning"),
    ("api_keys", "API access"),
    ("web_search", "Web search"),
    ("mcp_servers", "MCP servers"),
    ("plugins", "Plugins"),
    ("tool_acl", "Tool ACL"),
    ("rate_limits", "Rate limits"),
    ("retention", "Retention"),
    ("analytics", "Analytics"),
    ("persona", "Persona"),
    ("notifications", "Notifications"),
    ("deadline_alerts", "Deadline alerts"),
    ("daily_summary", "Daily summary and chat approvals"),
    ("webhooks", "Webhooks"),
    ("a2a", "A2A"),
]


def _step_indicator(index: int, *, done: list[str] | None = None) -> str:
    """Format the ``Step N/M`` progress line for the ``index``-th step
    (1-based), optionally trailed by a breadcrumb of completed labels.

    Returns plain text (no Rich markup): styling is applied by the caller
    via ``console.print(..., style=...)`` so the literal "Step N/M" text
    stays contiguous in rendered output instead of being fragmented by
    inline ANSI codes. Defined as a pure helper so tests can assert the
    formatting without driving the whole wizard.
    """
    total = len(STEPS)
    label = STEPS[index - 1][1] if 1 <= index <= total else ""
    line = f"Step {index}/{total} {label}"
    if done:
        line += f"  ({' > '.join(done)})"
    return line


def _prompt_positive_number(question: str, *, default: str, dollars: bool = False) -> float:
    """Keep a spending or duration answer explicit; never replace bad input."""
    while True:
        raw = _q_text(question, default=default).strip()
        if dollars and raw.startswith("$"):
            raw = raw[1:].strip()
        try:
            value = float(raw)
        except ValueError:
            value = float("nan")
        if math.isfinite(value) and value > 0:
            return value
        console.print("[yellow]Enter a number above zero (for example, $10).[/yellow]")


def _prompt_positive_dollars(question: str, *, default: str) -> float:
    return _prompt_positive_number(question, default=default, dollars=True)


def _prompt_positive_integer(question: str, *, default: str) -> int:
    while True:
        raw = _q_text(question, default=default).strip()
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if value > 0:
            return value
        console.print("[yellow]Enter a whole number above zero.[/yellow]")


# ---------- prompt primitives ----------


def _ask(question: Any) -> Any:
    """Run a questionary prompt, treating a ``None`` answer as an abort.

    questionary's ``.ask()`` returns ``None`` when the user presses
    Ctrl-C / Ctrl-D or when there's no interactive TTY (e.g. stdin is a
    pipe). Every call site then did ``.split()`` / ``.strip()`` on the
    result and crashed with an opaque ``AttributeError``. Convert that
    to ``KeyboardInterrupt`` so the entry point prints a clean "Aborted"
    message and exits 130 instead of dumping a traceback.
    """
    answer = question.ask()
    if answer is None:
        raise KeyboardInterrupt
    return answer


def _q_select(message: str, choices: list[str], default: str | None = None) -> str:
    if questionary is None:
        print(message)
        for i, c in enumerate(choices):
            marker = "*" if default == c else " "
            print(f"  {marker} {i + 1}) {c}")
        while True:
            choice = input("> ").strip()
            if not choice and default:
                return default
            if choice.isdigit() and 1 <= int(choice) <= len(choices):
                return choices[int(choice) - 1]
    return _ask(questionary.select(message, choices=choices, default=default))


def _q_text(message: str, default: str = "") -> str:
    if questionary is None:
        val = input(f"{message} [{default}]: ").strip()
        return val or default
    return _ask(questionary.text(message, default=default))


def _q_secret(message: str) -> str:
    if questionary is None:
        import getpass

        return getpass.getpass(f"{message}: ").strip()
    # Route through _ask so Ctrl-C / Ctrl-D / non-TTY (questionary returns
    # None) raises KeyboardInterrupt and aborts the wizard, like every other
    # prompt. The old `.ask() or ""` swallowed the abort into "", which
    # callers read as "skip this key" -- so Ctrl-C silently continued.
    return _ask(questionary.password(message)) or ""


def _q_checkbox(message: str, choices: list[str], default: list[str] | None = None) -> list[str]:
    if questionary is None:
        print(f"{message} (comma-separated numbers, blank = none)")
        for i, c in enumerate(choices):
            marker = "*" if default and c in default else " "
            print(f"  {marker} {i + 1}) {c}")
        raw = input("> ").strip()
        if not raw:
            return default or []
        picks = [c.strip() for c in raw.split(",")]
        return [choices[int(p) - 1] for p in picks if p.isdigit() and 1 <= int(p) <= len(choices)]
    # questionary.checkbox ignores `default` (it's documented "not used by
    # checkbox"). To actually pre-select the defaults, wrap them as
    # pre-checked Choice objects whose value is the title string -- so
    # callers still get back the same strings they passed in.
    default_set = set(default or [])
    q_choices: Any = (
        [questionary.Choice(c, checked=c in default_set) for c in choices]
        if default_set
        else choices
    )
    return _ask(questionary.checkbox(message, choices=q_choices))


def _q_confirm(message: str, default: bool = True) -> bool:
    if questionary is None:
        val = input(f"{message} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not val:
            return default
        return val.startswith("y")
    return _ask(questionary.confirm(message, default=default))


# ---------- preflight ----------


_FILE_WORK_RECOVERY = (
    "Start Docker or Podman, then open Lightwork > Permissions > Where work "
    "runs, choose its container, and select Allow file work."
)


def preflight() -> bool:
    """Check the environment before asking any questions.

    Returns True if all critical checks pass. Warnings are shown but
    don't block the wizard.
    """
    console.print("\n[dim]Checking your environment...[/dim]")
    all_ok = True

    # Python version
    if sys.version_info < (3, 11):
        console.print(f"[red]✗[/red] Python 3.11+ required (you have {sys.version.split()[0]})")
        all_ok = False
    else:
        console.print(f"[green]✓[/green] Python {sys.version.split()[0]}")

    # Config dir writable
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        test_file = CONFIG_DIR / ".write-test"
        test_file.write_text("ok")
        test_file.unlink()
        console.print(f"[green]✓[/green] {CONFIG_DIR} is writable")
    except (PermissionError, OSError) as e:
        console.print(f"[red]✗[/red] Can't write to {CONFIG_DIR}: {e}")
        all_ok = False

    # Docker availability determines whether the simple setup can safely
    # offer file changes and command execution in an isolated work area.
    if shutil.which("docker"):
        try:
            subprocess.run(
                ["docker", "version"],
                capture_output=True,
                timeout=5,
                check=True,
            )
            console.print("[green]✓[/green] Docker is running")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            console.print(
                "[yellow]![/yellow] Docker isn't running. Simple setup will keep "
                "file changes and program execution off until an isolated work area is available. "
                + _FILE_WORK_RECOVERY
            )
    else:
        console.print(
            "[yellow]![/yellow] Docker is not installed. Simple setup will keep "
            "file changes and program execution off until an isolated work area is available. "
            + _FILE_WORK_RECOVERY
        )

    return all_ok


# ---------- validators ----------


def _sdk_import_skip_message(name: str, exc: ImportError) -> str:
    """Say WHY validation is skipped. A corrupt install raises ImportError
    exactly like an absent package; reporting "not installed" while pip lists
    the package sent a user the wrong fix (field finding: the cure was
    --force-reinstall). Only a ModuleNotFoundError for the package itself is
    "not installed"."""
    if isinstance(exc, ModuleNotFoundError) and exc.name == name:
        return f"{name} SDK not installed -- skipping validation"
    return (
        f"{name} SDK failed to import ({exc}) -- skipping validation; "
        f"try: pip install --force-reinstall {name}"
    )


def _arm_validation_egress() -> str | None:
    """Arm the process egress boundary before importing a provider SDK.

    The installer can be imported before :mod:`maverick`, so relying only on
    the core package's import side effect leaves credential probes dependent on
    import order. Return a non-sensitive reason instead of attempting an
    unguarded validation call when the boundary cannot be armed.
    """
    try:
        from maverick.egress_guard import install

        if install():
            return None
        return "guard did not report active"
    except Exception as exc:
        return type(exc).__name__


def _validate_anthropic_key(key: str) -> tuple[bool, str]:
    """Ping Anthropic with the key. Returns (ok, message).

    Skip the prefix check: Anthropic now ships admin keys, batch keys,
    and several legacy formats. The API ping handles whatever shape
    the key takes.
    """
    if not key.strip():
        return False, "empty key"
    if reason := _arm_validation_egress():
        return True, f"validation skipped: egress guard unavailable ({reason})"
    try:
        import anthropic
    except ImportError as e:
        return True, _sdk_import_skip_message("anthropic", e)
    try:
        # Credential validation is intentionally one-shot: a five-second
        # probe reports auth, while an outage remains a non-fatal skip.
        client = anthropic.Anthropic(api_key=key, timeout=5.0, max_retries=0)
        # Minimal call -- list available models is enough to verify auth.
        list(client.models.list(limit=1))
        return True, "validated"
    except anthropic.AuthenticationError:
        return False, "API rejected the key"
    except Exception as e:
        return True, f"validation skipped: {type(e).__name__}"


def _validate_openai_key(key: str) -> tuple[bool, str]:
    if not key.strip():
        return False, "empty key"
    # Azure OpenAI keys are 32-char hex with no prefix; OpenAI ships
    # sk-, sk-proj-, sk-svcacct-. Just ping the API and let it tell us.
    if reason := _arm_validation_egress():
        return True, f"validation skipped: egress guard unavailable ({reason})"
    try:
        from openai import AuthenticationError, OpenAI
    except ImportError as e:
        return True, _sdk_import_skip_message("openai", e)
    try:
        # Keep the interactive five-second credential probe to one attempt.
        client = OpenAI(api_key=key, timeout=5.0, max_retries=0)
        list(client.models.list().data[:1])
        return True, "validated"
    except AuthenticationError:
        return False, "API rejected the key"
    except Exception as e:
        return True, f"validation skipped: {type(e).__name__}"


def _validate_openai_compat_key(key: str, base_url: str, label: str) -> tuple[bool, str]:
    """For openai-compatible endpoints (Moonshot, DeepSeek, xAI, Gemini)."""
    if not key:
        return False, "empty key"
    if reason := _arm_validation_egress():
        return True, f"validation skipped: egress guard unavailable ({reason})"
    try:
        from openai import AuthenticationError, OpenAI
    except ImportError as e:
        return True, _sdk_import_skip_message("openai", e)
    try:
        # One bounded probe per endpoint keeps setup latency predictable.
        client = OpenAI(
            api_key=key,
            base_url=base_url,
            timeout=5.0,
            max_retries=0,
        )
        list(client.models.list().data[:1])
        return True, f"validated against {label}"
    except AuthenticationError:
        return False, f"{label} rejected the key"
    except Exception as e:
        # Network / route errors are non-fatal -- saving still useful.
        return True, f"validation skipped: {type(e).__name__}"


def _validate_moonshot_key(key: str) -> tuple[bool, str]:
    return _validate_openai_compat_key(
        key,
        "https://api.moonshot.ai/v1",
        "Moonshot",
    )


def _validate_deepseek_key(key: str) -> tuple[bool, str]:
    return _validate_openai_compat_key(
        key,
        "https://api.deepseek.com/v1",
        "DeepSeek",
    )


def _validate_xai_key(key: str) -> tuple[bool, str]:
    return _validate_openai_compat_key(
        key,
        "https://api.x.ai/v1",
        "xAI",
    )


def _validate_gemini_key(key: str) -> tuple[bool, str]:
    return _validate_openai_compat_key(
        key,
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "Gemini",
    )


def _validation_marker(ok: bool, msg: str) -> str:
    """Status marker for a key-validation result. A SKIPPED check (SDK missing /
    couldn't reach the API) is NOT a confirmed key -- render it distinctly so a
    green "ok" never appears next to "validation skipped"."""
    if not ok:
        return "[red]x[/red]"
    if "skipped" in msg.lower():
        return "[yellow]?[/yellow]"
    return "[green]ok[/green]"


_VALIDATORS = {
    "ANTHROPIC_API_KEY": _validate_anthropic_key,
    "OPENAI_API_KEY": _validate_openai_key,
    "MOONSHOT_API_KEY": _validate_moonshot_key,
    "DEEPSEEK_API_KEY": _validate_deepseek_key,
    "XAI_API_KEY": _validate_xai_key,
    "GEMINI_API_KEY": _validate_gemini_key,
    # Channel tokens validated when 'maverick serve' starts (less time-critical).
}


# ---------- validation cache ----------

VALIDATION_CACHE_PATH = CONFIG_DIR / "validation-cache.json"
_VALIDATION_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def _key_fingerprint(env_name: str, key: str) -> str:
    import hashlib

    digest = hashlib.sha256(f"{env_name}\x00{key}".encode()).hexdigest()
    return digest[:32]


def _load_validation_cache() -> dict[str, Any]:
    try:
        import json as _json

        return _json.loads(VALIDATION_CACHE_PATH.read_text())
    except (OSError, ValueError):
        return {}


def _save_validation_cache(cache: dict[str, Any]) -> None:
    import json as _json

    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        VALIDATION_CACHE_PATH.write_text(_json.dumps(cache, default=str))
        try:
            os.chmod(VALIDATION_CACHE_PATH, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _cached_validation(env_name: str, key: str) -> tuple[bool, str] | None:
    """Return cached (ok, msg) if the same key was validated within the TTL."""
    import time as _time

    if not key.strip():
        return None
    cache = _load_validation_cache()
    fp = _key_fingerprint(env_name, key)
    entry = cache.get(fp)
    if not entry:
        return None
    ts = float(entry.get("ts", 0))
    if (_time.time() - ts) > _VALIDATION_TTL_SECONDS:
        return None
    return bool(entry.get("ok", False)), str(entry.get("msg", "cached"))


def _remember_validation(env_name: str, key: str, ok: bool, msg: str) -> None:
    import time as _time

    if not key.strip():
        return
    cache = _load_validation_cache()
    cache[_key_fingerprint(env_name, key)] = {
        "ts": _time.time(),
        "ok": ok,
        "msg": msg,
    }
    _save_validation_cache(cache)


# ---------- error UI ----------


def show_bad_key_error(env_name: str, msg: str) -> None:
    """Error screen: the provider rejected the key."""
    console.print()
    console.print(
        Panel.fit(
            f"[bold]That {env_name.split('_')[0].title()} key didn't work.[/bold]\n\n"
            f"{msg}\n\n"
            "Common causes:\n"
            "  1. Typo (the secret is long; copy/paste, don't retype).\n"
            "  2. The key was deleted from your account.\n"
            "  3. Billing isn't set up on the provider.",
            border_style="red",
        )
    )


def show_network_error(provider: str, exception_type: str) -> None:
    """Error screen: the validator couldn't reach the provider."""
    console.print()
    console.print(
        Panel.fit(
            f"[bold]Couldn't reach {provider} to check the key ({exception_type}).[/bold]\n\n"
            "Usually a network block or proxy. Your key is saved either way;\n"
            "if it's wrong the first goal you run will say so.",
            border_style="yellow",
        )
    )


def show_install_failure(exc: BaseException) -> None:
    """Error screen: catch-all for unexpected setup failures."""
    console.print()
    console.print(
        Panel.fit(
            "[bold]Setup hit a problem and stopped.[/bold]\n\n"
            f"{type(exc).__name__}: {exc}\n\n"
            "Nothing was changed. Try again, or report the issue with the\n"
            "diagnostic output of [bold]maverick doctor[/bold].",
            border_style="red",
        )
    )


# ---------- wizard steps ----------


def welcome() -> None:
    console.print(
        Panel.fit(
            "[bold]Lightwork installer[/bold]\n\n"
            "Next you'll pick a setup mode: a quick consumer flow (a few\n"
            "questions, safe defaults) or advanced (configure every model,\n"
            "channel, safety level, and budget). After setup, use Lightwork\n"
            "Settings for supported changes.\n\n"
            f"Setup will be saved at {CONFIG_FILE}.",
            border_style="cyan",
        )
    )


def pick_deployment() -> str:
    choices = [
        "desktop  - This computer (recommended for first-time users)",
        "docker   - Local Docker container (isolated, easy to remove)",
        "vps      - Remote server you own (always-on)",
        "phone    - Phone companion (Lightwork runs on desktop/VPS; phone is a frontend)",
    ]
    # Preview the previously recorded target when this step is called directly;
    # the setup entry points will not replace an existing installation.
    default = None
    try:
        from maverick.config import get_deployment

        prior = get_deployment().get("type", "")
        default = next((c for c in choices if c.split()[0] == prior), None)
    except Exception:  # pragma: no cover -- never block the wizard
        default = None
    pick = _q_select("Where will Lightwork run?", choices, default=default)
    return pick.split()[0]


def pick_providers() -> list[str]:
    choices = []
    for prov_id, info in catalog.PROVIDERS.items():
        tag = "[ready]" if info["status"] == "ready" else "[v0.2]"
        choices.append(f"{prov_id:10} {tag} - {info['label']}")

    picks = _q_checkbox(
        "Which AI providers do you want to use?",
        choices,
        default=[choices[0]],
    )
    return [p.split()[0] for p in picks]


def pick_bedrock_auth() -> dict[str, Any]:
    """How Lightwork authenticates to AWS Bedrock; written to
    ``[providers.bedrock]``. IAM is the standard enterprise path
    (instance/task role, profile, or env keys) and needs no bearer token."""
    console.print(
        "[dim]Bedrock can sign requests with your AWS IAM credentials -- an "
        "instance or task role, an AWS profile, or AWS_ACCESS_KEY_ID/"
        "AWS_SECRET_ACCESS_KEY (the standard enterprise path; needs the "
        "bedrock extra: boto3) -- or send a Bedrock bearer token.[/dim]"
    )
    pick = _q_select(
        "  How should Lightwork authenticate to Bedrock?",
        [
            "iam     - AWS IAM credentials / role (SigV4, recommended)",
            "api_key - Bedrock bearer token in BEDROCK_API_KEY",
        ],
        default="iam     - AWS IAM credentials / role (SigV4, recommended)",
    )
    return {"auth_mode": pick.split()[0]}


def pick_vertex() -> dict[str, Any]:
    """Where Lightwork reaches Claude on Google Cloud Vertex AI; written to
    ``[providers.vertex]``. Google sign-in (Application Default Credentials)
    replaces a key, so the step asks for the project, the region and the model
    ID exactly as shown in the Vertex AI Model Garden."""
    console.print(
        "[dim]Vertex AI signs in with Google Cloud credentials -- a service account, "
        "gcloud login, or workload identity (Application Default Credentials). No API "
        "key is stored. It needs the vertex extra: google-auth.[/dim]"
    )
    project_default = (os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
                       or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip())
    while True:
        project = _q_text("  Google Cloud project ID", default=project_default).strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:_-]{0,127}", project):
            break
        console.print("[yellow]Enter the Google Cloud project ID.[/yellow]")
    while True:
        region = _q_text("  Vertex AI region (for example us-east5)",
                         default=os.environ.get("CLOUD_ML_REGION", "").strip()).strip()
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", region):
            break
        console.print("[yellow]Enter a lowercase Vertex AI region such as us-east5.[/yellow]")
    while True:
        model_id = _q_text("  Claude model ID, exactly as shown in the Vertex AI Model Garden",
                           default="").strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}@[A-Za-z0-9][A-Za-z0-9._-]{0,63}", model_id):
            break
        console.print("[yellow]Enter the model ID as shown in the Model Garden, for example claude-haiku-4-5@20251001.[/yellow]")
    return {"project_id": project, "region": region, "model_id": model_id}


def pick_per_tenant_keys() -> bool:
    """Offer per-tenant BYOK provider keys (multi-tenant deployments only).

    Off by default -- the whole install shares the deployment-global provider
    key. When on, an active tenant that opted in (``maverick`` sets the tenant's
    ``byok`` flag) runs on ITS OWN key, resolved from the secret provider under a
    tenant-scoped name; a tenant with no key configured falls back to the global
    key. The key bytes are never stored in config."""
    return _q_confirm(
        "Let individual tenants bring their own provider API key (BYOK)? "
        "Off = every tenant shares the deployment key.",
        default=False,
    )


def pick_models_per_role(providers: list[str],
                         provider_options: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    console.print()
    if _q_confirm(
        "Use the default model for each role?",
        default=True,
    ):
        return {}

    console.print()
    console.print(
        "[bold]Pick a model for each agent role.[/bold] "
        "Large models (orchestrator, revisor) suit big roles; "
        "cheap roles (summarizer) can use smaller ones.\n"
    )

    role_models: dict[str, str] = {}
    for role, hint in catalog.ROLES:
        choices: list[str] = []
        for prov in providers:
            info = catalog.PROVIDERS.get(prov)
            if not info:
                continue
            tag = "" if info["status"] == "ready" else " [v0.2]"
            models = info["models"]
            typed = str(((provider_options or {}).get(prov) or {}).get("model_id") or "").strip()
            if prov == "vertex" and typed:
                models = [{"id": typed, "notes": "Claude on Vertex AI, the model ID you entered"}]
            for m in models:
                choices.append(f"{prov}:{m['id']}{tag}  - {m['notes']}")
        choices.append("[skip - use default]")

        default_spec = catalog.default_for_role(role)
        default_choice = next((c for c in choices if c.startswith(default_spec)), choices[0])

        pick = _q_select(f"  {role}: {hint}", choices, default=default_choice)
        if pick.startswith("[skip"):
            continue
        role_models[role] = pick.split()[0]
    return role_models


# Inbound channels enforce a sender allowlist (fail-closed): only these
# IDs can drive the agent and spend budget. The wizard must collect it or
# the channel refuses to start. See maverick_channels.base.is_allowed.
_ALLOWLIST_CHANNELS = {
    "telegram",
    "discord",
    "slack",
    "teams",
    "signal",
    "email",
    "matrix",
    "bluesky",
    "mastodon",
    "irc",
    "imessage",
    "sms",
    "whatsapp",
    "whatsapp_cloud",
    "threads",
    "rcs",
}
_ALLOWLIST_HINT = {
    "telegram": "numeric Telegram user IDs",
    "discord": "numeric Discord user IDs",
    "slack": "Slack user IDs, e.g. U01ABC",
    "teams": "Microsoft Entra object IDs of the people allowed, e.g. 12345678-abcd-abcd-abcd-1234567890ab",
    "signal": "phone numbers, e.g. +12345550199",
    "email": "email addresses",
    "matrix": "MXIDs, e.g. @you:matrix.org",
    "bluesky": "handles or DIDs",
    "mastodon": "acct names, e.g. you@instance",
    "irc": "authenticated IRC account names (requires IRCv3 account-tag)",
    "imessage": "phone numbers or emails",
    "sms": "phone numbers, e.g. +14155551234",
    "whatsapp": "senders as Twilio sends them, e.g. whatsapp:+14155551234",
    "whatsapp_cloud": "bare wa_id digits, e.g. 14155551234",
    "threads": "Threads usernames of allowed authors",
    "rcs": "E.164 MSISDNs, e.g. +14155551234",
}


def _channel_base_cfg(ch_id: str, envs: set[str]) -> dict[str, Any]:
    """Build the channel-specific config for ``ch_id`` (excluding allowlists).

    May add provider-specific env vars to ``envs`` (e.g. voice keys).
    """
    cfg: dict[str, Any] = {"enabled": True}

    if ch_id == "telegram":
        cfg["bot_token"] = "${TELEGRAM_BOT_TOKEN}"
    elif ch_id == "discord":
        cfg["bot_token"] = "${DISCORD_BOT_TOKEN}"
    elif ch_id == "slack":
        cfg["app_token"] = "${SLACK_APP_TOKEN}"
        cfg["bot_token"] = "${SLACK_BOT_TOKEN}"
    elif ch_id == "teams":
        cfg["app_id"] = "${TEAMS_APP_ID}"
        cfg["app_password"] = "${TEAMS_APP_PASSWORD}"
        cfg["tenant_id"] = _q_text(
            "  Microsoft Entra tenant ID (blank only for a multi-tenant app registration)",
            default="",
        ).strip()
        cfg["port"] = _safe_int(_q_text("  Webhook port (forward /webhook/teams here)", default="8771"),
                                default=8771)
        cfg["approvals_enabled"] = _q_confirm(
            "  Let linked approvers decide approval requests from Teams cards?", default=False,
        )
        console.print(
            "  [dim]Register the bot in Azure and point its messaging endpoint at "
            "https://<your address>/webhook/teams. Steps: docs/channels/teams.md[/dim]"
        )
    elif ch_id == "signal":
        cfg["phone_number"] = _q_text("  Signal phone number (e.g., +12345550199)", default="")
    elif ch_id == "email":
        from maverick.mail_auth import valid_trusted_mail_server

        cfg["imap_host"] = _q_text("  IMAP server", default="imap.gmail.com")
        cfg["smtp_host"] = _q_text("  SMTP server", default="smtp.gmail.com")
        cfg["smtp_port"] = _safe_int(_q_text("  SMTP port", default="465"), default=465)
        trusted_server = _q_text(
            "  Server that checks incoming senders (ask your mail administrator; blank leaves Email off)",
            default="",
        ).strip()
        if valid_trusted_mail_server(trusted_server):
            cfg["trusted_authserv_id"] = trusted_server.lower()
        else:
            cfg["enabled"] = False
            console.print("  [yellow]Email stays off until you set the incoming sender-check server on the Channels page.[/yellow]")
        cfg["imap_user"] = "${EMAIL_USER}"
        cfg["imap_password"] = "${EMAIL_APP_PASSWORD}"
        cfg["smtp_user"] = "${EMAIL_USER}"
        cfg["smtp_password"] = "${EMAIL_APP_PASSWORD}"
        cfg["poll_interval"] = 30
    elif ch_id == "matrix":
        cfg["homeserver"] = _q_text("  Matrix homeserver URL", default="https://matrix.org")
        cfg["user_id"] = _q_text("  Matrix user ID (e.g., @you:matrix.org)", default="")
        cfg["access_token"] = "${MATRIX_ACCESS_TOKEN}"
    elif ch_id == "bluesky":
        cfg["handle"] = "${BLUESKY_HANDLE}"
        cfg["password"] = "${BLUESKY_PASSWORD}"
        cfg["poll_interval"] = 60
    elif ch_id == "mastodon":
        cfg["instance"] = _q_text(
            "  Mastodon instance URL",
            default="https://mastodon.social",
        )
        cfg["access_token"] = "${MASTODON_ACCESS_TOKEN}"
        cfg["poll_interval"] = 30
    elif ch_id == "voice":
        provider = (
            _q_text(
                "  Phone service (vapi or retell for conversations; bland for outgoing calls only)",
                default="vapi",
            )
            .strip()
            .lower()
            or "vapi"
        )
        cfg["provider"] = provider
        key_env = {
            "vapi": "VAPI_API_KEY",
            "retell": "RETELL_API_KEY",
            "bland": "BLAND_API_KEY",
        }.get(provider, "VAPI_API_KEY")
        # Collect the provider-specific key so the wizard actually prompts
        # for it; otherwise a retell/bland config references ${RETELL_API_KEY}
        # / ${BLAND_API_KEY} that the user was never asked to enter.
        envs.add(key_env)
        cfg["api_key"] = "${" + key_env + "}"
        # Existing installation secret name; both supported services use the
        # same explicitly configured private Bearer check key.
        cfg["webhook_token"] = "${VAPI_WEBHOOK_TOKEN}"
        cfg["phone_number"] = _q_text(
            "  Phone number (starts with + and the country code, optional)",
            default="",
        )
        cfg["assistant_id"] = _q_text(
            "  Saved assistant ID from Vapi, or saved agent ID from Retell",
            default="",
        )
        cfg["port"] = _safe_int(
            _q_text("  Webhook port", default="8770"),
            default=8770,
        )
        console.print("  Finish the provider's function form in Settings > All settings > Set up phone conversations. "
                      "The hosted Lightwork address receives supported requests; no transcript notification starts work. "
                      "A permitted number does not grant company sign-in or a role.")
    elif ch_id == "whatsapp":
        cfg["account_sid"] = "${TWILIO_ACCOUNT_SID}"
        cfg["auth_token"] = "${TWILIO_AUTH_TOKEN}"
        cfg["from_number"] = _q_text("  WhatsApp 'from' (e.g., whatsapp:+14155238886)", default="")
        cfg["port"] = _safe_int(_q_text("  Webhook port", default="8765"), default=8765)
    elif ch_id == "sms":
        cfg["account_sid"] = "${TWILIO_ACCOUNT_SID}"
        cfg["auth_token"] = "${TWILIO_AUTH_TOKEN}"
        cfg["from_number"] = _q_text("  SMS 'from' number (e.g., +14155551234)", default="")
        cfg["port"] = _safe_int(_q_text("  Webhook port", default="8766"), default=8766)
    elif ch_id == "imessage":
        cfg["poll_interval"] = 5

    return cfg


def _channel_allowlist(ch_id: str, cfg: dict[str, Any]) -> None:
    """Prompt for and apply per-channel sender allowlists in-place on ``cfg``."""
    if ch_id in _ALLOWLIST_CHANNELS:
        hint = _ALLOWLIST_HINT.get(ch_id, "sender IDs")
        raw_ids = _q_text(
            f"  Allowed senders, comma-separated ({hint}) — only these can drive the agent",
            default="",
        )
        ids = _csv_list(raw_ids)
        if ids:
            cfg["allowed_user_ids"] = ids
        else:
            env_name = (
                "IRC_ALLOWED_ACCOUNTS" if ch_id == "irc" else ch_id.upper() + "_ALLOWED_USER_IDS"
            )
            console.print(
                "  [yellow]No allowlist set — this channel will refuse "
                f"all senders until you set {env_name} "
                "or add allowed_user_ids to config.[/yellow]"
            )
    elif ch_id == "voice":
        raw = _q_text(
            "  Permitted caller numbers (+countrycode, comma-separated; blank refuses all callers)",
            default="",
        )
        callers = _csv_list(raw)
        if callers:
            cfg["allowed_callers"] = callers


def pick_channels(deployment: str) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Returns (channels_config, env_vars_needed)."""
    console.print()
    if deployment == "desktop":
        if not _q_confirm(
            "Enable any messaging channels (Telegram, Discord, Signal, etc.) for remote access?",
            default=False,
        ):
            return {}, set()
    elif deployment == "phone":
        console.print("[bold]Phone-companion mode:[/bold] pick the channels your phone will use.\n")

    selectable = [c for c in CHANNELS if c[0] not in EXPERIMENTAL_CHANNELS]
    if _q_confirm(
        "Show experimental/unfinished channels (WhatsApp, SMS, iMessage)? "
        "These are scaffolds and may not work end-to-end.",
        default=False,
    ):
        selectable += [
            (ch_id, f"{label} [experimental]", envs)
            for ch_id, label, envs in CHANNELS
            if ch_id in EXPERIMENTAL_CHANNELS
        ]

    choices = [f"{ch_id:9} - {label}" for ch_id, label, _ in selectable]
    picked = _q_checkbox("Which channels do you want to enable?", choices)
    picked_ids = [p.split()[0] for p in picked]

    channels: dict[str, dict[str, Any]] = {}
    envs: set[str] = set()

    for ch_id in picked_ids:
        info = next((c for c in CHANNELS if c[0] == ch_id), None)
        if info is None:
            continue
        envs.update(info[2])

        cfg = _channel_base_cfg(ch_id, envs)
        _channel_allowlist(ch_id, cfg)

        channels[ch_id] = cfg

    return channels, envs


def pick_safety() -> dict[str, Any]:
    pick = _q_select(
        "Safety profile:",
        [
            "strict     - Block on any medium+ threat. Best for sensitive use.",
            "balanced   - Block on high+ threats. Recommended default.",
            "permissive - Block only on critical threats. For research/experimentation.",
            "off        - No safety scanning. NOT recommended.",
        ],
        default="balanced   - Block on high+ threats. Recommended default.",
    )
    profile = pick.split()[0]
    threshold = {
        "strict": "medium",
        "balanced": "high",
        "permissive": "critical",
        "off": "critical",
    }[profile]
    # Agent compartments: when one agent's scan blocks a threat, record its
    # signature so the rest of the swarm is immune to the same attack for the
    # run. Moot with safety off (nothing scans). Off by default.
    compartments = False
    if profile != "off":
        compartments = _q_confirm(
            "  Enable agent compartments (one agent's blocked threat immunizes "
            "the rest of the swarm for the run)?",
            default=False,
        )
    # Task-start check (off by default): Lightwork reads each task's wording
    # and, if asked, holds risky-looking tasks until a person approves them.
    # Every action is still checked on its own either way.
    wait = _q_select(
        "Ask a person before starting tasks whose wording looks risky?",
        [
            "never  - Start tasks straight away (default).",
            "high   - Tasks that look high risk wait for a person.",
            "medium - Tasks that look medium or high risk wait for a person.",
        ],
        default="never  - Start tasks straight away (default).",
    ).split()[0]
    picked = {
        "profile": profile,
        "block_threshold": threshold,
        "scan_input": profile != "off",
        "scan_tool_calls": profile != "off",
        "scan_output": profile != "off",
        "compartments": compartments,
    }
    if wait in ("high", "medium"):
        picked["goal_risk_require_human"] = wait
    return picked


def pick_signed_skills() -> dict[str, Any]:
    """Optional Ed25519 signing policy for installed skills.

    Returns a dict written under ``[skills]``. Defaults keep current
    behavior (no trusted publishers, unsigned skills allowed)."""
    console.print()
    console.print(
        "[dim]Signed skills: a publisher can sign a SKILL.md with an Ed25519 "
        "key. Paste trusted publisher public keys (hex) to verify against; "
        "leave blank to skip.[/dim]"
    )
    raw = _q_text("  Trusted skill publisher pubkeys (comma-separated hex)", default="")
    trusted = _csv_list(raw)
    require = _q_confirm(
        "  Reject unsigned skills (only install signed + trusted ones)?",
        default=False,
    )
    require_catalog = _q_confirm(
        "  Require a verified signature for catalog installs (even with no trusted keys above)?",
        default=False,
    )
    return {
        "trusted_pubkeys": trusted,
        "require_signed": require,
        "require_signed_catalog": require_catalog,
    }


def pick_approvals() -> dict[str, Any]:
    """``[approval]``: the undo window, the high-risk confirmation and who
    approves a risky action the requester asked for.

    The Approvals page is the human-in-command loop: a decision can be undone
    for ``undo_grace_seconds`` (the agent waits that long before acting),
    approving a high or critical risk request needs an explicit confirmation,
    and ``separate_approver`` says whether someone other than the person who
    asked must approve it (default: whenever another approver is available).
    """
    console.print()
    console.print(
        "[dim]Risky actions wait on the Approvals page for a person for up to 30 "
        "minutes; after 10 minutes the people who can decide get one in-app "
        "reminder, and with no decision in time the action is refused. A decision "
        "can be undone for a short while; the agent only acts once that window "
        "has passed.[/dim]"
    )
    undo_seconds = _safe_int(
        _q_text("  Seconds a decision can be undone (0 = act at once)",
                default=str(INTEGER_SETTINGS["approval.undo_grace_seconds"].default)),
        default=INTEGER_SETTINGS["approval.undo_grace_seconds"].default,
    )
    require_ack = _q_confirm(
        "  Ask for an explicit confirmation before approving high or critical risk "
        "requests? (a ticked box for high, typing APPROVE for critical)",
        default=BOOLEAN_SETTINGS["approval.require_acknowledgement"].default,
    )
    separate = _q_select(
        "  Who approves a high or critical risk action someone asked for?",
        [
            "when_available - Someone else, whenever another approver is available (default).",
            "always         - Always someone else, even if the request then waits and expires.",
            "never          - The person who asked may approve it.",
        ],
        default=CHOICE_SETTINGS["approval.separate_approver"].default
        + " - Someone else, whenever another approver is available (default).",
    ).split()[0]
    record_checks = _q_confirm(
        "  Keep a record of each approval check (when, risk, kind of action, agent and "
        "outcome; never the content) so you can preview a threshold change later?",
        default=BOOLEAN_SETTINGS["approval.record_checks"].default,
    )
    retention = _safe_int(
        _q_text("  Days to keep that record", default=str(INTEGER_SETTINGS["approval.check_retention_days"].default)),
        default=INTEGER_SETTINGS["approval.check_retention_days"].default,
    ) if record_checks else INTEGER_SETTINGS["approval.check_retention_days"].default
    return {
        "undo_grace_seconds": max(INTEGER_SETTINGS["approval.undo_grace_seconds"].minimum,
                                   min(undo_seconds, INTEGER_SETTINGS["approval.undo_grace_seconds"].maximum)),
        "require_acknowledgement": bool(require_ack),
        "separate_approver": separate,
        "record_checks": bool(record_checks),
        "check_retention_days": max(INTEGER_SETTINGS["approval.check_retention_days"].minimum,
                                    min(retention, INTEGER_SETTINGS["approval.check_retention_days"].maximum)),
    }


def pick_budget() -> dict[str, Any]:
    console.print()
    console.print("[dim]Task limits are optional. Organization spending controls still apply.[/dim]")
    enabled = _q_confirm(
        "  Use task limits? Standard goals stop at $2 and 30 minutes; choose No for no task limit.",
        default=True,
    )
    budget: dict[str, Any] = {
        "max_dollars": _prompt_positive_dollars("  Max $ per run", default="2.0"),
        "max_wall_seconds": _prompt_positive_number(
            "  Max wall-clock seconds per run", default="1800"
        ),
        "max_tool_calls": _prompt_positive_integer("  Max tool calls per run", default="500"),
    } if enabled else {"task_limits_enabled": False}
    # Keep the safe default and explain the in-product recovery for a private
    # rate. The legacy estimate mode remains an explicit operator choice.
    budget["strict_pricing"] = _q_confirm(
        "  Require a reviewed price before paid AI work? Recommended. "
        "You can add your contract's spending ceiling in Settings after installation. "
        "Choose No only if you accept that dollar limits may be under-counted",
        default=BOOLEAN_SETTINGS["budget.strict_pricing"].default,
    )
    budget["guidance"] = _q_confirm(
        "  Show known budget headroom before work? This never changes execution limits.",
        default=BOOLEAN_SETTINGS["budget.guidance"].default)
    budget["warnings"] = _q_confirm(
        "  Show in-product warnings as tasks approach their limits?",
        default=BOOLEAN_SETTINGS["budget.warnings"].default)
    if budget["warnings"]:
        import math
        contract = NUMBER_LIST_SETTINGS["budget.warning_thresholds"]
        while True:
            raw_thresholds = _q_text("  Warning thresholds, as fractions of the limit",
                                     default=", ".join(str(value) for value in contract.default))
            try:
                values = [float(part.strip()) for part in raw_thresholds.split(",")]
                if not 1 <= len(values) <= contract.max_items or any(
                    not math.isfinite(value) or not contract.minimum_exclusive < value <= contract.maximum
                    for value in values
                ):
                    raise ValueError
            except (TypeError, ValueError):
                console.print("[yellow]Enter one to ten finite numbers above 0 and at most 1, separated by commas.[/yellow]")
                continue
            budget["warning_thresholds"] = sorted(set(values))
            break
    return budget


def pick_capabilities() -> dict[str, Any]:
    """Opt-in to high-impact tools that ship disabled.

    Computer-use, browser, ROS robotics, and code-exec tools have real safety
    side effects (mouse/keyboard control, arbitrary navigation, robot/simulator
    commands, or sandboxed tool orchestration), so they default to off until you
    explicitly enable them.
    """
    console.print()
    use_computer = _q_confirm(
        "Enable computer-use? Lets the agent see your screen and drive the mouse/keyboard.",
        default=False,
    )
    use_browser = _q_confirm(
        "Enable browser? Lets the agent navigate the web via Playwright.",
        default=False,
    )
    use_ros = _q_confirm(
        "Enable ROS robotics? Lets the agent publish topics or call services "
        "against ROS_BRIDGE_URL over rosbridge. Only enable for trusted robot/sim "
        "operators.",
        default=False,
    )
    use_code_exec = _q_confirm(
        "Enable code_exec? Lets the agent run a sandboxed Python script that "
        "orchestrates several tool calls in one turn (keeps large intermediate "
        "outputs out of context). Runs code in the sandbox, like the shell tool.",
        default=False,
    )
    # The embedded-device tool (JTAG/I2C) is always registered, but its
    # DESTRUCTIVE ops (flash write, target reset) stay refused until the
    # operator opts in here -> [embedded] allow_flash. Default off.
    embedded_flash = _q_confirm(
        "Allow embedded-device flashing? The JTAG tool can erase/reflash YOUR "
        "OWN connected device's firmware (OpenOCD). Off = it refuses flash/reset.",
        default=False,
    )
    deferred_tools = _q_confirm(
        "Use deferred tool loading? The model sees the core toolset and "
        "discovers the 400+ SaaS connectors on demand via find_tools -- "
        "cuts per-call token cost ~60%. Disable only if you want every "
        "connector schema offered on every turn.",
        default=True,
    )
    # [tools] exposure: what each request describes up front. The short list
    # is role-aware (about 30-40 tools; a specialist pack sees its own allow
    # list) and the rest is one find_tools call away; every tool means the
    # previous ~240-tool catalog (~47k tokens) on every turn.
    _exposure_short = "Show agents a short tool list and let them look up the rest (recommended)"
    _exposure_full = "Show every tool on every request (costs far more per task)"
    tool_exposure = "core" if _q_select(
        "How much of the tool list should each request to the AI describe?",
        [_exposure_short, _exposure_full], default=_exposure_short,
    ) == _exposure_short else "full"
    jd_hiring = _q_confirm(
        "Enable JD hiring in the Agent Factory? HR can upload a job "
        "description to match it against the specialist roster or draft a "
        "new specialist from it (drafts stay envelope-clamped and require "
        "human approval to save).",
        default=True,
    )
    require_passing_tests = pick_agent_publish_gate()
    agent_tests = pick_agent_test_rules()
    practice_mode = pick_practice_mode()
    practice_cap = pick_practice_spend_cap() if practice_mode else 1.0
    return {
        "computer_use": use_computer,
        "browser": use_browser,
        "ros": use_ros,
        "code_exec": use_code_exec,
        "embedded_flash": embedded_flash,
        "deferred_tools": deferred_tools,
        "tool_exposure": tool_exposure,
        "jd_hiring": jd_hiring,
        "require_passing_tests": require_passing_tests,
        **agent_tests,
        "practice_mode": practice_mode,
        "practice_daily_spend_cap": practice_cap,
    }


def pick_practice_mode() -> bool:
    """Offer practice mode. ON by default.

    People can switch to a separate practice workspace to try tasks,
    specialists and approvals; anything that would leave Lightwork is
    recorded instead of sent, and a marker shows on every screen. Written
    under ``[practice]`` as ``enable`` only when turned off.
    """
    return _q_confirm(
        "Offer practice mode? People can try tasks, specialists and approvals in "
        "a separate practice workspace where nothing is sent, paid or changed.",
        default=True,
    )


def pick_practice_spend_cap() -> float:
    """Daily practice spending cap per person, in dollars. 1.00 by default.

    AI answers in practice are real provider calls that cost real money; they
    are counted apart from real spending limits and capped by this amount
    (never more than a real limit that applies). Written under ``[practice]``
    as ``daily_spend_cap`` only when changed.
    """
    return _prompt_positive_dollars(
        "  Practice spending cap per person per day, in dollars (AI answers in practice "
        "still cost real money, counted apart from real spending limits)",
        default="1.00",
    )


def pick_agent_publish_gate() -> bool:
    """Agent Factory publish gate. ON by default.

    Changed instructions for an agent or specialist are published only after
    every saved test passes on exactly those instructions; publishing anyway
    needs a reason that goes to the activity record. Written under
    ``[agent_factory]`` as ``require_passing_tests`` only when turned off.
    """
    return _q_confirm(
        "Require passing tests before changed agent or specialist instructions "
        "are published? (Someone can still publish without them by giving a "
        "reason, which is recorded.)",
        default=True,
    )


def pick_agent_test_rules() -> dict[str, Any]:
    """Saved answer checks that gate publishing. The defaults keep today's behaviour.

    How many checks one specialist may keep (1 to 200, 20 by default); whether a
    brand-new specialist needs a passing full run before it is published; whether a
    second administrator must approve publishing without a passing run; and whether
    checks may test which tools a specialist calls (off by default). Also asks for the
    gradual-rollout share (``canary_percent``, 0 is off) and whether a trial version
    rolls back on its own. Written under
    ``[agent_tests]`` only when an answer differs from the default.
    """
    limit = _prompt_check_limit()
    new_needs_run = _q_confirm(
        "Require a passing run of every saved answer check before a brand-new specialist "
        "is published? (A reason does not skip this.)",
        default=BOOLEAN_SETTINGS["agent_tests.require_for_new_specialists"].default,
    )
    second_person = _q_confirm(
        "Should a second administrator approve publishing changed instructions without "
        "passing tests? (The person who asked cannot approve their own reason.)",
        default=BOOLEAN_SETTINGS["agent_tests.bypass_requires_second_person"].default,
    )
    tool_checks = _q_confirm(
        "Allow saved answer checks to test which tools a specialist calls? (Tools are "
        "replaced by test stubs that record the call and answer with a fixed result. "
        "No real tool, file, network call or shell command runs.)",
        default=BOOLEAN_SETTINGS["agent_tests.tool_checks"].default,
    )
    canary = _prompt_canary_percent()
    auto_rollback = bool(canary) and _q_confirm(
        "Roll a trial version back automatically when it fails clearly more often than the current "
        "version? (It needs at least 10 finished goals on the trial first.)",
        default=BOOLEAN_SETTINGS["agent_tests.canary_auto_rollback"].default,
    )
    return {"max_cases_per_specialist": limit, "require_for_new_specialists": new_needs_run,
            "bypass_requires_second_person": second_person, "tool_checks": tool_checks,
            "canary_percent": canary,
            "canary_auto_rollback": auto_rollback}


def _prompt_canary_percent() -> int:
    contract = INTEGER_SETTINGS["agent_tests.canary_percent"]
    while True:
        raw = _q_text(
            "When a changed specialist is published, what share of new goals should try it first? "
            "(0 publishes changes straight away; 1 to 50 is a trial share)",
            default=str(contract.default),
        ).strip()
        try:
            value = int(raw)
        except ValueError:
            value = -1
        if contract.minimum <= value <= contract.maximum:
            return value
        console.print("[yellow]Enter a whole number from 0 to 50.[/yellow]")


def _prompt_check_limit() -> int:
    contract = INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"]
    while True:
        raw = _q_text(
            "How many saved answer checks may one specialist keep? (1 to 200; 20 is the default)",
            default=str(contract.default),
        ).strip()
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if contract.minimum <= value <= contract.maximum:
            return value
        console.print("[yellow]Enter a whole number from 1 to 200.[/yellow]")


def pick_self_learning() -> dict[str, Any]:
    """Configure default-on governed capability learning.

    Catalog skills, API discovery, pack provisioning and local distillation are
    on by default. Generating executable tools remains a separate trust choice.
    Returns a dict written under ``[self_learning]``.

    MCP-server acquisition is a separate, even-higher-trust knob: it allows
    acquiring MCP servers, but only curated, hash-pinned catalog servers AND
    only after explicit operator approval. It ships OFF independently of the
    self-learning master switch.
    """
    console.print()
    console.print(
        "[dim]Self-learning lets the agent close capability gaps on its own: "
        "install skills, discover REST APIs, even write & run new tools. "
        "Governed learning is ON by default; executable tool generation and "
        "external MCP processes remain separate opt-ins.[/dim]"
    )
    enable = _q_confirm("Enable governed self-learning?", default=True)
    if not enable:
        return {"enable": False}
    create_tools = _q_confirm(
        "  Allow the agent to GENERATE and run new tools (full autonomy)?",
        default=False,
    )
    preflight = _q_confirm(
        "  Pre-acquire likely skills before each run (local catalog pass)?",
        default=True,
    )
    allow_provider_egress = _q_confirm(
        "  Allow learning helpers to make EXTRA model calls with redacted task "
        "or result text (may use another configured provider)?",
        default=False,
    )
    provision_packs = _q_confirm(
        "  Equip newly onboarded packs: install the catalog skills and "
        "synthesize the tools a pack's workflow needs, at approval time?",
        default=True,
    )
    console.print(
        "[dim]  MCP acquisition: the agent may PROPOSE adding a curated, "
        "hash-pinned catalog MCP server (never a free-text command). Each one "
        "still needs your explicit approval before it starts.[/dim]"
    )
    allow_mcp = _q_confirm(
        "  Allow agent to propose catalog MCP servers (operator-approved)?",
        default=False,
    )
    distill_local = _q_confirm(
        "  Distill successful runs into local skills? After a successful run, "
        "save a reusable skill under ~/.maverick/learned-skills.",
        default=True,
    )
    return {
        "enable": True,
        "preflight": preflight,
        "create_tools": create_tools,
        "provision_packs": provision_packs,
        "allow_mcp_acquisition": allow_mcp,
        "allow_provider_egress": allow_provider_egress,
        "distill_local": distill_local,
        "max_acquisitions": 5,
    }


_EKKO_BLOCKED_APPS = [
    "email",
    "outlook",
    "gmail",
    "chat",
    "teams",
    "slack",
    "crm",
    "salesforce",
    "erp",
    "sap",
    "database",
]


def pick_ekko() -> dict[str, Any]:
    """Configure explicit enrollment for the Ekko work-discovery sensor.

    The wizard never starts a collector or asks the operating system for
    monitoring permissions. It only writes policy; the client enrolls a named
    device and starts a reviewed collector separately with ``maverick ekko``.
    """
    console.print()
    console.print(
        "[dim]Ekko finds repeatable work that Lightwork could improve or "
        "automate. It records authorized application names and timing only by "
        "default -- never screen pixels, window titles, clipboard, keystrokes, "
        "URLs, or document contents. Data stays local and recommendations "
        "remain drafts until a person approves them.[/dim]"
    )
    if not _q_confirm(
        "Enable Ekko policy for explicitly enrolled devices?",
        default=False,
    ):
        return {"enable": False}

    requested_apps = _csv_list(
        _q_text(
            "  Canonical applications Ekko may observe (for example excel, "
            "powerpoint, chrome; blank = deny all)",
            default="",
        ),
        lower=True,
    )[:128]
    from maverick.work_discovery import KNOWN_APPS

    allowed_apps = [app for app in requested_apps if app in KNOWN_APPS]
    dropped_apps = sorted(set(requested_apps) - set(allowed_apps))
    if dropped_apps:
        console.print(
            "[yellow]  Ignored unknown application IDs: "
            + ", ".join(dropped_apps)
            + ". Platform collectors map executable/bundle IDs to the "
            "canonical names before capture.[/yellow]"
        )
    if not allowed_apps:
        console.print(
            "[yellow]  No applications authorized. Ekko remains unable to "
            "enroll or record until [ekko].allowed_apps is configured.[/yellow]"
        )
    capture_pick = _q_select(
        "  Capture mode",
        [
            "application_metadata - application identity + timing only",
            "guided - accept user/integration supplied action labels",
        ],
        default="application_metadata - application identity + timing only",
    )
    capture_level = capture_pick.split()[0]
    if capture_level not in {"application_metadata", "guided"}:
        capture_level = "application_metadata"

    retention_days = max(
        2,
        min(
            30,
            _safe_int(
                _q_text(
                    "  Raw event retention in days (2-30)",
                    default="14",
                ),
                default=14,
            ),
        ),
    )
    min_occurrences = max(
        2,
        min(
            100,
            _safe_int(
                _q_text(
                    "  Repetitions before Ekko suggests a process (2-100)",
                    default="3",
                ),
                default=3,
            ),
        ),
    )
    min_distinct_days = max(
        2,
        min(
            retention_days,
            _safe_int(
                _q_text(
                    "  Distinct days required for a suggestion (2-30)",
                    default="2",
                ),
                default=2,
            ),
        ),
    )
    return {
        "enable": True,
        "planning_enabled": _q_confirm(
            "  Allow people to save private opportunity plans and pilot results? "
            "These expire within the Ekko retention period; no recording or automation starts.",
            default=False,
        ),
        "build_enabled": _q_confirm(
            "  Allow Ekko to find business tasks and build private workflow drafts in batches? "
            "Drafts require review and publication before running.", default=False,
        ),
        "retention_days": retention_days,
        "enrollment_days": 30,
        "min_occurrences": min_occurrences,
        "min_distinct_days": min_distinct_days,
        "poll_interval_seconds": 5,
        "capture_level": capture_level,
        "allowed_apps": allowed_apps,
        "blocked_apps": list(_EKKO_BLOCKED_APPS),
        # Reserved for a future audited provider-summary path. Local discovery
        # has no egress implementation and this must remain false.
        "provider_egress": False,
    }


def pick_automation_import() -> dict[str, Any]:
    """Opt-in to importing clients' existing automations into Lightwork.

    Off by default. When on, ``maverick import`` can pull workflow definitions
    from platforms that expose them (n8n/Make/Workato/Power Automate/UiPath) and
    turn each into a Lightwork template, plus connect-and-trigger for Zapier/
    Notion. It reaches out to third-party platforms and writes user templates,
    so it ships disabled. Returns a dict written under ``[automation_import]``.
    """
    console.print()
    console.print(
        "[dim]Automation import pulls workflows your clients already built "
        "(n8n/Make/Workato/Power Automate/UiPath) into Lightwork templates, and "
        "lets Zapier/Notion trigger Lightwork. It calls third-party APIs and "
        "writes templates, so it's OFF by default.[/dim]"
    )
    enable = _q_confirm("Enable automation import?", default=BOOLEAN_SETTINGS["automation_import.enable"].default)
    if not enable:
        return {"enable": False}
    create_schedules = _q_confirm(
        "  Offer to recreate imported schedules (each reviewed after its draft is published)? "
        "(off = import the draft, then schedule it yourself in Automations)",
        default=BOOLEAN_SETTINGS["automation_import.create_schedules"].default,
    )
    return {"enable": True, "create_schedules": create_schedules}


def pick_event_triggers() -> dict[str, Any]:
    """Opt-in to polled event triggers ("when X appears, run this workflow").

    Off by default. When on, the dashboard can bind a workflow to an event
    source (e.g. a JSON REST feed or an RSS feed) and the app polls it on a
    background tick, firing the workflow per new item. It reaches out to
    third-party endpoints on a schedule, so it ships disabled. Returns a dict
    written under ``[event_triggers]``.
    """
    console.print()
    console.print(
        "[dim]Event triggers poll a source (a JSON API or RSS feed) and run a "
        "workflow for each new item -- the 'when a new lead/row/post appears' "
        "half of automation. The app polls on a background tick. It calls "
        "third-party endpoints on a schedule, so it's OFF by default.[/dim]"
    )
    enable = _q_confirm("Enable event triggers?", default=False)
    return {"enable": bool(enable)}


def pick_flows() -> dict[str, Any]:
    """Opt-in to the flow engine (multi-step visual workflows).

    Off by default. When on, the dashboard's visual designer can build and run
    flows -- a deterministic graph of agent/action/branch/loop/approval nodes,
    schedulable on a cron, with self-rewrite + rollback. When a flow pauses for
    approval it can post signed Approve/Reject links to a channel; those links
    need the dashboard's externally-reachable base URL, collected here and
    written as ``[flows] public_url``. Optionally lets the loop self-correct
    (``[flows] auto_evolve``). Returns a dict written under ``[flows]``.
    """
    console.print()
    console.print(
        "[dim]The flow engine runs multi-step visual workflows (agent + action + "
        "branch + loop + approval), schedulable on a cron, with self-rewrite and "
        "rollback. OFF by default.[/dim]"
    )
    if not _q_confirm("Enable the flow engine?", default=False):
        return {"enable": False}
    out: dict[str, Any] = {"enable": True}
    out["learned_operators"] = _q_confirm(
        "Enable bounded learned pure operators from reviewed examples? "
        "All retained expressions must agree; other inputs use the original agent.",
        default=False,
    )
    out["learned_operator_questions"] = _q_confirm(
        "Enable stored learned-operator review questions? "
        "Reviewed answers create drafts; nothing is automatically published.",
        default=False,
    )
    out["composed_operators"] = _q_confirm(
        "Enable bounded composed pure operators? "
        "Also requires learned operators; every retained expression must agree.",
        default=False,
    )
    out["action_recipes"] = _q_confirm(
        "Enable learning action sequences from reviewed examples? "
        "Generated flows retain approval gates and stop on ambiguous data bindings.",
        default=False,
    )
    out["action_recipe_transforms"] = _q_confirm(
        "Enable learned transformations in action arguments? "
        "Also requires action recipes and explicit data bounds; every retained expression must agree. "
        "Approvals remain required and uncertainty stops further actions.",
        default=False,
    )
    out["action_recipe_choices"] = _q_confirm(
        "Enable learned binary action choices after one shared action? "
        "Also requires action recipes and transformed arguments. Every retained guard must agree; "
        "the chosen terminal action needs approval, and uncertainty never repeats the shared action.",
        default=False,
    )
    out["action_recipe_teaching"] = _q_confirm(
        "Enable human teaching at a real completed action prefix? "
        "Requires action recipes, transformed arguments, choices and governed lineage. "
        "Both continuation arguments must agree; human choice and a separate action approval remain required. "
        "Teaching never repeats the shared action.",
        default=False,
    )
    out["action_episode_capture"] = _q_confirm(
        "Enable retaining workflow examples for learning? "
        "Each run needs enrollment, encrypted storage, an expiry and a separate human review. "
        "Older unsigned learned flows may stop until rebuilt from permitted signed examples.",
        default=False,
    )
    out["action_workflow_learning"] = _q_confirm(
        "Enable bounded workflow learning from signed reviewed executions? "
        "Requires action recipes, transformed arguments and governed lineage. "
        "Learns next actions and completion from observed history, up to eight actions; "
        "approvals remain required and ambiguity stops further work. "
        "Signed execution receipts are mandatory; execution refuses if signing or persistence is unavailable. "
        "This choice does not enable audit signing or other dependencies.",
        default=False,
    )
    out["action_workflow_memory_learning"] = _q_confirm(
        "Enable bounded integer history accumulator learning? "
        "Requires workflow learning, action recipes, transformed arguments and governed lineage. "
        "One fixed update program runs across each history; all consistent models must agree. "
        "Native approvals remain in force and ambiguity or resource exhaustion stops further work. "
        "Signed execution receipts are mandatory; execution refuses if signing or persistence is unavailable. "
        "This choice does not enable audit signing or other dependencies.",
        default=False,
    )
    out.update(_pick_action_recipe_lineage())
    from maverick.flow.ir import MAX_FLOW_NODE_RETRIES

    console.print(
        "[dim]Retries can recover temporary failures, but each attempt can spend "
        "money or repeat earlier changes. Choose the smallest number you need.[/dim]"
    )
    while True:
        try:
            retry_cap = int(_q_text(
                f"Retries for each workflow step (0–{MAX_FLOW_NODE_RETRIES}; zero turns retries off)",
                default="5",
            ).strip())
        except ValueError:
            retry_cap = -1
        if 0 <= retry_cap <= MAX_FLOW_NODE_RETRIES:
            out["max_node_retries"] = retry_cap
            break
        console.print(f"[yellow]Enter a whole number from 0 to {MAX_FLOW_NODE_RETRIES}.[/yellow]")
    console.print(
        "[dim]For actionable channel approvals (clickable Approve/Reject links), "
        "the dashboard needs its externally-reachable base URL. Leave blank to "
        "skip -- approvals then happen from the dashboard.[/dim]"
    )
    url = _q_text(
        "Public base URL for approval links (e.g. https://ops.acme.com)", default=""
    ).strip()
    if url:
        out["public_url"] = url
    console.print(
        "[dim]Self-correction lets a scheduled pass autonomously revert a node "
        "rewrite whose grounded outcomes measurably regressed -- the loop undoes "
        "its own bad changes. Off by default; surfaced proposals + human apply "
        "work without it.[/dim]"
    )
    if _q_confirm(
        "Let flows self-correct (autonomous revert of a regressed rewrite)?", default=False
    ):
        out["auto_evolve"] = True
        # Workflow suggestions always need a person's review, so the wizard
        # offers no automatic forward apply.
    return out


def pick_knowledge() -> dict[str, Any]:
    """Opt-in to per-domain vector RAG (the maverick-knowledge package).

    Off by default; the kernel never requires maverick-knowledge. When on,
    ``embedder`` selects the embedding provider (hosted Voyage / local /
    deterministic) and ``store`` selects SQLite/pgvector for ingestion or
    Qdrant for existing-corpus reads and erasure.
    Returns a dict written under ``[knowledge]``.
    """
    console.print()
    console.print(
        "[dim]Knowledge RAG gives the agent per-domain document recall via a "
        "vector store (the knowledge_search tool). Needs the maverick-knowledge "
        "package + an embedder. OFF by default.[/dim]"
    )
    if not _q_confirm("Enable per-domain knowledge RAG?", default=False):
        return {"enable": False}
    out: dict[str, Any] = {"enable": True}
    out["reindex_jobs"] = _q_confirm("Enable bounded search index rebuilds with review, progress and cancellation? Paid embedding requires verified cost admission.", default=False)
    if out["reindex_jobs"]:
        out["reindex_max_dollars"] = min(1000.0, max(0.0, _safe_float(
            _q_text("Maximum provider reservation per rebuild (USD, at reviewed standard rates; 0 permits local only)", default="5.0"), default=5.0)))
    embedder = _q_select(
        "  Embedder:",
        [
            "hosted        - Voyage AI (needs VOYAGE_API_KEY)",
            "local         - on-box sentence-transformers (no API key)",
            "deterministic - hashing stub (offline; low quality, for testing)",
        ],
        default="hosted        - Voyage AI (needs VOYAGE_API_KEY)",
    ).split()[0]
    out["embedder"] = embedder
    if embedder != "deterministic":
        console.print(
            "[dim]Optional embedding revision: local models use a resolved commit hash; "
            "a hosted revision is your recorded provider version, not provider verification. "
            "Changing the model or revision requires knowledge reindex.[/dim]"
        )
        revision = _q_text("  Embedding revision (blank = automatic/default identity)", default="").strip()
        if revision:
            out["revision"] = revision
    store = _q_select(
        "  Vector store:",
        [
            "sqlite   - single-file, local (default; fine to a few million chunks)",
            "pgvector - Postgres + pgvector (enterprise: one DB to encrypt/back up/audit)",
            "qdrant   - existing corpus reads/erasure (new ingestion unavailable)",
        ],
        default="sqlite   - single-file, local (default; fine to a few million chunks)",
    ).split()[0]
    out["store"] = store
    if store == "pgvector":
        dsn = _q_text("  pgvector DSN (blank = MAVERICK_KNOWLEDGE_DSN env)", default="").strip()
        if dsn:
            out["dsn"] = dsn
    elif store == "qdrant":
        console.print(
            "[yellow]Qdrant can read and erase existing documents. Adding or repairing "
            "documents is unavailable. Choose SQLite or pgvector to ingest new documents.[/yellow]"
        )
        url = _q_text("  Qdrant URL (blank = QDRANT_URL env)", default="").strip()
        if url:
            out["url"] = url
    return out


# Size limits for saved company folders and spaces (dashboard Knowledge sources):
# key, label, default, lowest and highest allowed value. They match
# config.get_knowledge_sources, which refuses anything outside these ranges.
_KNOWLEDGE_SOURCE_LIMITS: tuple[tuple[str, str, int, int, int], ...] = (
    ("max_items", "Most items in one saved folder or space", 64, 1, 1000),
    ("max_pages", "Most listing pages for one saved source", 16, 1, 200),
    ("max_download_mib", "Largest SharePoint, OneDrive or Drive file (MiB)", 4, 1, 32),
    ("max_text_kib", "Most source text kept per refresh (KiB)", 256, 1, 8192),
    ("max_refresh_minutes", "Longest time one saved refresh may run (minutes)", 5, 1, 60),
)


def pick_knowledge_source_permissions() -> dict[str, Any]:
    """Who sees each file of a saved SharePoint, OneDrive, Google Drive or
    Confluence source. Off (the default) keeps the rule that anyone the
    connection is shared with can use its cached content. Email matching
    shows a file only to people the file itself is shared with, by email,
    email domain or link. Group-shared files are withheld because group
    members are not read. Returns {"permission_filter": "by_email"} or {}.
    """
    console.print()
    console.print(
        "[dim]By default, anyone the saved account is shared with can use a company folder's "
        "cached files. Matching each file's own sharing settings is stricter: a file is shown only "
        "to people it is shared with by email or email domain, or to anyone with its link. Files "
        "shared only with a group are left out, because group members are not checked. People who "
        "sign in with SAML, or whose provider does not confirm their email, see no saved company "
        "files while this is on.[/dim]"
    )
    if not _q_confirm("Show each saved company file only to the people it is shared with?", default=False):
        return {}
    return {"permission_filter": "by_email"}


def pick_knowledge_sources() -> dict[str, Any]:
    """Optional size limits for saved SharePoint, OneDrive, Google Drive and
    Confluence sources. Asked only when Knowledge RAG is on, because saved
    sources are searched through it. Declining keeps the defaults, which are
    the bounds the dashboard has always used. Returns a dict written under
    ``[knowledge_sources]``, or {} to write nothing.
    """
    console.print()
    console.print(
        "[dim]Saved company folders and spaces use these limits for each refresh. "
        "Defaults: 64 items, 16 listing pages, 4 MiB per document, 256 KiB of "
        "source text and 5 minutes per refresh. Keep the defaults unless a folder or space is larger.[/dim]"
    )
    if not _q_confirm("Change the size limits for saved company folders and spaces?", default=False):
        return {}
    out: dict[str, Any] = {}
    for key, label, default, low, high in _KNOWLEDGE_SOURCE_LIMITS:
        while True:
            raw = _q_text(f"  {label} ({low}-{high}, default {default})", default=str(default)).strip()
            try:
                value = int(raw)
            except ValueError:
                value = None
            if value is not None and low <= value <= high:
                break
            console.print(f"[yellow]Enter a whole number from {low} to {high}.[/yellow]")
        out[key] = value
    return out


def pick_oauth_vault() -> dict[str, Any]:
    """Opt-in to sealing captured OAuth tokens in the per-tenant vault.

    Off by default. When on, the OAuth helper seals access/refresh tokens
    encrypted-at-rest under the tenant's DEK (one data key per tenant) instead
    of writing them to a plaintext file. Returns a dict written under
    ``[oauth]``.
    """
    console.print()
    console.print(
        "[dim]The OAuth token vault seals captured access/refresh tokens "
        "encrypted-at-rest under each tenant's own key (no plaintext token "
        "files, no cross-tenant readability). Recommended for hosted/multi-"
        "tenant deploys. It also enables renewable named Google Drive, Google "
        "Cloud Storage and Jira Cloud accounts in Connections. Save app "
        "registration credentials inside the app, then review the provider's "
        "consent screen. Provider registration and consent remain external "
        "requirements. OFF by default.[/dim]"
    )
    vault = _q_confirm("Seal OAuth tokens in the per-tenant vault?", default=False)
    desktop_return = vault and _q_confirm(
        "Enable system-browser account sign-in returns to the desktop app? An administrator must also register and confirm http://127.0.0.1:8766/connections for each provider in Connections.", default=False)
    return {"vault": vault, "desktop_return": desktop_return}


def pick_governed_connectors() -> dict[str, Any]:
    """Opt-in to routing live system-of-record writes through governed Actions.

    Off by default. When on, a selected enterprise connector (Salesforce,
    ServiceNow) is registered as a typed governed Action: a write previews its
    effect, hits the approval floor (``[actions] require_approval_at``), and
    records a tamper-evident lineage link -- instead of a bare confirm-gated
    tool call. Returns a dict written under ``[governed_connectors]``.
    """
    try:
        from maverick.governed_rest import available_rest_connectors

        choices = available_rest_connectors()
    except Exception:  # pragma: no cover -- never block the wizard
        choices = ["salesforce", "servicenow"]
    console.print()
    console.print(
        "[dim]Governed connectors route a live system-of-record write "
        f"({', '.join(choices)}) through simulate -> approve -> commit -> "
        "lineage: the write hits the approval floor and is recorded in a "
        "tamper-evident chain. OFF by default.[/dim]"
    )
    if not _q_confirm("Enable governed system-of-record connectors?", default=False):
        return {"enable": False}
    selected = [
        c for c in choices if _q_confirm(f"  Register {c} as a governed connector?", default=False)
    ]
    # Standing approver of record: when these connectors are wrapped in the live
    # tool path, a write is approval-gated against this identity (the agent can't
    # self-approve). Blank = writes are previewed but refused until an operator
    # commits them out of band.
    approver = _q_text(
        "  Approver of record for governed writes (blank = refuse agent writes "
        "without out-of-band approval):",
        default="",
    ).strip()
    # Restore points: one read-only GET before an in-place update, so the write
    # carries a real undo instead of an asserted one. Without it every update is
    # irreversible and routes to a human -- safe, but nothing ever earns
    # autonomy. Off is the right answer for a write-only service account.
    console.print(
        "[dim]  Restore points read a record's prior values before changing "
        "them (one read-only GET), so the write ships a genuine undo. Off = "
        "every update is treated as irreversible.[/dim]"
    )
    restore_points = _q_confirm("  Capture restore points before in-place updates?", default=True)
    return {
        "enable": True,
        "connectors": selected,
        "approver": approver,
        "restore_points": restore_points,
    }


def pick_durable() -> dict[str, Any]:
    """Opt-in to durable execution (crash-resume via checkpoints).

    Off by default. When on, a long-running goal checkpoints its loop state at
    each step so ``maverick resume`` continues from where a crash left off
    instead of re-running from the start. Returns a dict written under
    ``[durable]``.
    """
    console.print()
    console.print(
        "[dim]Durable execution checkpoints a goal's progress so a crash or "
        "restart resumes from the last step instead of starting over. Adds a "
        "small write per step; OFF by default.[/dim]"
    )
    if not _q_confirm("Enable durable execution (crash-resume)?", default=BOOLEAN_SETTINGS["durable.enabled"].default):
        return {"enabled": False}
    return {"enabled": True, "keep_last": INTEGER_SETTINGS["durable.keep_last"].default}


def pick_workspace_journal() -> dict[str, Any]:
    """Opt-in workspace mutation journal (pre-images + ``maverick journal
    revert``).

    Off by default. Returns keys for the ``[workspace]`` table (``journal``,
    ``journal_strict``); written only when enabled.
    """
    console.print()
    console.print(
        "[dim]The workspace journal captures every file the agents overwrite "
        "or create through the file tools — BEFORE the mutation — so "
        "a named task owner can review and restore captured files inside "
        "the app when strict capture is selected below. The legacy CLI journal "
        "remains available for other runs. Shell-driven mutations "
        "(rm/mv/redirects) are not covered — the audit trail records those "
        "commands. Bounded disk per goal; OFF by default.[/dim]"
    )
    if not _q_confirm(
            "Enable the workspace mutation journal (undoable file edits)?",
            default=False):
        return {"journal": False}
    strict = _q_confirm(
        "Strict mode: REFUSE any write whose pre-image cannot be journaled? "
        "(enables encrypted, reviewed file recovery inside the app for named local tasks)",
        default=False)
    out: dict[str, Any] = {"journal": True}
    if strict:
        out["journal_strict"] = True
    return out


def pick_value() -> dict[str, Any]:
    """The savings (ROI) report's cost/value assumptions -- the CLIENT's own
    numbers, editable later on the dashboard Savings page.

    The Savings dashboard compares real completed work against the typical
    human cost: ``(tasks x hours per task x hourly rate) - agent spend``.
    Defaults are deliberately conservative ($75/h, 2h/task). Returns a dict
    written under ``[value]``.
    """
    console.print()
    console.print(
        "[dim]Savings report: the dashboard's Savings page compares real "
        "completed work against what the same work would cost a human -- "
        "using YOUR numbers. Set them now or tune them later on the page "
        "itself. Conservative defaults keep the claim defensible.[/dim]"
    )
    if not _q_confirm("Set your human-cost assumptions now?", default=True):
        return {}
    rate = _safe_float(
        _q_text("  Fully-loaded human hourly rate ($/hour)", default="75"), default=75.0
    )
    hours = _safe_float(
        _q_text("  Human hours one comparable task takes", default="2"), default=2.0
    )
    return {"hourly_rate": max(0.0, rate), "hours_per_task": max(0.0, hours)}


def pick_intent_value() -> dict[str, Any]:
    """Optional read-only inference and customer-controlled draft suggestions."""
    console.print("[dim]Work value groups related work, requires execution receipts for benefit, and uses editable provisional benchmarks. Suggestions create drafts only.[/dim]")
    enabled = _q_confirm("Enable intent-based work value and opportunities?", default=True)
    return {"enabled": enabled, "recommendations": enabled,
            "completion_confirmation": False}


def pick_finance() -> dict[str, Any]:
    """Opt-in to the finance suite governance (finance-agent-suite §5/§8).

    Off by default. When enabled, governance pauses money movement for a human,
    you pick the compliance regimes to enforce (strictest-wins), set the
    delegation-of-authority dollar tiers, and point at an OFAC SDN list. The
    optional finance-operations module adds deterministic regulatory feeds,
    anomaly rules, governed screening cases, and scheduled GRC evidence work.
    Returns a dict written under ``[governance]`` / ``[finance]`` /
    ``[screening]`` / ``[finance_operations]``.
    """
    console.print()
    console.print(
        "[dim]Finance suite: the CFO-office governance wrapper -- segregation of "
        "duties, maker-checker, dollar-threshold approvals, and a signed book of "
        "record. Enabling pauses every money movement for a human and lets you "
        "enforce compliance regimes. OFF by default.[/dim]"
    )
    if not _q_confirm("Enable the finance suite governance?", default=False):
        return {"enable": False}
    regimes = _q_checkbox(
        "Compliance regimes to enforce (strictest-wins union):",
        [
            "sox",
            "coso",
            "gaap",
            "pci",
            "glba",
            "aml",
            "sec",
            "irs",
            "dora",
            "basel_iii",
            "ifrs_17",
        ],
        default=["sox", "gaap"],
    )
    require_human_above = _safe_float(
        _q_text("  Pause money movement above $ (DoA threshold; 0 = pause all)", default="5000"),
        default=5000.0,
    )
    deny_above = _safe_float(
        _q_text("  Hard-deny money movement above $ (0 = no hard ceiling)", default="0"),
        default=0.0,
    )
    require_fresh = _q_confirm(
        "  Require a FRESH human approval each time a paused action runs "
        "(ignore any prior 'remember this' grant)?",
        default=False,
    )
    sdn_path = _q_text(
        "  OFAC SDN list path for sanctions screening (blank to set later)",
        default="",
    ).strip()
    operations_enable = _q_confirm(
        "  Enable deterministic regulatory monitoring, anomaly cases, governed "
        "AML screening, and scheduled GRC control tests?",
        default=True,
    )
    operations: dict[str, Any] = {"operations_enable": operations_enable}
    if operations_enable:
        operations["federal_register_enable"] = _q_confirm(
            "  Poll the official Federal Register API?",
            default=True,
        )
        operations["texas_register_enable"] = _q_confirm(
            "  Poll the official Texas Register RSS and queue each issue for review?",
            default=False,
        )
        operations["eur_lex_enable"] = _q_confirm(
            "  Poll EUR-Lex (all EU Parliament and Council legislation) for review?",
            default=False,
        )
        operations["edpb_enable"] = _q_confirm(
            "  Poll the EDPB news feed (GDPR guidance and decisions) for review?",
            default=False,
        )
        operations["regulatory_domains"] = _q_checkbox(
            "  Regulatory domains to route into the review queue:",
            ["finance", "money_transmitter", "insurance_producer", "lending"],
            default=["finance", "money_transmitter", "insurance_producer"],
        )
        regulatory_minutes = max(
            5,
            min(
                10_080,
                _safe_int(
                    _q_text("  Regulatory feed poll interval (minutes)", default="60"),
                    default=60,
                ),
            ),
        )
        control_hours = max(
            1,
            min(
                744,
                _safe_int(
                    _q_text("  Finance-to-GRC control test interval (hours)", default="24"),
                    default=24,
                ),
            ),
        )
        operations.update(
            {
                "regulatory_poll_seconds": regulatory_minutes * 60,
                "control_test_interval_seconds": control_hours * 3600,
                "anomaly_enable": True,
                "sanctions_max_age_hours": 72,
                "control_owner": _q_text(
                    "  Finance control/evidence owner",
                    default="Finance Control Owner",
                ).strip()
                or "Finance Control Owner",
            }
        )
        operations.update(pick_finance_profile())
    return {
        "enable": True,
        "regimes": regimes,
        "require_human_above": require_human_above,
        "deny_above": deny_above,
        "require_fresh_human_approval": require_fresh,
        "sdn_path": sdn_path,
        **operations,
    }


# The Finance Operating Profile (finance-agent-suite §3.8) -- the same keys
# and values the dashboard's Settings > All settings > Finance rows write and
# maverick.finance.profile reads.
FINANCE_FRAMEWORKS = ("us_gaap", "ifrs")
FINANCE_AUTOMATION_LEVELS = ("draft", "approve", "auto_threshold", "straight_through")
FINANCE_SOD_MODES = ("enforce", "warn")


def pick_finance_profile() -> dict[str, Any]:
    """The finance operating profile, asked only with finance operations on.

    Returns ``finance_framework`` / ``finance_materiality`` (0 = not set) /
    ``finance_automation_default`` / ``finance_sod_mode`` /
    ``finance_approvals_timeout``. The approval timeout has one value,
    ``fail_closed``: finance never lets an unanswered approval through.
    """
    console.print(
        "[dim]Finance operating profile: the accounting framework, the "
        "materiality amount that raises review, how far agents may go on "
        "finance actions (payments and postings always wait for a person), "
        "and whether separation-of-duties conflicts block or are recorded.[/dim]"
    )
    framework = _q_select(
        "  Accounting framework:", list(FINANCE_FRAMEWORKS), default="us_gaap",
    )
    materiality = max(0.0, _safe_float(
        _q_text("  Materiality amount (0 = not set)", default="0"), default=0.0,
    ))
    automation = _q_select(
        "  How far agents go on finance actions by default "
        "(draft = prepare only; approve = act after a person approves; "
        "auto_threshold = act alone under the approval limit; "
        "straight_through = act alone):",
        list(FINANCE_AUTOMATION_LEVELS), default="draft",
    )
    sod_mode = _q_select(
        "  Separation-of-duties conflicts (enforce = block; warn = record and "
        "ask a person):",
        list(FINANCE_SOD_MODES), default="enforce",
    )
    return {
        "finance_framework": framework if framework in FINANCE_FRAMEWORKS else "us_gaap",
        "finance_materiality": materiality,
        "finance_automation_default": (
            automation if automation in FINANCE_AUTOMATION_LEVELS else "draft"
        ),
        "finance_sod_mode": sod_mode if sod_mode in FINANCE_SOD_MODES else "enforce",
        # The only value: an unanswered finance approval is refused.
        "finance_approvals_timeout": "fail_closed",
    }


def pick_api_keys() -> dict[str, Any]:
    """API access for scripts and integrations: personal and service-account
    keys with scopes, an expiry date and rotation.

    On by default (a key only exists once a signed-in person creates one).
    Returns the ``[dashboard]`` keys ``api_keys`` and, when changed from the
    defaults, ``api_key_default_days`` / ``api_key_max_days`` /
    ``api_key_rotation_grace_hours``; read by ``maverick.config.api_key_settings``.
    """
    console.print(
        "[dim]API access for scripts and integrations: people create their own "
        "keys on their account page, and administrators create service accounts "
        "for programs. A key does only what its scopes allow and never more than "
        "its owner's role, stops on its expiry date, and can be rotated or "
        "revoked at any time. The shared server token stays as break-glass "
        "access only.[/dim]"
    )
    result: dict[str, Any] = {
        "api_keys": _q_confirm("Allow API keys for scripts and integrations?", default=True),
    }
    if not result["api_keys"]:
        return result
    default_days = _safe_int(
        _q_text("  How many days should a new key last unless the person picks fewer?", default="90"),
        default=90,
    )
    max_days = _safe_int(
        _q_text("  The longest a key may last, in days", default="365"),
        default=365,
    )
    grace_hours = _safe_int(
        _q_text("  After rotating a key, how many hours should the old one keep working?", default="24"),
        default=24,
    )
    if default_days != 90:
        result["api_key_default_days"] = max(1, min(default_days, 3650))
    if max_days != 365:
        result["api_key_max_days"] = max(1, min(max_days, 3650))
    if grace_hours != 24:
        result["api_key_rotation_grace_hours"] = max(0, min(grace_hours, 720))
    return result


def _docker_available() -> bool:
    """Return True iff the `docker` binary is on PATH AND the daemon
    responds. Used to pick a safe sandbox default in consumer mode and
    to choose the wizard's default in dev mode."""
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=2,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


# Container backends pick their image from the coding language (see
# sandbox._IMAGE_BY_LANGUAGE). local/ssh run model shell on the host toolchain
# and devcontainer reuses the user's own image, so the language hint only
# changes anything for these three.
_LANGUAGE_BACKENDS = {"docker", "gvisor", "podman", "kubernetes"}


def _ssh_destination(value: Any) -> str:
    """Validate a destination's structure without invoking SSH or resolving DNS."""
    destination = value.strip() if isinstance(value, str) else ""
    if any(ord(character) < 32 or ord(character) == 127 for character in destination) or not re.fullmatch(r"(?:[^\s@/:\\]+@)?[^\s@/\\]+", destination):
        raise ValueError("SSH destination must be a host, user@host, or SSH config alias")
    if destination.rsplit("@", 1)[-1].startswith("-") or destination.startswith("-"):
        raise ValueError("SSH destination cannot start with an option prefix")
    return destination


def pick_sandbox() -> dict[str, Any]:
    # Security-first default: keep Docker selected by default regardless
    # of current daemon reachability to avoid silently falling back to
    # the least isolated local backend.
    docker_default = "docker - Throwaway Docker container (recommended)"
    pick = _q_select(
        "Sandbox backend (where the agent runs shell commands):",
        [
            "local  - Subprocess on this machine (fastest, least isolated)",
            "docker - Throwaway Docker container (recommended)",
            "gvisor - Docker + gVisor runsc kernel (strongest isolation)",
            "podman - Throwaway Podman container (rootless)",
            "devcontainer - Reuse a .devcontainer config",
            "kubernetes - Pod-per-command in a cluster (kubectl)",
            "ssh    - Remote machine",
        ],
        default=docker_default,
    )
    backend = pick.split()[0]
    remote = backend == "ssh"
    workdir = _q_text(
        "  Remote workspace directory" if remote else "  Workspace directory",
        default="~/maverick-workspace" if remote else os.environ.get("MAVERICK_WORKDIR") or str(Path.home() / "maverick-workspace"),
    )
    cfg: dict[str, Any] = {"backend": backend, "workdir": workdir, "timeout": 60}
    if remote:
        while True:
            try:
                cfg["host"] = _ssh_destination(_q_text("  SSH destination (user@host or SSH config alias)", default=""))
                break
            except ValueError as exc:
                console.print(f"[red]{exc}[/red]")
        console.print("[dim]SSH connectivity is checked when the sandbox starts; setup does not contact the remote host.[/dim]")
    # Non-Python coders get a toolchain image that can actually run their tests
    # (cargo/go test, the JS runner, ...). Python is the default image, so we
    # only write [sandbox] language when it's something else -- existing and
    # Python configs stay byte-identical.
    if backend in _LANGUAGE_BACKENDS:
        languages = [
            "python     - python:3.12-slim (default)",
            "javascript - node:22 (JavaScript / TypeScript)",
            "go         - golang:1",
            "rust       - rust:1",
            "java       - eclipse-temurin:21 (Java / Kotlin)",
            "ruby       - ruby:3",
        ]
        lang = _q_select(
            "  What do you mostly code in? (sets the container's toolchain)",
            languages,
            default=languages[0],
        ).split()[0]
        if lang != "python":
            cfg["language"] = lang
    if backend == "kubernetes":
        # The backend fails closed when allow_network=false and the namespace
        # has no deny-all NetworkPolicy (a transient pod can't block its own
        # egress), so a config written without asking ran nothing. Ask, and
        # hand over the exact manifest to apply.
        namespace = _q_text("  Kubernetes namespace for sandbox pods", default="default").strip()
        cfg["namespace"] = namespace or "default"
        net = _q_select(
            "  Pod networking (a transient pod cannot block its own egress):",
            [
                "deny  - No network: apply the deny-all NetworkPolicy shown next (recommended)",
                "allow - Pods may use the cluster network (package installs, HTTP fetches)",
            ],
            default="deny  - No network: apply the deny-all NetworkPolicy shown next (recommended)",
        )
        cfg["allow_network"] = net.split()[0] == "allow"
        if not cfg["allow_network"]:
            console.print(
                "\n  Apply this once to the namespace before the first run "
                "(commands fail closed until it is present):\n"
            )
            console.print(kubernetes_deny_all_manifest(cfg["namespace"]), highlight=False)
            console.print("\n  kubectl apply -f - <<'EOF' ... EOF   (paste the manifest above)\n")
    return cfg


def pick_research_execution() -> dict[str, Any]:
    """Configure the installation-owned, exact-output research controller.

    This remains off by default. The wizard collects one deterministic
    evaluator without retaining its expected output text; administrators can
    add or replace evaluators later from the Research lab page.
    """
    console.print()
    console.print(
        "[dim]The Research lab runs submitted Python source in a reviewed, "
        "locally present Linux container after an installation administrator "
        "opens the exact source. Results are checked against an exact expected "
        "output. No image is downloaded and there is no host-process fallback.[/dim]"
    )
    if not _q_confirm("Enable bounded Research lab execution?", default=False):
        return {"enable": False}

    image_id = ""
    while not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        image_id = _q_text(
            "  Immutable ID of a reviewed local Linux image (sha256: plus 64 lowercase hex)",
            default="",
        ).strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            console.print("[yellow]Enter the immutable sha256 image ID shown by your container runtime.[/yellow]")

    evaluator_id = _q_text("  Evaluator name", default="smoke").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", evaluator_id):
        console.print("[yellow]Using the safe evaluator name 'smoke'.[/yellow]")
        evaluator_id = "smoke"
    version = _q_text("  Evaluator version", default="v1").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", version):
        console.print("[yellow]Using the safe evaluator version 'v1'.[/yellow]")
        version = "v1"
    expected = _q_text(
        "  One exact output line that a passing candidate must print",
        default="ok",
    )
    stdout_sha256 = hashlib.sha256((expected + "\n").encode("utf-8")).hexdigest()
    queue_seconds = max(30, min(86400, _safe_int(
        _q_text("  How many seconds may a submission wait for review?", default="3600"),
        default=3600,
    )))
    return {
        "enable": True,
        "image_id": image_id,
        "queue_seconds": queue_seconds,
        "evaluators": {
            evaluator_id: {"version": version, "stdout_sha256": stdout_sha256},
        },
    }


def pick_candidate_promotion() -> dict[str, Any]:
    """Choose the guarded research-to-production promotion surface."""

    console.print()
    console.print(
        "[dim]Candidate promotion lets named administrators review an exact "
        "research result, stage it behind a canary, activate it, and recover "
        "or roll it back from inside Lightwork. Enable it only after the "
        "installation has a reviewed promotion policy, artifact resolver, "
        "and deployment adapter; missing authorities always fail closed.[/dim]"
    )
    if not _q_confirm("Enable governed candidate promotion in the app?", default=False):
        return {"enable": False}
    target_id = _q_text("  Deployment target name", default="installed-lightwork").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target_id) is None:
        console.print("[yellow]Using the safe target name 'installed-lightwork'.[/yellow]")
        target_id = "installed-lightwork"
    return {
        "enable": True,
        "allowed_targets": [target_id],
        "review_ttl_seconds": 3600,
        "canary_metric": "error_rate",
        "canary_comparison": "at_most",
        "canary_threshold": 0.05,
    }


def pick_knowledge_access() -> dict[str, bool]:
    """Choose the in-app current-rights organizational-memory surface."""

    console.print()
    console.print(
        "[dim]Governed Knowledge shows only exact registry versions whose "
        "source checksum, approval, purpose, current data-use authority, "
        "consent, and parent lineage pass at read time. It also provides "
        "correction, exclusion, deletion, recovery, and evidence-export flows "
        "inside the app.[/dim]"
    )
    return {
        "enable": _q_confirm(
            "Enable governed Knowledge in the app (recommended)?",
            default=True,
        ),
        "task_context": _q_confirm(
            "Allow tool-free AI tasks using employee-selected approved source versions?",
            default=False,
        ),
    }


def kubernetes_deny_all_manifest(namespace: str) -> str:
    """The deny-all NetworkPolicy the kubernetes sandbox backend requires when
    ``allow_network = false`` -- the kernel's own manifest when it is
    importable, else an identical local copy (the wizard runs before core)."""
    try:
        from maverick.sandbox.kubernetes import _DENY_ALL_NETWORKPOLICY
    except Exception:
        _DENY_ALL_NETWORKPOLICY = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: maverick-deny-all\n"
            "  namespace: {ns}\n"
            "spec:\n"
            "  podSelector: {{}}\n"
            "  policyTypes: [Ingress, Egress]"
        )
    return _DENY_ALL_NETWORKPOLICY.format(ns=namespace)


# ---------- additional wizard steps ----------


def pick_web_search() -> tuple[bool, list[str]]:
    """Enable web search + pick a default backend. Returns (enabled, env_vars_needed)."""
    if not _q_confirm(
        "Enable web search? (Tavily / Brave / SerpAPI / DuckDuckGo)",
        default=True,
    ):
        return False, []
    pick = _q_select(
        "  Default backend:",
        [
            "tavily   - best quality, free tier ~1k/mo, BYOK",
            "brave    - generous free tier, BYOK",
            "serpapi  - paid, covers more engines",
            "ddg      - no key, rate-limited",
        ],
        default="tavily   - best quality, free tier ~1k/mo, BYOK",
    )
    backend = pick.split()[0]
    envs = {
        "tavily": ["TAVILY_API_KEY"],
        "brave": ["BRAVE_API_KEY"],
        "serpapi": ["SERPAPI_API_KEY"],
        "ddg": [],
    }[backend]
    os.environ["MAVERICK_SEARCH_BACKEND"] = backend  # picked up by web_search tool
    return True, envs


def pick_mcp_servers() -> dict[str, dict[str, Any]]:
    """Configure MCP servers the agent will consume as tools.

    MCP servers expose their own tools (filesystem, GitHub, etc.) via a
    JSON-RPC protocol. The agent calls them as ``mcp_<name>__<tool>``.
    Skip if you don't know what MCP is.
    """
    if not _q_confirm(
        "Add MCP servers? (extensibility hook; skip if unsure)",
        default=False,
    ):
        return {}
    servers: dict[str, dict[str, Any]] = {}
    console.print(
        "[dim]Example: name 'filesystem', command 'npx', "
        "args '-y @modelcontextprotocol/server-filesystem /tmp'.[/dim]"
    )
    while True:
        name = _q_text("  Name (blank to finish)", default="").strip()
        if not name:
            break
        cmd = _q_text(f"  {name}: command", default="").strip()
        if not cmd:
            console.print("  [yellow]skipped (no command)[/yellow]")
            continue
        args_raw = _q_text(f"  {name}: args (space-separated)", default="").strip()
        args = args_raw.split() if args_raw else []
        servers[name] = {"command": cmd, "args": args}
        if not _q_confirm("  Add another?", default=False):
            break
    return servers


def pick_plugins() -> list[str]:
    """Allowlist for pip-installed plugin packages.

    Plugins are loaded only when listed in ``[plugins].enabled``. We
    scan installed entry-points and offer a checkbox; if nothing is
    installed, the step is a no-op.
    """
    discovered: set[str] = set()
    try:
        from maverick.plugins import _entry_points  # type: ignore[attr-defined]

        for group in (
            "maverick.tools",
            "maverick.channels",
            "maverick.skills",
            "maverick.personas",
        ):
            for ep in _entry_points(group):
                discovered.add(ep.name)
    except Exception as e:
        console.print(
            f"[yellow]Plugin discovery skipped: {e}[/yellow] "
            "(no plugins will be offered during setup; review plugins in Lightwork later)"
        )
        return []
    if not discovered:
        return []
    console.print()
    console.print(
        "[bold]Plugins discovered via entry_points:[/bold] " + ", ".join(sorted(discovered))
    )
    if not _q_confirm(
        "Enable any of these? (allow-listed for security; skip is safe)",
        default=False,
    ):
        return []
    return _q_checkbox("Enable plugins:", sorted(discovered))


def pick_ts_plugins() -> list[list[str]]:
    """TypeScript (NDJSON stdio) plugin commands — writes ``[plugins].ts``.

    Each entry is the argv that serves the plugin (e.g.
    ``node /path/to/plugin.js``); Lightwork discovers its tools via
    ``--describe`` at boot. Skipped by default — most setups have none.
    """
    if not _q_confirm(
        "Add any TypeScript plugins? (commands like: node /path/plugin.js)",
        default=False,
    ):
        return []
    commands: list[list[str]] = []
    while True:
        raw = _q_text("  Plugin command (blank to finish)", default="")
        if not raw.strip():
            break
        commands.append(raw.split())
    return commands


def pick_plugin_permissions() -> tuple[list[str], bool]:
    """Grants + enforcement for enabled plugins (writes ``[plugins].grant`` /
    ``enforce_permissions``).

    A plugin declares the permissions it needs (network / fs_write / subprocess)
    in its manifest. By default an ungranted request is loaded with a warning;
    granting here silences it, and enforcing *skips* a plugin that requests
    something ungranted. Returns ``(grant, enforce)``; only asked when at least
    one plugin is enabled.
    """
    grant = _q_checkbox(
        "Permissions enabled plugins may use "
        "(ungranted requests warn, or are skipped if you enforce next):",
        ["network", "fs_write", "subprocess"],
        default=[],
    )
    enforce = _q_confirm(
        "Skip plugins that request a permission you didn't grant? "
        "(recommended; off = load with a warning)",
        default=False,
    )
    return grant, enforce


def pick_tool_acl(channels: dict[str, Any]) -> dict[str, Any]:
    """Optional per-tool / per-channel allow/deny lists.

    Common pattern: a Telegram channel may chat but shouldn't run
    shell. Power users only; defaults to no restriction.
    """
    if not _q_confirm(
        "Restrict tools the agent may run? (skip for full access)",
        default=False,
    ):
        return {}
    acl: dict[str, Any] = {}
    common = ["shell", "write_file", "computer", "browser", "http_fetch", "apply_patch"]
    denied = _q_checkbox(
        "Deny these tools globally (rare; usually empty):",
        common,
        default=[],
    )
    if denied:
        acl["denied_tools"] = denied
    for ch_id in channels:
        if not _q_confirm(f"  Restrict tools available over {ch_id}?", default=False):
            continue
        ch_denied = _q_checkbox(
            f"    Deny over {ch_id}:",
            common,
            default=["shell", "computer"],
        )
        acl.setdefault("channels", {})[ch_id] = {"denied_tools": ch_denied}
    return acl


def pick_rate_limits(channels: dict[str, Any]) -> dict[str, str]:
    """Per-tool sliding-window rate caps."""
    default = bool(channels)  # default ON when exposing via channels
    if not _q_confirm(
        "Cap call rate per tool? (recommended when exposing via channels)",
        default=default,
    ):
        return {}
    limits: dict[str, str] = {}
    proposed = [
        ("web_search", "10/60"),
        ("http_fetch", "30/60"),
        ("shell", "30/60"),
        ("mcp_*", "60/60"),
    ]
    for name, spec_default in proposed:
        spec = _q_text(
            f"  {name} (N/seconds, blank to skip)",
            default=spec_default,
        ).strip()
        if spec:
            limits[name] = spec
    return limits


def pick_retention() -> dict[str, int]:
    """Auto-prune audit logs and world-model rows."""
    if not _q_confirm(
        "Auto-prune audit logs + old episodes after N days?",
        default=True,
    ):
        return {}
    return {
        "audit_days": _safe_int(_q_text("  Audit log retention days", default="90"), default=90),
        "episodes_days": _safe_int(_q_text("  Episode retention days", default="365"), default=365),
        "events_days": _safe_int(
            _q_text("  Goal-event retention days", default="180"), default=180
        ),
        "messages_days": _safe_int(
            _q_text("  Message retention days", default="180"), default=180
        ),
    }


def pick_analytics() -> dict[str, Any]:
    """Consent step for MCP-client language analytics. OFF by default.

    When granted, the MCP server tallies a coarse language bucket from each
    client's User-Agent (typescript / go / rust / c# / java / python) into a
    local counts file — no request content, no identifiers, nothing leaves
    the machine. The operator reads it with
    ``maverick.mcp_analytics.client_language_counts()`` and
    ``non_python_share()``. Returns a dict written under ``[analytics]``.
    """
    console.print()
    console.print(
        "[dim]Optional: count which languages drive this agent over MCP "
        "(a coarse bucket from each client's User-Agent). Counts stay in a "
        "local file — no request content, no identifiers, nothing is "
        "uploaded. It shows you which languages your MCP clients use; OFF "
        "by default.[/dim]"
    )
    if not _q_confirm("Count MCP client languages locally?", default=False):
        return {}
    return {"mcp_client_language": True}


def pick_usability_survey() -> dict[str, Any]:
    """Optional in-product ease-of-use survey. OFF by default.

    When on, each signed-in person is offered the 10-question System
    Usability Scale at most once a quarter (one click hides it) and one ease
    question after a few common tasks. Answers stay on this server, are
    reported by the role people choose and never by name. Written under
    ``[analytics]`` as ``usability_survey``.
    """
    console.print()
    console.print(
        "[dim]Optional: ask people how easy Lightwork is to use - ten short "
        "questions at most once a quarter, and one question after a few common "
        "tasks. Answers stay on this server, are reported by role and never by "
        "name, and nothing is sent anywhere. OFF by default.[/dim]"
    )
    if not _q_confirm("Ask people how easy Lightwork is to use?", default=False):
        return {}
    return {"usability_survey": True}


def pick_web_vitals() -> dict[str, Any]:
    """Optional page speed for real visitors (field Core Web Vitals). OFF by default.

    When on, the dashboard times a sample of real page loads in the browser
    (LCP, INP and CLS) and keeps only counts per page and device class, so
    Settings > Page speed shows the 75th percentile over the last 28 days.
    No names, addresses or browsing history are kept, and nothing is sent
    anywhere. Written under ``[analytics]`` as ``web_vitals`` and
    ``web_vitals_sample_rate`` (the share of visits measured, 0 to 1).
    """
    console.print()
    console.print(
        "[dim]Optional: measure how fast pages load and respond for the people "
        "using Lightwork, on phones and computers. Only counts per page are "
        "kept on this server; no names or browsing history, and nothing is "
        "sent anywhere. OFF by default.[/dim]"
    )
    if not _q_confirm("Measure page speed for real visitors?", default=False):
        return {}
    # ``[analytics] web_vitals_sample_rate``: the share of visits measured.
    while True:
        raw = _q_text("Share of visits to measure, from 0 to 1 (0.5 measures every other visit):", default="0.5").strip()
        rate = _safe_float(raw, default=float("nan"))
        if math.isfinite(rate) and 0 <= rate <= 1:
            return {"web_vitals": True, "web_vitals_sample_rate": rate}
        console.print("[yellow]Enter a number from 0 to 1, for example 0.5.[/yellow]")


def pick_usage_measures() -> dict[str, Any]:
    """Optional, name-free usage measures. OFF by default.

    When on, Lightwork counts whether new people see a finished result of
    their own task in their first session, and how often AI suggestions are
    shown, used or dismissed. People and suggestions are kept only as one-way
    codes and nothing is sent anywhere. Written under ``[analytics]`` as
    ``usage_measures``.
    """
    console.print()
    console.print(
        "[dim]Optional: count, without names, whether new people get a first result "
        "in their first session and how often AI suggestions are used or dismissed. "
        "Counts stay on this server. OFF by default.[/dim]"
    )
    if not _q_confirm("Count first results and AI suggestions, without names?", default=False):
        return {}
    return {"usage_measures": True}


def pick_persona() -> dict[str, str]:
    """Agent identity: name + voice."""
    if not _q_confirm(
        "Customise the agent's name and style? (skip for defaults)",
        default=False,
    ):
        return {}
    name = _q_text("  Agent name", default="Lightwork").strip() or "Lightwork"
    style_pick = _q_select(
        "  Style:",
        [
            "concise   - terse, direct",
            "balanced  - default",
            "verbose   - explains its reasoning",
        ],
        default="balanced  - default",
    )
    return {"name": name, "style": style_pick.split()[0]}


def _https_origin(value: str) -> str | None:
    """The origin as private-channel delivery will accept it, else None (the
    kernel refuses every other value at send time)."""
    from maverick.personal_notification_delivery import _base_url

    try:
        return _base_url({"personal_dashboard_url": value})
    except ValueError:
        return None


def pick_notifications() -> tuple[dict[str, Any], list[str]]:
    """Private task alerts and shared organization delivery setup."""
    personal_alerts = _q_confirm(
        "Show signed-in people in-app alerts (the bell) when their tasks finish, need an answer, or wait for their approval? On by default; email, Slack and Teams stay off until you set them up. They can choose quiet hours and daily digests in Your notifications. Requires personal preferences.",
        default=True,
    )
    personal_critical_bypass = personal_alerts and _q_confirm(
        "Allow people to opt approval/deadline alerts out of their quiet hours and digest timing?", default=False,
    )
    personal_background = personal_alerts and _q_confirm(
        "Refresh enrolled people's alert inboxes and release digests while their pages are closed? The dashboard must remain running.", default=False,
    )
    personal_config = {"personal_alerts": personal_alerts, "personal_critical_bypass": personal_critical_bypass,
                       "personal_background": personal_background}
    personal_config["metric_alerts"] = personal_alerts and _q_confirm(
        "Show each person task performance and recorded usage alerts? By default, alert when fewer than 80% of at least ten of their recent recorded runs finish successfully. This measures completion, not answer accuracy. Uses up to 5,000 current-access runs completed in the last seven days; recorded usage may not include every provider charge. Change thresholds in All settings; personal Needs attention choices and quiet hours still apply.",
        default=False,
    )
    if personal_background and _q_confirm(
        "Allow people to opt into alerts in their verified Slack, Telegram or Teams private conversations? Requires My data identity verification and configured channel access.", default=False,
    ):
        origin = _https_origin(_q_text("HTTPS dashboard origin for authenticated notification links (no path):", default=""))
        if origin:
            personal_config["personal_external"] = True
            personal_config["personal_dashboard_url"] = origin
        else:
            console.print("[yellow]Private delivery needs the HTTPS address people sign in at, with no path "
                          "(like https://lightwork.example.com), so it stays off. Set it later in Lightwork > Settings.[/yellow]")
    if not _q_confirm(
        "Send shared organization alerts to a channel? Personal task alerts use each person's own notification choices.",
        default=False,
    ):
        return personal_config, []


    delivery_receipts = _q_confirm(
        "Keep content-free delivery results for seven days and enable in-product delivery tests?", default=True,
    )
    pick = _q_select(
        "  Backend:",
        [
            "ntfy      - free, no signup, push to phone via ntfy.sh",
            "pushover  - one-time $5, phone push",
            "slack     - incoming webhook",
            "discord   - webhook URL",
        ],
        default="ntfy      - free, no signup, push to phone via ntfy.sh",
    )
    backend = pick.split()[0]
    if backend == "ntfy":
        topic = _q_text(
            "  ntfy topic (any unique string; treat as a password)",
            default="",
        ).strip()
        return ({**personal_config, "backend": "ntfy", "ntfy_topic": topic, "delivery_receipts": delivery_receipts}, []) if topic else (personal_config, [])
    if backend == "pushover":
        return (
            {
                **personal_config,
                "backend": "pushover",
                "delivery_receipts": delivery_receipts,
                "user_key": "${PUSHOVER_USER_KEY}",
                "app_token": "${PUSHOVER_APP_TOKEN}",
            },
            ["PUSHOVER_USER_KEY", "PUSHOVER_APP_TOKEN"],
        )
    if backend == "slack":
        return (
            {**personal_config, "backend": "slack", "slack_webhook": "${SLACK_NOTIFY_WEBHOOK}", "delivery_receipts": delivery_receipts},
            ["SLACK_NOTIFY_WEBHOOK"],
        )
    if backend == "discord":
        return (
            {**personal_config, "backend": "discord", "discord_webhook": "${DISCORD_NOTIFY_WEBHOOK}", "delivery_receipts": delivery_receipts},
            ["DISCORD_NOTIFY_WEBHOOK"],
        )
    return {}, []


def _resolve_private_alert_linking(advanced: dict[str, Any], notifications: dict[str, Any]) -> None:
    """Do not save private delivery without its in-product linking path."""
    if not notifications.get("personal_external") or advanced.get("allow_personal_data_controls") is True:
        return
    if _q_confirm(
        "Private Slack and Telegram alerts need My Data so people can verify their own account. Turn on My Data now?",
        default=False,
    ):
        advanced["allow_personal_data_controls"] = True
    else:
        notifications["personal_external"] = False
        notifications.pop("personal_dashboard_url", None)
        console.print("Private delivery stays off. People can still use in-product task alerts.")


def pick_deadline_alerts(notifications: dict[str, Any] | None = None) -> dict[str, Any]:
    """Alerts when a privacy or governance record is due (``[deadline_alerts]``).

    Reads ``maverick.deadline_alerts``: on by default while the privacy register
    is on, so declining writes ``enabled = false`` explicitly. Lead times are
    stored under ``[deadline_alerts.lead_days]`` / ``[deadline_alerts.lead_hours]``.
    """
    if not (notifications or {}).get("backend"):
        console.print(
            "  [dim]Deadline alerts use the notification backend above; without one "
            "they are recorded on the record page but reach nobody.[/dim]"
        )
    if not _q_confirm(
        "Alert people when a data request, incident clock, assessment renewal, "
        "vendor contract or approval is due?",
        default=True,
    ):
        return {"enabled": False}
    mode = _q_select(
        "  How should alerts be sent?",
        ["immediate - one message per deadline", "digest - one message per person per check"],
        default="immediate - one message per deadline",
    ).split()[0]
    owner = _q_text(
        "  Who is named when a record has no assignee?", default="the privacy owner"
    ).strip() or "the privacy owner"
    quiet = _q_text(
        "  Quiet hours for non-urgent alerts (HH:MM-HH:MM, server time; empty = none)",
        default="",
    ).strip()
    cfg: dict[str, Any] = {"enabled": True, "mode": mode, "owner": owner}
    if quiet:
        cfg["quiet_hours"] = quiet
    lead_days = _q_text("  Days before a data request is due to warn (comma-separated)", default="7, 2")
    cfg["lead_days"] = {"dsar": [_safe_int(x, default=0) for x in _csv_list(lead_days)] or [7, 2],
                        "assessment": [30, 7], "vendor": [30, 7]}
    cfg["lead_days"]["dsar"] = [d for d in cfg["lead_days"]["dsar"] if d > 0] or [7, 2]
    cfg["lead_hours"] = {"incident": [24, 4], "approval": [24, 4]}
    return cfg


def _deadline_alerts_step(state: dict[str, Any], notifications: dict[str, Any] | None) -> dict[str, Any]:
    """Resume-aware wrapper: reuse a saved answer, else ask and save it."""
    picked = state.get("deadline_alerts")
    if picked is None:
        picked = pick_deadline_alerts(notifications)
        state["deadline_alerts"] = picked
        _save_partial(state)
    return picked


def pick_daily_summary(
    channels: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    """Daily summary and chat approvals. Returns ``(my_work, notifications_email,
    slack_extras, env_vars_needed)``.

    The daily summary ([my_work]) sends each person what is waiting for them
    (approvals, questions, results, spending) at their own hour through their
    linked chat apps and email; off unless asked for. Slack approvals need the
    channel to post cards in and, for the web (non-Socket) receiver, the
    signing secret.
    """
    my_work: dict[str, Any] = {}
    mail: dict[str, Any] = {}
    slack: dict[str, Any] = {}
    envs: list[str] = []
    if _q_confirm(
        "Send each person a daily summary of what is waiting for them "
        "(approvals, questions, results, spending)?",
        default=False,
    ):
        hour = _safe_int(_q_text("  Usual local hour to send it (0-23)", default="8"), default=8)
        my_work = {"digest_enable": True, "digest_hour": max(0, min(23, hour))}
        if _q_confirm("  Send summaries by email too? (needs a mail server)", default=False):
            host = _q_text("  Outgoing mail server (e.g. smtp.example.com)", default="").strip()
            port = _safe_int(_q_text("  Mail server port", default="587"), default=587) if host else 587
            sender = _q_text("  Send as (address)", default="").strip() if host else ""
            if "@" in sender:
                mail = {
                    "host": host,
                    "port": port,
                    "user": "${MAVERICK_SMTP_USER}",
                    "password": "${MAVERICK_SMTP_PASSWORD}",
                    "from_address": sender,
                    # Port 465 is TLS from the first byte (RFC 8314); others upgrade with STARTTLS.
                    "tls": "ssl" if port == 465 else "starttls",
                }
                envs += ["MAVERICK_SMTP_USER", "MAVERICK_SMTP_PASSWORD"]
            elif host:
                # Without a sender the server above is never used for summaries.
                console.print("  [yellow]Email summaries need a sender address, so email stays off. "
                              "Add it later in Lightwork > Settings > Email alerts.[/yellow]")
    if channels and "slack" in channels and _q_confirm(
        "Post new approval requests in a Slack channel with Approve / Reject buttons?",
        default=False,
    ):
        room = _q_text("  Slack channel id (starts with C)", default="").strip()
        if room:
            slack["approvals_channel"] = room
        if _q_confirm(
            "  Will buttons and /lightwork commands reach this server over the web "
            "(Interactivity URL) rather than Socket Mode?",
            default=False,
        ):
            slack["signing_secret"] = "${SLACK_SIGNING_SECRET}"
            envs.append("SLACK_SIGNING_SECRET")
    return my_work, mail, slack, envs


def _daily_summary_step(
    state: dict[str, Any], channels: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Run (or resume) the daily-summary step and fold Slack extras into the
    Slack channel table. Returns ``(my_work, notifications_email, envs)``."""
    parts = state.get("_daily_summary") or list(pick_daily_summary(channels))
    state["_daily_summary"] = parts
    my_work, mail, slack_extras, envs = parts
    if slack_extras and isinstance(channels.get("slack"), dict):
        channels["slack"].update(slack_extras)
    return my_work, mail, list(envs)


def pick_webhooks() -> tuple[dict[str, Any], list[str]]:
    """Outbound run-lifecycle webhooks. Returns (config, env_vars_needed).

    Distinct from pick_notifications (a single run-end ping): these are
    signed POSTs fired on every lifecycle event (goal_created,
    goal_finished, episode_finished, final_emitted) to one or more
    endpoints, for integrations (Zapier, custom receivers, dashboards).
    """
    if not _q_confirm(
        "POST run events to your own endpoint(s)? (signed lifecycle webhooks)",
        default=False,
    ):
        return {}, []
    raw = _q_text(
        "  Endpoint URL(s), comma-separated",
        default="",
    ).strip()
    urls = _csv_list(raw)
    if not urls:
        return {}, []
    cfg: dict[str, Any] = {"outbound": urls}
    envs: list[str] = []
    if _q_confirm("  Sign payloads with an HMAC secret?", default=True):
        cfg["secret"] = "${MAVERICK_WEBHOOK_SECRET}"
        envs.append("MAVERICK_WEBHOOK_SECRET")
    return cfg, envs


def pick_support() -> dict[str, Any]:
    """Help and support links, asked with the daily summary. Returns the
    ``[support]`` table (empty when skipped).

    ``status_page_url``: a public service-status page the Help menu links to.
    ``contact_email``: where "Get help from a person" requests are addressed;
    without one people send them to their Lightwork administrator. Nothing is
    ever sent automatically (``maverick.config.get_support``)."""
    if not _q_confirm(
        "Add a service-status page or a support contact to the Help menu? Without them, people send help requests to their Lightwork administrator.",
        default=False,
    ):
        return {}
    # The kernel's own patterns: get_support() drops any other value unseen.
    from maverick.config import _SUPPORT_EMAIL_RE, _SUPPORT_URL_RE

    support: dict[str, Any] = {}
    url = _q_text("  Public service-status page (https://..., empty for none):", default="").strip()
    if _SUPPORT_URL_RE.fullmatch(url):
        support["status_page_url"] = url
    elif url:
        console.print("[yellow]Skipped: the status page must be a secure https:// address.[/yellow]")
    email = _q_text("  Support contact email (empty: people ask their administrator):", default="").strip()
    if _SUPPORT_EMAIL_RE.fullmatch(email):
        support["contact_email"] = email
    elif email:
        console.print("[yellow]Skipped: that is not an email address.[/yellow]")
    return support


def pick_collaboration() -> dict[str, Any]:
    """Comments and @mentions on tasks, runs, approvals and policies. ON by default.

    People discuss a piece of work where it lives and mention a colleague, who
    gets it in their own notifications. Only people who can open the item can
    read its comments or be mentioned. Written as ``[collaboration] comments``
    (``maverick.comments``); declining writes ``comments = false``.
    """
    if _q_confirm(
        "Let people comment on tasks, runs, approval requests and policies, and mention a colleague "
        "to notify them? Only people who can open the item see its comments.",
        default=True,
    ):
        return {}
    return {"comments": False}


def pick_suggestions() -> dict[str, Any]:
    """Suggested edits to AI use rules, data use rules and privacy notices. ON by default.

    Agents and colleagues suggest new wording; each suggestion changes nothing
    until a person accepts it. Written as ``[collaboration] suggestions`` and
    ``ai_suggestions`` (``maverick.policy_suggestions``); declining writes false.
    """
    if not _q_confirm(
        "Let agents and colleagues suggest edits to your AI use rules, data use rules and privacy notices? "
        "Each suggestion shows what it changes and why. Accepting one creates a draft that still needs its usual approval.",
        default=True,
    ):
        return {"suggestions": False}
    if _q_confirm(
        "Let the AI assistant draft a suggested edit when someone asks? Each draft uses the AI service "
        "within the spending cap for one task.",
        default=True,
    ):
        return {}
    return {"ai_suggestions": False}


def pick_contact_centre() -> tuple[dict[str, Any], list[str]]:
    """Where a human handoff goes outside Lightwork. Returns (config, env_vars_needed).

    Off unless chosen, and nothing is sent until the chosen provider is complete.
    The Zendesk API token and the webhook signing secret are not asked for here
    and are never written to the config file: enter them on the Settings page
    (Integrations, Contact centre; stored sealed), or set the
    MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN or MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET
    environment variable (``maverick.contact_centre``)."""
    from maverick.config import (
        _CONTACT_CENTRE_EMAIL_RE,
        _CONTACT_CENTRE_SUBDOMAIN_RE,
        _https_or_empty,
    )

    provider = _q_select(
        "Send handed-off conversations to a contact centre outside Lightwork?",
        ["off", "zendesk", "webhook"],
        default="off",
    )
    if provider == "off":
        return {}, []
    cfg: dict[str, Any] = {"provider": provider}
    if provider == "zendesk":
        subdomain = _q_text("  Zendesk subdomain (the part before .zendesk.com):", default="").strip()
        email = _q_text("  Zendesk agent email whose API token is used:", default="").strip()
        if not _CONTACT_CENTRE_SUBDOMAIN_RE.fullmatch(subdomain) or not _CONTACT_CENTRE_EMAIL_RE.fullmatch(email):
            console.print("[yellow]Skipped: enter a Zendesk subdomain such as acme-support and an agent email.[/yellow]")
            return {}, []
        cfg.update(zendesk_subdomain=subdomain, zendesk_email=email)
    else:
        url = _q_text("  Webhook address (https://...):", default="").strip()
        if not _https_or_empty(url):
            console.print("[yellow]Skipped: the webhook must be a secure https:// address.[/yellow]")
            return {}, []
        cfg["webhook_url"] = url
    link = _q_text("  Lightwork web address for links in each ticket (https://..., empty for none):", default="").strip()
    if link and _https_or_empty(link):
        cfg["dashboard_url"] = link
    elif link:
        console.print("[yellow]Skipped the link: use a secure https:// address.[/yellow]")
    console.print("[dim]Add the API token or signing secret on the Settings page (Contact centre) "
                  "before handoffs are sent. Until then nothing is sent.[/dim]")
    return cfg, []


def pick_deliverable_handoff() -> tuple[dict[str, Any], list[str]]:
    """System-of-record hand-off for APPROVED deliverables. Returns
    (config, env_vars_needed).

    Distinct from lifecycle webhooks: this fires only when a human signs off a
    gated deliverable (a forecast, a CECL memo), POSTing it to a downstream
    system (treasury / GL / Jira) so an approved result lands there instead of
    being re-keyed by hand. Signed with the same [webhooks] HMAC secret."""
    if not _q_confirm(
        "POST approved deliverables to a system-of-record endpoint?",
        default=False,
    ):
        return {}, []
    url = _q_text("  System-of-record endpoint URL", default="").strip()
    if not url:
        return {}, []
    return {"handoff_webhook": url}, []


def pick_persona_roles() -> dict[str, Any]:
    """Bind the operator to persona consumer role(s) for the deliverables inbox.

    Sets ``[personas] default`` so the signed-in user lands on their own
    deliverables ("my forecasts") instead of the full list. Per-user mappings
    (``[personas]`` keyed by principal) are added later like RBAC roles; this is
    the single-user default."""
    if not _q_confirm(
        "Default the deliverables inbox to your own role(s)?",
        default=False,
    ):
        return {}
    raw = _q_text(
        "  Your primary role(s) (e.g. fpa_analyst, controller; space/comma separated)",
        default="",
    ).strip()
    roles = [r.strip() for r in raw.replace(",", " ").split() if r.strip()]
    return {"default": roles} if roles else {}


def pick_connectors() -> dict[str, str]:
    """Collect credentials for enterprise connectors (ServiceNow, Salesforce,
    Snowflake, SAP, ...).

    Connectors are always registered in the kernel; they only need their
    BASE_URL/TOKEN env vars set to work. Returns ``{ENV_NAME: value}`` for the
    systems the user chose to connect now, merged into ~/.maverick/.env. The
    catalog (and ``docs/connectors.md``) come from ``connector_catalog()`` in
    maverick-core, so this stays in sync as connectors are added. Secrets
    collected here are never persisted to the partial-state file.
    """
    try:
        from maverick.tools.enterprise_connectors import connector_catalog

        entries = connector_catalog()
    except Exception as e:  # maverick-core not importable / catalog moved
        console.print(f"[yellow]Connector catalog unavailable: {e}[/yellow]")
        return {}
    if not entries:
        return {}
    console.print()
    console.print(
        f"[dim]Lightwork ships {len(entries)} enterprise connectors "
        "(ServiceNow, Salesforce, Snowflake, SAP, Workday, Datadog, ...). "
        "Connect any now, or add supported systems later on the "
        "Lightwork Connections page.[/dim]"
    )
    if not _q_confirm("Connect any enterprise systems now?", default=False):
        return {}
    by_name = {e["name"]: e for e in entries}
    raw = _q_text(
        "  Which systems? (comma-separated names, e.g. servicenow, snowflake)",
        default="",
    )
    picked = _csv_list(raw, lower=True)
    keys: dict[str, str] = {}
    for name in dict.fromkeys(picked):  # dedupe, preserve order
        entry = by_name.get(name)
        if entry is None:
            console.print(
                f"  [yellow]unknown connector '{name}' — skipped "
                "(see docs/connectors.md for valid names)[/yellow]"
            )
            continue
        console.print(f"  [bold]{entry['label']}[/bold]")
        for env_name, is_secret in entry["env"]:
            current = os.environ.get(env_name, "")
            if is_secret:
                masked = (current[:4] + "...") if current else "(none)"
                val = _q_secret(f"    {env_name} [current: {masked}] (blank = keep current)")
                if not val and current:
                    val = current
            else:
                val = _q_text(f"    {env_name}", default=current)
            if val:
                keys[env_name] = val
    return keys


# ---------- monitoring and key management ----------

_MONITORING_TRACE_DEFAULT = TEXT_SETTINGS["observability.otel_endpoint"].runtime_default
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Syntax is shared with dashboard settings through maverick.config_contracts.
_SIEM_KINDS: list[tuple[str, str]] = [
    ("https", "A web address (https://)"),
    ("tcp", "Syslog over TCP (host:port)"),
    ("udp", "Syslog over UDP (host:port)"),
    ("datadog", "Datadog"),
    ("sentinel", "Microsoft Sentinel"),
]
_SIEM_ADDRESS_EXAMPLES = {
    "https": "https://collector.example.com/services/collector/raw",
    "tcp": "siem.example.com:514",
    "udp": "siem.example.com:514",
    "sentinel": "sentinel://<data-collection-host>/<dcr-id>/Custom-<stream>",
}
# The schemes each kind of destination may use: https also takes http, which is asked for.
_SIEM_SCHEMES = {
    "https": {"https", "http"}, "tcp": {"tcp"}, "udp": {"udp"}, "sentinel": {"sentinel"},
}
_KMS_PROVIDERS: list[tuple[str, str]] = [
    ("local", "On this computer (Lightwork's own keys, the default)"),
    ("aws", "Amazon Web Services key service"),
    ("gcp", "Google Cloud key service"),
    ("vault", "HashiCorp Vault"),
    ("azure", "Azure Key Vault or Managed HSM"),
]


def _choice_value(choices: list[tuple[str, str]], label: str) -> str:
    """The value behind a label that a select prompt returned."""
    return next(value for value, shown in choices if shown == label)


def _ask_until(message: str, *, default: str, check: Callable[[str], str | None]) -> str:
    """Ask a text question until ``check`` accepts the answer; ``check`` returns the
    problem to show, or ``None`` when the answer is fine."""
    while True:
        answer = _q_text(message, default=default).strip()
        problem = check(answer)
        if problem is None:
            return answer
        console.print(f"  [yellow]{problem}[/yellow]")


def _web_address_problem(value: str, schemes: tuple[str, ...]) -> str | None:
    """Why ``value`` is not a web address of one of ``schemes``, or ``None``."""
    try:
        parts = urlsplit(value)
        valid = (parts.scheme in schemes and bool(parts.hostname)
                 and "@" not in parts.netloc)
    except ValueError:
        valid = False
    if valid:
        return None
    return ("Enter a web address that starts with " + " or ".join(f"{s}://" for s in schemes)
            + " and has no user name or password in it.")


def _ask_credential(env_name: str, label: str) -> str:
    """A credential for ~/.maverick/.env, asked the way the connector prompts ask: blank
    keeps the value the environment already holds."""
    current = os.environ.get(env_name, "")
    masked = (current[:4] + "...") if current else "(none)"
    return _q_secret(f"  {label} [current: {masked}] (blank = keep current)").strip() or current


def _ask_azure_id(env_name: str, label: str) -> str:
    """An Azure directory or app ID, checked with the forwarder's own pattern. Blank
    returns ``""``, which leaves the service off."""
    from maverick.audit.forwarder import _AZURE_ID_RE

    current = os.environ.get(env_name, "")
    while True:
        answer = _q_text(f"  {label} (blank = leave this service off)", default=current).strip()
        if not answer or _AZURE_ID_RE.fullmatch(answer):
            return answer
        console.print("  [yellow]Enter the ID as Azure shows it: letters, digits, dots and "
                      "dashes.[/yellow]")


def _collector_problem(address: str) -> str | None:
    problem = _web_address_problem(address, ("http", "https"))
    if problem is not None:
        return problem
    # Traces name tasks and tools, so plain http is only for a collector on this computer.
    if urlsplit(address).scheme == "http" and urlsplit(address).hostname not in _LOCAL_HOSTS:
        return ("Only a collector on this computer may use http://. Enter an https:// address, "
                "so the traces are encrypted on the way.")
    if not TEXT_SETTINGS["observability.otel_endpoint"].matches(address):
        return "Enter a collector address with no spaces, quotes, question marks or # in it."
    return None


def _ask_measurements(address: str) -> bool:
    """Whether measurements also go to ``address``. They need an address that ends in
    /v1/traces, so a yes with another address is asked again; a no always stands."""
    from maverick.observability import _otlp_metrics_endpoint

    while True:
        if not _q_confirm(
            "  Also send measurements (counts, timings and spending) to the same collector? "
            "(They name tools and models.)",
            default=False,
        ):
            return False
        if _otlp_metrics_endpoint(address) is not None:
            return True
        console.print("  [yellow]Measurements need a collector address that ends in /v1/traces. "
                      "Answer no to leave them off.[/yellow]")


def _pick_trace_collector() -> dict[str, Any]:
    """The ``[observability]`` table for an OpenTelemetry collector, or ``{}`` to skip."""
    if not _q_confirm(
        "Send a trace of each task's steps to a monitoring collector? "
        "(Traces name tasks and tools.)",
        default=False,
    ):
        return {}
    address = _ask_until(
        "  Collector address",
        default=_MONITORING_TRACE_DEFAULT,
        check=_collector_problem,
    )
    observability: dict[str, Any] = {"otel_exporter": "otlp", "otel_endpoint": address}
    if _ask_measurements(address):
        observability["otlp_metrics"] = True
    return {"observability": observability}


def _key_name_problem(value: str) -> str | None:
    if not TEXT_SETTINGS["kms.key_id"].matches(value):
        return ("Enter the key name exactly as your key service shows it: letters, digits and "
                ": / . _ - only, without spaces.")
    return None


def _azure_key_problem(value: str) -> str | None:
    from maverick.kms_backends import _azure_key_parts

    if not TEXT_SETTINGS["kms.key_id"].matches(value) or _azure_key_parts(value) is None:
        return ("Enter the key's web address, such as https://<vault>.vault.azure.net/keys/<name>, "
                "optionally with its version at the end.")
    return None


def _region_problem(value: str) -> str | None:
    if value and not TEXT_SETTINGS["kms.region"].matches(value):
        return "Enter a region name such as us-east-1, or leave the answer blank."
    return None


def _vault_address_problem(value: str) -> str | None:
    problem = _web_address_problem(value, ("https",))
    if problem is None and not TEXT_SETTINGS["kms.address"].matches(value):
        return "Enter a web address with no spaces, quotes, question marks or # in it."
    return problem


def _vault_mount_problem(value: str) -> str | None:
    if value and not TEXT_SETTINGS["kms.mount"].matches(value):
        return "Enter the name of the Vault key area: letters, digits and . _ - only."
    return None


def _pick_key_service(keys: dict[str, str]) -> dict[str, Any]:
    """The ``[kms]`` table for a cloud key service, or ``{}`` to keep the built-in keys."""
    labels = [label for _value, label in _KMS_PROVIDERS]
    provider = _choice_value(_KMS_PROVIDERS, _q_select(
        "Where should Lightwork lock each workspace's data keys? Choose before Lightwork stores "
        "any data: data already locked with the built-in keys is not moved to a new service.",
        labels, default=labels[0],
    ))
    if provider == "local":
        return {}
    kms: dict[str, Any] = {"provider": provider}
    if provider == "azure":
        kms["key_id"] = _ask_until(
            "  Key address (https://<vault>.vault.azure.net/keys/<name>)",
            default="", check=_azure_key_problem)
    else:
        kms["key_id"] = _ask_until(
            "  Key name at the service", default="", check=_key_name_problem)
    if provider == "aws":
        region = _ask_until(
            "  Region of the key (blank = the AWS_REGION setting)", default="",
            check=_region_problem)
        if region:
            kms["region"] = region
    if provider == "vault":
        kms["address"] = _ask_until(
            "  Vault web address (https://...)", default="", check=_vault_address_problem)
        mount = _ask_until(
            "  Vault key area", default=TEXT_SETTINGS["kms.mount"].runtime_default,
            check=_vault_mount_problem) or TEXT_SETTINGS["kms.mount"].runtime_default
        if mount != TEXT_SETTINGS["kms.mount"].runtime_default:
            kms["mount"] = mount
        token = _ask_credential("VAULT_TOKEN", "Vault access token")
        if not token:
            console.print("  [yellow]Not saved: HashiCorp Vault needs its access token, so the "
                          "built-in keys stay in use.[/yellow]")
            return {}
        keys["VAULT_TOKEN"] = token
    return {"kms": kms}


def _siem_address_problem(address: str, kind: str) -> str | None:
    """Why ``address`` is not a valid destination of ``kind``, or ``None``.

    The kernel's own parser decides. Its error text can echo the address, so that text
    is not shown.
    """
    from maverick.audit.forwarder import parse_dest

    try:
        if "@" in urlsplit(address).netloc:
            return "Leave out any user name or password. The access key is asked on its own."
        scheme = parse_dest(address)[0]
    except ValueError:
        return "Lightwork cannot send to that address. Check it against the example."
    if scheme not in _SIEM_SCHEMES[kind]:
        return ("That address is not one of the kind you chose. Example: "
                f"{_SIEM_ADDRESS_EXAMPLES[kind]}")
    if not TEXT_SETTINGS["audit.siem_dest"].matches(address):
        return "Lightwork cannot send to that address. Check it against the example."
    return None


def _ask_siem_address(kind: str) -> str | None:
    """A destination address of ``kind``, asked until the kernel accepts it; ``None`` when
    left blank. A plain http:// address is accepted only when the operator says so."""
    from maverick.audit.forwarder import parse_dest

    while True:
        answer = _q_text(
            f"  Address (for example {_SIEM_ADDRESS_EXAMPLES[kind]}; blank = leave this off)",
            default="",
        ).strip()
        if not answer:
            return None
        if kind in ("tcp", "udp") and "://" not in answer:
            answer = f"{kind}://{answer}"
        problem = _siem_address_problem(answer, kind)
        if problem is not None:
            console.print(f"  [yellow]{problem}[/yellow]")
            continue
        if parse_dest(answer)[0] == "http" and not _q_confirm(
            "  This address is not encrypted, so activity records cross the network in plain "
            "text. Use it anyway?",
            default=False,
        ):
            continue
        return answer


def _siem_credentials(scheme: str) -> dict[str, str] | None:
    """The credentials a destination needs, as ``{ENV_NAME: value}`` for ~/.maverick/.env,
    or ``None`` when a required one is left blank."""
    if scheme == "https":
        # Sent only over https: the kernel refuses to send it over plain http.
        token = _ask_credential("MAVERICK_SIEM_TOKEN", "Access key for the service")
        return {"MAVERICK_SIEM_TOKEN": token} if token else {}
    if scheme == "datadog":
        values = {"MAVERICK_DATADOG_API_KEY": _ask_credential(
            "MAVERICK_DATADOG_API_KEY", "Datadog API key")}
    elif scheme == "sentinel":
        values = {
            "MAVERICK_SENTINEL_TENANT_ID": _ask_azure_id(
                "MAVERICK_SENTINEL_TENANT_ID", "Directory (tenant) ID"),
            "MAVERICK_SENTINEL_CLIENT_ID": _ask_azure_id(
                "MAVERICK_SENTINEL_CLIENT_ID", "App (client) ID"),
            "MAVERICK_SENTINEL_CLIENT_SECRET": _ask_credential(
                "MAVERICK_SENTINEL_CLIENT_SECRET", "App client secret"),
        }
    else:
        # tcp and udp carry no credentials; plain http gets no token, which the kernel
        # would refuse to send anyway.
        return {}
    if not all(values.values()):
        console.print("  [yellow]Not saved: this service needs its access details. Add the "
                      "destination later in Lightwork Settings.[/yellow]")
        return None
    return values


def _pick_siem_destination() -> tuple[str, dict[str, str]] | None:
    """``(siem_dest, credentials)`` for a security monitoring service, or ``None`` to skip."""
    from maverick.audit.forwarder import _DATADOG_SITES, parse_dest

    if not _q_confirm(
        "Send each activity record to a security monitoring service?", default=False,
    ):
        return None
    labels = [label for _value, label in _SIEM_KINDS]
    kind = _choice_value(_SIEM_KINDS, _q_select(
        "Which kind of service?", labels, default=labels[0]))
    if kind == "datadog":
        site = _q_select("Datadog site", sorted(_DATADOG_SITES), default="datadoghq.com")
        address = f"datadog://{site}"
    else:
        address = _ask_siem_address(kind)
        if address is None:
            return None
    creds = _siem_credentials(parse_dest(address)[0])
    if creds is None:
        return None
    return address, creds


def _siem_destination(monitoring: dict[str, Any] | None) -> str:
    """The ``[audit] siem_dest`` the monitoring step chose, or ``""``."""
    return str(((monitoring or {}).get("audit") or {}).get("siem_dest") or "")


def _cfg_monitoring(monitoring: dict[str, Any] | None) -> list[str]:
    """``[observability]`` and ``[kms]`` from the monitoring step. A skipped answer writes
    nothing; ``[audit] siem_dest`` is written by ``_cfg_advanced``, which owns that table."""
    monitoring = monitoring or {}
    return (_cfg_table("observability", monitoring.get("observability"))
            + _cfg_table("kms", monitoring.get("kms")))


def pick_monitoring() -> tuple[dict[str, Any], dict[str, str]]:
    """The optional monitoring and key-management step. Returns ``(config, keys)``.

    ``config`` holds the ``[observability]`` and ``[kms]`` tables and the ``[audit]``
    ``siem_dest``. ``keys`` maps environment names to credential values for
    ~/.maverick/.env, the file that holds the provider keys and connector credentials, so
    config.toml never holds a credential. Every question defaults to no, and a skipped
    answer writes nothing.
    """
    config: dict[str, Any] = {}
    keys: dict[str, str] = {}
    console.print()
    console.print(
        "[dim]Optional. Skip a question to keep the default, which sends nothing and keeps "
        "Lightwork's own keys.[/dim]"
    )
    config.update(_pick_trace_collector())
    config.update(_pick_key_service(keys))
    destination = _pick_siem_destination()
    if destination is not None:
        address, creds = destination
        config["audit"] = {"siem_dest": address}
        keys.update(creds)
    return config, keys


def collect_api_keys(providers: list[str], channel_envs: set[str]) -> dict[str, str]:
    keys: dict[str, str] = {}
    needed: list[str] = []

    for prov in providers:
        info = catalog.PROVIDERS.get(prov, {})
        env_name = info.get("env")
        if env_name:
            needed.append(env_name)
        needed.extend(info.get("env_vars", []))

    needed.extend(sorted(channel_envs))

    if not needed:
        return keys

    console.print()
    console.print("[bold]API keys / tokens[/bold] (stored in ~/.maverick/.env, chmod 600)")
    for env_name in dict.fromkeys(needed):  # dedupe preserving order
        current = os.environ.get(env_name, "")
        masked = (current[:7] + "...") if current else "(none)"
        val = _q_secret(f"  {env_name} [current: {masked}] (leave blank to keep current)")
        if not val:
            if current:
                keys[env_name] = current
            continue

        # Validate when we know how, with a 7-day cache so re-runs of
        # the wizard don't burn an API round-trip on every key.
        validator = _VALIDATORS.get(env_name)
        if validator:
            cached = _cached_validation(env_name, val)
            if cached is not None:
                ok, msg = cached
                console.print(f"    {_validation_marker(ok, msg)} {msg} (cached)")
            else:
                ok, msg = validator(val)
                console.print(f"    {_validation_marker(ok, msg)} {msg}")
                _remember_validation(env_name, val, ok, msg)
            if not ok and not _q_confirm("Save anyway?", default=False):
                continue
        keys[env_name] = val
    return keys


# ---------- write + verify ----------


def pick_a2a() -> tuple[dict[str, Any], list[str]]:
    """Expose Lightwork to other agents over A2A. Returns (config, envs).

    Off by default: A2A is an outward-facing surface (other agents can
    discover this instance and delegate budget-spending goals to it). When
    enabled we require a bearer token (MAVERICK_A2A_TOKEN) so the task
    endpoint isn't open; the agent card + task endpoint mount on the
    dashboard at /a2a/v1.
    """
    if not _q_confirm(
        "Expose this agent over A2A so other agents can delegate goals to it?",
        default=False,
    ):
        return {}, []
    console.print(
        "  [dim]A2A serves an agent card at /.well-known/agent-card.json and a "
        "task endpoint at /a2a/v1 (on `maverick dashboard`). Budget is clamped "
        "to operator caps; a bearer token is required. A2A goals run under a "
        "tool ceiling (medium by default). After installation, use All settings > "
        "Security > Requests from other agents to manage its password, public "
        "address, tool permissions and limits. External agents issues individual "
        "access keys.[/dim]"
    )
    return {"enabled": True, "max_risk": "medium"}, ["MAVERICK_A2A_TOKEN"]


# Business-function agent suites the factory can spawn from (domain packs under
# maverick/domains/). The kernel's enabled_domains() honors the [suites] table
# this writes; suites are ON by default (opt-out), so writing nothing keeps all.
AGENT_SUITES: list[tuple[str, str]] = [
    ("operations", "Operations / Supply Chain"),
    ("legal", "Legal (General Counsel)"),
    ("finance", "Finance"),
    ("it_grc", "IT / GRC / Security / Privacy / AI-Governance"),
    ("sales_gtm", "Sales / GTM"),
    ("hr", "HR / People"),
    ("product_engineering", "Product & Engineering"),
    ("strategy", "Strategy / Corp Dev / Exec"),
    ("customer_experience", "Customer Experience / Support"),
    ("marketing", "Marketing / Communications"),
    ("procurement", "Procurement / Sourcing"),
    ("data_analytics", "Data & Analytics"),
    ("security_ops", "Security Operations"),
    ("executive_office", "Executive Office / Chief of Staff"),
    ("facilities_ehs", "Facilities / EHS"),
    ("healthcare", "Healthcare (RCM / Payer Ops)"),
    ("insurance", "Insurance (Claims / Underwriting Support)"),
    ("banking", "Banking / Credit Union Ops"),
    ("retail", "Retail / E-commerce"),
    ("manufacturing_vertical", "Manufacturing (Vertical)"),
    ("construction", "Construction / AEC"),
    ("logistics", "Logistics / Transportation"),
    ("professional_services", "Professional Services"),
    ("government_contracting", "Government Contracting"),
    ("education_nonprofit", "Education / Nonprofit"),
    ("tax", "Tax Preparation (CPA Firms)"),
    # Additional verticals.
    ("utilities", "Energy / Utilities"),
    ("real_estate", "Real Estate / Property Management"),
    ("pharma_lifesciences", "Pharma / Life Sciences"),
    ("telecom_media", "Telecom / Media & Entertainment"),
    ("hospitality", "Hospitality / Travel"),
    ("capital_markets", "Capital Markets / Asset Management"),
    # New industry suites (2026 build-out).
    ("oil_gas", "Oil & Gas / Energy (Upstream-Downstream)"),
    ("automotive", "Automotive (OEM / Dealership / Mobility)"),
    ("public_sector", "Public Sector (State & Local Government Operations)"),
    ("agriculture", "Agriculture / Agribusiness"),
    ("aerospace_defense", "Aerospace & Defense"),
    ("maritime", "Maritime / Shipping & Ports"),
    ("travel_aviation", "Travel / Airlines & Aviation"),
    ("mining_metals", "Mining & Metals"),
    ("crypto_digital_assets", "Crypto & Digital Assets"),
    ("chemicals", "Chemicals (Bulk / Specialty / Petrochemical)"),
    ("food_beverage_cpg", "Food, Beverage & CPG"),
    ("medical_devices", "Medical Devices & Diagnostics"),
    ("private_equity_vc", "Private Equity & Venture Capital"),
    ("water_utilities", "Water & Wastewater Utilities"),
    ("renewables_cleantech", "Renewables & Clean Energy"),
    ("semiconductors", "Semiconductors & Electronics"),
    # Horizontal-function suites.
    ("esg_sustainability", "ESG & Sustainability"),
    ("enterprise_risk", "Enterprise Risk & Corporate Insurance"),
    ("knowledge_management", "Knowledge Management"),
    ("trust_safety", "Trust & Safety"),
    ("process_automation", "Process Automation & Workflows"),
    ("commerce", "Commerce (Shopper & Merchant Agents)"),
]


def pick_suites() -> dict[str, bool]:
    """Which business-function agent suites to enable. All on unless customized.

    Returns a ``suite -> bool`` map for the ``[suites]`` config table (empty when
    the operator keeps the default, so the kernel enables every suite)."""
    console.print()
    console.print(
        "[bold]Agent suites[/bold] — the business functions the agent "
        "factory can spawn (finance, operations, legal, ...)."
    )
    console.print(
        "[dim]All enabled by default. A disabled suite's agents can't be "
        "spawned. Choose carefully: suite availability is an "
        "installation-level choice.[/dim]"
    )
    if not _q_confirm("  Customize which suites are enabled? (No = keep all on)", default=False):
        return {}
    out: dict[str, bool] = {}
    for key, label in AGENT_SUITES:
        out[key] = _q_confirm(f"    Enable the {label} suite?", default=True)
    return out


def _cfg_deployment(deployment: str | None) -> list[str]:
    if not deployment:
        return []
    # Record the chosen deployment topology (laptop / vps / ...) for
    # provenance.
    return [
        "[deployment]",
        f"type = {_toml_str(str(deployment))}",
        "",
    ]


def _cfg_governance(
    profile: str | None,
    finance: dict[str, Any] | None = None,
) -> list[str]:
    values: list[str] = []
    # Record the governance level chosen at onboarding. This is a label for
    # humans + dashboards: the enforceable knobs it expanded to ([audit],
    # [quotas], [self_improvement], retention, ...) are written explicitly
    # elsewhere in this file. Use the reviewed Settings control to switch levels.
    if profile:
        values.append(
            f"profile = {_toml_str(str(profile))}   "
            "# essentials | standard | regulated | custom"
        )
    if finance:
        # Finance governance scalars share this table with the onboarding
        # profile. Keeping a single owner prevents a profile + finance install
        # from declaring [governance] twice and invalidating the whole config.
        values.append('require_human_min_risk = "high"')
        if finance.get("require_fresh_human_approval"):
            # A prior persistent consent grant won't satisfy the Art-14 gate --
            # each paused action needs a fresh human decision.
            values.append("require_fresh_human_approval = true")
    if not values:
        return []
    return ["[governance]", *values, ""]


def _cfg_providers(
    providers: list[str],
    per_tenant_keys: bool = False,
    provider_options: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    lines: list[str] = []
    options = provider_options or {}
    if per_tenant_keys:
        # Bring-your-own-key: let an active tenant override the deployment-global
        # provider key with its own (resolved from the secret provider under a
        # tenant-scoped name; never stored in config). Bare [providers] scalars
        # MUST precede the [providers.<name>] subtables -- TOML rejects a scalar
        # added to a table after a subtable has opened it.
        lines.append("[providers]")
        lines.append("per_tenant_keys = true")
        lines.append("")
    for prov in providers:
        info = catalog.PROVIDERS.get(prov, {})
        lines.append(f"[providers.{prov}]")
        env_name = info.get("env")
        if prov == "bedrock":
            # Native Bedrock: IAM signing needs no key; a bearer token does.
            mode = str((options.get("bedrock") or {}).get("auth_mode") or "iam")
            lines.append("# iam = sign with AWS credentials/role (needs the bedrock "
                         "extra); api_key = Bedrock bearer in BEDROCK_API_KEY.")
            _emit_kv(lines, "auth_mode", mode)
            if mode == "api_key":
                lines.append(f'api_key = "${{{env_name}}}"')
            lines.append('# endpoint = "mantle"   # Opus 4.7+ (anthropic.claude-*); '
                         '"legacy" for Opus 4.6 and earlier')
            lines.append("")
            continue
        if prov == "vertex":
            # Google sign-in: no key. The project, region and model ID the operator entered.
            vertex = options.get("vertex") or {}
            for field in ("project_id", "region", "model_id"):
                value = str(vertex.get(field) or "").strip()
                if value:
                    _emit_kv(lines, field, value)
            lines.append("# Google Application Default Credentials sign in (gcloud login, a "
                         "service account, or workload identity); no key is stored.")
            lines.append("")
            continue
        if env_name:
            lines.append(f'api_key = "${{{env_name}}}"')
        if prov == "ollama":
            lines.append('base_url = "http://localhost:11434"')
        if prov == "openai_compatible":
            lines.append('base_url = "${OPENAI_COMPATIBLE_BASE_URL}"')
        lines.append("")
    return lines


def _cfg_role_models(role_models: dict[str, str], *, discovery: bool = True, guidance: bool = True, capability_tests: bool = False) -> list[str]:
    if not role_models and discovery and guidance and not capability_tests:
        return []
    lines = ["[models]"]
    if capability_tests:
        lines.append("capability_tests = true")
    if not guidance:
        lines.append("guidance = false")
    for role, spec in role_models.items():
        lines.append(f'{role} = "{spec}"')
    if not discovery:
        # Default-on in the app; only a deliberate "no" is written.
        lines.append("# Live model discovery off: Settings offers the shipped catalog only.")
        lines.append("discovery = false")
    lines.append("")
    return lines


def _cfg_channels(channels: dict[str, dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for ch_id, cfg in channels.items():
        lines.append(f"[channels.{ch_id}]")
        for k, v in cfg.items():
            # _emit_kv handles lists (e.g. the allowed_user_ids array) and
            # escapes string values; the old inline branch emitted a list as
            # a quoted string and didn't escape backslash paths.
            _emit_kv(lines, k, v)
        lines.append("")
    return lines


def _cfg_core(
    budget: dict[str, Any],
    safety: dict[str, Any],
    sandbox: dict[str, Any],
) -> list[str]:
    lines = ["[budget]"]
    for k, v in budget.items():
        _emit_kv(lines, k, v)
    lines.append("")
    lines.append("[safety]")
    for k, v in safety.items():
        _emit_kv(lines, k, v)
    lines.append("")
    lines.append("[sandbox]")
    for k, v in sandbox.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_approval(approval: dict[str, Any] | None) -> list[str]:
    if not approval:
        return []
    # Approvals page: undo window (the agent waits it out), high-risk
    # confirmation, and who approves a risky action the requester asked for.
    lines = ["", "[approval]"]
    for k, v in approval.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_skills(skills: dict[str, Any] | None) -> list[str]:
    if not skills:
        return []
    # Signed-skill policy. trusted_pubkeys = hex Ed25519 publisher keys
    # a signed SKILL.md must match; require_signed rejects unsigned ones.
    lines = ["", "[skills]"]
    for k, v in skills.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_self_learning(self_learning: dict[str, Any] | None) -> list[str]:
    if not self_learning:
        return []
    # Self-learning. enable gates the whole feature; sub-toggles let the
    # agent install skills, add MCP servers, and generate+run new tools.
    lines = ["", "[self_learning]"]
    for k, v in self_learning.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_research_execution(research_execution: dict[str, Any] | None) -> list[str]:
    """Emit the controller profile accepted by ``ResearchProfile`` exactly."""
    if research_execution is None:
        return []
    if research_execution == {"enable": False}:
        return ["", "[research_execution]", "enable = false"]

    from dataclasses import asdict

    from maverick.research_jobs import ResearchProfile

    profile = ResearchProfile.from_config(research_execution)
    lines = [
        "", "[research_execution]", "enable = true",
        f"image_id = {_toml_str(profile.image_id)}",
        f"queue_seconds = {profile.queue_seconds}",
    ]
    for evaluator in profile.evaluators:
        lines.extend((
            "", f"[research_execution.evaluators.{evaluator.id}]",
            f"version = {_toml_str(evaluator.version)}",
            f"stdout_sha256 = {_toml_str(evaluator.stdout_sha256)}",
        ))
    lines.extend(("", "[research_execution.limits]"))
    for name, value in asdict(profile.limits).items():
        _emit_kv(lines, name, value)
    return lines


def _cfg_candidate_promotion(candidate_promotion: dict[str, Any] | None) -> list[str]:
    if candidate_promotion is None:
        return []
    enabled = candidate_promotion.get("enable")
    if type(enabled) is not bool:
        raise ValueError("candidate promotion enable must be boolean")
    if enabled is False:
        if candidate_promotion != {"enable": False}:
            raise ValueError("disabled candidate promotion cannot retain active policy")
        return ["", "[candidate_promotion]", "enable = false"]
    expected = {
        "enable",
        "allowed_targets",
        "review_ttl_seconds",
        "canary_metric",
        "canary_comparison",
        "canary_threshold",
    }
    if set(candidate_promotion) != expected:
        raise ValueError("candidate promotion policy is incomplete or unsupported")
    targets = candidate_promotion["allowed_targets"]
    if (
        not isinstance(targets, list)
        or not targets
        or targets != sorted(set(targets))
        or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is None for value in targets)
    ):
        raise ValueError("candidate promotion targets must be unique safe names")
    ttl = candidate_promotion["review_ttl_seconds"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= 604800:
        raise ValueError("candidate promotion review lifetime is outside its bound")
    metric = candidate_promotion["canary_metric"]
    comparison = candidate_promotion["canary_comparison"]
    threshold = candidate_promotion["canary_threshold"]
    if not isinstance(metric, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", metric) is None:
        raise ValueError("candidate promotion canary metric is invalid")
    if comparison not in {"at_least", "at_most"}:
        raise ValueError("candidate promotion canary comparison is invalid")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int | float)
        or not math.isfinite(float(threshold))
    ):
        raise ValueError("candidate promotion canary threshold must be numeric")
    lines = ["", "[candidate_promotion]"]
    for key in (
        "enable",
        "allowed_targets",
        "review_ttl_seconds",
        "canary_metric",
        "canary_comparison",
        "canary_threshold",
    ):
        _emit_kv(lines, key, candidate_promotion[key])
    return lines


def _cfg_knowledge_access(knowledge_access: dict[str, Any] | None) -> list[str]:
    if knowledge_access is None:
        return []
    enabled = knowledge_access.get("enable")
    if type(enabled) is not bool:
        raise ValueError("knowledge access enable must be boolean")
    task_context = knowledge_access.get("task_context", False)
    if type(task_context) is not bool:
        raise ValueError("knowledge task context must be boolean")
    return ["", "[knowledge_access]", f"enable = {str(enabled).lower()}",
            f"task_context = {str(task_context).lower()}"]


def _cfg_ekko(ekko: dict[str, Any] | None) -> list[str]:
    if not ekko:
        return []
    # Policy only. The installer never starts/enrolls a workstation collector.
    lines = ["", "[ekko]"]
    for k, v in ekko.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_automation_import(automation_import: dict[str, Any] | None) -> list[str]:
    if not automation_import:
        return []
    # Automation import. enable gates the whole feature; create_schedules lets a
    # recovered cron trigger auto-create a Lightwork schedule on import.
    lines = ["", "[automation_import]"]
    for k, v in automation_import.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_event_triggers(event_triggers: dict[str, Any] | None) -> list[str]:
    if not event_triggers:
        return []
    # Event triggers. enable gates the whole feature; the app polls bound
    # sources on a background tick and fires the workflow per new item.
    lines = ["", "[event_triggers]"]
    for k, v in event_triggers.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_flows(flows: dict[str, Any] | None) -> list[str]:
    if not flows:
        return []
    # Flow engine. enable gates the visual multi-step workflow designer/runner;
    # public_url (optional) is the base URL for signed channel-approval links.
    lines = ["", "[flows]"]
    for k, v in flows.items():
        _emit_kv(lines, k, v)
    return lines


def _fold_flow_operator_options(flows: dict[str, Any], advanced: dict[str, Any]) -> None:
    """Keep explicit dedicated answers when merging the advanced flow step."""
    for key in ("learned_operators", "learned_operator_questions", "composed_operators",
                "action_recipes", "action_recipe_transforms", "action_recipe_choices", "action_recipe_teaching",
                "action_episode_capture", "action_workflow_learning", "action_workflow_memory_learning",
                "action_recipe_lineage", "require_action_recipe_lineage",
                "action_evidence_issuer", "action_evidence_revoked_keys"):
        advanced_key = "flows_" + key
        if advanced_key in advanced:
            flows.setdefault(key, advanced.pop(advanced_key))


def _cfg_knowledge(knowledge: dict[str, Any] | None) -> list[str]:
    if not knowledge:
        return []
    # Per-domain vector RAG (maverick-knowledge). enable gates the whole
    # feature; embedder/store/dsn are read by config.get_knowledge.
    lines = ["", "[knowledge]"]
    for k, v in knowledge.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_knowledge_sources(knowledge_sources: dict[str, Any] | None) -> list[str]:
    if not knowledge_sources:
        return []
    # Saved company folder and space limits. config.get_knowledge_sources reads
    # them at each refresh and refuses any value outside its range.
    lines = ["", "[knowledge_sources]"]
    for key, _label, _default, low, high in _KNOWLEDGE_SOURCE_LIMITS:
        value = knowledge_sources.get(key)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"knowledge_sources.{key} must be a whole number from {low} to {high}")
        lines.append(f"{key} = {value}")
    return lines


def _cfg_oauth(oauth: dict[str, Any] | None) -> list[str]:
    if not (oauth and oauth.get("vault")):
        return []
    # Seal captured OAuth tokens in the per-tenant vault (encrypted at rest).
    return ["", "[oauth]", "vault = true", f"desktop_return = {'true' if oauth.get('desktop_return') is True else 'false'}"]


def _cfg_governed_connectors(governed_connectors: dict[str, Any] | None) -> list[str]:
    if not (governed_connectors and governed_connectors.get("enable")):
        return []
    # Governed system-of-record connectors. enable turns on the governed write
    # path; connectors selects which reference REST connectors to register.
    lines = ["", "[governed_connectors]"]
    for k, v in governed_connectors.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_durable(durable: dict[str, Any] | None) -> list[str]:
    if not (durable and durable.get("enabled")):
        return []
    # Durable execution: checkpoint loop state so `maverick resume`
    # continues from the last step after a crash. Off unless opted in.
    lines = ["", "[durable]"]
    for k, v in durable.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_workspace(workspace: dict[str, Any] | None) -> list[str]:
    if not (workspace and workspace.get("journal")):
        return []
    # Workspace mutation journal: pre-image every file-tool write so
    # `maverick journal revert` can restore a goal's workspace. Off unless
    # opted in; journal_strict refuses writes it cannot journal.
    lines = ["", "[workspace]"]
    for k, v in workspace.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_value(value: dict[str, Any] | None) -> list[str]:
    if not value:
        return []
    # The client's cost/value assumptions behind the dashboard Savings page
    # (read by config.get_value; per-department overrides are added later from
    # the page itself).
    lines = ["", "[value]"]
    for k, v in value.items():
        _emit_kv(lines, k, v)
    return lines


def _cfg_intent_value(value: dict[str, Any] | None) -> list[str]:
    if value is None:
        return []
    lines = ["", "[intent_value]"]
    for key, setting in value.items():
        _emit_kv(lines, key, setting)
    return lines


def _cfg_finance(finance: dict[str, Any] | None) -> list[str]:
    if not finance:
        return []
    # Finance suite governance (finance-agent-suite): pause money movement for
    # a human, enforce compliance regimes (strictest-wins), and screen
    # sanctions. _cfg_governance owns the parent table and its scalar keys;
    # this helper emits only the finance-owned child and peer tables.
    lines: list[str] = []
    rha = finance.get("require_human_above") or 0
    if rha and rha > 0:
        lines.append("")
        lines.append("[governance.require_human_above]")
        lines.append(f'"*" = {rha}')
    da = finance.get("deny_above") or 0
    if da and da > 0:
        lines.append("")
        lines.append("[governance.deny_above]")
        lines.append(f'"*" = {da}')
    regimes = finance.get("regimes") or []
    framework = finance.get("finance_framework") or ""
    materiality = finance.get("finance_materiality") or 0
    if regimes or framework or materiality:
        lines.append("")
        lines.append("[finance]")
        if regimes:
            _emit_kv(lines, "regimes", regimes)
        if framework:
            _emit_kv(lines, "framework", framework)
        if materiality and materiality > 0:
            _emit_kv(lines, "materiality", materiality)
    for table, key, value in (
        ("finance.automation", "default", finance.get("finance_automation_default")),
        ("finance.sod", "mode", finance.get("finance_sod_mode")),
        ("finance.approvals", "timeout", finance.get("finance_approvals_timeout")),
    ):
        if value:
            lines.append("")
            lines.append(f"[{table}]")
            _emit_kv(lines, key, value)
    sdn = (finance.get("sdn_path") or "").strip()
    if sdn:
        lines.append("")
        lines.append("[screening]")
        _emit_kv(lines, "sdn_path", sdn)
    if "operations_enable" in finance:
        lines.append("")
        lines.append("[finance_operations]")
        _emit_kv(lines, "enable", finance.get("operations_enable") is True)
        if finance.get("operations_enable") is True:
            for key in (
                "federal_register_enable",
                "texas_register_enable",
                "eur_lex_enable",
                "edpb_enable",
                "regulatory_domains",
                "regulatory_poll_seconds",
                "control_test_interval_seconds",
                "anomaly_enable",
                "sanctions_max_age_hours",
                "control_owner",
            ):
                if key in finance:
                    _emit_kv(lines, key, finance[key])
            # State register sources are explicit arrays of tables added after
            # onboarding; an empty list is a clear, safe starting posture.
            lines.append("state_feeds = []")
    return lines


def _cfg_capabilities(
    capability_config: dict[str, Any],
    embedded_flash: bool,
) -> list[str]:
    lines: list[str] = []
    if capability_config:
        lines.append("")
        lines.append("[capabilities]")
        for k, v in capability_config.items():
            lines.append(f"{k} = {str(v).lower()}")
    if embedded_flash:
        lines.append("")
        lines.append("[embedded]")
        lines.append("allow_flash = true")
    return lines


def _cfg_practice(offered: bool, daily_spend_cap: float) -> list[str]:
    """``[practice]``: written only where it differs from the defaults (on, $1.00 a day)."""
    body = [] if offered else ["enable = false"]
    if offered and daily_spend_cap != 1.0:
        body.append(f"daily_spend_cap = {round(daily_spend_cap, 2)}")
    return ["", "[practice]", *body] if body else []


def _cfg_agent_factory(jd_hiring: bool, require_passing_tests: bool = True) -> list[str]:
    # JD hiring (maverick.jd_hiring) and the publish gate
    # (maverick.agent_publish_policy) are default-on in the kernel; only write
    # the table when the operator opted OUT, matching the
    # write-only-on-divergence convention.
    lines = []
    if not jd_hiring:
        lines.append("jd_hiring = false")
    if not require_passing_tests:
        lines.append("require_passing_tests = false")
    return ["", "[agent_factory]", *lines] if lines else []


def _cfg_agent_tests(values: dict[str, Any]) -> list[str]:
    # Saved answer checks (maverick.agent_tests_policy) default to today's
    # behaviour, so the table is written only where an answer differs.
    lines = []
    limit = int(values["max_cases_per_specialist"])
    if limit != INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].default:
        lines.append(f"max_cases_per_specialist = {limit}")
    if values["require_for_new_specialists"]:
        lines.append("require_for_new_specialists = true")
    if values["bypass_requires_second_person"]:
        lines.append("bypass_requires_second_person = true")
    if values.get("tool_checks"):
        lines.append("tool_checks = true")
    canary = int(values.get("canary_percent", INTEGER_SETTINGS["agent_tests.canary_percent"].default))
    if canary:
        lines.append(f"canary_percent = {canary}")
    if canary and values.get("canary_auto_rollback"):
        lines.append("canary_auto_rollback = true")
    return ["", "[agent_tests]", *lines] if lines else []


def _cfg_suites(suites: dict[str, bool] | None) -> list[str]:
    if not suites:
        return []
    # Per-suite enable/disable; the kernel's enabled_domains() reads this.
    lines = ["", "[suites]"]
    for k, v in suites.items():
        lines.append(f"{k} = {str(v).lower()}")
    return lines


# ``allow_*`` wizard key, the answer that writes a lock, and the ``[features]``
# line it writes. Order is the order the lines appear in the table.


def _cfg_mcp_servers(mcp_servers: dict[str, dict[str, Any]] | None) -> list[str]:
    if not mcp_servers:
        return []
    lines: list[str] = []
    for name, cfg in mcp_servers.items():
        lines.append("")
        # The server name is free text: a bare identifier goes in as-is, but a
        # name with dots/spaces/quotes must be a quoted+escaped TOML key or it
        # corrupts the table header (e.g. `foo"bar` or `a.b`).
        key = name if name.replace("_", "").replace("-", "").isalnum() else _toml_str(name)
        lines.append(f"[mcp_servers.{key}]")
        for k, v in cfg.items():
            _emit_kv(lines, k, v)
    return lines


def _cfg_registries(header: str, indexes: list[str] | None) -> list[str]:
    if not indexes:
        return []
    lines = ["", f"[{header}]"]
    _emit_kv(lines, "indexes", indexes)
    return lines


def _cfg_plugins(
    plugins: list[str] | None,
    plugin_grant: list[str] | None,
    plugin_enforce: bool,
    ts_plugins: list[list[str]] | None,
    workbench: bool | None = None,
) -> list[str]:
    if not (plugins or ts_plugins or workbench is not None):
        return []
    lines = ["", "[plugins]"]
    if workbench is not None:
        _emit_kv(lines, "workbench", workbench is True)
    if plugins:
        _emit_kv(lines, "enabled", plugins)
    if plugin_grant:
        _emit_kv(lines, "grant", plugin_grant)
    if plugin_enforce:
        _emit_kv(lines, "enforce_permissions", plugin_enforce)
    if ts_plugins:
        _emit_kv(lines, "ts", ts_plugins)
    return lines


def _cfg_security(
    tool_acl: dict[str, Any] | None, autofix: bool, dual_approval: bool = False
) -> list[str]:
    if not (tool_acl or autofix or dual_approval):
        return []
    lines = ["", "[security]"]
    if autofix:
        lines.append("auto_fix = true")
    if dual_approval:
        # N-of-M dual control (two-person rule): high/critical-risk actions need
        # 2 distinct approvers and the requester can't self-approve. See
        # docs/security-hardening.md. Use a [security.approvals_required] table
        # to vary N per risk band.
        lines.append("approvals_required = 2")
        lines.append("allow_self_approval = false")
    for k, v in (tool_acl or {}).items():
        if k == "channels":
            continue
        _emit_kv(lines, k, v)
    for ch_id, ch_cfg in ((tool_acl or {}).get("channels") or {}).items():
        lines.append("")
        lines.append(f"[security.channels.{ch_id}]")
        for k, v in ch_cfg.items():
            _emit_kv(lines, k, v)
    return lines


def _cfg_rate_limits(rate_limits: dict[str, str] | None) -> list[str]:
    if not rate_limits:
        return []
    lines = ["", "[rate_limits]"]
    for name, spec in rate_limits.items():
        # Quote names that aren't bare identifiers (e.g. "mcp_*").
        key = name if name.replace("_", "").isalnum() else f'"{name}"'
        # spec is free-text ("N/seconds"); escape via _toml_str so a stray
        # quote/backslash can't corrupt the config the wizard writes.
        lines.append(f"{key} = {_toml_str(spec)}")
    return lines


def _cfg_deadline_alerts(cfg: dict[str, Any] | None) -> list[str]:
    """``[deadline_alerts]`` plus its lead-time sub-tables (nested dicts are
    not something _emit_kv renders)."""
    if not cfg:
        return []
    flat = {k: v for k, v in cfg.items() if not isinstance(v, dict)}
    lines = _cfg_table("deadline_alerts", flat)
    for sub in ("lead_days", "lead_hours"):
        table = cfg.get(sub)
        if isinstance(table, dict) and table:
            # Lead times are whole numbers, not strings (what _emit_kv would write).
            lines += ["", f"[deadline_alerts.{sub}]"]
            for key, values in table.items():
                rendered = ", ".join(str(int(v)) for v in (values or []))
                lines.append(f"{key} = [{rendered}]")
    return lines


def _cfg_table(header: str, mapping: dict[str, Any] | None) -> list[str]:
    if not mapping:
        return []
    lines = ["", f"[{header}]"]
    for k, v in mapping.items():
        _emit_kv(lines, k, v)
    return lines


def _backup_wizard_file(path: Path) -> None:
    """Best-effort private backup of a file the wizard is about to replace."""

    try:
        if not path.exists():
            return
        backup = Path(f"{path}.bak")
        temporary = Path(f"{backup}.tmp")
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with path.open("rb") as source, os.fdopen(fd, "wb") as destination:
                fd = -1
                shutil.copyfileobj(source, destination)
            try:
                stat = path.stat()
                os.utime(temporary, (stat.st_atime, stat.st_mtime))
            except OSError:
                pass
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, backup)
            try:
                os.chmod(backup, 0o600)
            except OSError:
                pass
        finally:
            if fd != -1:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except OSError:
        pass


def _wizard_file_unchanged(path: Path, data: bytes) -> bool:
    try:
        if not path.is_file():
            return False
        # Text-mode writes use CRLF on Windows. Compare logical content so the
        # same wizard answers are idempotent on every supported OS.
        existing = path.read_bytes().replace(b"\r\n", b"\n")
        expected = data.replace(b"\r\n", b"\n")
        return existing == expected
    except OSError:
        return False


def _tighten_wizard_file(path: Path) -> None:
    # A true no-op re-run still repairs custody if an older install left a
    # matching file with broad permissions.
    try:
        from maverick.file_lock import ensure_private_file

        ensure_private_file(path, 0o600)
    except ImportError:  # pragma: no cover -- installer normally depends on core
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _write_wizard_file(path: Path, body: str) -> None:
    """Write one private wizard file, preserving a logically equivalent retry."""
    from maverick.file_lock import atomic_write_text

    if _wizard_file_unchanged(path, body.encode("utf-8")):
        _tighten_wizard_file(path)
        console.print(f"[green]ok[/green] unchanged {path} (chmod 600)")
        return
    _backup_wizard_file(path)
    atomic_write_text(path, body, mode=0o600)
    console.print(f"[green]ok[/green] wrote {path} (chmod 600)")


def _publish_wizard_configuration(
    config_body: str, env_body: str | None, *, protect_existing: bool = False,
) -> None:
    """Publish complete files; first installs can resume after an abrupt exit."""
    from maverick.file_lock import atomic_write_text, cross_process_lock

    tomllib.loads(config_body)  # Never replace .env for an invalid configuration.
    with cross_process_lock(CONFIG_FILE, strict=True):
        if protect_existing and _existing_setup():
            raise FileExistsError(
                "Lightwork found saved setup files. Nothing was replaced; "
                "open Lightwork Settings to make changes."
            )
        old_env = ENV_FILE.read_text(encoding="utf-8") if ENV_FILE.exists() else None
        env_changed = env_body is not None and not _wizard_file_unchanged(ENV_FILE, env_body.encode("utf-8"))
        receipt_path = _pending_setup_path()
        if protect_existing:
            receipt = json.dumps({"version": 1, "config": config_body, "env": env_body})
            if len(receipt.encode("utf-8")) > 4_000_000:
                raise ValueError("Lightwork setup is too large to save safely")
            atomic_write_text(receipt_path, receipt, mode=0o600)
        try:
            if env_body is not None:
                _write_wizard_file(ENV_FILE, env_body)
            _write_wizard_file(CONFIG_FILE, config_body)
        except BaseException:
            if env_changed:
                if old_env is None:
                    ENV_FILE.unlink(missing_ok=True)
                else:
                    atomic_write_text(ENV_FILE, old_env, mode=0o600)
            if protect_existing and not CONFIG_FILE.exists():
                receipt_path.unlink(missing_ok=True)
            raise
        if protect_existing:
            receipt_path.unlink()


def _prepare_wizard_workspace(sandbox: dict[str, Any]) -> dict[str, Any]:
    """Prepare host workspaces before a configuration is advertised as usable."""
    result = dict(sandbox)
    if str(result.get("backend", "local")).strip().lower() == "ssh":
        result["host"] = _ssh_destination(result.get("host"))
        return result  # Remote POSIX paths must never be provisioned on this host.
    workdir = Path(result.get("workdir") or os.environ.get("MAVERICK_WORKDIR") or "~/maverick-workspace").expanduser().resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    # Permission bits alone are insufficient for ACLs and mounted volumes.
    with tempfile.TemporaryFile(dir=workdir, prefix=".lightwork-setup-") as probe:
        probe.write(b"workspace-ready\n")
        probe.flush()
        os.fsync(probe.fileno())
    result["workdir"] = str(workdir)
    return result


def write_config(
    providers: list[str],
    role_models: dict[str, str],
    channels: dict[str, dict[str, Any]],
    safety: dict[str, Any],
    budget: dict[str, Any],
    sandbox: dict[str, Any],
    keys: dict[str, str],
    capabilities: dict[str, bool] | None = None,
    *,
    research_execution: dict[str, Any] | None = None,
    candidate_promotion: dict[str, Any] | None = None,
    knowledge_access: dict[str, Any] | None = None,
    advanced: dict[str, Any] | None = None,
    provider_options: dict[str, dict[str, Any]] | None = None,
    mcp_servers: dict[str, dict[str, Any]] | None = None,
    mcp_registries: list[str] | None = None,
    template_registries: list[str] | None = None,
    plugins: list[str] | None = None,
    plugin_grant: list[str] | None = None,
    plugin_enforce: bool = False,
    ts_plugins: list[list[str]] | None = None,
    tool_acl: dict[str, Any] | None = None,
    rate_limits: dict[str, str] | None = None,
    retention: dict[str, int] | None = None,
    analytics: dict[str, Any] | None = None,
    persona: dict[str, str] | None = None,
    notifications: dict[str, Any] | None = None,
    deadline_alerts: dict[str, Any] | None = None,
    webhooks: dict[str, Any] | None = None,
    deliverables: dict[str, Any] | None = None,
    contact_centre: dict[str, Any] | None = None,
    personas: dict[str, Any] | None = None,
    a2a: dict[str, Any] | None = None,
    my_work: dict[str, Any] | None = None,
    notifications_email: dict[str, Any] | None = None,
    support: dict[str, Any] | None = None,
    collaboration: dict[str, Any] | None = None,
    web_search_enabled: bool = False,
    skills: dict[str, Any] | None = None,
    self_learning: dict[str, Any] | None = None,
    ekko: dict[str, Any] | None = None,
    automation_import: dict[str, Any] | None = None,
    event_triggers: dict[str, Any] | None = None,
    flows: dict[str, Any] | None = None,
    knowledge: dict[str, Any] | None = None,
    knowledge_sources: dict[str, Any] | None = None,
    oauth: dict[str, Any] | None = None,
    governed_connectors: dict[str, Any] | None = None,
    durable: dict[str, Any] | None = None,
    workspace: dict[str, Any] | None = None,
    finance: dict[str, Any] | None = None,
    value: dict[str, Any] | None = None,
    intent_value: dict[str, Any] | None = None,
    assessments: dict[str, Any] | None = None,
    security_suite: dict[str, Any] | None = None,
    monitoring: dict[str, Any] | None = None,
    deployment: str | None = None,
    suites: dict[str, bool] | None = None,
    governance_profile: str | None = None,
    per_tenant_keys: bool = False,
    first_outcome: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    protect_existing: bool = False,
) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    sandbox = _prepare_wizard_workspace(sandbox)

    keys = dict(keys)
    if security_suite and security_suite.get("red_team_assurance"):
        commitment_name = "MAVERICK_RED_TEAM_COMMITMENT_KEY"
        prior = os.environ.get(commitment_name, "")
        if not prior and ENV_FILE.is_file():
            try:
                for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
                    name, separator, value = line.partition("=")
                    if separator and name == commitment_name:
                        prior = value
                        break
            except OSError:
                prior = ""
        keys.setdefault(
            commitment_name,
            prior or secrets.token_urlsafe(48),
        )

    # Preserve private backups of hand-edited files. Compose both new files
    # before replacing either active file, and publish through private temps.
    env_body = "\n".join(f"{k}={v}" for k, v in keys.items()) + "\n" if keys else None

    # [flows] can be requested by two independent wizard steps: the dedicated
    # flow-engine step (the `flows` arg) and the advanced-reasoning "Flow
    # engine?" toggle (`advanced["flows"]`). Emitting the table from both paths
    # writes [flows] twice, which is invalid TOML -- tomllib rejects the WHOLE
    # file and load_config() silently falls back to {} (every wizard choice
    # lost; the smoke test then reports "sandbox backend missing"). Fold the
    # advanced flow extras into the single dedicated [flows] table so it is
    # emitted exactly once. Copy `advanced` so we never mutate the caller's dict.
    advanced = dict(advanced or {})
    if security_suite and security_suite.get("vendor_onboarding"):
        advanced["vendor_management"] = True
        advanced["connections"] = True
    if advanced.pop("flows", False):
        flows = dict(flows or {})
        flows.setdefault("enable", True)
        if advanced.pop("flows_auto_evolve", False):
            flows.setdefault("auto_evolve", True)
        _fold_flow_operator_options(flows, advanced)
        _flows_url = advanced.pop("flows_public_url", None)
        if _flows_url:
            flows.setdefault("public_url", _flows_url)

    # The security-suite questionnaire owns these shared tables. The advanced
    # questionnaire can also enable them, so OR its answers into a copied suite
    # config and remove the duplicate emit path before composing TOML.
    security_suite = None if security_suite is None else dict(security_suite)
    for shared_key in ("ai_regulatory_feed", "ai_literacy"):
        if advanced.pop(shared_key, False):
            security_suite = dict(security_suite or {})
            security_suite[shared_key] = True

    # The assessment questionnaire owns the single [entity_graph] table. The
    # shared governance inventory requires that projection, so reconcile a
    # prior assessment-time decline here instead of emitting a second table
    # from _cfg_advanced (duplicate TOML tables invalidate the whole config).
    assessments = dict(assessments or {})
    if advanced.get("governance_inventory"):
        assessments["entity_graph"] = True

    # Push-based red-team campaigns are delivered only through the enrolled,
    # self-authenticating external-agent boundary. Enabling the campaign plane
    # therefore prepares that dependency once in the advanced config block.
    if security_suite and security_suite.get("red_team_assurance"):
        advanced["external_agents"] = True
    if security_suite and security_suite.get("administration_document_access"):
        # The document token ledger is externally consequential and refuses to
        # run without the signed audit chain.  Preserve the user's other
        # advanced choices while deriving this mandatory dependency.
        advanced["audit_sign"] = True

    lines = [
        "# Lightwork config. Regenerate with:  maverick init",
        "",
    ]
    lines += _cfg_deployment(deployment)
    lines += _cfg_governance(governance_profile, finance)
    lines += _cfg_providers(
        providers, per_tenant_keys=per_tenant_keys, provider_options=provider_options,
    )
    lines += _cfg_role_models(
        role_models, discovery=advanced.get("model_discovery") is not False,
        guidance=advanced.get("model_guidance") is not False,
        capability_tests=advanced.get("model_capability_tests") is True,
    )
    lines += _cfg_channels(channels)
    lines += _cfg_core(budget, safety, sandbox)
    lines += _cfg_approval(approval)
    lines += _cfg_skills(skills)
    lines += _cfg_research_execution(research_execution)
    lines += _cfg_candidate_promotion(candidate_promotion)
    lines += _cfg_knowledge_access(knowledge_access)
    lines += _cfg_self_learning(self_learning)
    lines += _cfg_ekko(ekko)
    lines += _cfg_automation_import(automation_import)
    lines += _cfg_event_triggers(event_triggers)
    lines += _cfg_flows(flows)
    lines += _cfg_knowledge(knowledge)
    lines += _cfg_knowledge_sources(knowledge_sources)
    lines += _cfg_oauth(oauth)
    lines += _cfg_governed_connectors(governed_connectors)
    lines += _cfg_durable(durable)
    lines += _cfg_workspace(workspace)
    lines += _cfg_finance(finance)
    lines += _cfg_value(value)
    lines += _cfg_intent_value(intent_value)
    lines += _cfg_assessments(assessments)
    lines += _cfg_security_suite(
        security_suite, governed_pg_pool=bool(advanced.get("governed_pg_pool")),
    )
    if security_suite is not None:
        lines += [
            "", "[vendor_onboarding]",
            f"enable = {'true' if security_suite.get('vendor_onboarding', False) else 'false'}",
            "resource_owner = " + _toml_str(security_suite.get("vendor_onboarding_owner", "")),
            f"reviewed_uploads = {'true' if security_suite.get('vendor_reviewed_uploads', True) else 'false'}",
            'document_connection = "gdrive"',
            'ticket_connection = "jira"',
            "safe_read_attempts = 3",
            "safe_read_backoff_seconds = 0.25",
        ]

    capability_config = dict(capabilities or {})
    if web_search_enabled and not capability_config.get("web_search"):
        # web_search is wired through enable_web_search at kernel
        # boot; reflect the wizard's pick under [capabilities].
        capability_config["web_search"] = True
    if advanced and advanced.get("enforce_capabilities"):
        capability_config["enforce"] = True
    if advanced and advanced.get("per_call_token_exchange"):
        # Per-call token exchange only makes sense atop capability enforcement
        # (a token minted from no grant has nothing to scope), so turning it on
        # implies enforcement.
        capability_config["enforce"] = True
        capability_config["per_call_tokens"] = True

    # The embedded-device flash gate lives under [embedded], not
    # [capabilities] -- pull it out before emitting the capabilities block.
    embedded_flash = bool(capability_config.pop("embedded_flash", False))
    # JD hiring lives under [agent_factory] (kernel: maverick.jd_hiring).
    jd_hiring = bool(capability_config.pop("jd_hiring", True))
    require_passing_tests = bool(capability_config.pop("require_passing_tests", True))
    # Saved answer checks live under [agent_tests] (kernel: maverick.agent_tests_policy).
    agent_tests = {
        "max_cases_per_specialist": capability_config.pop(
            "max_cases_per_specialist", INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].default),
        "require_for_new_specialists": bool(capability_config.pop(
            "require_for_new_specialists", BOOLEAN_SETTINGS["agent_tests.require_for_new_specialists"].default)),
        "bypass_requires_second_person": bool(capability_config.pop(
            "bypass_requires_second_person", BOOLEAN_SETTINGS["agent_tests.bypass_requires_second_person"].default)),
        "tool_checks": bool(capability_config.pop("tool_checks", BOOLEAN_SETTINGS["agent_tests.tool_checks"].default)),
        "canary_percent": capability_config.pop("canary_percent", INTEGER_SETTINGS["agent_tests.canary_percent"].default),
        "canary_auto_rollback": bool(capability_config.pop(
            "canary_auto_rollback", BOOLEAN_SETTINGS["agent_tests.canary_auto_rollback"].default)),
    }
    # Practice mode lives under [practice] (kernel: maverick.practice), written only when off.
    practice_mode = bool(capability_config.pop("practice_mode", True))
    practice_cap = _safe_float(capability_config.pop("practice_daily_spend_cap", 1.0), default=1.0)
    # Tool exposure lives under [tools] (kernel: maverick.agent via
    # config.get_tool_exposure); "core" is the default, so only "full" is
    # written (write-only-on-divergence, like the other [tools] keys).
    if str(capability_config.pop("tool_exposure", "core")).lower() == "full":
        advanced["tool_exposure"] = "full"

    lines += _cfg_capabilities(capability_config, embedded_flash)
    lines += _cfg_agent_factory(jd_hiring, require_passing_tests)
    lines += _cfg_agent_tests(agent_tests)
    lines += _cfg_practice(practice_mode, practice_cap)
    lines += _cfg_suites(suites)
    lines += _cfg_advanced(advanced, providers, siem_dest=_siem_destination(monitoring))
    lines += _cfg_mcp_servers(mcp_servers)
    lines += _cfg_registries("mcp_registries", mcp_registries)
    lines += _cfg_registries("template_registries", template_registries)
    lines += _cfg_plugins(plugins, plugin_grant, plugin_enforce, ts_plugins, workbench=(advanced or {}).get("plugin_workbench"))
    lines += _cfg_security(
        tool_acl,
        bool((advanced or {}).get("security_autofix")),
        dual_approval=bool((advanced or {}).get("dual_approval")),
    )
    lines += _cfg_rate_limits(rate_limits)
    lines += _cfg_table("retention", retention)
    lines += _cfg_table("analytics", analytics)
    lines += _cfg_table("persona", persona)
    lines += _cfg_table("notifications", notifications)
    lines += _cfg_table("mobile_offline", (advanced or {}).get("mobile_offline"))
    lines += _cfg_table("device_pairing", (advanced or {}).get("device_pairing"))
    lines += _cfg_deadline_alerts(deadline_alerts)
    lines += _cfg_table("notifications.email", notifications_email)
    lines += _cfg_table("my_work", my_work)
    lines += _cfg_table("support", support)
    lines += _cfg_table("collaboration", collaboration)
    lines += _cfg_table("webhooks", webhooks)
    lines += _cfg_table("deliverables", deliverables)
    lines += _cfg_table("contact_centre", contact_centre)
    lines += _cfg_table("personas", personas)
    lines += _cfg_table("a2a", a2a)
    lines += _cfg_table("first_outcome", first_outcome)
    lines += _cfg_monitoring(monitoring)

    # SECURITY: config.toml is NOT secret-free. Unlike API keys (which live in
    # ~/.maverick/.env and are referenced via ${VAR}), the OIDC browser-login
    # client_secret and session_secret (HMAC session-cookie signing key) are
    # written here as literal values. The 0600 mode below is therefore load-
    # bearing, not just tidiness -- never relax it, and treat this file as
    # secret-bearing in backups/log redaction. chmod 600 so multi-user hosts
    # don't leak it to other accounts.
    config_body = "\n".join(lines) + "\n"
    _publish_wizard_configuration(config_body, env_body, protect_existing=protect_existing)


def smoke_test() -> bool:
    console.print()
    console.print("[dim]Running smoke test...[/dim]")
    try:
        from maverick.config import load_config

        cfg = load_config()
        assert cfg.get("sandbox", {}).get("backend"), "sandbox backend missing"
        if str(cfg["sandbox"]["backend"]).strip().lower() == "ssh":
            _ssh_destination(cfg["sandbox"].get("host"))
        console.print("[green]✓[/green] Config readable")
    except Exception as e:
        console.print(f"[red]✗[/red] Config read failed: {e}")
        return False

    try:
        import maverick_shield  # noqa: F401

        console.print("[green]✓[/green] Lightwork Shield available")
    except ImportError:
        console.print("[yellow]⚠[/yellow] maverick-shield not installed (safety will be disabled)")

    try:
        import anthropic  # noqa: F401

        console.print("[green]✓[/green] Anthropic SDK available")
    except ImportError:
        console.print(
            "[yellow]⚠[/yellow] anthropic not installed; install with: pip install anthropic"
        )

    return True


PARTIAL_STATE_PATH = CONFIG_DIR / "wizard-partial.json"


def _save_partial(state: dict[str, Any]) -> None:
    """Persist wizard progress so --resume can pick up later."""
    try:
        import json as _json

        from maverick.file_lock import atomic_write_text

        saved = dict(state)
        advanced = saved.get("advanced")
        oidc = advanced.get("oidc") if isinstance(advanced, dict) else None
        if isinstance(oidc, dict) and any(oidc.get(key) for key in ("client_secret", "session_secret")):
            # Resume must ask for this step again; omitting just the secrets
            # would silently write an incomplete browser SSO configuration.
            saved.pop("advanced", None)
        atomic_write_text(PARTIAL_STATE_PATH, _json.dumps(saved, default=str), mode=0o600)
    except OSError:
        pass


def _load_partial() -> dict[str, Any] | None:
    """Return persisted partial state, or None if absent."""
    if not PARTIAL_STATE_PATH.exists():
        return None
    try:
        import json as _json

        state = _json.loads(PARTIAL_STATE_PATH.read_text())
        if not isinstance(state, dict):
            return None
        advanced = state.get("advanced")
        oidc = advanced.get("oidc") if isinstance(advanced, dict) else None
        if isinstance(oidc, dict) and any(oidc.get(key) for key in ("client_secret", "session_secret")):
            # Older versions wrote these secrets to the resume file. Remove
            # them immediately and require the operator to re-enter the step.
            from maverick.file_lock import atomic_write_text

            state.pop("advanced", None)
            try:
                atomic_write_text(PARTIAL_STATE_PATH, _json.dumps(state, default=str), mode=0o600)
            except OSError as exc:
                raise RuntimeError(
                    "Cannot securely remove old OIDC secrets from the wizard resume file. "
                    f"Secure or remove {PARTIAL_STATE_PATH} before resuming."
                ) from exc
        return state
    except (OSError, ValueError):
        return None


def _clear_partial() -> None:
    try:
        if PARTIAL_STATE_PATH.exists():
            PARTIAL_STATE_PATH.unlink()
    except OSError:
        pass


def run_fast() -> int:
    """``maverick init --fast``: zero-question setup with sensible defaults.

    Skips every prompt. Writes a minimal config that runs on Anthropic
    Claude (BYOK via ANTHROPIC_API_KEY env), the Docker sandbox when its
    daemon is up (else local), balanced safety, $5/run cap. Users can
    use Lightwork Settings after installation to change supported options.
    """
    guard = _first_setup_guard()
    if guard is not None:
        return guard
    welcome()
    if not preflight():
        console.print("[red]Preflight failed.[/red] Fix the issues above and re-run.")
        return 1
    console.print(
        "[bold]Fast setup:[/bold] using safe defaults. "
        "Open Lightwork Settings after setup to make changes.\n"
        f"Setup will be saved at {CONFIG_FILE}.\n"
    )
    providers = ["anthropic"]
    role_models: dict[str, str] = {}  # use ROLE_MODELS defaults
    channels: dict[str, Any] = {}
    safety = {
        "profile": "balanced",
        "block_threshold": "high",
        "scan_input": True,
        "scan_tool_calls": True,
        "scan_output": True,
        "compartments": False,
    }
    budget = {"strict_pricing": True}
    # Prefer the isolated Docker sandbox, but fall back to local when the
    # daemon isn't up -- otherwise fast-setup writes a docker config that the
    # very next `maverick start` can't run (the user never chose docker, yet
    # hits "Docker not available"). Mirrors write_consumer_config.
    backend = "docker" if _docker_available() else "local"
    sandbox = {
        "backend": backend,
        "workdir": str(Path.home() / "maverick-workspace"),
        "timeout": 60,
    }
    denied_tools = ["computer", "browser"]
    if backend == "local":
        denied_tools.extend(["shell", "write_file", "apply_patch", "str_replace_editor", "ast_edit"])
        console.print(
            "[yellow]![/yellow] Docker isn't running. Lightwork can answer questions, "
            "but it cannot create files or run programs in this setup. "
            + _FILE_WORK_RECOVERY
        )
    capabilities = {"computer_use": False, "browser": False, "ros": False}
    # Pick up the API key from the env if it's already there;
    # otherwise a key can be added from Lightwork Settings.
    keys: dict[str, str] = {}
    if os.environ.get("ANTHROPIC_API_KEY"):
        keys["ANTHROPIC_API_KEY"] = os.environ["ANTHROPIC_API_KEY"]
    write_config(
        providers,
        role_models,
        channels,
        safety,
        budget,
        sandbox,
        keys,
        capabilities,
        tool_acl={"denied_tools": denied_tools},
        protect_existing=True,
    )
    # smoke_test() returns a bool and it was discarded, so `maverick init
    # --fast` printed "Fast setup finished" and exited 0 over a broken install
    # -- the one command whose entire promise is that you can trust the result
    # without answering questions. An installer that cannot fail is an
    # installer whose success means nothing.
    if not smoke_test():
        console.print()
        console.print(
            Panel.fit(
                "[bold red]Fast setup failed its smoke test.[/bold red]\n\n"
                "The config was written, but the checks above did not pass, so "
                "this install is not ready to run.\n"
                "Review the failures above and open Lightwork Settings "
                "to finish setup.",
                border_style="red",
            )
        )
        return 1
    if not keys:
        console.print()
        console.print(
            Panel.fit(
                "[bold yellow]Setup saved, but AI is not connected.[/bold yellow]\n\n"
                "No AI provider key was found, so Lightwork cannot run a task yet. "
                "Open Lightwork > Settings > AI services and add your provider key.\n"
                f"Saved setup: {CONFIG_FILE}",
                border_style="yellow",
            )
        )
        return 1
    console.print()
    console.print(
        Panel.fit(
            ("[bold yellow]Fast setup saved. File work is off.[/bold yellow]\n\n"
             if backend == "local" else "[bold green]Fast setup finished.[/bold green]\n\n")
            + 'Try: [bold]maverick start "hello"[/bold]\n'
            + (_FILE_WORK_RECOVERY + "\n" if backend == "local" else "")
            + f"Saved setup: {CONFIG_FILE}\n"
            + "[dim]The maverick command is also available as lightwork.[/dim]",
            border_style="yellow" if backend == "local" else "green",
        )
    )
    return 0


def first_outcome_choices() -> list[str]:
    """Menu labels for the department picker, from the kernel's list."""
    from maverick.sample_outcomes import departments

    return [row["label"] for row in departments()]


def pick_first_outcome() -> str:
    """Final consumer question: which team tries Lightwork first?

    Returns the department slug for :mod:`maverick.sample_outcomes`. Falls
    back to the default department on anything it doesn't recognise, so an
    <Enter> or a stubbed answer never lands outside the eight choices.
    """
    from maverick.sample_outcomes import DEFAULT_DEPARTMENT, get, resolve_department

    console.print()
    console.print(
        "[dim]Your first task runs a real specialist on bundled sample data "
        "(a made-up company). Everything it produces is marked as sample "
        "data and never counts as real evidence.[/dim]"
    )
    pick = _q_select(
        "Which team will try Lightwork first?",
        first_outcome_choices(),
        default=get(DEFAULT_DEPARTMENT).label,
    )
    return resolve_department(pick) or DEFAULT_DEPARTMENT


def prepare_first_outcome(department: str, workdir: str) -> dict[str, Any]:
    """Create the department's sample workspace under ``workdir``.

    Returns the ``[first_outcome]`` table to record: the chosen department
    and whether the sample workspace was actually created (a copy failure
    is recorded as ``false``, never hidden).
    """
    from maverick.sample_outcomes import create_sample_workspace

    created = True
    try:
        create_sample_workspace(department, workdir)
    except OSError:
        created = False
    return {"department": department, "sample_workspace_created": created}


def pick_mode() -> str:
    """First-screen picker: consumer vs advanced.

    Every launch starts here so a non-technical
    user lands in a four-question flow with safe defaults, and a power
    user can opt straight into the full wizard.
    """
    console.print()
    console.print(
        Panel.fit(
            "[bold]How do you want to set this up?[/bold]\n\n"
            "  consumer  Four questions, safe defaults. About a minute.\n"
            "  express   A few questions, then turn ON all safe features.\n"
            "  advanced  Pick every model, channel, safety level, budget.",
            border_style="cyan",
        )
    )
    pick = _q_select(
        "Pick a mode:",
        [
            "consumer - just get me running",
            "express  - turn on all features, few questions",
            "advanced - let me configure everything",
        ],
        default="consumer - just get me running",
    )
    return pick.split()[0]


def _consumer_budget() -> dict[str, Any]:
    """Single-question budget chip picker for consumer mode."""
    pick = _q_select(
        "Task limits for each goal? Standard is $2 and 30 minutes.",
        ["Standard ($2, 30 minutes)", "No task limit", "$1", "$5", "$20", "custom"],
        default="Standard ($2, 30 minutes)",
    )
    if pick == "No task limit":
        return {"task_limits_enabled": False}
    if pick == "Standard ($2, 30 minutes)":
        return {"max_dollars": 2.0, "max_wall_seconds": 1800.0}
    if pick == "custom":
        dollars = _prompt_positive_dollars("  Custom cap ($)", default="5.0")
    else:
        dollars = float(pick.lstrip("$"))
    return {"max_dollars": dollars, "max_wall_seconds": 1800.0}


def _consumer_api_key() -> dict[str, str]:
    """Single-screen Anthropic key collection for consumer mode.

    No DevTools paste, no jargon. Three escape hatches:
      1. Paste the key (the default).
      2. Skip for now (write config without keys; add one in Settings later).
      3. Open the console in a browser to make a key.
    """
    console.print()
    console.print(
        "Lightwork needs an account with Claude (Anthropic). "
        "Get a key at: [cyan]https://console.anthropic.com/settings/keys[/cyan]\n"
        "[dim]It looks like 'sk-ant-...' and is about 100 characters long.[/dim]",
    )
    val = _q_secret("  Paste your Anthropic API key (leave blank to skip):")
    if not val.strip():
        console.print(
            "[yellow]Skipped.[/yellow] You can add one later in Lightwork Settings."
        )
        return {}
    # Validate with the 7-day cache.
    cached = _cached_validation("ANTHROPIC_API_KEY", val)
    if cached is not None:
        ok, msg = cached
    else:
        ok, msg = _validate_anthropic_key(val)
        _remember_validation("ANTHROPIC_API_KEY", val, ok, msg)
    if ok:
        console.print(f"  {_validation_marker(ok, msg)} {msg}")
        return {"ANTHROPIC_API_KEY": val}
    # On failure, surface the branded error and let the user decide.
    show_bad_key_error("ANTHROPIC_API_KEY", msg)
    if _q_confirm("Save the key anyway and continue?", default=False):
        return {"ANTHROPIC_API_KEY": val}
    return {}


def write_consumer_config(
    *,
    user_name: str,
    keys: dict[str, str],
    workdir: str,
    budget: dict[str, Any],
    profile: str | None = None,
    first_outcome: str | None = None,
    protect_existing: bool = False,
) -> str:
    """Write a consumer-mode config with the safe defaults.

    Used by the consumer setup flow (``run_consumer``). ``profile`` is the
    governance level from :data:`GOVERNANCE_PROFILES` (unknown values fall
    back to the default) -- it layers the learning
    lifecycle + governance posture on top of the safe-default base, which
    is identical at every level. Creates the workspace dir, and the sample
    workspace for ``first_outcome`` (a department slug from
    :mod:`maverick.sample_outcomes`) when one was picked. Raises on write
    failure (caller renders the branded error). Returns the work-area backend
    actually saved so both installers can explain its capabilities honestly.
    """
    preset = GOVERNANCE_PROFILES.get(profile or "")
    if preset is None:
        profile, preset = (
            DEFAULT_GOVERNANCE_PROFILE,
            GOVERNANCE_PROFILES[DEFAULT_GOVERNANCE_PROFILE],
        )
    if protect_existing and _existing_setup():
        # A setup saved while the questions were answered: refuse before the
        # work folder and sample files are touched (publishing re-checks locked).
        raise FileExistsError("Lightwork found saved setup files. Nothing was replaced; "
                              "open Lightwork Settings to make changes.")
    Path(workdir).expanduser().mkdir(parents=True, exist_ok=True)
    first_outcome_table = (
        prepare_first_outcome(first_outcome, str(Path(workdir).expanduser()))
        if first_outcome else None
    )
    backend = "docker" if _docker_available() else "local"
    # Computer + browser always require explicit opt-in (consumer is
    # never asked). When there's no Docker sandbox to contain it, also
    # deny the host-mutating tools — fail closed on the host. With
    # Docker present, shell/write_file/apply_patch stay enabled because
    # the container is the blast radius, not the user's machine.
    denied_tools = ["computer", "browser"]
    if backend == "local":
        denied_tools.extend(["shell", "write_file", "apply_patch", "str_replace_editor", "ast_edit"])
    write_config(
        ["anthropic"],  # providers
        {},  # role_models -> kernel defaults
        {},  # channels -> none in consumer mode
        {
            "profile": "strict",  # strictest shield
            "block_threshold": "medium",  # block medium+ threats
            "scan_input": True,
            "scan_tool_calls": True,
            "scan_output": True,
        },
        budget,
        {
            "backend": backend,
            "workdir": str(Path(workdir).expanduser()),
            "timeout": 60,
        },
        keys,
        {"computer_use": False, "browser": False, "ros": False},  # capabilities
        advanced=dict(preset["advanced"]),
        self_learning=dict(preset["self_learning"]),
        tool_acl={"denied_tools": denied_tools},
        rate_limits={
            "web_search": "5/60",
            "http_fetch": "10/60",
            "shell": "5/60",
            "mcp_*": "20/60",
        },
        retention=dict(preset["retention"]),
        persona={"name": "Lightwork", "style": "balanced", "user_name": user_name},
        web_search_enabled=True,
        governance_profile=profile,
        first_outcome=first_outcome_table,
        protect_existing=protect_existing,
    )
    return backend


def run_consumer() -> int:
    """Four-question consumer flow. Writes a minimal config with
    consumer-grade safe defaults, then prints a one-line demo command."""
    guard = _first_setup_guard()
    if guard is not None:
        return guard
    console.print()
    console.print(
        Panel.fit(
            "[bold]Lightwork setup[/bold]\n\n"
            "Six quick questions. About a minute. You can change supported\n"
            "options later in Lightwork Settings.",
            border_style="cyan",
        )
    )

    if not preflight():
        console.print("[red]Setup can't continue.[/red] Fix the issues above and try again.")
        return 1

    user_name = (
        _q_text(
            "What should we call you?",
            default=os.environ.get("USER") or os.environ.get("USERNAME") or "",
        ).strip()
        or "you"
    )

    profile = pick_governance_profile()

    keys = _consumer_api_key()

    workdir = _q_text(
        "Where can Lightwork work?",
        default=os.environ.get("MAVERICK_WORKDIR") or str(Path.home() / "Documents" / "Maverick"),
    ).strip() or os.environ.get("MAVERICK_WORKDIR") or str(Path.home() / "Documents" / "Maverick")

    budget = _consumer_budget()

    department = pick_first_outcome()

    try:
        backend = write_consumer_config(
            user_name=user_name,
            keys=keys,
            workdir=workdir,
            budget=budget,
            profile=profile,
            first_outcome=department,
            protect_existing=True,
        )
    except Exception as e:
        show_install_failure(e)
        return 1

    if backend == "local":
        console.print(
            "[yellow]File changes and program execution are off.[/yellow] "
            "Docker was not running during setup. Lightwork can still answer "
            "questions and work with the features that do not need a work area. "
            + _FILE_WORK_RECOVERY
        )

    # First-outcome nudge. Don't run the task here (the kernel doesn't
    # stream into a wizard window today, and shelling out from inside
    # the installer is ugly); print the one-liner instead. No model flag:
    # the pack and the configured role models pick the model.
    from maverick.sample_outcomes import cli_command
    from maverick.sample_outcomes import get as first_outcome_for

    outcome = first_outcome_for(department)
    console.print()
    if keys:
        console.print(
            Panel.fit(
                (f"[bold yellow]Setup saved, {user_name}. File work is off.[/bold yellow]\n\n"
                 if backend == "local" else
                 f"[bold green]Setup complete, {user_name}.[/bold green]\n\n")
                + f"Your first task ({outcome.label}, on sample data, waits in {outcome.lands_in}):\n"
                + f"  [bold]{cli_command(department)}[/bold]\n\n"
                + (_FILE_WORK_RECOVERY + "\n\n" if backend == "local" else "")
                + "Then:\n"
                + "  [bold]maverick dashboard[/bold]   web UI at http://127.0.0.1:8765\n\n"
                + "[dim]The maverick command is also available as lightwork.[/dim]",
                border_style="yellow" if backend == "local" else "green",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[bold yellow]Setup saved without an API key, {user_name}.[/bold yellow]\n\n"
                "Open Lightwork Settings to add a provider key when ready.",
                border_style="yellow",
            )
        )
    _clear_partial()
    return 0


# Express mode turns on the safe, single-user PRODUCT + self-improvement
# features with sane defaults -- everything that makes Lightwork "fully lit up"
# WITHOUT the host-dangerous or infra-shaped toggles that must stay explicit
# opt-in (computer/browser control, code execution, autonomous self-
# modification, at-rest encryption + multi-tenancy, channel tokens). Kept as
# data so a test can assert exactly what express enables without driving the
# prompts. Every key here is one `_cfg_advanced` recognises.
_EXPRESS_ADVANCED: dict[str, Any] = {
    # cheaper + faster + stronger reasoning
    "cost_aware": True,
    "compact_history": True,
    "adaptive_compute": True,
    "risk_proportional_verify": True,
    "verify_ensemble": True,
    "autonomy_gate": True,
    "effort": True,
    "cache_prewarm": True,
    "output_cache": True,
    # the closed self-improvement lifecycle
    "reflexion": True,
    "dreaming": True,
    "experience_guidance": True,
    "skill_synthesis": True,
    "credit_assignment": True,
    "self_harness": True,
    "data_engine": True,
    "operations_scientist": True,
    "consequence": True,
    "rehearsal": True,
    "evaluator_evolution": True,
    "cortex": True,
    "shoring": True,
    # governed memory + provable-learning audit (non-blocking)
    "memory_guard": True,
    "temporal_memory": True,
    "fairness_monitor": True,
    "governed_actions": True,
    "calibration_enforce": True,
    "audit_sign": True,
    "audit_rewards": True,
    # product surface: named SaaS connections (flows go via the dedicated arg)
    "connections": True,
}

# Self-learning ON, but WITHOUT the generate-and-run-new-code autonomy
# (create_tools) and WITHOUT MCP-server acquisition (allow_mcp) -- those two are
# higher-trust and stay an explicit opt-in even in express.
_EXPRESS_SELF_LEARNING: dict[str, Any] = {
    "enable": True,
    "preflight": True,
    "create_tools": False,
    "provision_packs": True,
    "allow_mcp_acquisition": False,
    "allow_provider_egress": False,
    "distill_local": True,
}


# --- Governance profiles: business-shaped onboarding levels --------------------
#
# One early question -- "what kind of business is this?" -- maps to a preset
# bundle of ALREADY-EXISTING knobs. Every level gets the self-learning /
# self-improvement lifecycle (that's the product); what escalates is the
# governance posture around it. A gymnastics studio wants the learning without
# the signing ceremony; a manufacturer wants budgets + an audit trail; a bank
# wants everything signed, immutable, and quota-enforced. Kept as data (same
# convention as _EXPRESS_ADVANCED) so tests can assert exactly what each level
# enables without driving prompts. Budget caps are NOT part of a profile: they
# are collected separately and are never optional at any level.

# The closed learning lifecycle every level turns on. Safe-by-construction
# subset: in-process learning + consolidation only -- no generate-and-run-code
# autonomy, no MCP acquisition (those stay explicit opt-ins at every level).
_LEARNING_LIFECYCLE: dict[str, Any] = {
    "reflexion": True,
    "dreaming": True,
    "experience_guidance": True,
    "skill_synthesis": True,
    "credit_assignment": True,
    "self_harness": True,
    "data_engine": True,
    "evaluator_evolution": True,
    "consequence": True,
    "rehearsal": True,
    "cortex": True,
    "shoring": True,
}

_PROFILE_SELF_LEARNING: dict[str, Any] = dict(_EXPRESS_SELF_LEARNING)

# Governance additions by level (cumulative: standard ⊃ essentials,
# regulated ⊃ standard). Every key is one _cfg_advanced recognises.
_STANDARD_GOVERNANCE: dict[str, Any] = {
    "memory_guard": True,  # governed memory writes
    "governed_actions": True,  # side-effectful actions logged + gated
    "calibration_enforce": True,  # confidence calibration gate
    "fairness_monitor": True,
    "audit_sign": True,  # Ed25519-signed audit chain
    # No spending caps by default: administrators set workspace and
    # per-person limits in the dashboard (Admin > Spending limits).
}
_REGULATED_GOVERNANCE: dict[str, Any] = {
    **_STANDARD_GOVERNANCE,
    "audit_rewards": True,  # provable-learning reward audit
    "audit_worm": True,  # WORM export of closed audit day-files
    "signed_approval": True,  # human Ed25519 sign-off for code/weights rungs
}

GOVERNANCE_PROFILES: dict[str, dict[str, Any]] = {
    "essentials": {
        "advanced": dict(_LEARNING_LIFECYCLE),
        "self_learning": dict(_PROFILE_SELF_LEARNING),
        "retention": {
            "audit_days": 30, "episodes_days": 90, "events_days": 30,
            "messages_days": 30,
        },
    },
    "standard": {
        "advanced": {**_LEARNING_LIFECYCLE, **_STANDARD_GOVERNANCE},
        "self_learning": dict(_PROFILE_SELF_LEARNING),
        "retention": {
            "audit_days": 90, "episodes_days": 180, "events_days": 90,
            "messages_days": 90,
        },
    },
    "regulated": {
        "advanced": {**_LEARNING_LIFECYCLE, **_REGULATED_GOVERNANCE},
        "self_learning": dict(_PROFILE_SELF_LEARNING),
        "retention": {
            "audit_days": 365, "episodes_days": 365, "events_days": 365,
            "messages_days": 365,
        },
    },
}

DEFAULT_GOVERNANCE_PROFILE = "essentials"

# Menu strings start with the profile name so the picker can split()[0] them,
# same convention as pick_mode().
GOVERNANCE_CHOICES: list[str] = [
    "essentials - small business: learn + improve, stay out of my way (a gym, a studio, a shop)",
    "standard   - growing company: + signed audit trail, fairness and memory checks "
    "(a manufacturer, an agency)",
    "regulated  - bank / clinic / government: + human sign-off, immutable audit, long retention",
]


def _prior_governance_profile() -> str | None:
    """The [governance] profile recorded by a previous installation, if any.

    Kept for callers that preview the onboarding choice. The active setup
    entry points refuse to overwrite a saved installation; governance changes
    belong to Settings > All settings. Reads the wizard's configured path.
    """
    try:
        # The wizard writes config.toml as UTF-8; Windows' default is cp1252.
        cfg = tomllib.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:  # nothing saved yet: no prior
        return None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        # Say so rather than quietly offering the default in place of a saved level.
        console.print(
            "[yellow]Your saved settings file could not be read, so the governance "
            "level chosen before is not shown. Pick it again below.[/yellow]"
        )
        return None
    section = cfg.get("governance")
    prior = section.get("profile", "") if isinstance(section, dict) else ""
    return prior if isinstance(prior, str) and prior in GOVERNANCE_PROFILES else None


def pick_governance_profile() -> str:
    """One onboarding question: how much governance does this business need?

    Defaults to a previously configured level when previewed, else
    :data:`DEFAULT_GOVERNANCE_PROFILE`; falls back to the default on anything
    it doesn't recognise, so an <Enter> or a stubbed answer never lands
    outside the three supported levels.
    """
    console.print()
    console.print(
        "[dim]Every level gets self-learning and self-improvement. The level "
        "sets how much governance wraps it -- you can change it any time by "
        "using Lightwork > Settings > All settings.[/dim]"
    )
    prior = _prior_governance_profile()
    default = next(
        (c for c in GOVERNANCE_CHOICES if c.split()[0] == prior),
        GOVERNANCE_CHOICES[0],
    )
    pick = _q_select(
        "What kind of business is this for?",
        list(GOVERNANCE_CHOICES),
        default=default,
    )
    name = pick.split()[0]
    return name if name in GOVERNANCE_PROFILES else (prior or DEFAULT_GOVERNANCE_PROFILE)


def run_express() -> int:
    """Express setup: a few user-specific questions, then turn on every safe
    single-user feature at once. The shortcut for "I want everything on"
    without sitting through the full advanced wizard. Host-dangerous and
    infra-shaped toggles stay off (and are listed for the user)."""
    guard = _first_setup_guard()
    if guard is not None:
        return guard
    console.print()
    console.print(
        Panel.fit(
            "[bold]Lightwork express setup[/bold]\n\n"
            "A few questions, then every safe single-user feature is turned on:\n"
            "the flow engine, named connections, the self-improvement lifecycle\n"
            "(reflexion, dreaming, experience, self-harness, data engine),\n"
            "governed memory, web search, durable execution, and all 53 suites.\n\n"
            "[dim]Left off pending administrator review: computer/\n"
            "browser control, code execution, autonomous self-modification, at-rest\n"
            "encryption + multi-tenancy, and messaging channels.[/dim]",
            border_style="cyan",
        )
    )

    if not preflight():
        console.print("[red]Setup can't continue.[/red] Fix the issues above and try again.")
        return 1

    user_name = (
        _q_text(
            "What should we call you?",
            default=os.environ.get("USER") or os.environ.get("USERNAME") or "",
        ).strip()
        or "you"
    )
    profile = pick_governance_profile()
    keys = _consumer_api_key()
    workdir = _q_text(
        "Where can Lightwork work?",
        default=os.environ.get("MAVERICK_WORKDIR") or str(Path.home() / "Documents" / "Maverick"),
    ).strip() or os.environ.get("MAVERICK_WORKDIR") or str(Path.home() / "Documents" / "Maverick")
    budget = _consumer_budget()

    Path(workdir).expanduser().mkdir(parents=True, exist_ok=True)
    backend = "docker" if _docker_available() else "local"
    # Express turns on every safe single-user feature; the governance level
    # layers its posture (signed audit, quotas, WORM, signed approvals) on
    # top. Union of two all-True dicts, so profile keys can only ADD.
    preset = GOVERNANCE_PROFILES.get(profile, GOVERNANCE_PROFILES[DEFAULT_GOVERNANCE_PROFILE])
    # Computer + browser are never enabled by express. If Docker is
    # unavailable, fail closed on host-mutating tools too: the local backend
    # runs against the user's host filesystem, not a container blast radius.
    denied_tools = ["computer", "browser"]
    if backend == "local":
        denied_tools.extend(["shell", "write_file", "apply_patch", "str_replace_editor", "ast_edit"])
    try:
        write_config(
            providers=["anthropic"],
            role_models={},
            channels={},
            safety={
                "profile": "balanced",
                "scan_input": True,
                "scan_tool_calls": True,
                "scan_output": True,
            },
            budget=budget,
            sandbox={"backend": backend, "workdir": str(Path(workdir).expanduser()), "timeout": 60},
            keys=keys,
            # Host-mutating capabilities require explicit opt-in even in express.
            capabilities={
                "computer_use": False,
                "browser": False,
                "ros": False,
                "code_exec": False,
            },
            advanced={**_EXPRESS_ADVANCED, **preset["advanced"]},
            persona={"name": "Lightwork", "style": "balanced", "user_name": user_name},
            web_search_enabled=True,
            self_learning=dict(_EXPRESS_SELF_LEARNING),
            automation_import={"enable": True},
            event_triggers={"enable": True},
            flows={"enable": True},
            oauth={"vault": True},
            durable={"enabled": True},
            deployment="desktop",
            # Express writes NO [retention] table at the default level, and
            # absent means keep-forever (retention is opt-in pruning); only an
            # explicitly-picked governance upgrade introduces pruning windows.
            retention=(
                dict(preset["retention"]) if profile != DEFAULT_GOVERNANCE_PROFILE else None
            ),
            governance_profile=profile,
            tool_acl={"denied_tools": denied_tools},
            protect_existing=True,
        )
    except Exception as e:
        show_install_failure(e)
        return 1

    if backend == "local":
        console.print(
            "[yellow]File changes and program execution are off.[/yellow] "
            "Docker was not running during setup. Lightwork can still answer "
            "questions and use features that do not need a work area. "
            + _FILE_WORK_RECOVERY
        )

    console.print()
    if keys:
        console.print(
            Panel.fit(
                (f"[bold yellow]Setup saved, {user_name}. File work is off.[/bold yellow]\n\n"
                 if backend == "local" else
                 f"[bold green]Setup saved, {user_name}.[/bold green]\n\n")
                + "Open the dashboard:\n"
                + "  [bold]maverick dashboard[/bold]   web UI at http://127.0.0.1:8765\n\n"
                + (_FILE_WORK_RECOVERY + "\n\n" if backend == "local" else "")
                + "[dim]Open Lightwork Settings to change supported options.[/dim]",
                border_style="yellow" if backend == "local" else "green",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[bold yellow]Setup saved without an API key, {user_name}.[/bold yellow]\n\n"
                "Open Lightwork Settings to add a provider key.",
                border_style="yellow",
            )
        )
    _clear_partial()
    return 0


# (command, one-line description) surfaced after a regulated-posture setup, so a
# non-technical operator discovers the verification + GDPR/EU AI Act
# documentation commands they'd otherwise never find. Defined as data so a test
# can assert the set without rendering the Rich panel.
_COMPLIANCE_COMMANDS: list[tuple[str, str]] = [
    ("maverick enterprise verify", "check configured application-layer boundary controls"),
    ("maverick compliance", "GDPR + EU AI Act control coverage"),
    ("maverick ropa", "GDPR Art. 30 record-of-processing scaffold"),
    ("maverick dpia", "GDPR Art. 35 impact-assessment scaffold"),
    ("maverick ai-act", "EU AI Act risk classification"),
    ("maverick assess", "run a PIA / AIRA / vendor-risk assessment"),
    ("maverick hunt", "hunt the audit trail for agent attacks"),
    ("maverick remediate", "assess security posture + fix low-risk gaps"),
    ("maverick regulatory verify", "verify active obligations compile into non-vacuous gates enforced live"),
    ("maverick attest receipt mint", "hand an auditor a bearer-verifiable receipt for one decision"),
]


def _regulated_deployment(advanced: dict[str, Any]) -> bool:
    """True if the operator turned on a sensitive-data control, so the wizard
    should point them at the compliance + documentation commands."""
    advanced = advanced or {}
    return bool(
        advanced.get("enterprise")
        or advanced.get("compliance_profiles")
        or advanced.get("encrypt_at_rest")
        or advanced.get("audit_sign")
        or advanced.get("audit_worm")
        or advanced.get("dual_approval")
        or advanced.get("saml")
        or advanced.get("security_autofix")
    )


def show_compliance_commands(advanced: dict[str, Any]) -> None:
    """Print the compliance/documentation command panel after a regulated setup.

    No-op unless the deployment enabled a compliance profile or another
    regulated-data control such as enterprise mode, at-rest encryption, or
    audit signing -- otherwise it's just noise for a personal install.
    """
    if not _regulated_deployment(advanced):
        return
    rows = "\n".join(
        f"  [bold]{cmd}[/bold]{' ' * max(1, 28 - len(cmd))}# {desc}"
        for cmd, desc in _COMPLIANCE_COMMANDS
    )
    console.print()
    console.print(
        Panel.fit(
            "[bold]You enabled a regulated-data posture.[/bold] Verify configured "
            "controls and prepare documentation:\n\n"
            f"{rows}\n\n"
            "[dim]See docs/regulated-deployment.md. Control coverage, not legal advice.[/dim]",
            border_style="cyan",
            title="Compliance & documentation",
        )
    )


def _run_simple_picks(state: dict[str, Any], _announce) -> dict[str, Any]:
    """Run the contiguous block of single-answer ``state.get(x) or pick_x()``
    steps (safety through advanced), persisting each. Returns the answers."""
    _announce()
    safety = state.get("safety") or pick_safety()
    state["safety"] = safety
    _save_partial(state)

    _announce()
    signed_skills = state.get("signed_skills") or pick_signed_skills()
    state["signed_skills"] = signed_skills
    _save_partial(state)

    _announce()
    budget = state.get("budget") or pick_budget()
    state["budget"] = budget
    _save_partial(state)

    _announce()
    approval = state.get("approval") or pick_approvals()
    state["approval"] = approval
    _save_partial(state)

    _announce()
    sandbox = state.get("sandbox") or pick_sandbox()
    state["sandbox"] = sandbox
    _save_partial(state)

    _announce()
    research_execution = state.get("research_execution")
    if research_execution is None:
        research_execution = pick_research_execution()
        state["research_execution"] = research_execution
        _save_partial(state)

    _announce()
    candidate_promotion = state.get("candidate_promotion")
    if candidate_promotion is None:
        candidate_promotion = pick_candidate_promotion()
        state["candidate_promotion"] = candidate_promotion
        _save_partial(state)

    _announce()
    knowledge_access = state.get("knowledge_access")
    if knowledge_access is None:
        knowledge_access = pick_knowledge_access()
        state["knowledge_access"] = knowledge_access
        _save_partial(state)

    _announce()
    capabilities = state.get("capabilities") or pick_capabilities()
    state["capabilities"] = capabilities
    _save_partial(state)

    _announce()
    self_learning = state.get("self_learning") or pick_self_learning()
    state["self_learning"] = self_learning
    _save_partial(state)

    _announce()
    # Use an explicit None sentinel: {"enable": False} is a completed answer.
    ekko = state.get("ekko")
    if ekko is None:
        ekko = pick_ekko()
        state["ekko"] = ekko
        _save_partial(state)

    _announce()
    automation_import = state.get("automation_import") or pick_automation_import()
    state["automation_import"] = automation_import
    _save_partial(state)

    _announce()
    event_triggers = state.get("event_triggers") or pick_event_triggers()
    state["event_triggers"] = event_triggers
    _save_partial(state)

    _announce()
    flows = state.get("flows") or pick_flows()
    state["flows"] = flows
    _save_partial(state)

    _announce()
    knowledge = state.get("knowledge") or pick_knowledge()
    state["knowledge"] = knowledge
    _save_partial(state)
    # Part of the Knowledge step (no progress line of its own): saved sources need Knowledge RAG.
    knowledge_sources = state.get("knowledge_sources")
    if knowledge_sources is None:
        knowledge_sources = (
            {**pick_knowledge_sources(), **pick_knowledge_source_permissions()} if knowledge.get("enable") else {}
        )
        state["knowledge_sources"] = knowledge_sources
        _save_partial(state)

    _announce()
    oauth = state.get("oauth") or pick_oauth_vault()
    state["oauth"] = oauth
    _save_partial(state)

    _announce()
    governed_connectors = state.get("governed_connectors") or pick_governed_connectors()
    state["governed_connectors"] = governed_connectors
    _save_partial(state)

    _announce()
    durable = state.get("durable") or pick_durable()
    state["durable"] = durable
    _save_partial(state)

    _announce()
    workspace = state.get("workspace") or pick_workspace_journal()
    state["workspace"] = workspace
    _save_partial(state)

    _announce()
    finance = state.get("finance") or pick_finance()
    state["finance"] = finance
    _save_partial(state)

    # `is None` sentinel: declining the savings step legitimately returns {}.
    _announce()
    value = state.get("value")
    if value is None:
        value = pick_value()
        state["value"] = value
        _save_partial(state)

    _announce()
    intent_value = state.get("intent_value")
    if intent_value is None:
        intent_value = pick_intent_value()
        state["intent_value"] = intent_value
        _save_partial(state)

    # `is None` sentinel: keeping both defaults legitimately returns {}.
    _announce()
    assessments = state.get("assessments")
    if assessments is None:
        assessments = pick_assessments()
        state["assessments"] = assessments
        _save_partial(state)

    _announce()
    security_suite = state.get("security_suite")
    if security_suite is None:
        security_suite = pick_security_suite()
        state["security_suite"] = security_suite
        _save_partial(state)

    # Not saved with the partial state: its credentials must never be written there,
    # so a resumed run asks this optional step again.
    _announce()
    monitoring, monitoring_keys = pick_monitoring()

    _announce()
    advanced = state.get("advanced") or pick_advanced()
    state["advanced"] = advanced
    _save_partial(state)

    _announce()
    if "api_keys" not in advanced:
        # Carried inside ``advanced`` so write_config's signature stays put;
        # the writer emits the keys under [dashboard].
        advanced["api_keys"] = pick_api_keys()
        state["advanced"] = advanced
        _save_partial(state)

    return {
        "safety": safety,
        "signed_skills": signed_skills,
        "budget": budget,
        "approval": approval,
        "sandbox": sandbox,
        "research_execution": research_execution,
        "candidate_promotion": candidate_promotion,
        "knowledge_access": knowledge_access,
        "capabilities": capabilities,
        "self_learning": self_learning,
        "ekko": ekko,
        "automation_import": automation_import,
        "event_triggers": event_triggers,
        "flows": flows,
        "knowledge": knowledge,
        "knowledge_sources": knowledge_sources,
        "oauth": oauth,
        "governed_connectors": governed_connectors,
        "durable": durable,
        "workspace": workspace,
        "finance": finance,
        "value": value,
        "intent_value": intent_value,
        "assessments": assessments,
        "security_suite": security_suite,
        "monitoring": (monitoring, monitoring_keys),
        "advanced": advanced,
    }


def _run_plugin_picks(state: dict[str, Any], _announce, channels: dict[str, Any]) -> dict[str, Any]:
    """Run the plugin/ACL/policy block (mcp_servers through analytics).

    Uses the ``is None`` sentinel for steps whose legitimate answer is falsy.
    Returns the answers needed downstream by ``write_config``.
    """
    # NOTE: these steps use the `is None` sentinel (not `or`) because a
    # legitimately-declined answer is falsy ({}/[]); the `or` pattern treated
    # "I chose nothing" as "unanswered" and re-prompted it on --resume.
    _announce()
    mcp_servers = state.get("mcp_servers")
    if mcp_servers is None:
        mcp_servers = pick_mcp_servers()
        state["mcp_servers"] = mcp_servers
        _save_partial(state)

    _announce()
    plugins = state.get("plugins")
    if plugins is None:
        plugins = pick_plugins()
        state["plugins"] = plugins
        _save_partial(state)

    ts_plugins = state.get("ts_plugins")
    if ts_plugins is None:
        ts_plugins = pick_ts_plugins()
        state["ts_plugins"] = ts_plugins
        _save_partial(state)

    # Only ask about plugin permissions when at least one plugin is enabled --
    # most setups have none, so the step is skipped entirely.
    plugin_grant = state.get("plugin_grant")
    plugin_enforce = state.get("plugin_enforce", False)
    if plugins and plugin_grant is None:
        plugin_grant, plugin_enforce = pick_plugin_permissions()
        state["plugin_grant"] = plugin_grant
        state["plugin_enforce"] = plugin_enforce
        _save_partial(state)

    _announce()
    tool_acl = state.get("tool_acl")
    if tool_acl is None:
        tool_acl = pick_tool_acl(channels)
        state["tool_acl"] = tool_acl
        _save_partial(state)

    _announce()
    rate_limits = state.get("rate_limits")
    if rate_limits is None:
        rate_limits = pick_rate_limits(channels)
        state["rate_limits"] = rate_limits
        _save_partial(state)

    _announce()
    retention = state.get("retention")
    if retention is None:
        retention = pick_retention()
        state["retention"] = retention
        _save_partial(state)

    _announce()
    analytics = state.get("analytics")
    if analytics is None:
        analytics = {**pick_analytics(), **pick_usability_survey(), **pick_web_vitals(), **pick_usage_measures()}
        state["analytics"] = analytics
        _save_partial(state)

    return {
        "mcp_servers": mcp_servers,
        "plugins": plugins,
        "ts_plugins": ts_plugins,
        "plugin_grant": plugin_grant,
        "plugin_enforce": plugin_enforce,
        "tool_acl": tool_acl,
        "rate_limits": rate_limits,
        "retention": retention,
        "analytics": analytics,
    }


def _run_short_setup_mode(resume: bool) -> int | None:
    # A saved partial state belongs to the advanced flow, not the mode picker.
    if resume:
        return None
    mode = pick_mode()
    if mode == "consumer":
        return run_consumer()
    if mode == "express":
        return run_express()
    return None


def run(fast: bool = False, resume: bool = False) -> int:
    guard = _first_setup_guard()
    if guard is not None:
        return guard
    if fast:
        return run_fast()
    # A non-interactive stdin (CI, Docker build, `... | maverick init`) can't
    # answer prompts -- questionary just prints "Input is not a terminal" and
    # the first prompt aborts with a terse "Aborted!". Detect it up front and
    # point at the paths that DO work without a TTY.
    if not sys.stdin.isatty():
        console.print(
            "[yellow]maverick init needs an interactive terminal.[/yellow]\n"
            "  - run it in a terminal, or\n"
            "  - use  [bold]maverick init --fast[/bold]  for recommended defaults.\n"
            "After setup, use Lightwork Settings to make changes."
        )
        return 1
    welcome()
    short_result = _run_short_setup_mode(resume)
    if short_result is not None:
        return short_result
    if not preflight():
        console.print(
            "[red]Preflight failed.[/red] Fix the issues above and re-run `maverick init`."
        )
        return 1

    # --resume: load any persisted partial state and only ask
    # questions the user hasn't answered yet.
    state: dict[str, Any] = {}
    if resume:
        loaded = _load_partial()
        if loaded:
            state = loaded
            console.print(
                f"[dim]Resuming from {PARTIAL_STATE_PATH}: "
                f"{len(state)} answers already on file.[/dim]\n"
            )
        else:
            console.print(
                f"[yellow]⚠[/yellow] No partial state at {PARTIAL_STATE_PATH}; starting fresh.\n"
            )

    # Progress bar: announce "Step N/M <label>" before each pick_*, with a
    # breadcrumb of steps already behind us. Purely cosmetic.
    _done: list[str] = []
    _step = [0]

    def _announce() -> None:
        _step[0] += 1
        console.print(_step_indicator(_step[0], done=_done), style="bold cyan")
        _done.append(STEPS[_step[0] - 1][1])

    _announce()
    deployment = state.get("deployment") or pick_deployment()
    state["deployment"] = deployment
    _save_partial(state)

    _announce()
    providers = state.get("providers") or pick_providers()
    while not providers:
        # Aborting on empty selection forced the user to restart the
        # whole wizard. Re-ask instead.
        console.print("[yellow]Pick at least one provider; Lightwork needs an LLM.[/yellow]")
        providers = pick_providers()
    state["providers"] = providers
    _save_partial(state)

    provider_options = state.get("provider_options")
    if provider_options is None:
        provider_options = {}
        if "bedrock" in providers:
            provider_options["bedrock"] = pick_bedrock_auth()
        if "vertex" in providers:
            provider_options["vertex"] = pick_vertex()
        state["provider_options"] = provider_options
        _save_partial(state)

    per_tenant_keys = state.get("per_tenant_keys")
    if per_tenant_keys is None:
        per_tenant_keys = pick_per_tenant_keys()
        state["per_tenant_keys"] = per_tenant_keys
        _save_partial(state)

    _announce()
    role_models = state.get("role_models")
    if role_models is None:
        role_models = pick_models_per_role(providers, provider_options)
        state["role_models"] = role_models
        _save_partial(state)

    _announce()
    channels_state = state.get("channels")
    if channels_state is None:
        channels, channel_envs = pick_channels(deployment)
        # JSON-safe: store envs as a sorted list.
        state["channels"] = channels
        state["channel_envs"] = sorted(channel_envs)
        _save_partial(state)
    else:
        channels = channels_state
        channel_envs = set(state.get("channel_envs") or [])

    _simple = _run_simple_picks(state, _announce)
    safety = _simple["safety"]
    signed_skills = _simple["signed_skills"]
    budget = _simple["budget"]
    approval = _simple["approval"]
    sandbox = _simple["sandbox"]
    research_execution = _simple["research_execution"]
    candidate_promotion = _simple["candidate_promotion"]
    knowledge_access = _simple["knowledge_access"]
    capabilities = _simple["capabilities"]
    self_learning = _simple["self_learning"]
    ekko = _simple["ekko"]
    automation_import = _simple["automation_import"]
    event_triggers = _simple["event_triggers"]
    flows = _simple["flows"]
    knowledge = _simple["knowledge"]
    knowledge_sources = _simple["knowledge_sources"]
    oauth = _simple["oauth"]
    governed_connectors = _simple["governed_connectors"]
    durable = _simple["durable"]
    workspace = _simple["workspace"]
    finance = _simple["finance"]
    value = _simple["value"]
    intent_value = _simple["intent_value"]
    assessments = _simple["assessments"]
    security_suite = _simple["security_suite"]
    monitoring, monitoring_keys = _simple["monitoring"]
    advanced = _simple["advanced"]

    _announce()
    web_search_enabled, web_search_envs = state.get("_web_search_pair") or pick_web_search()
    state["_web_search_pair"] = [web_search_enabled, web_search_envs]
    _save_partial(state)

    _plugins_block = _run_plugin_picks(state, _announce, channels)
    mcp_servers = _plugins_block["mcp_servers"]
    plugins = _plugins_block["plugins"]
    ts_plugins = _plugins_block["ts_plugins"]
    plugin_grant = _plugins_block["plugin_grant"]
    plugin_enforce = _plugins_block["plugin_enforce"]
    tool_acl = _plugins_block["tool_acl"]
    rate_limits = _plugins_block["rate_limits"]
    retention = _plugins_block["retention"]
    analytics = _plugins_block["analytics"]

    _announce()
    persona = state.get("persona")
    if persona is None:
        persona = pick_persona()
        state["persona"] = persona
        _save_partial(state)

    _announce()
    notifications, notify_envs = state.get("_notifications_pair") or pick_notifications()
    _resolve_private_alert_linking(advanced, notifications)
    state["advanced"] = advanced
    state["_notifications_pair"] = [notifications, notify_envs]
    _save_partial(state)

    _announce()
    deadline_alerts = _deadline_alerts_step(state, notifications)

    _announce()
    my_work_cfg, notifications_email, summary_envs = _daily_summary_step(state, channels)
    support_cfg = state.get("_support") if isinstance(state.get("_support"), dict) else pick_support()
    state["_support"] = support_cfg
    collaboration_cfg = (state.get("_collaboration") if isinstance(state.get("_collaboration"), dict)
                         else {**pick_collaboration(), **pick_suggestions()})
    state["_collaboration"] = collaboration_cfg
    _save_partial(state)

    _announce()
    webhooks, webhook_envs = state.get("_webhooks_pair") or pick_webhooks()
    state["_webhooks_pair"] = [webhooks, webhook_envs]
    _save_partial(state)

    deliverables, deliverable_envs = state.get("_deliverables_pair") or pick_deliverable_handoff()
    state["_deliverables_pair"] = [deliverables, deliverable_envs]
    _save_partial(state)

    contact_centre, contact_centre_envs = state.get("_contact_centre_pair") or pick_contact_centre()
    state["_contact_centre_pair"] = [contact_centre, contact_centre_envs]
    _save_partial(state)

    personas = state.get("_personas") or pick_persona_roles()
    state["_personas"] = personas
    _save_partial(state)

    _announce()
    a2a_cfg, a2a_envs = state.get("_a2a_pair") or pick_a2a()
    state["_a2a_pair"] = [a2a_cfg, a2a_envs]
    _save_partial(state)

    # Keys/sessions are never persisted to disk in the partial state
    # (they're secrets; the only safe place is ~/.maverick/.env).
    extra_envs = (
        set(web_search_envs)
        | set(notify_envs)
        | set(summary_envs)
        | set(webhook_envs)
        | set(a2a_envs)
        | set(deliverable_envs)
    )
    keys = collect_api_keys(providers, channel_envs | extra_envs)
    # Enterprise connectors are always registered; collect any credentials the
    # user wants to wire up now (merged into ~/.maverick/.env, never persisted
    # to partial state). Editable later in the .env file.
    keys.update(pick_connectors())
    keys.update(monitoring_keys)

    suites = pick_suites()

    console.print()
    if not _q_confirm("Write config and finish?", default=True):
        # Be honest about where the state lives and what restore does.
        console.print(
            f"Stopped. Partial answers saved to {PARTIAL_STATE_PATH}.\n"
            "Resume with: maverick init --resume"
        )
        return 0

    write_config(
        providers,
        role_models,
        channels,
        safety,
        budget,
        sandbox,
        keys,
        capabilities,
        research_execution=research_execution,
        candidate_promotion=candidate_promotion,
        knowledge_access=knowledge_access,
        advanced=advanced,
        provider_options=provider_options,
        mcp_servers=mcp_servers,
        plugins=plugins,
        plugin_grant=plugin_grant,
        ts_plugins=ts_plugins,
        plugin_enforce=plugin_enforce,
        tool_acl=tool_acl,
        rate_limits=rate_limits,
        retention=retention,
        analytics=analytics,
        persona=persona,
        notifications=notifications,
        deadline_alerts=deadline_alerts,
        webhooks=webhooks,
        deliverables=deliverables,
        contact_centre=contact_centre,
        personas=personas,
        a2a=a2a_cfg,
        my_work=my_work_cfg,
        notifications_email=notifications_email,
        support=support_cfg,
        collaboration=collaboration_cfg,
        web_search_enabled=web_search_enabled,
        skills=signed_skills
        if (
            signed_skills.get("trusted_pubkeys")
            or signed_skills.get("require_signed")
            or signed_skills.get("require_signed_catalog")
        )
        else None,
        self_learning=self_learning if self_learning.get("enable") else None,
        # Persist the explicit default-off decision. Unlike default-on governed
        # learning, Ekko never inherits authority from another feature.
        ekko=ekko,
        automation_import=automation_import if automation_import.get("enable") else None,
        event_triggers=event_triggers if event_triggers.get("enable") else None,
        flows=flows if flows.get("enable") else None,
        knowledge=knowledge if knowledge.get("enable") else None,
        knowledge_sources=knowledge_sources if knowledge.get("enable") else None,
        oauth=oauth if oauth.get("vault") else None,
        governed_connectors=governed_connectors if governed_connectors.get("enable") else None,
        durable=durable if durable.get("enabled") else None,
        workspace=workspace if workspace.get("journal") else None,
        finance=finance if finance.get("enable") else None,
        value=value or None,
        intent_value=intent_value,
        assessments=assessments or None,
        security_suite=security_suite,
        monitoring=monitoring,
        approval=approval,
        suites=suites,
        # The advanced flow applies no preset -- the operator hand-picked
        # every knob -- so record "custom" rather than omitting the label
        # (dashboards keyed on [governance].profile would otherwise read
        # advanced-configured tenants, the most governance-sensitive ones,
        # as tier-less) or borrowing a level name the knobs may not match.
        governance_profile="custom",
        per_tenant_keys=per_tenant_keys,
        protect_existing=True,
    )
    _clear_partial()
    ok = smoke_test()
    if ok:
        console.print()
        next_step = "maverick serve" if channels else 'maverick start "hello"'
        console.print(
            Panel.fit(
                "[bold green]Setup complete.[/bold green]\n\n"
                "Try:\n"
                f"  [bold]{next_step}[/bold]\n"
                "  [bold]maverick status[/bold]\n"
                "  [bold]maverick dashboard[/bold]    # web UI at http://127.0.0.1:8765\n\n"
                "[dim]The maverick command is also available as lightwork.[/dim]",
                border_style="green",
            )
        )
        show_compliance_commands(advanced)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
