"""Dashboard Settings overlay for provider keys + capability/feature toggles.

Writes ``~/.maverick/dashboard-config.toml`` (config.dashboard_overrides_path),
which ``maverick.config.load_config`` deep-merges over config.toml — so a key
or toggle set in the UI takes effect on the next run without touching the
user's config.toml. The run-time overrides for models, budget and tool denials
(``maverick.runtime_overrides``) live in the separate runtime-overrides.toml,
read via their own hooks.
This file still holds some settings of those kinds: the ``[models]``
discovery switch, the ``models.*`` and ``budget.*`` settings saved from All
settings, and ``security.denied_tools`` when container file work is turned on.

Secrets: provider api_keys, webhook signing material, and channel credentials
are authenticated-encrypted with the deployment at-rest key before this file is
written (the file is also mode 0600). The kernel transparently opens those
values while loading the fixed dashboard overlay, so a key set here unblocks
goals immediately. The HTTP layer must NEVER echo a stored key back — callers
get a masked hint only (see ``state()``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from pathlib import Path

from maverick import config

from .settings_catalog import CHANNEL_ALLOWLISTS
from .settings_feature_metadata import FEATURE_DEFAULTS, FEATURE_INFO

# Serializes the overlay load-modify-save in-process; cross_process_lock in
# _locked() extends it across processes (multiple dashboard workers edit
# provider keys / toggles).
_SETTINGS_LOCK = threading.RLock()


class SecuritySuiteRevisionConflict(RuntimeError):
    """The admin edited an out-of-date deployment-wide security control."""


class SecuritySuiteConfigUnavailable(RuntimeError):
    """The security-suite overlay cannot be read without risking data loss."""


class SettingsNotStorable(SecuritySuiteConfigUnavailable):
    """The new overlay would not read back, so the file was left unchanged."""


class ProviderRotationConflict(RuntimeError):
    """Provider authority changed or rejected a dashboard credential rotation."""


class ProviderConfigurationUnavailable(RuntimeError):
    """Provider authority could not be inspected or restored safely."""


class ResearchSettingsConflict(RuntimeError):
    """The administrator reviewed an older research execution profile."""


class ResearchSettingsUnavailable(RuntimeError):
    """A higher-precedence operator source owns the research profile."""


def _locked(*, strict: bool = False):
    from contextlib import ExitStack

    from maverick.authority_effects import authority_effect_fence
    from maverick.file_lock import cross_process_lock
    stack = ExitStack()
    try:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_SETTINGS_LOCK)
        stack.enter_context(
            cross_process_lock(config.dashboard_overrides_path(), strict=strict)
        )
    except BaseException:
        # ``ExitStack`` is not itself entered until the caller's ``with``. If
        # the second acquisition fails here, release the already-held
        # in-process lock instead of wedging every later settings mutation.
        stack.close()
        raise
    return stack


def _security_suite_revision(data: dict) -> int:
    metadata = data.get("security_suite_control")
    value = metadata.get("revision") if isinstance(metadata, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return 1
    return value


def security_suite_revision() -> int:
    """Return the monotonic CAS revision for the four suite control bits."""
    with _locked():
        return _security_suite_revision(_load_security_suite_overlay())

# Providers offered in the UI: name, label, env var(s) that also satisfy it,
# whether a base_url (self-hosted endpoint) is relevant.
PROVIDERS: list[dict] = [
    {"name": "anthropic", "label": "Anthropic (Claude)", "env": ["ANTHROPIC_API_KEY"], "base_url": False},
    {"name": "openai", "label": "OpenAI", "env": ["OPENAI_API_KEY"], "base_url": False},
    {"name": "gemini", "label": "Google Gemini", "env": ["GEMINI_API_KEY", "GOOGLE_API_KEY"], "base_url": False},
    {"name": "openrouter", "label": "OpenRouter", "env": ["OPENROUTER_API_KEY"], "base_url": False},
    {"name": "moonshot", "label": "Moonshot", "env": ["MOONSHOT_API_KEY"], "base_url": False},
    {"name": "deepseek", "label": "DeepSeek", "env": ["DEEPSEEK_API_KEY"], "base_url": False},
    {"name": "xai", "label": "xAI (Grok)", "env": ["XAI_API_KEY", "GROK_API_KEY"], "base_url": False},
    {"name": "ollama", "label": "Ollama (self-hosted)", "env": [], "base_url": True},
    {"name": "vllm", "label": "vLLM (self-hosted)", "env": ["VLLM_BASE_URL"], "base_url": True},
    {"name": "tgi", "label": "Hugging Face TGI (self-hosted)", "env": ["TGI_BASE_URL"], "base_url": True},
    {"name": "openai_compatible", "label": "OpenAI-compatible server", "env": ["OPENAI_COMPATIBLE_BASE_URL"], "base_url": True},
    {"name": "azure", "label": "Azure OpenAI", "env": ["AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"], "base_url": True},
    {"name": "bedrock", "label": "Amazon Bedrock", "env": ["BEDROCK_API_KEY", "AWS_REGION"], "base_url": False},
    {"name": "vertex", "label": "Google Cloud Vertex AI (Claude)", "env": [], "base_url": False},
]
_PROVIDER_NAMES = {p["name"] for p in PROVIDERS}

# Mirror maverick.config.get_capabilities/get_features keys + defaults.
CAPABILITY_DEFAULTS = {
    "computer_use": False, "browser": False, "web_search": False,
    "mobile_tools": False, "ros": False, "code_exec": False,
}

# What each toggle actually turns on -- shown next to the checkbox so an
# admin knows what they are selecting before they select it.
CAPABILITY_INFO = {
    "computer_use": "Agents drive a real desktop inside the sandbox — click, "
                    "type, read the screen. The highest-impact capability; "
                    "enable only for workflows that need to use another app.",
    "browser": "Agents open web pages, follow links, and read page content. "
               "Your rules for external connections still apply.",
    "web_search": "Live web search for research tasks; results flow into the "
                  "agent's context with their sources.",
    "mobile_tools": "Agents use connected Android or iOS devices to tap, "
                    "swipe, and read screens for app testing and tasks.",
    "ros": "Agents exchange instructions and readings with connected robots. "
           "Requires an installed Robot Operating System connection.",
    "code_exec": "Agents run the code they write, inside the governed "
                 "work environment. Allowed actions are checked and recorded "
                 "before shell commands run.",
}

# The self-learning loop's subsystems -- ONE source of truth shared by the
# one-click toggle (set_learning writes each (section, config_key) to the
# overlay, which load_config deep-merges so every subsystem's enabled() sees it),
# each subsystem's own switch (set_learning_subsystem writes one of them; ``env``
# names the deployment variable that overrides it, ``needs`` a subsystem it only
# works under) and the /learning status view (which pairs each key with its live
# enabled()).
# Keeping both off one list stops the button and the view from drifting when a
# subsystem is added. Governed learning defaults ON; DGM is intentionally not
# in this registry and has its own high-risk production control.
LEARNING_SUBSYSTEMS: list[dict] = [
    {"key": "self_learning", "section": "self_learning", "config_key": "enable",
     "label": "Learn new skills from work",
     "description": "Agents notice a skill a task needs and pick up an approved one "
                    "from the catalog.",
     "env": "MAVERICK_SELF_LEARNING",
     "how": "[self_learning] enable — or MAVERICK_SELF_LEARNING=0 to opt out"},
    {"key": "distill_local", "section": "self_learning", "config_key": "distill_local",
     "label": "Suggest skills from repeated successes",
     "description": "Prepare a reusable skill suggestion on this server. Review and add it "
                    "from Skills before future tasks use it.",
     "env": "MAVERICK_DISTILL_LOCAL",
     "how": "[self_learning] distill_local — or MAVERICK_DISTILL_LOCAL=0"},
    {"key": "failure_telemetry", "section": "telemetry", "config_key": "failure_modes",
     "label": "Count the kinds of failures",
     "description": "Keep a count of how tasks fail, so learning can focus on the "
                    "common problems. Nothing leaves this server.",
     "env": "MAVERICK_FAILURE_TELEMETRY",
     "how": "[telemetry] failure_modes or MAVERICK_FAILURE_TELEMETRY=0"},
    {"key": "budget_tuning", "section": "budget", "config_key": "self_tuning",
     "default": False,
     "label": "Suggest task limits from experience",
     "description": "Learn how much each kind of task really needs and suggest a "
                    "spending limit for it. A limit you set always wins.",
     "env": "MAVERICK_BUDGET_SELF_TUNING",
     "how": "[budget] self_tuning or MAVERICK_BUDGET_SELF_TUNING=0"},
    {"key": "consequence", "section": "consequence", "config_key": "enable",
     "label": "Learn from real results",
     "description": "Learn from what really happened, such as an invoice paid, "
                    "instead of the answer checker's guess.",
     "env": "MAVERICK_CONSEQUENCE",
     "how": "[consequence] enable — or MAVERICK_CONSEQUENCE=0"},
    {"key": "reflexion", "section": "reflexion", "config_key": "enable",
     "label": "Remember lessons from mistakes",
     "description": "After a task goes wrong, write down what happened so later "
                    "tasks avoid it.",
     "env": "MAVERICK_REFLEXION",
     "how": "[reflexion] enable — or MAVERICK_REFLEXION=0"},
    {"key": "dreaming", "section": "dreaming", "config_key": "enable",
     "label": "Learn from recent work on a schedule",
     "description": "Regularly review finished work to write lessons and turn "
                    "repeated successes into skills.",
     "env": "MAVERICK_DREAMING",
     "how": "[dreaming] enable — or MAVERICK_DREAMING=0"},
    {"key": "experience", "section": "experience", "config_key": "enable",
     "label": "Plan from past experience",
     "description": "Use how similar past tasks went to plan and staff a new one.",
     "env": "MAVERICK_EXPERIENCE_GUIDANCE",
     "how": "[experience] enable — or MAVERICK_EXPERIENCE_GUIDANCE=0"},
    {"key": "skill_synthesis", "section": "skill_synthesis", "config_key": "enable",
     "label": "Prepare guidance for each task",
     "description": "Before a task starts, write short guidance for that task.",
     "env": "MAVERICK_SKILL_SYNTHESIS",
     "how": "[skill_synthesis] enable — or MAVERICK_SKILL_SYNTHESIS=0"},
    {"key": "self_improvement", "section": "self_improvement", "config_key": "enable",
     "label": "Adopt proven improvements",
     "description": "Adopt a learned change only after it passes its checks. Several "
                    "parts below need this on.",
     "env": "MAVERICK_SELF_IMPROVEMENT",
     "how": "[self_improvement] enable — or MAVERICK_SELF_IMPROVEMENT=0"},
    {"key": "prm_guidance", "section": "self_improvement", "config_key": "prm_guidance",
     "label": "Nudge agents that stall",
     "description": "Prompt an agent to change approach when several steps in a row "
                    "make no progress.",
     "env": "MAVERICK_PRM_GUIDANCE",
     "how": "[self_improvement] prm_guidance or MAVERICK_PRM_GUIDANCE=0"},
    {"key": "capture", "section": "self_improvement", "config_key": "capture",
     "label": "Keep an outline of how tasks ran",
     "description": "Save an outline of each task's steps, with secrets removed, as "
                    "the material learning works from.",
     "env": "MAVERICK_TRAJECTORY_CAPTURE",
     "how": "[self_improvement] capture — or MAVERICK_TRAJECTORY_CAPTURE=0"},
    {"key": "causal_promotion", "section": "self_improvement", "config_key": "causal_promotion",
     "label": "Require a controlled comparison before adopting changes",
     "description": "Ordinary task history suggests candidates. Automatic adoption needs "
                    "a prospectively controlled comparison with enough evidence.",
     "env": "MAVERICK_CAUSAL_PROMOTION", "needs": "self_improvement",
     "how": "[self_improvement] causal_promotion — or MAVERICK_CAUSAL_PROMOTION=0"},
    {"key": "factory_learning", "section": "self_improvement", "config_key": "factory_learning",
     "label": "Improve how new agents are built",
     "description": "Learn from the gaps found when new agents are set up, so the "
                    "next ones start better.",
     "env": "MAVERICK_FACTORY_LEARNING", "needs": "self_improvement",
     "how": "[self_improvement] factory_learning — or MAVERICK_FACTORY_LEARNING=0"},
    {"key": "evaluator_evolution", "section": "self_improvement", "config_key": "evaluator_evolution",
     "label": "Replace a drifting answer checker",
     "description": "When the answer checker drifts, try a better one against fixed, "
                    "locked examples.",
     "env": "MAVERICK_EVALUATOR_EVOLUTION", "needs": "self_improvement",
     "how": "[self_improvement] evaluator_evolution — or MAVERICK_EVALUATOR_EVOLUTION=0"},
    {"key": "self_harness", "section": "self_harness", "config_key": "enable",
     "label": "Improve agent instructions carefully",
     "description": "Find recurring mistakes and test a fix to agents' instructions on "
                    "unseen cases before using it.",
     "env": "MAVERICK_SELF_HARNESS",
     "how": "[self_harness] enable — or MAVERICK_SELF_HARNESS=0"},
    {"key": "data_engine", "section": "data_engine", "config_key": "enable",
     "label": "Improvement flywheel",
     "description": "Find the failures that cost the most and test a fix in a "
                    "simulation first.",
     "env": "MAVERICK_DATA_ENGINE",
     "how": "[data_engine] enable — or MAVERICK_DATA_ENGINE=0"},
    {"key": "operations_scientist", "section": "operations_scientist", "config_key": "enable",
     "label": "Look for better ways of working",
     "description": "Suggest a better step to replace one that keeps causing harm, "
                    "tested in a simulation first.",
     "env": "MAVERICK_OPERATIONS_SCIENTIST",
     "how": "[operations_scientist] enable — or MAVERICK_OPERATIONS_SCIENTIST=0"},
    {"key": "rehearsal", "section": "rehearsal", "config_key": "enable",
     "label": "Risky action predictions",
     "description": "Compare high-impact actions with past work. The Safety setting "
                    "decides whether predictions only watch or hold actions; Shield, "
                    "permissions, and required approvals still apply.",
     "env": "MAVERICK_REHEARSAL",
     "how": "[rehearsal] enable — or MAVERICK_REHEARSAL=0"},
    {"key": "credit", "section": "credit", "config_key": "enable",
     "label": "Score each agent's part in team work",
     "description": "Work out how much each agent in a team helped, to learn which "
                    "agents to use.",
     "env": "MAVERICK_CREDIT",
     "how": "[credit] enable — or MAVERICK_CREDIT=0"},
    {"key": "reasoning_reward", "section": "reasoning_reward", "config_key": "enable",
     "label": "Detailed answer scoring",
     "description": "Score final answers on several points, with a safety veto.",
     "env": "MAVERICK_REASONING_REWARD",
     "how": "[reasoning_reward] enable or MAVERICK_REASONING_REWARD=0"},
    {"key": "reward_audit", "section": "reasoning_reward", "config_key": "audit_rewards",
     "label": "Record answer scores in the activity log",
     "description": "Sign each detailed score into the tamper-evident activity log.",
     "env": "MAVERICK_REASONING_REWARD_AUDIT",
     "how": "[reasoning_reward] audit_rewards or MAVERICK_REASONING_REWARD_AUDIT=0"},
    {"key": "jit_rl", "section": "jit_rl", "config_key": "enable",
     "label": "Favour answers that worked before",
     "description": "When agents write several answers, lean toward the kind that "
                    "checked out well before.",
     "env": "MAVERICK_JIT_RL",
     "how": "[jit_rl] enable or MAVERICK_JIT_RL=0"},
]
LEARNING_TOGGLES = [(s["section"], s["config_key"]) for s in LEARNING_SUBSYSTEMS]
_LEARNING_SECTIONS = list(dict.fromkeys(s["section"] for s in LEARNING_SUBSYSTEMS))

# Channels offered in the UI: name + per-field spec. Keys MUST match what
# server.py's _wire_<name> reads from [channels.<name>] (verified against the
# wiring), so a value saved here actually configures the channel via the
# load_config() deep-merge. ``secret`` fields are masked + never echoed back;
# ``type: int`` fields are stored as numbers.
CHANNELS: list[dict] = [
    {"name": "telegram", "label": "Telegram", "fields": [
        {"key": "bot_token", "label": "Bot token", "secret": True},
    ]},
    {"name": "discord", "label": "Discord", "fields": [
        {"key": "bot_token", "label": "Bot token", "secret": True},
    ]},
    {"name": "slack", "label": "Slack", "fields": [
        {"key": "app_token", "label": "App-level token", "secret": True},
        {"key": "bot_token", "label": "Bot token", "secret": True},
        {"key": "signing_secret", "label": "Signing secret", "secret": True,
         "env": "SLACK_SIGNING_SECRET"},
        {"key": "approvals_channel", "label": "Approvals channel", "secret": False},
    ]},
    {"name": "whatsapp_cloud", "label": "WhatsApp (Cloud API)", "fields": [
        {"key": "access_token", "label": "Access token", "secret": True},
        {"key": "phone_number_id", "label": "Phone number ID", "secret": False},
        {"key": "verify_token", "label": "Verify token", "secret": True},
        {"key": "app_secret", "label": "App secret", "secret": True},
        {"key": "port", "label": "Webhook port", "secret": False, "type": "int"},
    ]},
    {"name": "sms", "label": "SMS (Twilio)", "fields": [
        {"key": "account_sid", "label": "Account SID", "secret": False},
        {"key": "auth_token", "label": "Auth token", "secret": True},
        {"key": "from_number", "label": "From number", "secret": False},
        {"key": "port", "label": "Webhook port", "secret": False, "type": "int"},
    ]},
    {"name": "email", "label": "Email (IMAP/SMTP)", "fields": [
        {"key": "email_auth", "label": "Email sign-in", "secret": False},
        {"key": "oauth_account", "label": "Connected Microsoft mailbox", "secret": False},
        {"key": "imap_host", "label": "IMAP host", "secret": False},
        {"key": "trusted_authserv_id", "label": "Incoming mail server identity", "secret": False},
        {"key": "imap_user", "label": "IMAP user", "secret": False},
        {"key": "imap_password", "label": "IMAP password", "secret": True},
        {"key": "smtp_host", "label": "SMTP host", "secret": False},
        {"key": "smtp_user", "label": "SMTP user", "secret": False},
        {"key": "smtp_password", "label": "SMTP password", "secret": True},
        {"key": "smtp_port", "label": "SMTP port", "secret": False, "type": "int"},
    ]},
    {"name": "mattermost", "label": "Mattermost", "fields": [
        {"key": "url", "label": "Server address", "secret": False, "type": "url"},
        {"key": "bot_token", "label": "Bot access token", "secret": True,
         "env": "MATTERMOST_BOT_TOKEN"},
    ]},
    {"name": "teams", "label": "Microsoft Teams", "fields": [
        {"key": "app_id", "label": "App ID", "secret": False},
        {"key": "app_password", "label": "Client secret", "secret": True,
         "env": "TEAMS_APP_PASSWORD"},
        {"key": "tenant_id", "label": "Tenant ID", "secret": False},
        {"key": "port", "label": "Webhook port", "secret": False, "type": "int"},
    ]},
]
# The main setup form must include the access list each adapter needs to
# start. Share the same identity formats as the guided All settings editor.
for _channel_spec in CHANNELS:
    _access = CHANNEL_ALLOWLISTS.get(_channel_spec["name"])
    if _access:
        _, _, _key, _item, _hint, _pattern, _error = _access
        _channel_spec["fields"].append({
            "key": _key, "label": "Who can message Lightwork", "type": "list",
            "help": f"Add each permitted {_item.lower()} on its own line. Example: {_hint}. "
                    "Saving a blank list stops everyone from messaging Lightwork through this app. "
                    "Use All settings to restore an inherited list instead.",
            "env": f"{_channel_spec['name'].upper()}_{_key.upper()}",
        })
_CHANNELS_BY_NAME = {c["name"]: c for c in CHANNELS}


def _tomllib():
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    return tomllib


def _unseal_overlay(data: dict) -> dict:
    """Open authenticated dashboard ciphertext without mutating parsed TOML."""
    # Reuse the config loader's bounded tree contract.  It performs a cheap
    # marker preflight, authenticates every token, and forces the deployment
    # key so an ambient tenant cannot change which key opens global settings.
    return config._unseal_config_tree(data)  # type: ignore[return-value]


def _seal_global_secret(value: object) -> str:
    """Return one deployment-key ciphertext, preserving existing ciphertext."""
    from maverick.crypto_at_rest import (
        deployment_key_scope,
        is_sealed_str,
        seal_to_str,
    )

    text = str(value)
    if is_sealed_str(text):
        return text
    with deployment_key_scope():
        return seal_to_str(text)


def load_overlay() -> dict:
    p = config.dashboard_overrides_path()
    if not p.exists():
        return {}
    try:
        with open(p, "rb") as f:
            return _unseal_overlay(_tomllib().load(f))
    except (OSError, ValueError):
        return {}


def _load_overlay_for_update() -> dict:
    """Strict overlay read for every load-modify-write operation.

    The general Settings UI historically treats a malformed optional overlay as
    empty. A mutation cannot: writing a newly constructed table over unreadable
    state would delete unrelated provider, channel, feature, and security-suite
    settings. Missing remains the one legitimate empty state.
    """
    path = config.dashboard_overrides_path()
    try:
        with open(path, "rb") as handle:
            value = _tomllib().load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise SecuritySuiteConfigUnavailable(
            "dashboard settings are unreadable; settings were not changed"
        ) from exc
    if not isinstance(value, dict):  # defensive: TOML roots are mappings
        raise SecuritySuiteConfigUnavailable(
            "dashboard settings are unreadable; settings were not changed"
        )
    return value


def _load_security_suite_overlay() -> dict:
    """Compatibility name for the strict security-suite CAS read."""
    return _load_overlay_for_update()


def _toml_str(value: str) -> str:
    # JSON strings are valid TOML basic strings, except that JSON leaves the
    # DEL character bare where TOML requires it escaped.
    return json.dumps(str(value)).replace("\x7f", "\\u007f")


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


def _toml_key(key: object) -> str:
    """A table key, quoted unless TOML allows it bare (``"mcp_*"`` must be)."""
    text = str(key)
    return text if _BARE_KEY.fullmatch(text) else _toml_str(text)


def _toml_value(value) -> str:
    """Render the bounded TOML value types load_overlay can return.

    Security connector selections and vendor extension settings may be arrays
    or inline tables. Coercing them through ``str()`` silently changed their
    type on every unrelated feature-toggle save.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _toml_str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        entries = (
            f"{_toml_str(str(key))} = {_toml_value(item)}"
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        )
        return "{ " + ", ".join(entries) + " }"
    raise TypeError(f"unsupported dashboard setting value: {type(value).__name__}")


def _dump_value(lines: list[str], val: dict) -> None:
    """Emit [value] -- the client's cost/value assumptions for the Savings
    page (hourly rate, hours per task, optional per-department overrides).
    Read back by maverick.config.get_value via the same deep-merge as
    everything else."""
    if not val:
        return
    lines.append("[value]")
    if "enable" in val:
        lines.append(f"enable = {'true' if val['enable'] else 'false'}")
    for k in ("hourly_rate", "hours_per_task"):
        if k in val:
            lines.append(f"{k} = {float(val[k])}")
    if val.get("currency"):
        lines.append(f"currency = {_toml_str(val['currency'])}")
    lines.append("")
    for name in sorted(val.get("departments") or {}):
        ov = val["departments"][name] or {}
        if not ov:
            continue
        lines.append(f"[value.departments.{_toml_str(name)}]")
        for k in ("hourly_rate", "hours_per_task"):
            if k in ov:
                lines.append(f"{k} = {float(ov[k])}")
        lines.append("")


def _dump_selector_sections(lines: list[str], data: dict) -> None:
    """Emit the [dashboard] and [sandbox] tables the dashboard owns:
    active_tenant (set_active_tenant), backend (set_sandbox_backend) and the
    catalog keys the All settings page writes (compress, timeout). _dump is an
    allowlist serializer, so a key missing here would be silently dropped by
    the next save."""
    for section in ("dashboard", "sandbox"):
        tbl = data.get(section) or {}
        keys = [k for k in sorted(tbl) if tbl[k] is not None and tbl[k] != ""]
        if not keys:
            continue
        sealed = _dashboard_secret_keys() if section == "dashboard" else frozenset()
        lines.append(f"[{section}]")
        for k in keys:
            value = tbl[k]
            if k in sealed and isinstance(value, str):
                # The sign-in session key: never written in the clear, even
                # when it arrived from a hand-edited overlay.
                value = _seal_global_secret(value)
            lines.append(f"{_toml_key(k)} = {_toml_value(value)}")
        lines.append("")


def _dashboard_secret_keys() -> frozenset[str]:
    """[dashboard] keys the All settings page keeps sealed."""
    from .settings_catalog import SETTINGS

    return frozenset(s.key for s in SETTINGS if s.section == "dashboard" and s.secret)


def _dump_plugins(lines: list[str], plugins: dict) -> None:
    """Emit [plugins] -- the dashboard-install allowlist + opt-in switch
    (set_installable_plugins / set_plugin_install_allowed) and every plugin
    setting the All settings page writes (permission grants, signing,
    isolation, version lock, usage counts). An emptied install allowlist is
    dropped, as before; every other key is written as stored."""
    keys = [
        k for k in sorted(plugins or {})
        if plugins[k] is not None and plugins[k] != ""
        and not (k == "installable" and not plugins[k])
    ]
    if not keys:
        return
    lines.append("[plugins]")
    for k in keys:
        lines.append(f"{_toml_key(k)} = {_toml_value(plugins[k])}")
    lines.append("")


def _dump_webhooks(lines: list[str], whk: dict) -> None:
    """Emit [webhooks]: the signing key the Settings page manages (sealed
    before persistence, never logged or re-displayed), the outbound addresses,
    and the delivery limits and tracker identities the All settings page
    writes. _dump is an allowlist serializer, so a catalog key missing here
    would be silently dropped by the next save."""
    keys = [k for k in sorted(whk) if whk[k] is not None and whk[k] != ""
            and (k not in {"secret", "outbound"} or whk[k])]
    if not keys:
        return
    lines.append("[webhooks]")
    for k in keys:
        if k == "secret":
            lines.append(f"secret = {_toml_str(_seal_global_secret(whk['secret']))}")
        elif k == "outbound":
            lines.append(f"outbound = {_toml_value(list(whk['outbound']))}")
        else:
            # Catalog secrets arrive already sealed (set_catalog_values).
            lines.append(f"{_toml_key(k)} = {_toml_value(whk[k])}")
    lines.append("")


# Provider fields the dashboard writes: keys and addresses on the Settings
# page, and sign-in mode, Bedrock endpoint/region and Azure deployment/version
# on the All settings page.
_PROVIDER_FIELDS = ("api_key", "base_url", "auth_mode", "endpoint", "region",
                    "model_id", "deployment", "api_version", "project_id")


def _dump_providers(lines: list[str], providers: dict) -> None:
    """Emit [providers] switches (per_tenant_keys) and each provider's table."""
    switches = {k: v for k, v in providers.items()
                if not isinstance(v, dict) and v is not None and v != ""}
    if switches:
        lines.append("[providers]")
        for k in sorted(switches):
            lines.append(f"{_toml_key(k)} = {_toml_value(switches[k])}")
        lines.append("")
    for name in sorted(k for k, v in providers.items() if isinstance(v, dict)):
        pcfg = providers[name]
        fields = [(f, pcfg.get(f)) for f in _PROVIDER_FIELDS if pcfg.get(f)]
        if not fields:
            continue
        lines.append(f"[providers.{name}]")
        for field, val in fields:
            if field == "api_key":
                val = _seal_global_secret(val)
            lines.append(f"{field} = {_toml_str(val)}")
        lines.append("")


def _dump(data: dict) -> str:
    lines = [
        "# Dashboard-managed settings overlay (provider keys + capability/feature",
        "# toggles). Edit via the dashboard Settings page, not by hand. Your",
        "# config.toml is never touched by the dashboard.",
        "",
    ]
    # "flows" carries the autonomous self-improvement knobs (auto_evolve/auto_apply,
    # both booleans) -- persisted here so set_flow_autonomy survives a restart.
    # _MODULE_TOP_SECTIONS: the governance-module tables set_module_enables
    # writes (nested subsection dicts serialize as inline tables, which
    # deep-merge identically to [a.b] headers). dict.fromkeys dedupes: a
    # section emitted twice is a duplicate TOML table, which invalidates the
    # WHOLE overlay file.
    for section in dict.fromkeys((
                    "capabilities", "features", "flows", "self_modify", "ekko",
                    "security_ops", "threat_hunt", "env_hunt",
                    "security_suite_control", "oauth", "workspace", "_dashboard_resets",
                    # Portal link keyring (portal_routing_key_api); sealed values.
                    "third_party_portal",
                    # Consent publication signing keyring
                    # (consent_publication_signing_api); sealed values.
                    "consent_publication_signing",
                    "research_execution", "models", "catalogs", "agent_trust", "immune",
                    *COMPLIANCE_SETTING_SECTIONS,
                    *_LEARNING_SECTIONS, *_MODULE_TOP_SECTIONS,
                    *SWITCHABLE_SECTIONS, *_catalog_generic_sections())):
        tbl = data.get(section) or {}
        if tbl:
            lines.append(f"[{section}]")
            for k in sorted(tbl):
                lines.append(f"{_toml_key(k)} = {_toml_value(tbl[k])}")
            lines.append("")
    _dump_selector_sections(lines, data)
    _dump_plugins(lines, data.get("plugins") or {})
    _dump_value(lines, data.get("value") or {})
    # [model_cost_tiers] -- manager-set cost bands per model. Keys are model
    # ids that can contain '/' or '.', so they are always quoted.
    tiers = data.get("model_cost_tiers") or {}
    if tiers:
        lines.append("[model_cost_tiers]")
        for model in sorted(tiers):
            lines.append(f"{_toml_str(model)} = {_toml_str(str(tiers[model]))}")
        lines.append("")
    _dump_webhooks(lines, data.get("webhooks") or {})
    _dump_providers(lines, data.get("providers") or {})
    channels = data.get("channels") or {}
    # Settings for every chat app at once ([channels] rich_render) sit in the
    # table itself; each app's own settings are a [channels.<name>] table.
    shared = {k: v for k, v in channels.items() if not isinstance(v, dict) and v is not None}
    if shared:
        lines.append("[channels]")
        for k in sorted(shared):
            lines.append(f"{_toml_key(k)} = {_toml_value(shared[k])}")
        lines.append("")
    for name in sorted(channels):
        ccfg = channels[name] or {}
        if not isinstance(ccfg, dict) or not ccfg:
            continue
        lines.append(f"[channels.{name}]")
        # Only an explicit on/off is written: a channel whose allow list alone
        # was set on the All settings page must keep the installer's on/off.
        if "enabled" in ccfg:
            lines.append(f"enabled = {'true' if ccfg.get('enabled') else 'false'}")
        secret_fields = {
            field["key"]
            for field in (_CHANNELS_BY_NAME.get(name) or {}).get("fields", [])
            if field.get("secret")
        }
        for k in sorted(ccfg):
            if k == "enabled":
                continue
            v = ccfg[k]
            if isinstance(v, str) and k in secret_fields:
                v = _seal_global_secret(v)
            # Catalog secrets arrive already sealed (set_catalog_values).
            lines.append(f"{_toml_key(k)} = {_toml_value(v)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write(data: dict, *, before_effect=None) -> None:
    # Unique temp + os.replace (0600): the fixed ".toml.tmp" collided between two
    # concurrent workers. RMW serialization is in the mutators via _locked().
    from maverick.file_lock import atomic_write_text
    text = _dump(data)
    # Read the new text back before it replaces the file: a value the file
    # format cannot hold would otherwise leave an overlay nothing can read,
    # and every dashboard-managed setting (and the dashboard itself) with it.
    try:
        _tomllib().loads(text)
    except ValueError as exc:
        raise SettingsNotStorable(
            "A value could not be saved safely, so the settings were not changed."
        ) from exc
    from .settings_audit import current_write

    change = current_write()
    if change is not None:
        change.prepare(_load_overlay_for_update(), data)
    if before_effect is not None:
        before_effect()
    if before_effect is None:
        atomic_write_text(config.dashboard_overrides_path(), text)
    else:
        atomic_write_text(config.dashboard_overrides_path(), text, effect_guard=before_effect)
    if change is not None and not change.deferred:
        change.complete()


def _write_provider_with_deferred_audit(data: dict) -> None:
    """Publish the credential, leaving success unclaimed until verification."""
    from .settings_audit import current_write

    change = current_write()
    if change is not None:
        change.deferred = True
    try:
        _write(data)
    finally:
        if change is not None:
            change.deferred = False


def _complete_provider_audit() -> None:
    from .settings_audit import current_write

    change = current_write()
    if change is not None:
        change.complete()


# Tests only: production saves go through ``rotate_provider`` and its checks.
def set_provider(name: str, api_key: str | None = None, base_url: str | None = None) -> None:
    """Set a provider's api_key/base_url. Empty/None values are left unchanged
    (so re-saving a base_url never wipes a key you can't see). Use
    ``clear_provider`` to remove."""
    if name not in _PROVIDER_NAMES:
        raise ValueError("unknown provider")
    with _locked():
        data = _load_overlay_for_update()
        pcfg = data.setdefault("providers", {}).setdefault(name, {})
        if api_key and api_key.strip():
            pcfg["api_key"] = api_key.strip()
        if base_url and base_url.strip():
            pcfg["base_url"] = base_url.strip()
        if not pcfg:
            data["providers"].pop(name, None)
        _write(data)


def _provider_authority_fingerprint(name: str) -> str:
    """Digest only provider sources that outrank the dashboard overlay.

    The digest is deliberately one-way because those source tables can contain
    credentials.  It binds a rotation to the operator/tenant generations that
    were authorized without ever returning or logging their values.
    """
    import hashlib

    # Resolve installer-persisted environment before reading interpolated
    # operator material, matching provider_configuration_state().
    config._load_wizard_env()
    sources: list[tuple[str, Path]] = []
    operator = os.environ.get(config.CONFIG_OVERLAY_ENV, "").strip()
    if operator:
        sources.append(("operator", Path(operator).expanduser()))
    tenant = config.tenant_config_path()
    if tenant is not None:
        sources.append(("tenant", tenant))

    authority: list[dict] = []
    for source, path in sources:
        loaded = config._load_config_file(path, interpolate=source != "tenant")
        providers = loaded.get("providers") if isinstance(loaded, dict) else None
        if providers is not None and not isinstance(providers, dict):
            raise ProviderConfigurationUnavailable(
                f"{source} provider configuration is invalid"
            )
        table = providers.get(name) if isinstance(providers, dict) else None
        if (
            isinstance(providers, dict)
            and name in providers
            and not isinstance(table, dict)
        ):
            raise ProviderConfigurationUnavailable(
                f"{source} provider configuration is invalid"
            )
        authority.append(
            {
                "source": source,
                "path": str(path.absolute()),
                "provider": table,
            }
        )
    encoded = json.dumps(
        authority,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verify_provider_rotation(
    *,
    authority_expected: str,
    authority_after: str,
    authority_after_confirm: str,
    observed_state: dict,
    observed: object,
    key_value: str,
    base_value: str,
    details: dict[str, str] | None = None,
    remove_key: bool = False,
) -> None:
    """Reject a post-commit generation that is not the authorized one."""
    import hashlib
    import hmac

    if observed_state["source_errors"]:
        raise ProviderConfigurationUnavailable(
            "provider configuration became unreadable during rotation"
        )
    if not isinstance(observed, dict):
        raise ProviderConfigurationUnavailable(
            "effective provider configuration is invalid"
        )
    if not (
        authority_expected == authority_after == authority_after_confirm
    ):
        raise ProviderRotationConflict(
            "provider configuration changed while the rotation was committing"
        )
    if key_value:
        expected_digest = hashlib.sha256(key_value.encode("utf-8")).digest()
        observed_digest = hashlib.sha256(
            str(observed.get("api_key") or "").strip().encode("utf-8")
        ).digest()
        if not hmac.compare_digest(expected_digest, observed_digest):
            raise ProviderRotationConflict(
                "provider key is not the effective credential; review the active source"
            )
    if base_value and str(observed.get("base_url") or "").strip() != base_value:
        raise ProviderRotationConflict(
            "provider base URL is not the effective endpoint; review the active source"
        )
    if remove_key and str(observed.get("api_key") or "").strip():
        raise ProviderRotationConflict("the previous key is still active; review its source")
    for field, expected in (details or {}).items():
        if str(observed.get(field) or "").strip() != expected:
            raise ProviderRotationConflict(
                f"provider {field.replace('_', ' ')} is controlled by another source"
            )


def _accepts_server_address(name: str) -> bool:
    """Whether Settings may save a server address for this provider (the catalog's base_url flag).

    Only self-hosted endpoints take one. Elsewhere the address decides where the
    provider's credential is sent, so the server configuration owns it.
    """
    return any(row["name"] == name and row["base_url"] for row in PROVIDERS)


def _provider_setup_details(name: str, values: dict[str, str] | None) -> dict[str, str]:
    """Accept only the native Azure/Bedrock fields exposed in the guided form."""
    allowed = {
        "azure": {"auth_mode", "deployment", "api_version"},
        "bedrock": {"auth_mode", "endpoint", "region", "model_id"},
        "vertex": {"project_id", "region", "model_id"},
    }.get(name, set())
    details = {str(k): str(v).strip() for k, v in (values or {}).items() if str(v).strip()}
    if set(details) - allowed:
        raise ValueError("this provider does not accept those connection details")
    if name == "azure":
        if details.get("auth_mode") not in (None, "api_key", "entra_id"):
            raise ValueError("choose Azure key or Microsoft sign-in")
        if "deployment" in details and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", details["deployment"]):
            raise ValueError("enter an Azure deployment name using letters, numbers, dots, dashes or underscores")
        if "api_version" in details and not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}(-preview)?", details["api_version"]):
            raise ValueError("enter an Azure service version as YYYY-MM-DD")
    if name == "bedrock":
        if details.get("auth_mode") not in (None, "iam", "api_key"):
            raise ValueError("choose AWS sign-in or a Bedrock access key")
        if details.get("endpoint") not in (None, "mantle", "legacy"):
            raise ValueError("choose the current or older Bedrock service")
        if "region" in details and not re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]", details["region"]):
            raise ValueError("enter an AWS region such as us-east-1")
        if "model_id" in details and not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,120}", details["model_id"]):
            raise ValueError("enter the Claude model ID shown in your AWS account")
    if name == "vertex":
        if "project_id" in details and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:_-]{0,127}", details["project_id"]):
            raise ValueError("enter the Google Cloud project ID")
        if "region" in details and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", details["region"]):
            raise ValueError("enter a Vertex AI region such as us-east5")
        if "model_id" in details and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}@[A-Za-z0-9][A-Za-z0-9._-]{0,63}", details["model_id"]):
            raise ValueError("enter the Claude model ID exactly as shown in the Vertex AI Model Garden, such as claude-haiku-4-5@20251001")
    return details


def _provider_detail_blocker(name: str, field: str) -> str | None:
    """A value this page cannot make effective must never be saved as success."""
    for label, path in (
        ("operator settings", os.environ.get(config.CONFIG_OVERLAY_ENV, "")),
        ("workspace settings", config.tenant_config_path()),
    ):
        if not path:
            continue
        loaded = config._load_config_file(Path(path).expanduser(), interpolate=label != "workspace settings")
        table = (loaded.get("providers") or {}).get(name) if isinstance(loaded, dict) else None
        if isinstance(table, dict) and str(table.get(field) or "").strip():
            return label
    env_name = {
        ("azure", "deployment"): "AZURE_OPENAI_DEPLOYMENT",
        ("azure", "api_version"): "AZURE_OPENAI_API_VERSION",
        ("bedrock", "region"): "AWS_REGION",
        ("bedrock", "model_id"): "BEDROCK_MODEL_ID",
    }.get((name, field))
    if env_name and os.environ.get(env_name, "").strip():
        return "server environment"
    if name == "bedrock" and field == "region" and os.environ.get("AWS_DEFAULT_REGION", "").strip():
        return "server environment"
    return None


def _checked_provider_setup(
    name: str, key_value: str, base_value: str, details: dict[str, str] | None,
) -> tuple[dict[str, str], bool]:
    values = _provider_setup_details(name, details)
    if base_value and not _accepts_server_address(name):
        raise ValueError(
            "this provider's server address is set on the server, not in Settings"
        )
    if base_value:
        from .integration_readiness import _valid_self_hosted_address

        if len(base_value) > 320 or not _valid_self_hosted_address(base_value):
            raise ValueError(
                "enter a server address starting with http:// or https://, without "
                "sign-in details, extra parameters or a bookmark; use the key field for access"
            )
        if name == "azure" and not base_value.lower().startswith("https://"):
            raise ValueError("enter the secure Azure resource address, starting with https://")
    if name in {"azure", "bedrock"} and len(key_value) > 500:
        raise ValueError("the provider key is too long")
    if name == "vertex" and key_value:
        raise ValueError("Vertex AI uses the server's Google sign-in, not a key")
    if key_value and values.get("auth_mode") in {"entra_id", "iam"}:
        raise ValueError("a key cannot be combined with server sign-in")
    if name == "bedrock" and values.get("auth_mode") == "iam" and any(
        os.environ.get(env_name, "").strip()
        for env_name in ("BEDROCK_API_KEY", "AWS_BEARER_TOKEN_BEDROCK")
    ):
        raise ValueError("remove the Bedrock access key from the server before choosing AWS sign-in")
    return values, values.get("auth_mode") in {"entra_id", "iam"}


def _confirm_cloud_setup(name: str, observed: dict) -> None:
    if name == "azure" and config.azure_provider_configuration_missing(observed):
        raise ProviderRotationConflict(
            "Azure still needs a resource address, deployment and one sign-in method"
        )
    if name == "bedrock":
        region = (os.environ.get("AWS_REGION", "").strip()
                  or os.environ.get("AWS_DEFAULT_REGION", "").strip()
                  or str(observed.get("region") or "").strip())
        if not region or str(observed.get("auth_mode") or "").strip() not in {"iam", "api_key"}:
            raise ProviderRotationConflict(
                "Bedrock still needs an AWS region and a sign-in method"
            )
        if observed.get("auth_mode") == "api_key" and not (
            observed.get("api_key") or os.environ.get("BEDROCK_API_KEY")
            or os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
        ):
            raise ProviderRotationConflict("enter a Bedrock access key or choose AWS sign-in")
        if not (str(observed.get("model_id") or "").strip()
                or os.environ.get("BEDROCK_MODEL_ID", "").strip()):
            raise ProviderRotationConflict("enter the Claude model ID shown in your AWS account")
    if name == "vertex":
        project = (str(observed.get("project_id") or "").strip()
                   or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
                   or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip())
        region = (str(observed.get("region") or "").strip()
                  or os.environ.get("CLOUD_ML_REGION", "").strip())
        model = (str(observed.get("model_id") or "").strip()
                 or os.environ.get("VERTEX_MODEL_ID", "").strip())
        if not (project and region and model):
            raise ProviderRotationConflict(
                "Vertex AI still needs a Google Cloud project, a region and the model ID"
            )


def _provider_rotation_blockers(
    name: str, state: dict, key_value: str, base_value: str,
    details: dict[str, str], remove_key: bool,
) -> list[str]:
    blockers: list[str] = []
    if key_value and not state["dashboard_can_set_api_key"]:
        blockers.append(f"API key is controlled by {state['api_key_source']}")
    if base_value and not state["dashboard_can_set_base_url"]:
        blockers.append(f"base URL is controlled by {state['base_url_source']}")
    if remove_key and not state["dashboard_can_set_api_key"]:
        blockers.append("the existing key is controlled outside Settings")
    for field in details:
        source = _provider_detail_blocker(name, field)
        if source:
            blockers.append(f"{field.replace('_', ' ')} is controlled by {source}")
    return blockers


def _restore_provider_overlay(
    *,
    path: Path,
    existed: bool,
    previous_bytes: bytes | None,
    previous_mode: int | None,
) -> None:
    """Restore the exact pre-rotation dashboard generation under its lock."""
    if existed:
        if previous_bytes is None or previous_mode is None:
            raise ProviderConfigurationUnavailable(
                "provider rollback state is unavailable"
            )
        from maverick.file_lock import atomic_write_bytes

        atomic_write_bytes(path, previous_bytes, mode=previous_mode)
    else:
        path.unlink(missing_ok=True)
    config.reset_config_cache()


def rotate_provider(
    name: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    details: dict[str, str] | None = None,
) -> dict:
    """Atomically publish a provider rotation only when it becomes effective.

    The entire dashboard read/modify/verify/rollback transaction holds the
    settings lock.  A one-way fingerprint detects an operator or tenant source
    changing while the transaction is in flight.  Any rejected post-write
    verification restores the exact preceding overlay generation before this
    function returns.
    """
    import copy
    if name not in _PROVIDER_NAMES:
        raise ValueError("unknown provider")
    key_value = str(api_key or "").strip()
    base_value = str(base_url or "").strip()
    detail_values, remove_key = _checked_provider_setup(name, key_value, base_value, details)
    if not key_value and not base_value and not detail_values:
        raise ValueError("enter a provider value to save")

    try:
        # Provider credentials are security-sensitive shared state. Refuse the
        # rotation when the filesystem cannot provide a real cross-process
        # lock; a process-local fallback could let two workers clobber a
        # successfully verified credential generation.
        with _locked(strict=True):
            overlay_path: Path | None = None
            overlay_existed = False
            before_overlay: dict | None = None
            before_bytes: bytes | None = None
            before_mode: int | None = None
            mutation_attempted = False
            try:
                overlay_path = config.dashboard_overrides_path()
                overlay_existed = overlay_path.exists()
                if overlay_existed:
                    import stat

                    before_bytes = overlay_path.read_bytes()
                    before_mode = stat.S_IMODE(overlay_path.stat().st_mode)
                before_overlay = _load_overlay_for_update()
                # Keep the sealed generation for byte-equivalent rollback, but
                # authenticate every ciphertext before changing anything. A
                # corrupt provider or unrelated secret must not be overwritten
                # into an apparently healthy generation by a rotation.
                _unseal_overlay(copy.deepcopy(before_overlay))

                config.reset_config_cache()
                authority_before = _provider_authority_fingerprint(name)
                before = config.provider_configuration_state(name)
                authority_confirm = _provider_authority_fingerprint(name)
                if before["source_errors"]:
                    raise ProviderConfigurationUnavailable(
                        "provider configuration is unreadable; repair the active "
                        "config source before rotating credentials"
                    )
                if authority_before != authority_confirm:
                    raise ProviderRotationConflict(
                        "provider configuration changed while the rotation was being authorized"
                    )

                blockers = _provider_rotation_blockers(
                    name, before, key_value, base_value, detail_values, remove_key,
                )
                if blockers:
                    raise ProviderRotationConflict(
                        "; ".join(blockers) + "; rotate that source instead"
                    )

                # A carried-forward address must not turn a key rotation into
                # a new dashboard override of an installer/server address.
                # Authorize first: unchanged protected fields remain refused.
                if ((key_value or detail_values) and base_value == before["base_url"]
                        and before["base_url_source"] != "dashboard"):
                    base_value = ""

                data = copy.deepcopy(before_overlay)
                provider_table = data.setdefault("providers", {}).setdefault(name, {})
                if key_value:
                    provider_table["api_key"] = key_value
                elif remove_key:
                    # Selecting server identity explicitly retires the saved
                    # dashboard key. A higher-authority key is rejected above.
                    provider_table.pop("api_key", None)
                if base_value:
                    # The form check above refuses this too; the write site
                    # refuses it independently so no caller can store one.
                    if not _accepts_server_address(name):
                        raise ProviderRotationConflict(
                            "a server address cannot be set for this provider in Settings"
                        )
                    provider_table["base_url"] = base_value
                provider_table.update(detail_values)

                # Recheck immediately before commit. The post-commit check below is
                # still required because higher-authority files do not share this
                # dashboard lock.
                if authority_confirm != _provider_authority_fingerprint(name):
                    raise ProviderRotationConflict(
                        "provider configuration changed before the rotation could commit"
                    )
                # atomic_write_text may replace the file before a later flush
                # or directory-sync error is reported. Treat any attempted
                # write as published so every failure takes the rollback path.
                mutation_attempted = True
                _write_provider_with_deferred_audit(data)
                config.reset_config_cache()

                authority_after = _provider_authority_fingerprint(name)
                observed_state = config.provider_configuration_state(name)
                observed = config.get_provider_config(name) or {}
                authority_after_confirm = _provider_authority_fingerprint(name)
                _verify_provider_rotation(
                    authority_expected=authority_confirm,
                    authority_after=authority_after,
                    authority_after_confirm=authority_after_confirm,
                    observed_state=observed_state,
                    observed=observed,
                    key_value=key_value,
                    base_value=base_value,
                    details=detail_values,
                    remove_key=remove_key,
                )
                _confirm_cloud_setup(name, observed)
                _complete_provider_audit()
                return observed_state
            except Exception as exc:
                if mutation_attempted:
                    try:
                        if overlay_path is None or before_overlay is None:
                            raise ProviderConfigurationUnavailable(
                                "provider rollback state is unavailable"
                            )
                        _restore_provider_overlay(
                            path=overlay_path,
                            existed=overlay_existed,
                            previous_bytes=before_bytes,
                            previous_mode=before_mode,
                        )
                    except Exception as rollback_exc:
                        raise ProviderConfigurationUnavailable(
                            "provider rotation failed and the previous dashboard "
                            "configuration could not be restored"
                        ) from rollback_exc
                if isinstance(
                    exc,
                    (ProviderConfigurationUnavailable, ProviderRotationConflict),
                ):
                    raise
                raise ProviderConfigurationUnavailable(
                    "provider configuration is unavailable; the rotation was "
                    "not committed"
                ) from exc
    except (ProviderConfigurationUnavailable, ProviderRotationConflict):
        raise
    except Exception as exc:
        # Lock acquisition, path inspection, and any failure before the inner
        # transaction are still recoverable configuration outages to the API,
        # never raw 500s.
        raise ProviderConfigurationUnavailable(
            "provider configuration is unavailable; settings were not changed"
        ) from exc


def clear_provider(name: str) -> None:
    if name not in _PROVIDER_NAMES:
        raise ValueError("unknown provider")
    with _locked():
        data = _load_overlay_for_update()
        table = (data.get("providers") or {}).get(name)
        if isinstance(table, dict):
            # Guided cloud setup removes its whole dashboard-owned connection;
            # other providers retain the All settings sign-in choices.
            fields = _PROVIDER_FIELDS if name in {"azure", "bedrock", "vertex"} else ("api_key", "base_url")
            for field in fields:
                table.pop(field, None)
            if not table:
                data["providers"].pop(name, None)
        else:
            (data.get("providers") or {}).pop(name, None)
        _write(data)


def set_webhooks_secret(secret: str, *, expected_generation: str, principal: str,
                        authorize, action: str = "set") -> dict:
    """Rotate only a reviewed effective generation; never silently save a shadow key."""
    from .webhook_settings import rotate
    return rotate(secret=secret, action=action, expected_generation=expected_generation,
                  principal=principal, authorize=authorize)


def set_model_discovery(enabled: bool) -> None:
    """Turn automatic model lists ([models] discovery) on or off in the overlay.

    The MAVERICK_MODEL_DISCOVERY environment variable still wins; the Settings
    page only offers this switch when no such override is present."""
    with _locked():
        data = _load_overlay_for_update()
        models = data.setdefault("models", {})
        if not isinstance(models, dict):
            raise SecuritySuiteConfigUnavailable(
                "dashboard settings are unreadable; settings were not changed"
            )
        models["discovery"] = bool(enabled)
        _write(data)


def set_catalog_indexes(urls) -> None:
    """Replace the skill-catalog addresses ([catalogs] indexes) in the overlay.

    Each entry must be a plain https web address (no credentials in it); at
    most five. An empty list removes the key so the built-in catalog is used
    again. Installing from any catalog still needs the admin role and the
    server's skill-install opt-in; this only changes what the Store lists."""
    from urllib.parse import urlsplit

    cleaned: list[str] = []
    for raw in urls or []:
        url = str(raw or "").strip().rstrip("/")
        if not url:
            continue
        parts = urlsplit(url)
        if (parts.scheme != "https" or not parts.hostname or parts.username
                or parts.password or len(url) > 300 or any(c.isspace() for c in url)):
            raise ValueError("catalog addresses must be plain https web addresses")
        if url not in cleaned:
            cleaned.append(url)
    if len(cleaned) > 5:
        raise ValueError("at most five catalog addresses")
    with _locked():
        data = _load_overlay_for_update()
        catalogs = data.setdefault("catalogs", {})
        if not isinstance(catalogs, dict):
            raise SecuritySuiteConfigUnavailable(
                "dashboard settings are unreadable; settings were not changed"
            )
        if cleaned:
            catalogs["indexes"] = cleaned
        else:
            catalogs.pop("indexes", None)
        _write(data)


def set_toggle(section: str, name: str, enabled: bool) -> None:
    """Override a [capabilities] or [features] flag in the overlay."""
    set_toggles(section, {name: enabled})


class FeatureSettingNotEffective(ValueError):
    """A higher-priority source still controls a dashboard-saved feature."""


def assert_effective_copilot_operations(enabled: bool) -> None:
    """Never report this optional action as enabled after a shadow overlay save."""
    from maverick import config

    if config.get_features().get("copilot_operations") is not bool(enabled):
        raise FeatureSettingNotEffective(
            "Copilot actions are controlled by another setting. The requested change is not active."
        )


def assert_effective_employee_companions(enabled: bool) -> None:
    """Report when a saved opt-in differs from the effective deployment policy."""
    from maverick import config

    if config.get_features().get("employee_companions") is not bool(enabled):
        raise FeatureSettingNotEffective(
            "Employee companions are controlled by another setting. "
            "The requested change is not active."
        )


def set_toggles(section: str, updates: dict[str, bool]) -> None:
    """Commit a complete group of flag changes in one atomic overlay write."""
    defaults = {"capabilities": CAPABILITY_DEFAULTS, "features": FEATURE_DEFAULTS}.get(section)
    if defaults is None or not isinstance(updates, dict) or any(name not in defaults for name in updates):
        raise ValueError("unknown setting")
    clean = {name: bool(enabled) for name, enabled in updates.items()}
    with _locked():
        data = _load_overlay_for_update()
        flags = data.setdefault(section, {})
        if not isinstance(flags, dict):
            raise SecuritySuiteConfigUnavailable(
                "dashboard settings are unreadable; settings were not changed"
            )
        flags.update(clean)
        _write(data)


def _research_settings_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")).hexdigest()


def research_execution_state() -> dict:
    """Return a non-secret, exact-revision view of the global research profile."""
    config.reset_config_cache()
    config.load_global_config()
    if config.config_source_errors(include_tenant=False):
        return {"settings_sha256": "", "configuration": {},
                "writable": False, "source": "unavailable"}
    base = config._load_config_file(config.config_path())
    overlay = load_overlay()
    # This security-sensitive table is a complete installation-owned profile.
    # Nested deep merge would make deleting a base-config evaluator impossible;
    # an explicit dashboard table therefore replaces the base table wholesale.
    raw = (overlay["research_execution"] if "research_execution" in overlay
           else base.get("research_execution", {}))
    source = "dashboard" if "research_execution" in overlay else "base"
    writable = True
    operator_overlay = os.environ.get(config.CONFIG_OVERLAY_ENV)
    if operator_overlay:
        operator = config._load_config_file(Path(operator_overlay).expanduser())
        if "research_execution" in operator:
            raw = operator["research_execution"]
            source = "operator_overlay"
            writable = False
    if not isinstance(raw, dict):
        raw = {"invalid": True}
    return {"settings_sha256": _research_settings_sha256(raw), "configuration": raw,
            "writable": writable, "source": source}


def set_research_execution(value: dict, *, expected_settings_sha256: str) -> dict:
    """Persist one validated global research profile in the dashboard overlay."""
    from dataclasses import asdict

    from maverick.research_jobs import ResearchProfile

    if (type(expected_settings_sha256) is not str or len(expected_settings_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_settings_sha256)):
        raise ValueError("invalid research settings revision")
    if not isinstance(value, dict):
        raise ValueError("invalid research execution settings")
    if value.get("enable") is True:
        profile = ResearchProfile.from_config(value)
        clean = {"enable": True, "image_id": profile.image_id,
                 "queue_seconds": profile.queue_seconds,
                 "evaluators": {item.id: {"version": item.version,
                                             "stdout_sha256": item.stdout_sha256}
                                for item in profile.evaluators},
                 "limits": asdict(profile.limits)}
    elif value == {"enable": False}:
        clean = {"enable": False}
    else:
        raise ValueError("disabled research settings may contain only enable=false")
    with _locked(strict=True):
        config.reset_config_cache()
        data = _load_overlay_for_update()
        operator_overlay = os.environ.get(config.CONFIG_OVERLAY_ENV)
        if operator_overlay and "research_execution" in config._load_config_file(
                Path(operator_overlay).expanduser()):
            raise ResearchSettingsUnavailable(
                "Research execution is owned by the operator config overlay")
        current = (data["research_execution"] if "research_execution" in data
                   else config._load_config_file(config.config_path()).get(
                       "research_execution", {}))
        if not hmac.compare_digest(expected_settings_sha256, _research_settings_sha256(current)):
            raise ResearchSettingsConflict("Research execution settings changed; reload before saving")
        data["research_execution"] = clean
        _write(data)
        config.reset_config_cache()
    return research_execution_state()


# Platform systems whose [section] enable flag an admin may switch from
# inside the app -- the single authority the /features/switches API trusts.
SWITCHABLE_SECTIONS: tuple[str, ...] = (
    "dreaming", "self_improvement", "self_harness", "fleet_memory",
    "rehearsal", "flows", "threat_hunt", "env_hunt", "entity_graph",
    "shoring",
)


def set_agent_trust_enforce(enforced: bool) -> None:
    """Overlay ``[agent_trust] enforce`` (block outside agents not on the list)."""
    with _locked():
        data = _load_overlay_for_update()
        data.setdefault("agent_trust", {})["enforce"] = bool(enforced)
        _write(data)


def set_immune_settings(*, canaries: bool | None = None, twin_record: bool | None = None) -> None:
    """Overlay the Safety monitoring page's two switches: reviewer tests
    (``[immune] canaries``) and recording tasks for practice re-runs
    (``[immune] twin_record``). Only these two keys, only booleans."""
    changes = {k: bool(v) for k, v in (("canaries", canaries), ("twin_record", twin_record))
               if v is not None}
    if not changes:
        raise ValueError("unknown setting")
    with _locked():
        data = _load_overlay_for_update()
        table = data.setdefault("immune", {})
        if not isinstance(table, dict):
            raise SecuritySuiteConfigUnavailable(
                "dashboard settings are unreadable; settings were not changed"
            )
        table.update(changes)
        _write(data)


def set_section_enable(section: str, enabled: bool) -> None:
    """Overlay one switchable platform system's ``enable`` flag."""
    if section not in SWITCHABLE_SECTIONS:
        raise ValueError("unknown setting")
    with _locked():
        data = _load_overlay_for_update()
        data.setdefault(section, {})["enable"] = bool(enabled)
        _write(data)


# Compliance controls the /compliance page can strengthen from inside the app.
# Only these exact (section, key) pairs are writable, and only to the value
# types listed; nothing here can turn a protection off except retention
# periods, which accept whole days within the bounds below, or 0 (the kernel
# then deletes nothing for that period).
COMPLIANCE_SETTINGS: dict[tuple[str, str], type] = {
    ("audit", "sign"): bool,
    ("privacy", "anonymous"): bool,
    ("encryption", "at_rest"): bool,
    ("enterprise", "mode"): bool,
    ("compliance", "disclosure_text"): str,
    ("compliance", "profiles"): list,
    ("retention", "audit_days"): int,
    ("retention", "episodes_days"): int,
    ("retention", "events_days"): int,
    ("retention", "messages_days"): int,
    ("retention", "usage_days"): int,
}
COMPLIANCE_SETTING_SECTIONS: tuple[str, ...] = tuple(
    dict.fromkeys(section for section, _key in COMPLIANCE_SETTINGS)
)
_RETENTION_DAY_BOUNDS = (1, 3650)
_PROFILE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def set_compliance_settings(updates: dict[tuple[str, str], object]) -> None:
    """Write a bounded group of compliance settings in one overlay save."""
    if not isinstance(updates, dict) or not updates:
        raise ValueError("unknown setting")
    clean: dict[tuple[str, str], object] = {}
    for pair, value in updates.items():
        kind = COMPLIANCE_SETTINGS.get(pair)
        if kind is None:
            raise ValueError("unknown setting")
        if kind is bool:
            if value is not True:
                # Protections can only be switched on from the dashboard.
                raise ValueError("unknown setting")
        elif kind is list:
            # Regulation keys only; callers must pass a superset of what is
            # already active (checked where the active set is known).
            if (
                not isinstance(value, list)
                or not value
                or len(value) > 16
                or any(
                    not isinstance(item, str) or not _PROFILE_KEY.fullmatch(item)
                    for item in value
                )
            ):
                raise ValueError("regulation list is invalid")
            value = list(dict.fromkeys(value))
        elif kind is int:
            low, high = _RETENTION_DAY_BOUNDS
            if isinstance(value, bool) or not isinstance(value, int) or not (value == 0 or low <= value <= high):
                raise ValueError("retention days are out of range")
        elif not isinstance(value, str) or not value.strip() or len(value) > 1000:
            raise ValueError("text setting is empty or too long")
        clean[pair] = value
    with _locked():
        data = _load_overlay_for_update()
        for (section, key), value in clean.items():
            table = data.setdefault(section, {})
            if not isinstance(table, dict):
                raise SecuritySuiteConfigUnavailable(
                    "dashboard settings are unreadable; settings were not changed"
                )
            table[key] = value
        _write(data)
    config.reset_config_cache()


# Governance-module enable flags an admin may switch from inside the app --
# each entry is a dotted path whose final table carries the ``enable``
# boolean the module's fail-closed gate reads (e.g.
# "consent_preferences.publishing" -> [consent_preferences.publishing]
# enable). The single authority the /features/switches API trusts for
# module switching; anything not listed stays config-file-only.
MODULE_ENABLE_PATHS: frozenset[str] = frozenset({
    "codebase",
    "connections",
    "ai_inventory",
    "ai_entity_tasks",
    "governed_document_vault",
    "tech_risk_compliance.grc_studio",
    "third_party_management.contracts",
    "vendor_onboarding",
    "ai_vendor_risk",
    "model_risk_assurance",
    "evidence_graph",
    "ai_evidence_analysis",
    "assessment_evidence_autopopulation",
    "consent_preferences",
    "consent_preferences.analytics",
    "consent_preferences.application_scanner",
    "consent_preferences.bulk_jobs",
    "consent_preferences.delivery",
    "consent_preferences.experiments",
    "consent_preferences.global_opt_out",
    "consent_preferences.native_sdk",
    "consent_preferences.profile_data",
    "consent_preferences.profile_data.custom_index",
    "consent_preferences.public_api",
    "consent_preferences.publishing",
    "consent_preferences.publishing.web_settings",
    "consent_preferences.scanner",
    "consent_preferences.scanner.notice_proposals",
    "consent_preferences.trust_center",
    "consent_registry",
    "data_map",
    "data_use_governance",
    "data_use_governance.compiler",
    "data_use_governance.databricks",
    "data_use_governance.enforcement",
    "data_use_governance.snowflake",
    "dsar_fulfillment",
    "external_agents",
    "finance_operations",
    "governance_agents",
    "privacy_automation",
    "privacy_automation.data_discovery",
    "privacy_automation.notice_governance",
    "privacy_automation.public_rights_form",
    "privacy_automation.regulatory_intelligence",
    "privacy_automation.rights_consumer_delivery",
    "privacy_automation.rights_orchestration",
    "tech_risk_compliance",
    "tech_risk_compliance.continuous_evidence",
    "tech_risk_compliance.policy_publication_links",
    "tech_risk_compliance.scope_actions",
    "tech_risk_compliance.scoping",
    "third_party_management",
    "third_party_management.executive_reports",
    "third_party_management.intelligence",
    "third_party_management.lifecycle",
    "third_party_management.lifecycle.portal",
    "vendor_management",
    "control_plane",
    "eu_conformity",
    "ai_literacy",
    "policy_packs",
    "evidence_gateway",
    "drift_monitoring",
    "ai_incident_reporting",
    "privacy_automation.drop_management",
    "explainability",
    "content_provenance",
    "breach_notification",
    "ediscovery",
    # agent_topology.enabled also needs the entity graph, which is on by
    # default and has its own switch on the Learning page.
    "agent_topology",
    "ai_regulatory_feed",
    "ai_business_intake",
    "ai_dynamic_risk",
    "ai_policy_management",
    "ai_runtime_guardrails",
    "ai_explainability",
    "ai_conformity_workflow",
    "ai_insurability",
    "ai_regulated_verticals",
    "ai_bank_mrm",
    "ai_discovery_sensors",
    "portfolio_risk",
    "ai_cost_roi",
    "eu_ai_incidents",
    "grc_outbound_sync",
    "incident_attachment_metadata",
})

# Top-level tables the module paths live under; _dump is an allowlist, so a
# section missing here would be silently dropped on the next save.
_MODULE_TOP_SECTIONS: tuple[str, ...] = tuple(sorted(
    {path.split(".", 1)[0] for path in MODULE_ENABLE_PATHS}
))


def set_module_enables(paths, enabled: bool) -> None:
    """Overlay ``enable`` for one or more governance-module dotted paths.

    All writes land in ONE locked read-modify-write, so "turn on this module
    and the parents its gate requires" is atomic -- a crash can't leave a
    child enabled under a disabled parent that the one click promised to
    open. Every path must be allowlisted in :data:`MODULE_ENABLE_PATHS`.
    """
    wanted = [str(p or "").strip() for p in paths]
    if not wanted:
        raise ValueError("no module sections given")
    for path in wanted:
        if path not in MODULE_ENABLE_PATHS:
            raise ValueError(f"unknown module section {path!r}")
    with _locked():
        data = _load_overlay_for_update()
        for path in wanted:
            node = data
            for part in path.split("."):
                child = node.get(part)
                if not isinstance(child, dict):
                    child = {}
                    node[part] = child
                node = child
            node["enable"] = bool(enabled)
        _write(data)


# Tables with their own serializer above; every other catalog table goes
# through the generic allowlisted loop in _dump.
_CATALOG_SPECIAL_SECTIONS = frozenset({
    "channels", "dashboard", "plugins", "providers", "sandbox", "webhooks",
})


def _catalog_generic_sections() -> tuple[str, ...]:
    from .settings_catalog import CATALOG_TOP_SECTIONS

    return tuple(s for s in CATALOG_TOP_SECTIONS if s not in _CATALOG_SPECIAL_SECTIONS)


#: Marker for "remove this key from the dashboard overlay".
REMOVE = object()


def set_catalog_values(changes: dict[tuple[str, ...], object], *, before_effect=None) -> dict[tuple[str, ...], object]:
    """Write All-settings values to the overlay in ONE locked save.

    ``changes`` maps a catalog key path (``("safety", "profile")``) to its
    already-validated value, or :data:`REMOVE` to drop the dashboard value so
    the installer's choice (or the default) applies again. Only paths in the
    settings catalog are writable. Secret values are sealed with the
    deployment key before they are stored. Returns the previous raw overlay
    value of each path (``REMOVE`` when absent) so a caller can undo the save
    if the change cannot be recorded in the audit trail.
    """
    from maverick.config_resets import METADATA, reset_spec

    from .settings_catalog import SETTINGS

    by_path = {s.path: s for s in SETTINGS if s.key_kind != "entries"}
    # "entries" tables (usage limits for any tool) own every other key of
    # their table: one path per row, never a key another setting owns.
    entries = {s.path: s for s in SETTINGS if s.key_kind == "entries"}
    if not isinstance(changes, dict) or not changes:
        raise ValueError("no settings given")
    reset_tables = {s.id: s for s in SETTINGS}
    for path in changes:
        if len(path) == 2 and path[0] == METADATA:
            table = reset_tables.get(path[1])
            value = changes[path]
            if table is None or (value is not None and value is not REMOVE and value != reset_spec(table)):
                raise ValueError("unknown product-default reset")
            by_path[path] = table
            continue
        table = entries.get(tuple(path[:-1]))
        if path in by_path:
            continue
        if table is None or not path[-1] or path[-1] in table.fixed_keys:
            raise ValueError("unknown setting")
        by_path[path] = table
    previous: dict[tuple[str, ...], object] = {}
    with _locked():
        data = _load_overlay_for_update()
        for path, value in changes.items():
            node = data
            for part in path[:-1]:
                child = node.get(part)
                if child is None:
                    child = {}
                    node[part] = child
                if not isinstance(child, dict):
                    raise SecuritySuiteConfigUnavailable(
                        "dashboard settings are unreadable; settings were not changed"
                    )
                node = child
            key = path[-1]
            previous[path] = node.get(key, REMOVE)
            if value is REMOVE or value is None:
                node.pop(key, None)
            elif by_path[path].secret:
                node[key] = _seal_global_secret(value)
            else:
                node[key] = value
        _prune_empty_tables(data, {path[0] for path in changes})
        _write(data, before_effect=before_effect)
    config.reset_config_cache()
    return previous


def _prune_empty_tables(data: dict, tops: set[str]) -> None:
    """Drop tables a reset emptied, so the overlay stays minimal."""
    def prune(node: dict) -> None:
        for key in list(node):
            child = node[key]
            if isinstance(child, dict):
                prune(child)
                if not child:
                    node.pop(key)

    for top in tops:
        table = data.get(top)
        if isinstance(table, dict):
            prune(table)
            if not table:
                data.pop(top, None)


SANDBOX_BACKENDS: tuple[str, ...] = ("local", "docker", "podman")
CONTAINER_FILE_TOOLS: tuple[str, ...] = (
    "shell", "write_file", "apply_patch", "str_replace_editor", "ast_edit",
)


def set_sandbox_backend(backend: str) -> None:
    """Overlay the sandbox backend ([sandbox] backend).

    Only the backend selector is dashboard-writable; the rest of [sandbox]
    (image, limits, network) stays config-file policy. The caller (the
    sandbox API) is responsible for probing daemon reachability first so a
    switch never silently strands every goal on an unreachable runtime.
    """
    cleaned = str(backend or "").strip().lower()
    if cleaned not in SANDBOX_BACKENDS:
        raise ValueError(f"unknown sandbox backend {cleaned!r}")
    with _locked():
        data = _load_overlay_for_update()
        data.setdefault("sandbox", {})["backend"] = cleaned
        _write(data)


def enable_container_file_work() -> None:
    """Remove only the first-run file-tool blocks after a container is selected.

    The operator must confirm and probe the live daemon at the API boundary.
    Here the same cross-process lock as other Settings writes protects the
    read/modify/write. A higher-precedence deployment or tenant denial remains
    authoritative and is never silently weakened by a latent dashboard value.
    """
    with _locked():
        if config.config_source_errors():
            raise SecuritySuiteConfigUnavailable(
                "Settings cannot be read safely; file work was not changed."
            )
        effective = config.load_config()
        backend = str((effective.get("sandbox") or {}).get("backend") or "local").lower()
        if backend not in ("docker", "podman"):
            raise ValueError("Choose a running Docker or Podman container first.")
        higher_paths = []
        operator_path = os.environ.get(config.CONFIG_OVERLAY_ENV, "").strip()
        if operator_path:
            higher_paths.append((Path(operator_path).expanduser(), True))
        tenant_path = config.tenant_config_path()
        if tenant_path is not None:
            higher_paths.append((tenant_path, False))
        for path, interpolate in higher_paths:
            layer = config._load_config_file(path, interpolate=interpolate)
            policy = (layer.get("security") or {}).get("denied_tools") or []
            if any(name in policy for name in CONTAINER_FILE_TOOLS):
                raise ValueError(
                    "A deployment or workspace rule still blocks file work. "
                    "Ask its administrator to review that rule."
                )
        denied = (effective.get("security") or {}).get("denied_tools") or []
        if not isinstance(denied, list) or not all(isinstance(name, str) for name in denied):
            raise SecuritySuiteConfigUnavailable(
                "Tool rules cannot be read safely; file work was not changed."
            )
        remaining = [name for name in denied if name not in CONTAINER_FILE_TOOLS]
        if remaining == denied:
            return
        data = _load_overlay_for_update()
        security = data.setdefault("security", {})
        if not isinstance(security, dict):
            raise SecuritySuiteConfigUnavailable(
                "Tool rules cannot be read safely; file work was not changed."
            )
        security["denied_tools"] = remaining
        _write(data)
        config.reset_config_cache()


def set_installable_plugins(names) -> None:
    """Replace the dashboard-install plugin allowlist ([plugins] installable).

    Every entry must be a plain distribution name or an exact pin
    ``name==version sha256:<hex>`` (maverick.plugins.parse_installable_entry:
    no URLs, version ranges, or shell metacharacters) -- the same check
    install_plugin() re-applies at install time, enforced here too so a bad
    entry is rejected at approval, not discovered at install.
    """
    from maverick.plugins import parse_installable_entry

    cleaned: list[str] = []
    for raw in names:
        name = str(raw or "").strip()
        if not name:
            continue
        if parse_installable_entry(name) is None:
            raise ValueError(f"unsafe package name: {name!r}")
        if name not in cleaned:
            cleaned.append(name)
    with _locked():
        data = _load_overlay_for_update()
        if cleaned:
            data.setdefault("plugins", {})["installable"] = cleaned
        else:
            (data.get("plugins") or {}).pop("installable", None)
            if not data.get("plugins"):
                data.pop("plugins", None)
        _write(data)


def set_plugin_install_allowed(enabled: bool) -> None:
    """Overlay the in-app plugin-install opt-in ([plugins] allow_install).

    The MAVERICK_ALLOW_PLUGIN_INSTALL env var still outranks it in BOTH
    directions (an explicit falsy value force-disables installs on a hardened
    deployment); this knob is the everyone-else path that needs no shell.
    """
    with _locked():
        data = _load_overlay_for_update()
        data.setdefault("plugins", {})["allow_install"] = bool(enabled)
        _write(data)


def active_tenant() -> str | None:
    """The dashboard-selected active tenant id, or ``None`` when unset.

    Read through the merged config (the overlay deep-merges over config.toml),
    so an operator can also pin ``[dashboard] active_tenant`` in config.toml
    and the UI selection overrides it the same way every other setting does.
    """
    loaded = config.load_config() or {}
    value = (loaded.get("dashboard") or {}).get("active_tenant")
    cleaned = str(value or "").strip()
    return cleaned or None


def set_active_tenant(tenant_id: str | None) -> None:
    """Persist (or clear) the dashboard's active tenant selection.

    The id must name an existing, active tenant in the registry -- selecting a
    tenant that does not exist would silently scope every workbench to an
    empty data root, which reads as data loss.
    """
    cleaned = str(tenant_id or "").strip()
    if cleaned:
        from maverick.tenant.registry import get_tenant

        record = get_tenant(cleaned)
        if record is None:
            raise ValueError(f"unknown tenant {cleaned!r}")
        if not record.active:
            raise ValueError(f"tenant {cleaned!r} is suspended")
    with _locked():
        data = _load_overlay_for_update()
        if cleaned:
            data.setdefault("dashboard", {})["active_tenant"] = cleaned
        else:
            (data.get("dashboard") or {}).pop("active_tenant", None)
            if not data.get("dashboard"):
                data.pop("dashboard", None)
        _write(data)


def clear_deleted_active_tenant(tenant_id: str) -> bool:
    """Remove the local operator's selection after its workspace is retired.

    An empty dashboard overlay masks a lower-priority config.toml selection;
    simply deleting the overlay key would expose that closed workspace again.
    """
    from maverick.paths import _tenant_namespace_key

    target = _tenant_namespace_key(tenant_id)
    with _locked():
        config.reset_config_cache()
        selected = active_tenant()
        if selected is None or _tenant_namespace_key(selected) != target:
            return False
        data = _load_overlay_for_update()
        data.setdefault("dashboard", {})["active_tenant"] = ""
        _write(data)
        config.reset_config_cache()
        if active_tenant() is not None:
            raise RuntimeError("removed workspace selection is still effective")
        return True


def set_model_cost_tier(model: str, band: str | None) -> None:
    """Persist a manager's cost-band override for a model in
    ``[model_cost_tiers]``. ``band=None`` clears the override (back to the
    price-derived band). Validated against the known bands."""
    from maverick.model_cost_tier import BANDS
    model = (model or "").strip()
    if not model:
        raise ValueError("model is required")
    if band is not None and band not in BANDS:
        raise ValueError(f"band must be one of {BANDS} or null")
    with _locked():
        data = _load_overlay_for_update()
        tiers = data.setdefault("model_cost_tiers", {})
        if band is None:
            tiers.pop(model, None)
            if not tiers:
                data.pop("model_cost_tiers", None)
        else:
            tiers[model] = band
        _write(data)


def set_security_suite(
    *,
    security_ops: bool,
    threat_hunt: bool,
    env_hunt: bool,
    response_execution: bool,
    actor: str,
    expected_revision: int,
) -> int:
    """Atomically publish deployment-wide security-suite enablement.

    Response execution can never be armed without the environment hunter. The
    signed authorization is durable before the overlay is published, so a
    crash or concurrent reader can never observe an unaudited authority bit.
    """
    if response_execution and not env_hunt:
        raise ValueError("response execution requires env_hunt")
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 1
    ):
        raise ValueError("expected_revision must be a positive integer")
    requested = {
        "security_ops": bool(security_ops),
        "threat_hunt": bool(threat_hunt),
        "env_hunt": bool(env_hunt),
        "response_execution": bool(response_execution),
    }
    with _locked():
        before = _load_security_suite_overlay()
        current_revision = _security_suite_revision(before)
        if current_revision != expected_revision:
            raise SecuritySuiteRevisionConflict(
                f"expected security-suite revision {expected_revision}, "
                f"found {current_revision}"
            )
        effective_before = config.load_global_config() or {}
        if config.config_source_errors(include_tenant=False):
            raise SecuritySuiteConfigUnavailable(
                "an active global config source is unreadable; "
                "security-suite configuration was not changed"
            )
        data = json.loads(json.dumps(before))
        security_section = dict(data.get("security_ops") or {})
        platform_section = dict(data.get("threat_hunt") or {})
        environment_section = dict(data.get("env_hunt") or {})
        security_section["enable"] = requested["security_ops"]
        platform_section["enable"] = requested["threat_hunt"]
        environment_section["enable"] = requested["env_hunt"]
        environment_section["response_execution"] = requested["response_execution"]
        # This endpoint owns only the four booleans above. Preserve connector
        # selections, polling intervals, limits, and vendor extension settings.
        data["security_ops"] = security_section
        data["threat_hunt"] = platform_section
        data["env_hunt"] = environment_section
        next_revision = current_revision + 1
        metadata = dict(data.get("security_suite_control") or {})
        metadata["revision"] = next_revision
        data["security_suite_control"] = metadata
        from maverick.config import reset_config_cache

        effective_security = effective_before.get("security_ops") or {}
        effective_platform = effective_before.get("threat_hunt") or {}
        effective_environment = effective_before.get("env_hunt") or {}
        previous = {
            "security_ops": effective_security.get("enable", True) is True,
            "threat_hunt": effective_platform.get("enable", False) is True,
            "env_hunt": effective_environment.get("enable", False) is True,
            "response_execution": (
                effective_environment.get("response_execution", False) is True
            ),
        }
        import time

        from maverick.audit import AuditEvent, EventKind, global_audit_log
        from maverick.privacy_ops import _actor_label

        accepted = global_audit_log().record(AuditEvent(
            ts=time.time(),
            kind=EventKind.SECURITY_SUITE_CONTROL_CHANGED,
            agent="dashboard",
            payload={
                "actor": _actor_label(actor),
                "previous": previous,
                "requested": requested,
                "revision": next_revision,
                "phase": "authorized",
            },
        ))
        if not accepted:
            raise RuntimeError("security-suite control audit was not accepted")
        _write(data)
        reset_config_cache()
        return next_revision


def set_learning(enabled: bool, *, actor: str = "local") -> None:
    """Turn the whole self-learning loop on or off in one action -- writes each
    of ``LEARNING_TOGGLES`` to the overlay, which ``load_config()`` deep-merges,
    so every subsystem's ``enabled()`` sees it. (An env var like
    ``MAVERICK_CONSEQUENCE`` still overrides the overlay if a deployment set
    one.)"""
    with _locked():
        before = _load_overlay_for_update()
        data = json.loads(json.dumps(before))
        for section, key in LEARNING_TOGGLES:
            data.setdefault(section, {})[key] = bool(enabled)
        # The product-wide control selects the conservative unattended harness
        # profile explicitly. Core config keeps legacy partial [self_harness]
        # tables backward-compatible, so relying on an implicit default here
        # could otherwise reactivate a weaker old policy.
        harness = data.setdefault("self_harness", {})
        harness["risk_limited"] = bool(enabled)
        harness["auto_run"] = bool(enabled)
        # Persist the authorization record before publishing a control bit.
        # Runtime readers do not take the dashboard settings lock, so writing
        # first would create a window where an unaudited state was observable.
        from maverick.audit import EventKind, audit_event
        from maverick.config import reset_config_cache

        audited = audit_event(
            EventKind.LEARNING_CONTROL_CHANGED,
            _global=True,
            control="governed_learning",
            enabled=bool(enabled),
            actor=actor,
            acknowledged=False,
            phase="authorized",
        )
        if not audited:
            raise RuntimeError("global learning control audit could not be persisted")
        _write(data)
        reset_config_cache()


def set_learning_subsystem(key: str, enabled: bool, *, actor: str = "local") -> None:
    """Turn ONE learning subsystem of ``LEARNING_SUBSYSTEMS`` on or off.

    The Learning page's per-system switch. ``set_learning`` still writes every
    subsystem at once, so the master switch can always turn everything off
    again. Raises ``KeyError`` for an unknown subsystem. The deployment
    variable named by ``env`` still overrides the value written here."""
    spec = next((s for s in LEARNING_SUBSYSTEMS if s["key"] == key), None)
    if spec is None:
        raise KeyError(key)
    with _locked():
        before = _load_overlay_for_update()
        data = json.loads(json.dumps(before))
        section = data.setdefault(spec["section"], {})
        if not isinstance(section, dict):
            raise SecuritySuiteConfigUnavailable(
                "dashboard settings are unreadable; settings were not changed"
            )
        if spec["section"] == "self_harness" and not config.load_global_config().get(
                "self_harness"):
            # The first key in an empty [self_harness] table would switch the
            # kernel to its historical, weaker defaults: keep the careful
            # profile the pristine default already gives (as set_learning does).
            section.setdefault("risk_limited", True)
            section.setdefault("auto_run", True)
        section[spec["config_key"]] = bool(enabled)
        from maverick.audit import EventKind, audit_event
        from maverick.config import reset_config_cache

        # Record the authorization before publishing the control bit.
        audited = audit_event(
            EventKind.LEARNING_CONTROL_CHANGED,
            _global=True,
            control=key,
            enabled=bool(enabled),
            actor=actor,
            acknowledged=False,
            phase="authorized",
        )
        if not audited:
            raise RuntimeError("learning control audit could not be persisted")
        _write(data)
        reset_config_cache()


def set_dgm(
    enabled: bool,
    *,
    actor: str = "local",
    acknowledged: bool = False,
) -> dict:
    """Set only the canonical, default-off DGM request bit.

    The editable surface and challenge tests are separate All settings rows
    (global admin, confirmed before they widen); evaluator policy and adoption
    authority are not dashboard-editable. The production runner rechecks all
    of them and never adopts code.
    """
    with _locked():
        from maverick import self_modify
        from maverick.config import reset_config_cache

        before_status = self_modify.production_status()
        blocker_codes = {item["code"] for item in before_status["blockers"]}
        if before_status["control_managed"]:
            raise PermissionError("a higher-precedence deployment policy owns DGM")
        if "config_source_error" in blocker_codes:
            raise PermissionError("an active global config source is invalid")
        if enabled and not acknowledged:
            raise ValueError("research-only acknowledgement is required")
        if enabled and any(code.startswith("invalid_") for code in blocker_codes):
            raise PermissionError("DGM boolean configuration is invalid")
        before = _load_overlay_for_update()
        data = json.loads(json.dumps(before))
        data.setdefault("self_modify", {})["enable"] = bool(enabled)
        # The global audit entry is the durable authorization record; the
        # subsequent atomic overlay replacement is the commit. Record the
        # authorization before publishing so an audit failure can never leave
        # even a transiently observable enabled state.
        from maverick.audit import EventKind, audit_event

        audited = audit_event(
            EventKind.LEARNING_CONTROL_CHANGED,
            _global=True,
            control="self_modify",
            enabled=bool(enabled),
            actor=actor,
            acknowledged=bool(acknowledged),
            previous_requested=bool(before_status["requested"]),
            previous_effective=bool(before_status["effective"]),
            previous_state=before_status["state"],
            phase="authorized",
        )
        if not audited:
            raise RuntimeError("global DGM control audit could not be persisted")
        _write(data)
        reset_config_cache()
        after = self_modify.production_status()
        if bool(after["requested"]) != bool(enabled):
            _write(before)
            reset_config_cache()
            raise PermissionError("a higher-precedence deployment policy owns DGM")
        return after


def _higher_precedence_ekko_enable_owner() -> str | None:
    """Return the active operator/tenant source that owns ``ekko.enable``.

    The dashboard overlay intentionally overrides the base config, but the
    optional operator and tenant sources are merged after it.  A non-table
    ``ekko`` value is also ownership for this purpose: it replaces the whole
    dashboard table and is invalid as an Ekko policy, so an expansive request
    must fail closed.
    """
    operator = os.environ.get(config.CONFIG_OVERLAY_ENV)
    sources = []
    if operator:
        sources.append((config.CONFIG_OVERLAY_ENV, Path(operator).expanduser()))
    tenant = config.tenant_config_path()
    if tenant is not None:
        sources.append(("tenant config", tenant))
    for owner, path in sources:
        source = config.load_config(path)
        if "ekko" not in source:
            continue
        section = source.get("ekko")
        if not isinstance(section, dict) or "enable" in section:
            return owner
    return None


def set_ekko(enabled: bool, *, actor: str = "local") -> dict:
    """Set the deployment-global, default-off Ekko request bit.

    The dashboard owns only ``[ekko] enable``.  Capture scope, retention,
    provider egress, device enrollment, and endpoint permissions remain in the
    client's higher-authority configuration and enrollment record.

    As with DGM, the durable global audit authorization is written before the
    atomic overlay commit.  Environment ownership is always rejected.  Before
    an expansive ON commit, active operator/tenant sources are inspected and
    an existing ``ekko.enable`` owner is rejected without publishing a latent
    dashboard ON bit.  A post-commit effective-state check remains as a race
    defense and rolls back a change superseded while this call was in flight.
    """
    from maverick.ekko_control import control_barrier

    # Serialize the complete authorization change with collector commits. A
    # disable call therefore cannot return while an append authorized under
    # the previous deployment policy is still in flight.
    with control_barrier(), _locked():
        from maverick.config import config_source_errors, get_ekko, reset_config_cache

        before_status = get_ekko()
        if "MAVERICK_EKKO" in os.environ:
            raise PermissionError("MAVERICK_EKKO owns the Ekko control")
        if config_source_errors():
            raise PermissionError("an active config source is invalid")
        if enabled:
            owner = _higher_precedence_ekko_enable_owner()
            if owner is not None:
                raise PermissionError(
                    f"higher-precedence {owner} owns the Ekko control"
                )
        before = _load_overlay_for_update()
        data = json.loads(json.dumps(before))
        data.setdefault("ekko", {})["enable"] = bool(enabled)
        from maverick.audit import EventKind, audit_event

        audited = audit_event(
            EventKind.EKKO_CONTROL_CHANGED,
            _global=True,
            control="ekko",
            enabled=bool(enabled),
            actor=actor,
            previous_enabled=bool(before_status.get("enable", False)),
            phase="authorized",
        )
        if not audited:
            raise RuntimeError("global Ekko control audit could not be persisted")

        _write(data)
        reset_config_cache()
        try:
            after = get_ekko()
        except Exception:
            _write(before)
            reset_config_cache()
            raise
        if bool(after.get("enable", False)) != bool(enabled):
            _write(before)
            reset_config_cache()
            raise PermissionError("a higher-precedence deployment policy owns Ekko")
        return after


def set_flow_autonomy(*, auto_evolve: bool | None = None,
                      auto_apply: bool | None = None) -> None:
    """Override the flow self-improvement loop's [flows] knobs in the overlay.

    Kept OFF the blanket ``set_learning`` list on purpose: autonomously rewriting
    a live workflow is a heavier consequence than the passive learning that button
    controls, so it gets its own explicit opt-in. Automatic proposal application
    is retired: ``auto_apply`` is retained for compatibility but applies nothing;
    proposals require human review. Only the fields passed are changed, except
    ``auto_apply`` is cleared while ``auto_evolve`` is off. An env var
    (``MAVERICK_FLOWS_AUTO``) still overrides the overlay if a deployment set one."""
    with _locked():
        data = _load_overlay_for_update()
        flows = data.setdefault("flows", {})
        if auto_evolve is not None:
            flows["auto_evolve"] = bool(auto_evolve)
        if auto_apply is not None:
            flows["auto_apply"] = bool(auto_apply)
        if not bool(flows.get("auto_evolve", False)):
            flows["auto_apply"] = False
        _write(data)


def set_value_assumptions(*, hourly_rate: float | None = None,
                          hours_per_task: float | None = None,
                          currency: str | None = None,
                          enable: bool | None = None,
                          departments: dict | None = None) -> None:
    """Persist the client's cost/value assumptions ([value]) in the overlay.

    Only the fields passed are changed. ``departments`` maps department name ->
    {hourly_rate, hours_per_task}; an entry whose dict is empty/None REMOVES
    that department's override (reverts it to the global assumption). Rates and
    hours must be non-negative -- the Savings page is a claim a client will
    repeat to their CFO, so junk never persists."""
    def _pos(v: object, label: str) -> float:
        try:
            f = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must be a number") from exc
        if f < 0:
            raise ValueError(f"{label} must be >= 0")
        return f

    with _locked():
        data = _load_overlay_for_update()
        val = data.setdefault("value", {})
        if hourly_rate is not None:
            val["hourly_rate"] = _pos(hourly_rate, "hourly_rate")
        if hours_per_task is not None:
            val["hours_per_task"] = _pos(hours_per_task, "hours_per_task")
        if currency is not None and currency.strip():
            val["currency"] = currency.strip().upper()[:8]
        if enable is not None:
            val["enable"] = bool(enable)
        for name, ov in (departments or {}).items():
            dep = val.setdefault("departments", {})
            if not ov:
                dep.pop(str(name), None)
                continue
            row = {}
            if ov.get("hourly_rate") is not None:
                row["hourly_rate"] = _pos(ov["hourly_rate"],
                                          f"{name} hourly_rate")
            if ov.get("hours_per_task") is not None:
                row["hours_per_task"] = _pos(ov["hours_per_task"],
                                             f"{name} hours_per_task")
            if row:
                dep[str(name)] = {**dep.get(str(name), {}), **row}
        if not val.get("departments"):
            val.pop("departments", None)
        if not val:
            data.pop("value", None)
        _write(data)


def _review_email_channel(ccfg, *, enabled, actor):
    from maverick import microsoft_mail
    mode = ccfg.get("email_auth", "password")
    if mode not in {"password", "microsoft"}:
        raise ValueError("Choose password sign-in or a connected Microsoft mailbox.")
    if mode == "microsoft" and enabled:
        try:
            ccfg.update(microsoft_mail.bind_account(ccfg.get("oauth_account"), actor=actor))
        except PermissionError as exc:
            raise ValueError(str(exc)) from exc
        problem = microsoft_mail.configuration_problem(ccfg)
        if problem:
            raise ValueError(problem)
    elif mode == "password":
        for key in ("oauth_account", "oauth_tenant", "oauth_principal"):
            ccfg.pop(key, None)


def set_channel(name: str, enabled: bool, values: dict | None = None, *, before_write=None, actor=None) -> None:
    """Enable/disable a channel and set its credentials in the overlay. A blank
    field value is left unchanged (so toggling enabled never wipes a secret you
    can't see). Writes [channels.<name>] to dashboard-config.toml, which
    load_config() deep-merges -- so `maverick serve` picks it up with no
    config.toml edit. Use ``clear_channel`` to remove."""
    spec = _CHANNELS_BY_NAME.get(name)
    if spec is None:
        raise ValueError("unknown channel")
    values = values or {}
    with _locked():
        data = _load_overlay_for_update()
        if before_write is not None:
            before_write()
        ccfg = data.setdefault("channels", {}).setdefault(name, {})
        ccfg["enabled"] = bool(enabled)
        for field in spec["fields"]:
            key = field["key"]
            raw = values.get(key)
            val = raw.strip() if isinstance(raw, str) else raw
            if field.get("type") == "list" and key in values:
                _access = CHANNEL_ALLOWLISTS[name]
                pattern, error = _access[5], _access[6]
                entries = (re.split(r"[,\r\n]+", val) if isinstance(val, str)
                           else val if isinstance(val, list) else None)
                if entries is None or len(entries) > 200:
                    raise ValueError("Add no more than 200 permitted people")
                people = []
                for entry in entries:
                    person = str(entry).strip()
                    if not person:
                        continue
                    if not re.fullmatch(pattern, person):
                        raise ValueError(f"Enter {error}")
                    if person not in people:
                        people.append(person)
                # An explicit empty list denies everyone. Removing this key
                # instead would silently restore installer/server access.
                ccfg[key] = people
                continue
            if val in (None, ""):
                continue  # blank -> keep the stored value (don't wipe a hidden secret)
            if field.get("type") == "int":
                try:
                    ccfg[key] = int(val)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{field['label']} must be a number") from exc
            elif field.get("type") == "url":
                ccfg[key] = _channel_server_address(field["label"], val)
            elif key == "trusted_authserv_id":
                from maverick.mail_auth import valid_trusted_mail_server

                if not valid_trusted_mail_server(val):
                    raise ValueError("Incoming mail server identity must be a server name")
                ccfg[key] = str(val).lower()
            else:
                ccfg[key] = str(val)
        def reviewed_write():
            if before_write is not None:
                before_write()
            if name == "email":
                _review_email_channel(ccfg, enabled=enabled, actor=actor)
        reviewed_write()
        _write(data, before_effect=reviewed_write)


def _channel_server_address(label: str, value: object) -> str:
    """A chat server's web address: https, or plain http only on this computer
    (the channel's access token is sent to it with every request)."""
    from urllib.parse import urlsplit

    text = str(value).strip().rstrip("/")
    parts = urlsplit(text)
    local = parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if (len(text) > 300 or not parts.netloc or parts.query or parts.fragment or parts.username
            or parts.password or not (parts.scheme == "https" or local)
            or any(ch.isspace() for ch in text)):
        raise ValueError(f"{label} must be a secure web address starting with https://")
    return text


def clear_channel(name: str, *, before_write=None) -> None:
    """Remove a channel's overlay table entirely (reverts to config.toml/env)."""
    if name not in _CHANNELS_BY_NAME:
        raise ValueError("unknown channel")
    with _locked():
        data = _load_overlay_for_update()
        if before_write is not None:
            before_write()
        (data.get("channels") or {}).pop(name, None)
        _write(data, before_effect=before_write)


def _raw_config_providers() -> dict:
    """Providers from config.toml ONLY (no overlay), to attribute the source."""
    try:
        return config._load_config_file(config.config_path()).get("providers", {}) or {}
    except Exception:
        return {}


def _raw_config_channels() -> dict:
    """Channels from config.toml ONLY (no overlay), to attribute the source."""
    try:
        return config._load_config_file(config.config_path()).get("channels", {}) or {}
    except Exception:
        return {}


def _mask(secret: str) -> str:
    s = str(secret)
    return ("•" * 4 + s[-4:]) if len(s) > 4 else "••••"


def provider_address_display(value: object) -> tuple[str, bool]:
    """A safe display only: never copy embedded URL credentials into a form."""
    from urllib.parse import urlsplit, urlunsplit

    from .integration_readiness import _valid_self_hosted_address

    text = str(value or "").strip()
    if not text:
        return "", False
    try:
        address = urlsplit(text)
        host = address.hostname
        if address.scheme not in {"http", "https"} or not host:
            raise ValueError("not a server address")
        host = f"[{host}]" if ":" in host else host
        if address.port is not None:
            host += f":{address.port}"
        display = urlunsplit((address.scheme, host, address.path, "", ""))
    except ValueError:
        return "Address needs attention", True
    return display, len(text) > 320 or not _valid_self_hosted_address(text)


def state() -> dict:
    """Redacted snapshot for the settings page. NEVER returns a raw key."""
    overlay = load_overlay()
    ov_providers = overlay.get("providers") or {}
    raw_providers = _raw_config_providers()
    providers = []
    for p in PROVIDERS:
        name = p["name"]
        ov = ov_providers.get(name) or {}
        raw = raw_providers.get(name) or {}
        effective = config.provider_configuration_state(name)
        provider_config = config.get_provider_config(name) or {}
        key = ov.get("api_key") or raw.get("api_key")
        setup_fields = {
            "azure": ("auth_mode", "deployment", "api_version"),
            "bedrock": ("auth_mode", "endpoint", "region", "model_id"),
            "vertex": ("project_id", "region", "model_id"),
        }.get(name, ())
        setup = {field: str(provider_config.get(field) or "").strip() for field in setup_fields}
        if name == "azure":
            setup["auth_mode"] = setup.get("auth_mode") or os.environ.get("AZURE_OPENAI_AUTH", "").strip()
            setup["deployment"] = (os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip()
                                   or setup.get("deployment", ""))
        if name == "bedrock":
            setup["auth_mode"] = setup.get("auth_mode") or os.environ.get("BEDROCK_AUTH_MODE", "").strip()
            setup["region"] = (os.environ.get("AWS_REGION", "").strip()
                               or os.environ.get("AWS_DEFAULT_REGION", "").strip()
                               or setup.get("region", ""))
            setup["model_id"] = (os.environ.get("BEDROCK_MODEL_ID", "").strip()
                                 or setup.get("model_id", ""))
        if name == "vertex":
            # Config first; the same environment names the client reads fill the gaps.
            setup["project_id"] = (setup.get("project_id")
                                   or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
                                   or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip())
            setup["region"] = setup.get("region") or os.environ.get("CLOUD_ML_REGION", "").strip()
            setup["model_id"] = setup.get("model_id") or os.environ.get("VERTEX_MODEL_ID", "").strip()
        setup_locked = {field: bool(_provider_detail_blocker(name, field)) for field in setup_fields}
        via = effective["via"]
        if not via and ov and setup.get("auth_mode") in {"iam", "entra_id"}:
            via = "dashboard"
        if not via and ov and name == "vertex" and setup.get("project_id"):
            via = "dashboard"
        address, address_needs_repair = provider_address_display(effective["base_url"])
        providers.append({
            "name": name, "label": p["label"], "base_url_field": p["base_url"],
            "configured": effective["configured"],
            "via": via,
            "setup": setup, "setup_locked": setup_locked,
            "key_hint": _mask(key) if (ov.get("api_key") or raw.get("api_key")) else None,
            "base_url": address, "base_url_needs_repair": address_needs_repair,
            "env_hint": ", ".join(p["env"]) if p["env"] else "",
            "dashboard_set": effective["dashboard_set"],
            "api_key_source": effective["api_key_source"],
            "base_url_source": effective["base_url_source"],
            "dashboard_can_set_api_key": effective["dashboard_can_set_api_key"],
            "dashboard_can_set_base_url": effective["dashboard_can_set_base_url"],
            "source_errors": effective["source_errors"],
        })
    caps_eff = config.get_capabilities()
    feats_eff = config.get_features()
    ov_caps = overlay.get("capabilities") or {}
    ov_feats = overlay.get("features") or {}
    capabilities = [
        {"name": k, "enabled": bool(caps_eff.get(k, v)),
         "overridden": k in ov_caps, "info": CAPABILITY_INFO.get(k, "")}
        for k, v in CAPABILITY_DEFAULTS.items()
    ]
    features = [
        {"name": k, "enabled": bool(feats_eff.get(k, v)),
         "overridden": k in ov_feats, "info": FEATURE_INFO.get(k, "")}
        for k, v in FEATURE_DEFAULTS.items()
    ]
    return {"providers": providers, "capabilities": capabilities, "features": features}


def channels_state() -> list[dict]:
    """Redacted snapshot for the channels page. NEVER returns a raw secret:
    secret fields are blanked (with a masked hint), non-secret fields prefill so
    the form shows the current host/port/etc."""
    overlay = load_overlay()
    ov_ch = overlay.get("channels") or {}
    raw_ch = _raw_config_channels()
    from . import settings_all_page as page
    from .integration_readiness import require_readable_config

    effective = require_readable_config().get("channels") or {}
    layers = page._sources()
    out = []
    for spec in CHANNELS:
        name = spec["name"]
        ov = ov_ch.get(name) or {}
        raw = raw_ch.get(name) or {}
        fields = []
        for f in spec["fields"]:
            ov_v = ov.get(f["key"])
            raw_v = raw.get(f["key"])
            v = ov_v if ov_v not in (None, "") else raw_v
            configured = v not in (None, "", [])
            # A value set on the server (environment) wins over this page.
            from_server = bool(f.get("env") and os.environ.get(f["env"], "").strip())
            people_source = ""
            people_locked = False
            if f.get("type") == "list":
                from maverick_channels.base import normalize_allowlist

                from .settings_catalog import BY_ID, lookup

                setting = BY_ID[f"channels.{name}.{f['key']}"]
                current = (effective.get(name) or {}).get(f["key"])
                if name == "teams" and f["key"] not in (effective.get(name) or {}):
                    current = (effective.get(name) or {}).get("allowed_user_ids")
                if current is not None and not isinstance(current, (list, tuple, set)):
                    raise ValueError("The permitted-people list could not be read safely.")
                v = sorted(normalize_allowlist(current, f["env"]))
                configured = bool(v)
                from_server = current is None and from_server
                resolved = page._resolve(setting, layers)
                people_source = resolved.get("source_text") or page.SOURCE_TEXT[resolved["source"]]
                people_locked = resolved["locked"] or lookup(layers["tenant"], setting.path)[0]
                if people_locked:
                    people_source = "Set by your server's deployment settings"
            fields.append({
                "key": f["key"], "label": f["label"],
                "secret": bool(f.get("secret")), "type": f.get("type", "text"),
                "help": f.get("help", ""), "advanced": bool(f.get("advanced")),
                "value": ("" if f.get("secret") else
                          "\n".join(str(item) for item in v) if f.get("type") == "list" and isinstance(v, list)
                          else str(v) if configured else ""),
                "hint": ("on the server" if from_server else
                         _mask(v) if (configured and f.get("secret")) else ""),
                "configured": configured or from_server,
                "people": v if f.get("type") == "list" else [],
                "people_source": people_source, "people_locked": people_locked,
            })
        out.append({
            "name": name, "label": spec["label"],
            "enabled": bool(ov.get("enabled", raw.get("enabled", False))),
            "fields": fields, "dashboard_set": bool(ov),
            "via": "dashboard" if ov else ("config.toml" if raw else None),
        })
    return out


__all__ = [
    "PROVIDERS", "CAPABILITY_DEFAULTS", "CAPABILITY_INFO",
    "FEATURE_DEFAULTS", "FEATURE_INFO", "CHANNELS",
    "LEARNING_SUBSYSTEMS", "load_overlay", "set_provider", "rotate_provider",
    "clear_provider", "ProviderRotationConflict",
    "ProviderConfigurationUnavailable",
    "SecuritySuiteConfigUnavailable", "SecuritySuiteRevisionConflict",
    "ResearchSettingsConflict", "ResearchSettingsUnavailable",
    "research_execution_state", "set_research_execution",
    "security_suite_revision",
    "set_dgm", "set_ekko", "set_security_suite",
    "set_toggle", "set_toggles", "set_learning", "set_learning_subsystem",
    "set_flow_autonomy", "state", "set_channel", "clear_channel",
    "channels_state", "CONTAINER_FILE_TOOLS", "enable_container_file_work",
]
