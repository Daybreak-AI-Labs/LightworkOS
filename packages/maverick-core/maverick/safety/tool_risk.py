"""Per-tool risk levels + per-identity max-risk ceiling.

Each tool has a coarse risk level -- ``low``, ``medium``, or ``high``.
A deployment can cap what a given context may reach by setting a
``max_risk`` ceiling; tools whose risk exceeds the ceiling are dropped
from the registry (in addition to the explicit allow/deny lists in
``tool_acl``).

Config (``~/.maverick/config.toml``):

    [security]
    max_risk = "medium"          # global ceiling (optional)

    [security.channels.telegram]
    max_risk = "low"             # nothing destructive over Telegram

    [security.users."tg:12345"]
    max_risk = "high"            # this user is trusted

    [security.tool_risk]
    my_plugin_tool = "high"      # override / classify a tool
    "mcp_*"        = "medium"    # glob -- relax MCP tools (they default to high)

Default ceiling is *unset*, meaning no cap (all risk levels allowed), so
behaviour is unchanged unless a ceiling is configured.
"""
from __future__ import annotations

import contextlib
import contextvars
import fnmatch
import logging

log = logging.getLogger(__name__)

# Ordered low -> high. Index is the comparable rank.
RISK_LEVELS = ("low", "medium", "high")

# Built-in risk classification. Anything not listed (and not matched by a
# configured override) defaults to ``high`` until it is deliberately rated.
# High-risk tools can mutate
# the host, run arbitrary code, or drive a real machine/browser; low-risk
# tools are read-only or pure lookups.
_DEFAULT_RISK: dict[str, str] = {
    "read_tool_result": "low",  # same-goal, same-principal screened artifact
    # high: arbitrary code / host mutation / full control
    "shell": "high",
    # The session kernel executes model-written Python. It is exactly as
    # consequential as `shell` and needs an intentional high classification.
    "repl_exec": "high",
    "computer": "high",
    "browser": "high",
    "apply_patch": "high",
    "write_file": "high",
    "str_replace_editor": "high",
    "ast_edit": "high",
    "compute": "high",
    "code_exec": "high",
    "memory": "high",
    "obsidian": "high",
    "clipboard": "high",
    "container_build": "high",
    "github_issues": "high",
    "gitlab_issues": "high",
    "anki": "high",
    "lsp_bridge": "high",
    "wasm_run": "high",
    "ros": "high",
    "serial": "high",
    # Bidirectional P2P data channel to an arbitrary peer: an exfil path with
    # no allow-list concept. Had no entry at all, so it fell to "medium".
    "webrtc": "high",
    "websocket": "high",
    # Native tools with paid/external data dispatch, credential exchange,
    # device control, shared-store mutation or executable document processing.
    "image_edit": "high", "huggingface": "high", "translate": "high",
    "newsapi": "high", "reddit": "high", "wolfram": "high",
    "bitbucket": "high", "view_image": "high", "speak": "high",
    "transcribe_audio": "high", "oidc": "high", "oauth_helper": "high",
    "embedded_device": "high", "ffmpeg": "high", "pandoc": "high",
    "imagemagick": "high", "office_convert": "high", "ocr": "high",
    "latex": "high", "cache_admin": "high",
    # Bounded native goal-local memory/link records, without an external effect.
    "kv_memory": "medium", "remember_outcome_key": "medium",
    # high: mutate external state / money / send messages / drive infra or a
    # device / recursively spawn. Listed explicitly so they do not fall through
    # to the "medium" default, which a max_risk="medium" ceiling would admit.
    "sql_query": "high",
    "lambda": "high",
    "cloudflare": "high",
    "vercel": "high",
    "git_advanced": "high",
    "github_actions": "high",
    "openapi_runner": "high",
    "pandas_query": "high",
    "vertex": "high",
    "s3": "high",
    "dynamodb": "high",
    "mongodb": "high",
    "redis": "high",
    "elasticsearch": "high",
    "stripe": "high",
    "plaid": "high",
    "truelayer": "high",
    "shopify": "high",
    "email": "high",
    "gmail": "high",
    "ses": "high",
    "sns": "high",
    "twilio": "high",
    "slack_bot": "high",
    "discord_bot": "high",
    "home_assistant": "high",
    "android": "high",
    "ios_sim": "high",
    "spawn_subagent": "high",
    "spawn_swarm": "high",
    "spawn_specialist": "high",
    "delegate_to_agent": "high",
    # Network-reachable Lightwork MCP actions.  These names are the server's
    # own tools (not third-party ``mcp_*`` imports), so classify them explicitly:
    # goal execution can fan out into arbitrary tools, and the remaining writes
    # mutate durable code/state/memory or resume privileged execution.
    "maverick_start": "high",
    "maverick_resume": "high",
    "maverick_answer": "high",
    "maverick_skill_install": "high",
    "maverick_fact_set": "high",
    "maverick_fleet_ingest": "high",
    # high (finance): money movement, posting to a system of record, filing with
    # an authority, or master-data mutation. Classified high so a max_risk="medium"
    # finance pack drops them from the registry and governance gates them as the
    # "never move money / post / file without a human" boundary (finance-agent-suite).
    "post_journal_entry": "high",
    "close_period": "high",
    "edit_chart_of_accounts": "high",
    "release_payment": "high",
    "release_payroll_payment": "high",
    "run_payroll": "high",
    "wire_transfer": "high",
    "ach_send": "high",
    "send_payment": "high",
    "send_invoice": "high",
    "write_off_balance": "high",
    "approve_expense": "high",
    "reimburse": "high",
    "vendor_master_change": "high",
    "approve_vendor": "high",
    "approve_po": "high",
    "edit_employee_bank_details": "high",
    "place_trade": "high",
    "create_order_instruction": "high",
    "delete_order_instruction": "high",
    "execute_fx_trade": "high",
    "dispose_asset": "high",
    "file_return": "high",
    "file_tax_return": "high",
    "remit_tax": "high",
    "file_with_sec": "high",
    "set_credit_limit": "high",
    # low (finance): read / draft / stage / propose / assurance. These never
    # mutate a system of record (drafts await a human post), so low-risk packs
    # (FP&A, SOX, Internal Audit) can use them under a max_risk="low" ceiling.
    "gl_read_trial_balance": "low", "gl_read_subledger": "low",
    "gl_read_journal": "low", "gl_read_actuals": "low",
    "ap_read_invoice": "low", "ap_read_po": "low", "ap_read_receipt": "low",
    "ar_read_aging": "low", "ar_read_invoice": "low", "fa_read_register": "low",
    "expense_read_report": "low", "expense_read_card": "low",
    "bank_read_balance": "low", "bank_read_transactions": "low",
    "hcm_read_employee": "low", "payroll_read_register": "low",
    "payroll_read_timesheet": "low", "epm_read_plan": "low",
    "bi_read_metric": "low", "audit_log_read": "low", "covenant_check": "low",
    "stage_journal_entry": "low", "reconcile_accounts": "low",
    "flux_analysis": "low", "stage_payment_batch": "low", "draft_invoice": "low",
    "propose_cash_application": "low", "stage_payroll_run": "low",
    "reconcile_payroll": "low", "draft_payroll_tax": "low",
    "draft_depreciation_schedule": "low", "stage_asset_entry": "low",
    "draft_revrec_schedule": "low", "stage_deferred_revenue": "low",
    "draft_elimination": "low", "draft_translation": "low",
    "flag_policy_violation": "low", "draft_accrual": "low",
    "build_variance_report": "low", "build_board_pack": "low",
    "build_forecast_scenario": "low", "build_cashflow_forecast": "low",
    "propose_transfer": "low", "propose_trade": "low", "propose_hedge": "low",
    "model_refinancing": "low", "compute_tax_provision": "low",
    "draft_tax_footnote": "low", "prepare_return": "low", "validate_nexus": "low",
    "tp_benchmark": "low", "draft_tp_documentation": "low", "test_control": "low",
    "log_deficiency": "low", "run_assessment": "low", "sod_conflict_scan": "low",
    "draft_workpaper": "low", "log_finding": "low",
    "assemble_evidence_package": "low", "run_fraud_model": "low",
    "open_case": "low", "flag_anomaly": "low", "scan_finance_anomalies": "low",
    "update_risk_register": "low",
    "build_risk_report": "low", "score_credit": "low",
    "propose_credit_limit": "low", "analyze_spend": "low", "draft_po": "low",
    "screen_sanctions": "low", "validate_bank_details": "low",
    "draft_filing": "low", "tag_xbrl": "low", "run_disclosure_checklist": "low",
    "draft_earnings_materials": "low", "compute_sbc_expense": "low",
    "draft_sbc_entry": "low",
    # high: dedicated-module enterprise connectors that mutate external business
    # state / move money / run remote code or SQL / send messages. (The long-tail
    # REST connectors in enterprise_connectors.py are covered by name separately.)
    "airtable": "high",
    "asana": "high",
    "bigquery": "high",
    "calendar": "high",
    "calendly": "high",
    "clickup": "high",
    "confluence": "high",
    "database": "high",
    "databricks": "high",
    "datadog": "high",
    "dropbox": "high",
    "dynamics": "high",
    "ga4": "high",
    "gdrive": "high",
    "gitlab": "high",
    "github_search": "high",
    "http_fetch": "high",
    "web_archive": "high",
    "hubspot": "high",
    "jira": "high",
    "learn_capability": "high",
    "linear": "high",
    "mixpanel": "high",
    "msgraph": "high",
    "notebook_exec": "high",
    "notify": "high",
    "notion": "high",
    "onetrust": "high",
    "oracle": "high",
    "pagerduty": "high",
    "plausible": "high",
    "posthog": "high",
    "replicate": "high",
    "salesforce": "high",
    "sap": "high",
    "sentry": "high",
    "servicenow": "high",
    "snowflake": "high",
    "spotify": "high",
    "spreadsheet": "high",
    "teams": "high",
    "trello": "high",
    "workday": "high",
    "zoom": "high",
    # low: read-only / pure lookups
    "read_file": "low",
    "sql_query_read": "low",  # forced SQLite read-only connection and authorizer
    "spreadsheet_read": "low",  # info/read only; no edits or recalculation
    "read_attachment": "low",
    "list_dir": "low",
    "list_specialists": "low",
    "repo_map": "low",
    "dep_graph": "low",
    "recall_past_goals": "low",  # real registered name (was "recall" -> dead)
    "web_search": "low",
    "knowledge_search": "low",
    "find_controls": "low",
    "wikipedia": "low",
    "arxiv": "low",
    "semantic_scholar": "low",
    "hackernews": "low",
    "geocode": "low",
    "dns_lookup": "low",
    "currency": "low",
    "preview_diff": "low",
    "erp_read": "low",  # read-only (GET) ERP access; no writes / host mutation
    # Commerce suite (tools/commerce_tools.py). Reads are pure lookups over the
    # storefront/merchant backend. The cart and proposal tools mutate only
    # session state under module-enforced caps, or stage a change a human
    # applies -- medium, never high: nothing here spends money or writes to the
    # store, and the checkout handoff returns an opaque cart reference only.
    "storefront_search": "low",
    "storefront_product": "low",
    "cart_view": "low",
    "cart_add": "medium",
    "cart_remove": "medium",
    "checkout_handoff": "medium",
    "shopper_orders_read": "low",
    "shopper_stage_return": "medium",
    "shopper_preferences": "medium",
    "catalog_read": "low",
    "inventory_read": "low",
    "pricing_read": "low",
    "orders_read": "low",
    "analytics_read": "low",
    "promotions_read": "low",
    "merchant_stage_change": "medium",
    # Read-only Lightwork MCP queries.  Agent Trust max_risk ceilings use this
    # same table, so a low-risk remote principal sees queries but not mutations.
    "maverick_status": "low",
    "maverick_skills_list": "low",
    "maverick_fleet_recall": "low",
    "maverick_facts_get": "low",
}

_DEFAULT_RISK_LEVEL = "medium"
_UNCLASSIFIED_RISK_LEVEL = "high"


# The long-tail enterprise connectors (built by ``enterprise_connectors.py`` via
# a shared REST/GraphQL factory) all expose write ops (post/put/patch/delete or
# GraphQL mutations), so they fail safe to "high" -- resolved by name from the
# connector spec list so newly-added connectors are covered automatically. The
# list is loaded lazily (the tools package imports this module, so a top-level
# import would be circular) and cached only on success; a config override or an
# explicit ``_DEFAULT_RISK`` entry still wins.
_ENTERPRISE_CONNECTORS: frozenset[str] | None = None
_READ_CONNECTORS: frozenset[str] | None = None
_READ_CONNECTOR_RISKS: dict[str, str] | None = None


def _enterprise_connector_names() -> frozenset[str]:
    global _ENTERPRISE_CONNECTORS
    if _ENTERPRISE_CONNECTORS is not None:
        return _ENTERPRISE_CONNECTORS
    try:
        from ..tools.enterprise_connectors import ENTERPRISE_CONNECTOR_NAMES
    except Exception:
        return frozenset()  # tools not importable yet -- retry on the next call
    _ENTERPRISE_CONNECTORS = frozenset(ENTERPRISE_CONNECTOR_NAMES)
    return _ENTERPRISE_CONNECTORS


def _read_connector_names() -> frozenset[str]:
    """Read-only (GET-only) connector variants."""
    global _READ_CONNECTORS
    if _READ_CONNECTORS is not None:
        return _READ_CONNECTORS
    try:
        from ..tools.enterprise_connectors import READ_CONNECTOR_NAMES
    except Exception:
        return frozenset()  # tools not importable yet -- retry on the next call
    _READ_CONNECTORS = frozenset(READ_CONNECTOR_NAMES)
    return _READ_CONNECTORS


def _read_connector_risks() -> dict[str, str]:
    """Explicit risk level for read-only connector variants.

    GET-only prevents writes, but it does not make arbitrary SaaS reads safe for
    low-risk channels: identity, HR, security, CI/CD, legal, and BI APIs often
    return high-confidentiality records. Connector generation therefore assigns
    an explicit risk and this helper fails closed to ``high`` for stale/unknown
    read seats.
    """
    global _READ_CONNECTOR_RISKS
    if _READ_CONNECTOR_RISKS is not None:
        return _READ_CONNECTOR_RISKS
    try:
        from ..tools.enterprise_connectors import READ_CONNECTOR_RISKS
    except Exception:
        return {}  # tools not importable yet -- retry on the next call
    _READ_CONNECTOR_RISKS = dict(READ_CONNECTOR_RISKS)
    return _READ_CONNECTOR_RISKS


# Operator-provisioned read adapters the audited pack catalog names as
# deployment prerequisites (``domain_prose_lint.ABSTRACT_ADAPTERS``, a ratchet).
# They are deliberately rated, not unknown: each is a read seat a medium-ceiling
# pack declares, so it keeps the medium rating it had before unrated names were
# raised to the high refusal floor. Medium, never low: these seats can return
# confidential records. An exact ``[security.tool_risk]`` override still wins,
# so an operator whose adapter can do more rates it higher.
_ABSTRACT_ADAPTER_RISK_LEVEL = "medium"
_ABSTRACT_ADAPTERS: frozenset[str] | None = None


def _abstract_adapter_names() -> frozenset[str]:
    global _ABSTRACT_ADAPTERS
    if _ABSTRACT_ADAPTERS is not None:
        return _ABSTRACT_ADAPTERS
    try:
        from ..domain_prose_lint import ABSTRACT_ADAPTERS
    except Exception:
        return frozenset()  # not importable yet -- fail closed, retry next call
    _ABSTRACT_ADAPTERS = frozenset(ABSTRACT_ADAPTERS)
    return _ABSTRACT_ADAPTERS


def risk_rank(level: str) -> int:
    """Rank of a risk level (0=low). Unknown levels rank as medium."""
    try:
        return RISK_LEVELS.index(level)
    except ValueError:
        return RISK_LEVELS.index(_DEFAULT_RISK_LEVEL)


def _load_overrides() -> dict[str, str]:
    """Read ``[security.tool_risk]`` overrides. name -> level."""
    try:
        from ..config import load_config
        cfg = load_config() or {}
    except Exception as e:
        log.debug("tool_risk: cannot load config: %s", e)
        return {}
    section = (cfg.get("security") or {}).get("tool_risk") or {}
    out: dict[str, str] = {}
    for name, level in section.items():
        if isinstance(level, str) and level in RISK_LEVELS:
            out[name] = level
        else:
            log.warning("tool_risk: bad risk level for %s: %r", name, level)
    return out


#: Overrides pinned for the duration of one registry build (see
#: :func:`pinned_overrides`). ``None`` outside such a block.
_PINNED_OVERRIDES: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "maverick_tool_risk_pinned_overrides", default=None,
)


@contextlib.contextmanager
def pinned_overrides():
    """Read ``[security.tool_risk]`` once for everything inside the block.

    Building a base registry registers thousands of tools, and each
    ``register`` runs the ACL's ``tool_risk`` check, which re-read the whole
    config every time (measured: 2,937 ``load_config`` calls per ``Agent()``).
    The config cannot meaningfully change mid-build, so pin one snapshot for
    the block; outside it every call reads the live config as before. Nested
    blocks reuse the outer snapshot.
    """
    if _PINNED_OVERRIDES.get() is not None:
        yield
        return
    token = _PINNED_OVERRIDES.set(_load_overrides())
    try:
        yield
    finally:
        _PINNED_OVERRIDES.reset(token)


@contextlib.contextmanager
def reviewed_ratings(ratings: dict[str, str]):
    """Apply operator-reviewed ratings for otherwise *unrated* names in the block.

    An external agent's tool names are its own, so its enrollment carries the
    operator's rating for each. Those ratings only fill the unrated high
    floor; a name Lightwork (or ``[security.tool_risk]``) already classifies
    keeps that classification, so an enrollment can never down-rate it.
    """
    base = _current_overrides(None)

    extra = {name: level for name, level in (ratings or {}).items()
             if level in RISK_LEVELS and tool_risk_is_unrated(name, base)}
    token = _PINNED_OVERRIDES.set({**extra, **base})
    try:
        yield
    finally:
        _PINNED_OVERRIDES.reset(token)


def _current_overrides(overrides: dict[str, str] | None) -> dict[str, str]:
    if overrides is not None:
        return overrides
    pinned = _PINNED_OVERRIDES.get()
    return pinned if pinned is not None else _load_overrides()


def tool_risk(name: str, overrides: dict[str, str] | None = None) -> str:
    """Risk level for a tool: config override (exact then glob), then the
    built-in default.

    Two classes of tool fail safe to ``high`` when otherwise unclassified: an
    MCP tool (``mcp_*``), which runs arbitrary code through a third-party
    server; and an enterprise connector (the long-tail REST/GraphQL connectors
    from ``enterprise_connectors.py``), which is write-capable by construction.
    A config override is checked first, so either can be relaxed deliberately,
    e.g. ``[security.tool_risk]`` ``"mcp_*" = "medium"`` or ``okta = "medium"``.
    Any other unclassified tool falls back to ``high``. That refusal floor is
    not an intentional classification; ``tool_risk_is_classified`` stays false.
    """
    overrides = _current_overrides(overrides)
    if name in overrides:
        return overrides[name]  # exact override wins, even lowering a built-in
    builtin = _DEFAULT_RISK.get(name)
    for pattern, level in overrides.items():
        if any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(name, pattern):
            # A glob may raise risk or classify an unknown tool, but must not
            # silently *lower* a built-in classification below its floor -- a
            # broad wildcard (e.g. "s*"="low") would otherwise declassify
            # shell / wire_transfer and defeat the max_risk ceiling + risk gate.
            # Dropping a built-in below its floor requires an explicit exact
            # override (handled above). mcp_*/connector fail-safes are not in
            # the built-in table, so they stay glob-relaxable as documented.
            if builtin is not None and risk_rank(level) < risk_rank(builtin):
                return builtin
            return level
    if builtin is not None:
        return builtin
    # Unclassified. An MCP tool is externally-defined arbitrary code reached
    # through a third-party server, and an enterprise connector is write-capable
    # by construction -> both fail safe to high. Other unknown names likewise
    # cannot enter a low/medium risk ceiling merely because they were unrated.
    if name.startswith("mcp_"):
        return "high"
    if name in _read_connector_names():
        return _read_connector_risks().get(name, "high")
    if name in _enterprise_connector_names():
        return "high"
    if name in _abstract_adapter_names():
        return _ABSTRACT_ADAPTER_RISK_LEVEL
    # A namespaced action (``salesforce.write``, ``servicenow.read``) inherits
    # its namespace's classification when it has none of its own -- UPWARD
    # ONLY, so a suffix never launders a high-risk connector into a lower
    # inherited rating. Unknown suffixes otherwise retain the high refusal
    # floor; they are not thereby marked intentionally classified.
    namespace = name.split(".", 1)[0]
    if namespace and namespace != name:
        inherited = tool_risk(namespace, overrides)
        if risk_rank(inherited) > risk_rank(_DEFAULT_RISK_LEVEL):
            return inherited
    return _UNCLASSIFIED_RISK_LEVEL


def tool_risk_is_classified(
    name: str, overrides: dict[str, str] | None = None,
) -> bool:
    """Whether ``name`` has an intentional risk classification.

    ``tool_risk`` conservatively refuses unknown names under low/medium
    ceilings, but reliability and workflow governance must distinguish that
    fallback from an explicitly reviewed medium-risk tool. Otherwise a newly
    installed mutating plugin silently gains automatic retries and bypasses
    high-risk approval gates merely because its name is absent from the table.
    """
    name = str(name or "")
    overrides = _current_overrides(overrides)
    if name in overrides or name in _DEFAULT_RISK:
        return True
    if any(
        any(ch in pattern for ch in "*?[") and fnmatch.fnmatchcase(name, pattern)
        for pattern in overrides
    ):
        return True
    return bool(
        name.startswith("mcp_")
        or name in _read_connector_names()
        or name in _enterprise_connector_names()
        or name in _abstract_adapter_names()
    )


def tool_risk_is_unrated(
    name: str, overrides: dict[str, str] | None = None,
) -> bool:
    """Whether ``name`` only carries the unrated high refusal floor.

    A namespaced name (``salesforce.write``) inherits its namespace's rating
    upward, so a classified namespace makes the name rated too.
    """
    name = str(name or "")
    overrides = _current_overrides(overrides)
    namespace = name.split(".", 1)[0]
    return not (tool_risk_is_classified(name, overrides)
                or (namespace != name and tool_risk_is_classified(namespace, overrides)))


def tools_exceeding(
    tool_names,
    max_risk: str | None,
    overrides: dict[str, str] | None = None,
) -> set[str]:
    """Names whose risk exceeds ``max_risk``. Empty set when no ceiling."""
    if not max_risk:
        return set()
    ceiling = risk_rank(max_risk)
    overrides = _current_overrides(overrides)
    return {
        n for n in tool_names
        if risk_rank(tool_risk(n, overrides)) > ceiling
    }


def risk_map(tool_names, overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Risk level for each name, loading the config overrides once.

    The efficient way to classify a whole registry: per-name :func:`tool_risk`
    re-reads config every call (it is uncached), so a UI listing ~1000 tools
    would re-parse config ~1000 times. This reads the overrides a single time
    and reuses them."""
    overrides = _current_overrides(overrides)
    return {n: tool_risk(n, overrides) for n in tool_names}


__all__ = [
    "RISK_LEVELS", "risk_rank", "tool_risk", "tool_risk_is_classified",
    "tools_exceeding", "risk_map", "pinned_overrides",
]
