"""All-settings catalog rows for structured settings: lists, tables and documents.

Kept apart from settings_catalog.py so each group can be extended without
editing the shared catalog. entries receives the catalog's own row and
column types (a plain import would be circular).

Every row here is filled in by choosing, never by typing an identifier or a
block of settings text: tools and people are picked from searchable lists,
voices from the voices each speech service offers, teams from the teams given
a gateway password, kinds of failure from the ones the learning loop has
seen, program locations are checked on the server, a trusted-keys document is
imported from the file a coordinator sent, and a pinned fingerprint is worked
out from an uploaded file (settings_catalog_governance). Each row names the
kernel module that reads it; ``cross_checks`` refuses the combinations that
module would reject.

Not given a row, with the reason:

* ``[client] id``: it is the deployment's data root (every record, the
  activity chain and its keys live under ``tenants/<client>/``) and it places
  the encryption key that seals this page's own settings. Changing it while
  Lightwork runs would switch to an empty data root and a new key, leaving
  every sealed setting and record unreadable. A safe change is an offline
  migration with Lightwork stopped (move the client folder and its keys, check
  every sealed value still opens, then change the id and start again), not a
  page control.
* ``tech_risk_compliance.continuous_evidence.stock_collectors.sources``: each
  source belongs to the workspace's signed continuous-evidence definition,
  rather than this installation-wide overlay. Continuous evidence supplies
  the named account, provider check and control form; independent approval
  and enrollment use the same exact retained definition. Credentials remain
  in sealed Connections. Older deployment source manifests remain separate.
"""
from __future__ import annotations

from .settings_catalog_patterns import HTTPS as _HTTPS

_TEAM = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
_OPTION = r"[A-Za-z_][A-Za-z0-9_]{0,63}"
_PARAM = r"[A-Za-z0-9_.:-]{1,64}"
_PERSONA = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
_FEED_KEY = r"[a-z0-9][a-z0-9._-]{0,127}"
_LOCAL_TARGET = (r"(localhost|127\.0\.0\.1|\[::1\]):[0-9]{1,5}"
                 r"|unix:///[^\s\"'<>]{1,300}")
_WORD = r"[^\s,]{1,256}"
_FEED_FIELDS = ("items", "id", "title", "summary", "published_at", "effective_at", "url",
                "citation", "tags", "agencies", "regimes", "domains", "jurisdiction")
_FIELD_MAP = rf"({'|'.join(_FEED_FIELDS)})=[^=,\s][^=,]{{0,255}}"
_RISKS = (("low", "Low risk"), ("medium", "Medium risk"), ("high", "High risk"),
          ("critical", "Critical risk"))
_CEILING = (("", "No extra limit"), ("low", "Low risk only"),
            ("medium", "Up to medium risk"), ("high", "Up to high risk"))
_LEVEL = (("", "The agent's own setting"), ("observe", "Only watch"),
          ("suggest", "Draft for a person"), ("request", "Act after approval"),
          ("auto", "Act on its own"))

# Pairs the kernel rejects (merged into the catalog's cross-checks).
REQUIRES_NONEMPTY = {
    "audit.unified.custody.siem_enable": "audit.unified.custody.siem_destination_template",
}
REQUIRES_ANY = {
    # Custody copies need somewhere to go.
    "audit.unified.custody.enable": ("audit.unified.custody.checkpoint_enable",
                                     "audit.unified.custody.worm_enable",
                                     "audit.unified.custody.siem_enable"),
}


def _tools(S) -> tuple:  # noqa: N803 -- the catalog's row type
    part = "Tools everywhere"
    return (
        S("security", "allowed_tools", "Only these tools, everywhere",
          "When you choose tools here, agents may use only those, whatever app the work came "
          "from. Leave it empty to allow every tool not blocked below.", "picks", "Security",
          [], "maverick.safety.tool_acl", subgroup=part, choices_from="tools", max_items=500,
          weaker="widen", empty_text="No limit: every tool that is not blocked may be used.",
          warning="Agents will be able to use more tools.",
          aliases="allow list tool access whitelist"),
        S("security", "denied_tools", "Tools blocked everywhere",
          "Agents never use these tools, whatever app the work came from.", "picks",
          "Security", [], "maverick.safety.tool_acl", subgroup=part, choices_from="tools",
          max_items=500, weaker="shrink", empty_text="No tools are blocked everywhere.",
          warning="Agents will be able to use a tool that was blocked.",
          aliases="deny list block tool access blacklist"),
    )


def _people(S, C) -> tuple:  # noqa: N803
    return (
        S("security", "users", "Tools allowed for each person",
          "Limit what agents may do for one person who writes to Lightwork from a chat app. "
          "These rules add to the ones for their app: the stricter rule wins.", "table",
          "Security", {}, "maverick.safety.tool_acl", subgroup="Tools per person",
          row_kind="grid", choices_from="chat_users",
          columns=(
              C("denied_tools", "Blocked tools", "picks", choices_from="tools", max_items=500),
              C("allowed_tools", "Only these tools", "picks", choices_from="tools",
                max_items=500),
              C("max_risk", "Riskiest tools allowed", "select", choices=_CEILING, default=""),
          ),
          row_label="Person", item_label="Person", add_label="Add rules for this person",
          empty_text="Nobody has tool rules of their own yet.",
          empty_hint="Nobody has written to Lightwork from a chat app yet.",
          weaker="acl", warning="Agents will be able to use more tools, or riskier tools, "
                                "for that person.",
          aliases="per user tool access person deny allow"),
    )


def _approvals(S, C) -> tuple:  # noqa: N803
    return (
        S("security", "approvals_required_by_risk", "More approvers for riskier actions",
          "Ask more people to approve actions at the risk levels you choose. A level listed "
          "here never needs fewer people than the number for every action above.", "table",
          "Security", {}, "maverick.safety.dual_control", subgroup="Approvals",
          row_kind="grid", choices=_RISKS, scalar=True,
          columns=(C("people", "People who must approve", "number", minimum=1, maximum=5,
                     integer=True, unit="people", required=True),),
          env=("MAVERICK_APPROVALS_REQUIRED",), row_label="Risk level", item_label="Risk level",
          add_label="Add a risk level", empty_text="Every risk level uses the number above.",
          weaker="floor", warning="Fewer people will need to approve risky actions.",
          aliases="dual control quorum approvers per risk"),
    )


def _gateway(S, C) -> tuple:  # noqa: N803
    part, group = "AI gateway", "AI governance"
    return (
        S("llm_gateway", "team_passwords", "Team passwords for the AI gateway",
          "Give each team its own password, so the gateway knows which team sent a request "
          "and can hold it to that team's limits below. Use at least 24 characters; each "
          "password is stored sealed and never shown again.", "table", group, {},
          "maverick.llm_gateway", subgroup=part, row_kind="named", scalar=True,
          pattern=_TEAM, fixed_keys=("default",),
          item_error="letters, numbers, dots, dashes and underscores, starting with a letter "
                     "or number",
          columns=(C("password", "Password", "secret", required=True, max_length=512,
                     pattern=r"\S{24,512}", item_error="at least 24 characters, no spaces"),),
          row_label="Team", item_label="Team", add_label="Add a team",
          empty_text="No team has its own password yet.", weaker="grow",
          warning="Another team will be able to send AI requests through the gateway.",
          aliases="gateway team token credential"),
        S("llm_gateway.team_budgets", "teams", "Limits for each team",
          "The most each team may use in one budget period. 0 means no limit.", "table",
          group, {}, "maverick.llm_gateway", subgroup=part, key_kind="entries",
          row_kind="grid", choices_from="gateway_teams", fixed_keys=("default",),
          columns=(
              C("max_requests", "Requests", "number", minimum=0, maximum=2000000000,
                integer=True, default=0, unit="requests"),
              C("max_prompt_tokens", "Request tokens", "number", minimum=0,
                maximum=2000000000, integer=True, default=0, unit="tokens"),
              C("max_completion_tokens", "Answer tokens", "number", minimum=0,
                maximum=2000000000, integer=True, default=0, unit="tokens"),
          ),
          row_label="Team", item_label="Team", add_label="Add limits for this team",
          empty_text="No team has limits of its own yet.",
          empty_hint="Give a team a password above first.", weaker="cap",
          warning="A team will be able to send more requests and spend more.",
          aliases="gateway team budget quota"),
    )


def _voice(S, C) -> tuple:  # noqa: N803
    part, group, reader = "Voice", "AI models", "maverick.voice_personas"
    return (
        S("voice", "personas", "Named voices",
          "Voices agents and chat apps can ask for by name, such as a warm voice for "
          "customers.", "table", group, {}, reader, subgroup=part, row_kind="named",
          pattern=_PERSONA,
          item_error="letters, numbers, dashes and underscores, starting with a letter or "
                     "number",
          columns=(C("voice", "Voice", "pick", choices_from="tts_voices", required=True),
                   C("language", "Language", "select", choices_from="persona_languages",
                     default="")),
          row_label="Name", item_label="Voice", add_label="Add a named voice",
          empty_text="No named voices yet.", aliases="persona voice preset tts speech"),
        S("voice", "languages", "Voice for each language",
          "Spoken replies in these languages use the voice you choose.", "table", group, {},
          reader, subgroup=part, row_kind="grid", choices_from="voice_languages",
          columns=(C("voice", "Voice", "pick", choices_from="tts_voices", required=True),),
          row_label="Language", item_label="Language", add_label="Add a language",
          empty_text="Every language uses the default voice.",
          aliases="language voice multilingual speech"),
    )


def _sandbox(S, C) -> tuple:  # noqa: N803
    return (
        S("sandbox", "options", "Options for an outside work area program",
          "Extra options passed to a work area program added from outside Lightwork. Use "
          "the names its maker documents.", "table", "Protected work area", {},
          "maverick.sandbox", subgroup="Work area", row_kind="named", scalar=True,
          pattern=_OPTION, item_error="letters, numbers and underscores, starting with a "
                                      "letter",
          columns=(C("value", "Value", "text", required=True, max_length=256),),
          row_label="Option", item_label="Option", add_label="Add an option",
          empty_text="No options.", weaker="change",
          warning="The outside work area program will run with different options.",
          aliases="sandbox backend options"),
    )


def _plugins(S, C) -> tuple:  # noqa: N803
    part = "Plugin programs"
    words = C("args", "Extra words", "words", pattern=_WORD, max_items=16,
              item_error="a word without spaces or commas")
    return (
        S("plugins", "ts", "TypeScript plugins",
          "Programs on this server that offer tools to agents, written with Lightwork's "
          "TypeScript kit. Each one is started, asked what tools it offers, and checked "
          "before its tools are used.", "rules", "Integrations", [],
          "maverick.ts_plugin_host", subgroup=part,
          columns=(C("program", "Program", "program", required=True),
                   C("file", "Plugin file", "path"), words),
          item_label="Plugin", add_label="Add a plugin", empty_text="No TypeScript plugins.",
          weaker="grow", warning="Lightwork will run another program on this server and "
                                 "offer its tools to agents.",
          aliases="typescript node plugin sdk"),
        S("plugins", "grpc", "Plugins on this server's network",
          "Tool programs that listen on this server only. Lightwork can start the program "
          "itself, or connect to one that is already running.", "rules", "Integrations", [],
          "maverick.grpc_plugin_host", subgroup=part,
          columns=(C("target", "Address on this server", "text", required=True, unique=True,
                     pattern=_LOCAL_TARGET, max_length=320,
                     item_error="localhost with a port, such as localhost:50051, or a "
                                "unix:/// socket"),
                   C("program", "Program to start", "program"), words),
          item_label="Plugin", add_label="Add a plugin", empty_text="No plugins of this kind.",
          weaker="grow", warning="Lightwork will connect to another program and offer its "
                                 "tools to agents.",
          aliases="grpc plugin multi-language"),
    )


def _workforce(S, C) -> tuple:  # noqa: N803
    return (
        S("workforce", "agents", "Independence of each agent",
          "Choose how much an agent or specialist may do by itself at each risk level. Needs "
          "per-agent independence levels on. One that is still being supervised acts "
          "one step more carefully.", "rules", "Safety", [], "maverick.config",
          columns=(C("name", "Agent or specialist", "pick", choices_from="specialists", required=True,
                     unique=True),
                   C("default", "Usually", "select", choices=_LEVEL, default=""),
                   C("low", "Low risk", "select", choices=_LEVEL, default=""),
                   C("medium", "Medium risk", "select", choices=_LEVEL, default=""),
                   C("high", "High risk", "select", choices=_LEVEL, default=""),
                   C("onboarding", "Still supervised", "switch", default=True)),
          item_label="Agent", add_label="Add an agent",
          empty_text="Every agent uses its own setting.", weaker="change",
          warning="Agents may act with a different level of independence.",
          aliases="autonomy levels hired agents"),
    )


def _finance(S, C) -> tuple:  # noqa: N803
    return (
        S("finance_operations", "state_feeds", "Other official rule feeds",
          "Official feeds of new rules, such as a state register, to check along with the "
          "ones above. For a data feed, name where each field is, such as "
          "title=headline.", "rules", "Finance", [], "maverick_dashboard.finance_scheduler",
          subgroup="Regulatory monitoring", max_rows=50,
          columns=(
              C("key", "Short name", "text", required=True, unique=True, pattern=_FEED_KEY,
                item_error="lowercase letters, numbers, dots and dashes"),
              C("name", "Name", "text", required=True, max_length=200),
              C("jurisdiction", "Where it applies", "select", choices_from="jurisdictions",
                required=True),
              C("url", "Address", "text", required=True, pattern=_HTTPS, max_length=300,
                item_error="a secure web address starting with https://"),
              C("format", "Kind of feed", "select", required=True, default="rss",
                choices=(("rss", "RSS news feed"), ("atom", "Atom news feed"),
                         ("json", "Data feed"))),
              C("default_regimes", "Rules it is about", "picks",
                choices_from="regulatory_regimes", max_items=64),
              C("default_domains", "Business areas", "picks",
                choices_from="regulatory_domains", max_items=64),
              C("field_map", "Where each field is", "words", pattern=_FIELD_MAP,
                max_items=32, max_length=300, omit_empty=True,
                item_error="a field name, =, and where it is in the feed, such as "
                           "title=headline"),
          ),
          item_label="Feed", add_label="Add a feed", empty_text="No other feeds.",
          weaker="grow", warning="Lightwork will fetch notices from another address.",
          aliases="state register regulatory feed rss"),
    )


def _governance(S, C) -> tuple:  # noqa: N803
    return (
        S("grc_sync", "response_field_params", "Extra details asked of your GRC system",
          "Names and values sent with each record so your GRC system replies with the "
          "fields Lightwork links to. Your GRC administrator can give you these.", "table",
          "AI governance", {}, "maverick.grc_sync", subgroup="GRC record sync",
          row_kind="named", scalar=True, pattern=_PARAM, max_rows=8,
          item_error="letters, numbers, dots, colons, dashes and underscores",
          columns=(C("value", "Value", "text", required=True, max_length=128),),
          row_label="Name", item_label="Detail", add_label="Add a detail",
          empty_text="Nothing extra is asked for.", aliases="grc response fields params"),
        S("candidate_promotion", "canary_metric", "The trial is judged on",
          "The measure a small trial of a research result is checked on. Your release setup "
          "lists what it measures.", "select", "AI governance", "error_rate",
          "maverick_dashboard.candidate_promotion_composition",
          subgroup="Moving research results into use", choices_from="canary_metrics",
          weaker="change", warning="Trials will be judged on a different measure.",
          aliases="canary metric trial"),
        S("ai_benchmark_exchange", "trust_roots", "Trusted benchmark signing keys",
          "Import the trusted-keys file your benchmark coordinator sends. Each new version "
          "must keep every key it had; keys can only be retired.", "document",
          "AI governance", None, "maverick.ai_benchmark_exchange",
          subgroup="Benchmark sharing", document="benchmark_trust_roots", weaker="grow",
          warning="Benchmark results signed with a newly trusted key will be accepted.",
          aliases="trust roots signing keys rotation"),
        S("governance", "profile", "Governance level",
          "Saving a level applies every setting it stands for, as the installer does. You "
          "see the changes before saving; anything that lowers a protection asks first.",
          "select", "Security", "", "maverick.governance_levels",
          subgroup="Governance level", preview="governance_level",
          choices=(("", "Not chosen"),
                   ("essentials", "Essentials: learn and improve, little else"),
                   ("standard", "Standard: adds signed records and fairness checks"),
                   ("regulated", "Regulated: adds human sign-off and long retention")),
          order=("regulated", "standard", "essentials", ""), weaker="lower",
          warning="The level's settings are applied, which can shorten how long records "
                  "are kept.", aliases="governance profile level essentials regulated"),
    )


def _learning(S, C) -> tuple:  # noqa: N803
    return (
        S("self_harness", "min_support_by_class", "Repeats needed for each kind of mistake",
          "How many times a kind of mistake must happen before Lightwork writes a fix for "
          "it. Kinds not listed use the number above.", "table", "Memory & learning", {},
          "maverick.config", subgroup="Self-improving instructions", row_kind="grid",
          choices_from="failure_classes", scalar=True,
          columns=(C("support", "Repeats", "number", minimum=1, maximum=1000, integer=True,
                     unit="times", required=True),),
          row_label="Kind of mistake", item_label="Kind of mistake",
          add_label="Add a kind of mistake", empty_text="Every kind uses the number above.",
          weaker="floor", warning="Fixes will be written from fewer repeats of a mistake.",
          aliases="min support failure class"),
    )


def _access(S) -> tuple:  # noqa: N803
    grp, custody = "People & access", "Activity record custody"
    return (
        S("audit.unified.custody", "siem_enable", "Copy to your security monitoring service",
          "Also send each activity entry to your security monitoring service at the address "
          "below.", "toggle", grp, False, "maverick.unified_audit_custody", subgroup=custody,
          weaker=False, warning="Copies will stop going to your security monitoring service."),
        S("audit.unified.custody", "siem_destination_template",
          "Security monitoring address for custody copies",
          "The secure web address entries are sent to. Lightwork adds a part of its own for "
          "each workspace; choose where it goes.", "text", grp, "",
          "maverick.unified_audit_custody", subgroup=custody, max_length=2048,
          workspace_segment=True, weaker="change",
          warning="Activity entries will be sent to a different address.",
          aliases="siem destination template custody"),
        S("channels", "public_base_url", "Public address of this server",
          "The address chat services such as Twilio use to reach Lightwork, when it sits "
          "behind a proxy. Leave empty to work it out from each request.", "text",
          "Chat channels", "", "maverick_channels.base", pattern=_HTTPS, max_length=300,
          env=("MAVERICK_PUBLIC_BASE_URL",), aliases="public url base webhook twilio"),
    )


def entries(S, C, Column) -> list:  # noqa: N803 -- the catalog's row and column types
    del Column
    return [*_tools(S), *_people(S, C), *_approvals(S, C), *_gateway(S, C), *_voice(S, C),
            *_sandbox(S, C), *_plugins(S, C), *_workforce(S, C), *_finance(S, C),
            *_governance(S, C), *_learning(S, C), *_access(S)]


def cross_checks(effective: dict, by_id: dict, error: type) -> None:
    """Refuse combinations the readers of these rows reject."""
    _gateway_teams(effective, error)
    careful = effective.get("self_harness.risk_limited") is True
    by_class = effective.get("self_harness.min_support_by_class")
    if careful and isinstance(by_class, dict) and any(
            isinstance(v, int) and v < 3 for v in by_class.values()):
        raise error(f"{by_id['self_harness.min_support_by_class'].label}: the careful "
                    "improvement profile needs at least 3 repeats for each kind.")


def _gateway_teams(effective: dict, error: type) -> None:
    passwords = effective.get("llm_gateway.team_passwords")
    passwords = passwords if isinstance(passwords, dict) else {}
    values = [v for v in passwords.values() if isinstance(v, str) and v]
    shared = effective.get("llm_gateway.gateway_token")
    if len(set(values)) != len(values) or (isinstance(shared, str) and shared in values):
        raise error("Team passwords for the AI gateway: give each team a different password, "
                    "different from the gateway's own password.")
    budgets = effective.get("llm_gateway.team_budgets.teams")
    if not isinstance(budgets, dict) or not budgets:
        return
    try:
        from maverick.config import load_config

        section = (load_config() or {}).get("llm_gateway") or {}
        server_teams = set((section.get("team_tokens") or {}) if isinstance(section, dict)
                           else ())
    except Exception:  # an unreadable configuration names no server-side teams
        server_teams = set()
    missing = [name for name in budgets if name not in passwords and name not in server_teams]
    if missing:
        raise error(f"Limits for each team: “{missing[0]}” has no password any more. Remove "
                    "its limits first, or give it a password.")


__all__ = ["REQUIRES_ANY", "REQUIRES_NONEMPTY", "cross_checks", "entries"]
