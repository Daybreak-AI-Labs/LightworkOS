"""Registry of the product settings an administrator can change in the dashboard.

Every entry names a config table + key that the kernel really reads (the
``reader`` module is checked by ``tests/test_settings_catalog.py``), with the
plain words, control, bounds, default and safety posture the "All settings"
page (``/settings/all``) renders. Values are written to the dashboard settings
overlay through :func:`maverick_dashboard.settings_store.set_catalog_values`;
the kernel's ``load_config`` deep-merges that overlay over config.toml, so a
change applies without editing a file or re-running the installer.

Precedence shown on the page (highest first): deployment settings (an
environment variable named in ``env`` or the operator config overlay) > this
page (dashboard overlay) > the installer's config.toml > the built-in default.

Deliberately NOT in the catalog:

* Developer / operations plumbing with no business meaning: ``[langchain]``,
  ``[coding]``, ``[local_runtime]`` (serving engines). Profiling
  (``[perf.profiling]``), the kernel activity monitor (``[ebpf_monitor]``) and
  the model proxy (``[model_proxy]``) ARE here (settings_catalog_runtime): the
  dashboard starts them with itself when they are on
  (``background_programs``). Only the model proxy's AI service key stays on the
  server (``MAVERICK_PROXY_KEY``), on purpose: a key kept in the settings would
  be loaded into the agent process the proxy protects it from. The research
  rungs (``[self_modify]`` files and tests, ``[adapter_rung]``,
  ``[emergent_protocol]``/``[emergent_codec]``) are in
  settings_catalog_learning.py, off by default and confirmed before they widen;
  the code-experiment on/off switch itself stays on the Learning page.
* Sign-in, workspaces, key custody, record stores, the work queue, remote
  workers, linked servers and trusted update publishers ARE here
  (settings_catalog_access), behind the lock-out guard in
  ``settings_access_guard``: a change that would lock the person saving (or
  saved records) out is refused until its check passes. Still
  deployment-only by design: ``[client] id`` (it also places the encryption
  key; see settings_catalog_structured for why and what a safe change needs),
  ``[deployment] type`` (installer provenance), and the settings that
  name an environment variable or a server program (``*_token_env``,
  ``signal_cli_path``, ``[screening] sdn_path``) until their groups add a
  ``path`` row; the credentials themselves (AI gateway, Stripe, Pushover,
  webhooks) can be set, sealed. Exceptions: the Obsidian notes folder
  (checked to be a folder path), the voice program and model file, picked by
  name from the checked lists of Lightwork's own programs and speech model
  folders, and the privacy modules' key names, as sealed rows restricted to
  their own module's names (settings_catalog_privacy).
* Settings that already have a dedicated control elsewhere: provider keys,
  models, the per-task spending cap, capabilities, the chat
  channels on the Channels page (their sign-in fields and on/off), plugins,
  connections (the account-connection and desktop-return switches are on
  the Connections page, vendor onboarding's connections and owner on its
  setup page), the learning switches, research execution, savings
  assumptions, workspace selection, the security suite's on/off switches.
* Structured policies that need their module's own page to author safely:
  privacy notice publishing targets and the continuous-evidence collector
  sources (see ``settings_catalog_structured``). Tool lists, per-person tool
  rules, per-team gateway passwords and limits, plugin programs, voices,
  agent independence, rule feeds, the benchmark trusted-keys document, the
  governance level and pinned fingerprints ARE here, as controls filled in
  by choosing (settings_catalog_structured).

A ``path`` control names a file or folder on the server; the server checks it
(settings_paths). A row with ``test`` gets a "Test connection" button whose
check (settings_tests) is bounded, SSRF-guarded and never repeats a secret.

Controls beyond single values: ``keys`` (trusted publisher keys, added from an
uploaded or pasted key file and shown only by fingerprint), ``picks`` (several
choices from a long list the page searches), ``fingerprint`` (worked out on
the server from an uploaded file or the installed files, never typed),
``document`` (a document imported from a file and checked by its own rules,
settings_documents), ``table`` (a list
of rows, e.g. usage limits per tool or reviewed tools with a risk level), and
lists/pickers whose options come from live data (``choices_from``: people,
tools, models, connected systems) resolved by the page at request time. A
``table`` with row kind ``grid`` holds one row per chosen option (a chat app,
an AI service, a department) with the ``columns`` described by
:class:`Column`; ``rules`` is an ordered list of such rows (approval rules,
incident report deciders).

Settings a reader keeps but nothing in the running product consults are left
out, so the page never offers a control that changes nothing. ``[energy]``,
``[memory] learning_cache``, ``[tools] speculative``, ``[director] profiles``,
``[logging] crash_only_fsync`` and ``[tui] keys`` are used by the running
product and are in ``settings_catalog_runtime``. Voice unlock is offered, but
its switch is refused until the voice-unlock add-on and a speaker model are
present.
"""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass

from maverick.config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS
from maverick.persona import STYLES, style_choices

GROUPS: tuple[str, ...] = (
    "Work",
    "Safety",
    "Security",
    "AI models",
    "Spending & limits",
    "Memory & learning",
    "Privacy",
    "Data retention",
    "Integrations",
    "Performance",
    "Chat channels",
    "Protected work area",
    "Finance",
    "Security suite",
    "AI governance",
    "People & access",
    "Server & deployment",
)

GROUP_INTROS: dict[str, str] = {
    "Work": "The business details your team keeps alongside tasks and records.",
    "Safety": "How carefully agents are checked before and while they act.",
    "Security": "Protections for records, approvals and outside agents.",
    "AI models": "How agents plan, check their answers and pick models.",
    "Spending & limits": "Limits on money, time and effort for each task and each day.",
    "Memory & learning": "What agents remember and how they learn from past work.",
    "Privacy": "What is recorded, kept or shared about the people who use Lightwork.",
    "Data retention": "How long records are kept before they are removed automatically.",
    "Integrations": "Notifications and connections to other systems.",
    "Performance": "Speed and reliability settings.",
    "Chat channels": "Who may give agents work from each chat app, and how the apps not on the Channels page connect.",
    "Protected work area": "Where agent commands run and what that area is allowed to reach.",
    "Finance": "When money movements stop for a person, which rules apply and how finance monitoring runs.",
    "Security suite": "How the environment hunter gathers security events and how often the hunters run.",
    "AI governance": "Detailed policies for the AI governance modules, the AI gateway and outbound GRC records.",
    "People & access": "How people sign in, who administers Lightwork, and which departments people can use.",
    "Server & deployment": "Where Lightwork keeps its records, how its servers work together, and which update publishers it trusts. Most of these take effect after a restart.",
}

CONTROLS = frozenset({
    "toggle", "select", "number", "text", "list", "secret", "multiselect", "rate",
    "keys", "table", "rules", "path", "picks", "fingerprint", "document",
})
# ``picks``: several choices from a long list the page searches (tools, people).
# ``fingerprint``: a 64-character file fingerprint the server works out from a
# file the person uploads (the file itself is never kept).
# ``document``: a document a person imports from a file; ``document`` names
# the checker in settings_documents that reads, validates and describes it.
_FINGERPRINT_RE = r"[0-9a-f]{64}"

# ``path`` rows name a file or folder on the server; ``path_kind`` says which.
PATH_KINDS = frozenset({"file", "folder"})

COLUMN_KINDS = frozenset({"select", "pick", "picks", "number", "switch", "words", "text",
                          "secret", "color", "path", "program"})
_COLOR = r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})"


@dataclass(frozen=True)
class Column:
    """One column of a ``table`` (row kind ``grid``) or ``rules`` control.

    ``select`` is a short fixed list, ``pick`` one choice from a long list the
    page can search, ``picks`` several such choices in order, ``number`` a
    bounded number, ``switch`` on or off, ``words`` short references
    separated by commas, ``text`` one short value, ``secret`` a password
    for the row: sealed when saved, never shown again, and kept as it is when
    left empty (``rules`` rows are matched by their ``unique`` column), and
    ``color`` a colour chosen with a colour picker (optional ones may be left
    out), ``path`` a file on the server and ``program`` a program on the
    server Lightwork may run (both checked on the server, settings_paths).
    A ``table`` with row kind ``named`` has rows the person names
    (``pattern`` checks the name; ``fixed_keys`` are names it may not use).
    """

    key: str
    label: str
    kind: str
    choices: tuple[tuple[str, str], ...] = ()
    choices_from: str = ""
    required: bool = False
    unique: bool = False  # rules: no two rows may share this value
    default: object = None
    minimum: float | None = None
    maximum: float | None = None
    integer: bool = False
    unit: str = ""
    pattern: str = ""
    max_length: int = 128
    max_items: int = 64
    item_error: str = "a listed option"
    # ``rules`` rows: an empty value is left out of the row (for readers that
    # refuse an empty value but accept the key being absent).
    omit_empty: bool = False


_NO_PARTIAL = object()


@dataclass(frozen=True)
class Setting:
    section: str  # dotted table path, e.g. "safety" or "billing.stripe"
    key: str
    label: str
    help: str
    control: str
    group: str
    default: object
    reader: str  # kernel module that reads this key (checked by tests)
    choices: tuple[tuple[str, str], ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    step: float | None = None
    unit: str = ""
    integer: bool = False
    restart: bool = False
    # Safety posture. ``weaker`` says which direction lowers a protection:
    # toggle -> the boolean that weakens; select -> ``order`` is strongest
    # first; number or rate -> "lower" or "higher"; list -> "grow", "add"
    # (only additions) or "shrink"; text -> "insecure" (a plain http://
    # address) or "change". ``warning`` is the plain
    # consequence the page shows and the confirmation repeats.
    weaker: object = None
    order: tuple[str, ...] = ()
    warning: str = ""
    env: tuple[str, ...] = ()
    max_length: int = 200
    max_items: int = 20
    pattern: str = ""  # optional full-match rule for text/list items
    aliases: str = ""  # extra search words
    # "key" = a fixed key the reader names; "tool" = the key is a registered
    # tool name in a per-tool table (``[rate_limits]``); "entries" = every
    # other key of the table named by ``section`` (a ``table`` control whose
    # rows are the table's own keys, minus ``fixed_keys``).
    key_kind: str = "key"
    # A heading inside the group; each one is its own small form on the page.
    subgroup: str = ""
    # Options filled from live data at request time (see settings_all_page).
    choices_from: str = ""
    # list controls: how one entry is named, hinted and explained when wrong.
    item_label: str = "Address"
    item_hint: str = "https://"
    item_error: str = "a secure web address"
    # list controls: an emptied list stops setting the value here (so the
    # installer's or server's list applies) instead of storing an empty one.
    empty_unset: bool = False
    # number controls: the page shows value / scale in ``unit``; the kernel
    # stores value * scale (e.g. days shown, seconds stored).
    scale: float = 1.0
    # table controls: "rate" (usage limit per tool) or "risk" (reviewed tool
    # with a risk level); ``fixed_keys`` are rows other settings own.
    row_kind: str = ""
    fixed_keys: tuple[str, ...] = ()
    # ``grid`` tables and ``rules``: the columns of each row. A grid's rows are
    # named by an option from ``choices``/``choices_from`` (``row_label`` heads
    # that column); with ``scalar`` the single column's value is stored as the
    # row's value instead of a small table.
    columns: tuple[Column, ...] = ()
    scalar: bool = False
    row_label: str = ""
    add_label: str = ""
    empty_text: str = ""
    empty_hint: str = ""  # shown when there is nothing to add a row for
    # How the page words an empty value when "no limit" would be wrong.
    none_text: str = ""
    # The default when the setting's table already holds other keys (some
    # kernel readers keep older defaults for a partly written table).
    partial_default: object = _NO_PARTIAL
    # ``path`` controls: a "file" or a "folder" on the server. The server
    # checks it exists, stays inside the allowed places, and that Lightwork
    # may read it (``path_writable``: also save into it; ``path_private``: a
    # key file nobody else on the server may read). See settings_paths.
    path_kind: str = ""
    path_writable: bool = False
    path_private: bool = False
    # ``path_new``: a file Lightwork creates itself, so it may not exist yet
    # (its folder must). ``path_scope="data"``: only inside Lightwork's data
    # folder, unless the deployment's own list of places allows more.
    path_new: bool = False
    path_scope: str = ""
    # A "Test connection" button: the name of a check in settings_tests that
    # tries the entered (or saved) value and answers in one plain sentence.
    test: str = ""
    # ``document`` controls: the checker in settings_documents.
    document: str = ""
    # ``text`` controls: the page takes a secure web address and Lightwork adds
    # one path segment per workspace (the kernel's ``{tenant_sha256}``); the
    # page picks where that part goes among the address's parts.
    workspace_segment: bool = False
    # ``table``/``rules`` controls: the most rows the reader accepts (0: the
    # catalog-wide limit).
    max_rows: int = 0
    # ``fingerprint`` controls: besides uploading the file, the server can work
    # the fingerprint out from what is installed here (settings_fingerprints).
    fingerprint_of: str = ""
    # A preview the page shows before saving (``governance_level``: the
    # settings a governance level changes; settings_governance_level.
    # ``approval_checks``: what the recorded approval checks would have
    # needed at the chosen level; approval_threshold_preview. ``retention``:
    # what the next clean-up would delete for a keep period; policy_preview).
    preview: str = ""

    @property
    def id(self) -> str:
        return f"{self.section}.{self.key}"

    @property
    def top(self) -> str:
        return self.section.split(".", 1)[0]

    @property
    def path(self) -> tuple[str, ...]:
        if self.key_kind == "entries":
            return tuple(self.section.split("."))
        return (*self.section.split("."), self.key)

    @property
    def secret(self) -> bool:
        return self.control == "secret"

    @property
    def risky(self) -> bool:
        return bool(self.warning)


_RISK_ORDER = (("low", "Low risk only"), ("medium", "Up to medium risk"),
               ("high", "Up to high risk"), ("none", "No limit"))
_HTTPS = r"https://[^\s\"'<>]{1,300}"

S = Setting
SETTINGS: tuple[Setting, ...] = (
    # ------------------------------------------------------------------ Safety
    S("safety", "profile", "Safety level",
      "How strictly incoming requests, tool use and answers are screened for threats.",
      "select", "Safety", "balanced", "maverick.config",
      choices=(("strict", "Strict: block anything medium risk or above"),
               ("balanced", "Balanced: block high risk and above (recommended)"),
               ("permissive", "Permissive: block only critical threats"),
               ("off", "Off: no screening")),
      weaker=True, order=("strict", "balanced", "permissive", "off"),
      warning="Agents will be screened less strictly, so harmful requests or actions are more likely to get through.",
      aliases="shield threat scanning"),
    S("safety", "block_threshold", "Block threats from",
      "The lowest threat level that stops a request or action.",
      "select", "Safety", "high", "maverick.config",
      choices=(("medium", "Medium and above"), ("high", "High and above"),
               ("critical", "Critical only")),
      weaker=True, order=("medium", "high", "critical"),
      warning="Fewer threats will be blocked."),
    S("safety", "scan_input", "Check incoming requests",
      "Screen every request before an agent starts work on it.",
      "toggle", "Safety", True, "maverick.config", weaker=False,
      warning="Requests will reach agents without being checked for harmful instructions."),
    S("safety", "scan_tool_calls", "Check actions before they run",
      "Screen each tool an agent wants to use before it runs.",
      "toggle", "Safety", True, "maverick.config", weaker=False,
      warning="Agent actions will run without a safety check first."),
    S("safety", "scan_output", "Check answers before they are shown",
      "Screen agent answers for leaked secrets or harmful content.",
      "toggle", "Safety", True, "maverick.config", weaker=False,
      warning="Answers will be shown without being checked for leaked secrets or harmful content."),
    S("practice", "enable", "Offer practice mode",
      "Let people switch to a separate practice workspace to try tasks, specialists and approvals. In "
      "practice nothing is sent, paid or changed outside practice, and nothing counts as real work. AI "
      "answers still cost real money, counted apart from spending limits.", "toggle", "Safety", True,
      "maverick.practice", aliases="practice sandbox try test drive safe mode training demo"),
    S("practice", "daily_spend_cap", "Practice spending cap per person",
      "AI answers in practice come from the real AI service and cost real money. That spending is counted "
      "apart from real spending limits and stops at this amount per person each day (never more than a "
      "real limit that applies). Each task's own budget still applies.", "number", "Safety", 1.0,
      "maverick.practice", minimum=0, maximum=1000, unit="dollars per day", weaker="higher",
      aliases="practice budget practice spending sandbox cost"),
    S("safety", "compartments", "Share blocked threats across a team of agents",
      "When one agent's check blocks a threat, the other agents on the same task are protected from it too.",
      "toggle", "Safety", False, "maverick.config"),
    S("safety", "compartment_unseal", "Who may lift a safety lock",
      "Who can release an agent group that was locked after a blocked threat.",
      "select", "Safety", "human", "maverick.config",
      choices=(("human", "A person only (recommended)"),
               ("both", "A person or the lead agent"),
               ("orchestrator", "The lead agent")),
      weaker=True, order=("human", "both", "orchestrator"),
      warning="An agent, not only a person, will be able to lift a safety lock."),
    S("safety", "goal_risk_require_human", "Ask a person before starting risky-looking tasks",
      "Lightwork reads each task's wording before it starts (words such as pay, delete, "
      "deploy, passwords, all customers or production). Tasks that look risky enough wait "
      "on the Approvals page until a person approves them, and do not start if nobody does "
      "in time. It only reads the words: every action is still checked on its own once the "
      "task is running.",
      "select", "Safety", "never", "maverick.safety.goal_risk",
      choices=(("medium", "Tasks that look medium or high risk"),
               ("high", "Tasks that look high risk"),
               ("never", "Never (default)")),
      weaker=True, order=("medium", "high", "never"),
      env=("MAVERICK_GOAL_RISK_REQUIRE_HUMAN",),
      warning="Fewer tasks will wait for a person before they start.",
      aliases="goal risk approval before start"),
    S("safety", "goal_risk_floor", "Treat every task as at least",
      "The lowest risk level any task is given, whatever its wording. Combined with the "
      "setting above, this can make every task wait for a person.",
      "select", "Safety", "low", "maverick.safety.goal_risk",
      choices=(("high", "High risk"), ("medium", "Medium risk"),
               ("low", "As its wording suggests (default)")),
      weaker=True, order=("high", "medium", "low"),
      env=("MAVERICK_GOAL_RISK_FLOOR",),
      warning="Tasks will be treated as lower risk than before, so fewer may wait for a person."),
    S("skills", "require_signed", "Only allow signed skills",
      "Refuse saved procedures that are not signed by a trusted publisher.",
      "toggle", "Safety", False, "maverick.config", weaker=False,
      warning="Unsigned skills from unknown publishers will be accepted again."),
    S("skills", "builtin", "Use the built-in skills library",
      "Let agents recall Lightwork's own library of proven procedures.",
      "toggle", "Safety", True, "maverick.config"),
    S("ifc", "mode", "Sensitive data leaving Lightwork",
      "What happens when labelled sensitive data is about to reach an outside service.",
      "select", "Safety", "audit", "maverick.config",
      choices=(("block", "Block it"), ("approve", "Ask a person to approve"),
               ("audit", "Allow it and record it"), ("off", "Do nothing")),
      weaker=True, order=("block", "approve", "audit", "off"), env=("MAVERICK_IFC_MODE",),
      warning="Sensitive data will be able to reach outside services with less oversight.",
      aliases="information flow"),
    S("ifc", "scope", "When data counts as seen",
      "Whether an agent that has read sensitive data is treated as carrying it, or only when the data appears word for word.",
      "select", "Safety", "context", "maverick.config",
      choices=(("context", "Once an agent has read it (recommended)"),
               ("explicit", "Only when it appears word for word")),
      weaker=True, order=("context", "explicit"),
      warning="Sensitive data that an agent rephrases will no longer be caught."),
    S("codebase", "default_protect", "Protection for new code repositories",
      "What happens when work on a newly added repository tries to send its code elsewhere.",
      "select", "Safety", "block", "maverick.config",
      choices=(("block", "Block it"), ("approve", "Ask a person to approve"),
               ("audit", "Allow it and record it")),
      weaker=True, order=("block", "approve", "audit"),
      warning="Code from new repositories will be able to leave with less oversight."),
    S("autonomy", "enable", "Extra checks on uncertain work",
      "When agents disagree or are unsure, double-check the answer and tighten what risky tools may do.",
      "toggle", "Safety", False, "maverick.autonomy", env=("MAVERICK_AUTONOMY_GATE",)),
    S("autonomy", "confirm_plan", "Show the plan before acting",
      "Before a task's first action that could reach outside Lightwork (a message, a payment, a change in a "
      "connected system or a command), show its plan, first action and spending cap in Approvals and wait. "
      "Approve to carry on, reject to stop before anything runs, or send it back with what to change.",
      "toggle", "Safety", False, "maverick.autonomy",
      aliases="plan before acting confirm plan review plan approve plan"),
    S("autonomy", "headless_assume", "Carry on when nobody can answer",
      "When no person is available to answer a question, let the agent make a reasonable assumption instead of waiting.",
      "toggle", "Safety", False, "maverick.autonomy", env=("MAVERICK_AUTONOMOUS",), weaker=True,
      warning="Agents will act on their own assumptions instead of waiting for a person."),
    S("earned_autonomy", "enable", "Track which actions agents predict well",
      "Record how accurately agents predict the results of their actions, as evidence for trusting them more.",
      "toggle", "Safety", False, "maverick.config"),
    S("earned_autonomy", "auto_graduate", "Mark qualifying prediction evidence",
      "Mark action types whose predictions meet the evidence thresholds. Evidence does not grant approval.",
      "toggle", "Safety", False, "maverick.config"),
    S("earned_autonomy", "max_auto_risk", "Highest risk to evaluate for evidence",
      "The highest risk level considered when assessing prediction evidence.",
      "select", "Safety", "medium", "maverick.config",
      choices=(("low", "Low risk"), ("medium", "Medium risk"), ("high", "High risk"))),
    S("earned_autonomy", "require_reversible", "Only actions that can be undone",
      "Only count evidence from actions with a demonstrated undo.",
      "toggle", "Safety", True, "maverick.config"),
    S("workforce", "levels", "Per-agent independence levels",
      "Let each hired agent act on its own for the risk levels you choose, instead of only drafting for a person to commit.",
      "toggle", "Safety", False, "maverick.config", weaker=True,
      warning="Agents you have set to act on their own will commit work without a person."),
    S("workforce", "auto_graduate", "Promote agents automatically",
      "Move agents out of their supervised first weeks automatically once their record allows it.",
      "toggle", "Safety", False, "maverick.config", weaker=True,
      warning="Agents will leave supervision without a person deciding."),
    S("workforce", "data_grounding", "Check agent work against your records",
      "Compare agent claims with your connected systems before trusting them.",
      "toggle", "Safety", True, "maverick.config", weaker=False,
      warning="Agent claims will no longer be checked against your connected systems."),
    S("self_learning", "create_tools", "Let agents build new tools",
      "Agents may write and run new tools for themselves. Each new tool still needs approval.",
      "toggle", "Safety", False, "maverick.config", weaker=True,
      warning="Agents will be able to write new programs for themselves."),
    S("self_learning", "allow_mcp_acquisition", "Legacy MCP acquisition setting",
      "Catalog MCP acquisition is currently unavailable even when this setting is enabled.",
      "toggle", "Safety", False, "maverick.config", weaker=True,
      env=("MAVERICK_ALLOW_MCP_ACQUISITION",),
      warning="This setting has no effect until catalog publisher authentication is available."),
    S("self_learning", "allow_provider_egress", "Let learning send work to other AI services",
      "Extra learning steps may send task text to a different configured AI service.",
      "toggle", "Safety", False, "maverick.config", weaker=True,
      warning="Task text may be sent to additional AI services for learning."),
    S("self_learning", "max_acquisitions", "New skills or tools per task",
      "The most skills or tools an agent may add while working on one task.",
      "number", "Safety", 5, "maverick.config", minimum=1, maximum=50, integer=True,
      unit="per task"),
    S("harness_refine", "enable", "Let agents suggest changes to their instructions",
      "After a failure, agents may propose an improvement to their own working instructions.",
      "toggle", "Safety", False, "maverick.config", env=("MAVERICK_HARNESS_REFINE",)),
    S("harness_refine", "require_approval", "Instruction changes need approval",
      "A person must approve every suggested change to agent instructions before it applies.",
      "toggle", "Safety", True, "maverick.config", weaker=False,
      warning="Agents will be able to change their own instructions without a person approving."),
    S("repl", "enable", "Let agents run code step by step",
      "Agents may write and run code in the protected work area, with every step recorded.",
      "toggle", "Safety", False, "maverick.config", weaker=True, env=("MAVERICK_REPL",),
      warning="Agents will be able to run code they write."),
    S("repl", "max_seconds", "Time limit for each code step",
      "How long one step of agent code may run.",
      "number", "Safety", 30.0, "maverick.config", minimum=1, maximum=600, unit="seconds"),
    S("sandbox", "timeout", "Time limit for each command",
      "How long a single command in the protected work area may run.",
      "number", "Safety", 60, "maverick.config", minimum=5, maximum=3600, integer=True,
      unit="seconds"),
    S("a2a", "max_risk", "What other agents may ask for",
      "The riskiest tools a task sent by another agent may use.",
      "select", "Safety", "medium", "maverick.a2a_tasks", choices=_RISK_ORDER,
      weaker=True, order=("low", "medium", "high", "none"), env=("MAVERICK_A2A_MAX_RISK",),
      warning="Tasks sent by other agents will be able to use riskier tools."),

    # ---------------------------------------------------------------- Security
    S("audit", "sign", "Sign the activity record",
      "Seal each activity record entry so any later change can be detected.",
      "toggle", "Security", True, "maverick.audit.writer", weaker=False, restart=True,
      env=("MAVERICK_AUDIT_SIGN",),
      warning="New activity records will not be sealed, so changes to them could go unnoticed."),
    S("encryption", "at_rest", "Encrypt stored data",
      "Keep sensitive records and settings encrypted on disk.",
      "toggle", "Security", True, "maverick.crypto_at_rest", weaker=False,
      env=("MAVERICK_ENCRYPT_AT_REST",),
      warning="New records will be stored without encryption."),
    S("enterprise", "mode", "Enterprise protections",
      "Turn on the stricter protections expected in regulated organisations, such as required encryption and governed actions.",
      "toggle", "Security", False, "maverick.enterprise", weaker=False, env=("MAVERICK_ENTERPRISE",),
      warning="The stricter enterprise protections will stop applying."),
    S("security", "secure_defaults", "Secure defaults",
      "Keep protections such as record signing and encryption on unless they are turned off one by one.",
      "toggle", "Security", True, "maverick.security_defaults", weaker=False,
      env=("MAVERICK_SECURE_DEFAULT",),
      warning="Record signing, encryption and other protections that rely on this will turn off."),
    S("security", "approvals_required", "People needed to approve risky actions",
      "How many different people must approve a high-risk action. One means a single approver; "
      "whether that may be the person who asked is set by Who approves a risky action someone "
      "asked for. With two or more, the person who asked doesn't count unless people may approve "
      "their own requests.",
      "number", "Security", 1, "maverick.safety.dual_control", minimum=1, maximum=5, integer=True,
      unit="people", weaker="lower", env=("MAVERICK_APPROVALS_REQUIRED",),
      warning="Fewer people will need to approve risky actions."),
    S("security", "allow_self_approval", "Let people approve their own requests",
      "When two or more people must approve, let the person who asked count as one of them. "
      "With a single approver, Who approves a risky action someone asked for decides instead.",
      "toggle", "Security", False, "maverick.safety.dual_control", weaker=True,
      env=("MAVERICK_ALLOW_SELF_APPROVAL",),
      warning="The person who asked will count as one of the approvers."),
    S("security", "auto_fix", "Fix unsafe settings automatically",
      "When the security check finds a risky setting, correct it automatically.",
      "toggle", "Security", False, "maverick.remediation", env=("MAVERICK_SECURITY_AUTOFIX",)),
    S("agent_trust", "enforce", "Only trust registered outside agents",
      "Refuse outside agents that are not on your trusted list.",
      "toggle", "Security", False, "maverick.agent_trust", weaker=False,
      warning="Outside agents that are not on your trusted list will be able to connect."),
    S("agent_trust", "require_signed", "Require outside agents to sign",
      "Refuse outside agents that only present a shared password instead of a signature.",
      "toggle", "Security", False, "maverick.federation", weaker=False,
      env=("MAVERICK_FEDERATION_REQUIRE_SIGNED",),
      warning="Outside agents will be able to connect with a shared password alone."),
    S("external_agents", "require_signed", "Outside agents must use their strongest credential",
      "An outside agent registered with a signature key must always use it.",
      "toggle", "Security", False, "maverick.config", weaker=False,
      warning="Outside agents will be able to sign in with a weaker credential."),
    S("external_agents", "mint_approval", "Approve new outside-agent credentials",
      "A person must approve before a new sign-in credential is issued to an outside agent.",
      "toggle", "Security", False, "maverick.config", weaker=False,
      warning="Credentials for outside agents will be issued without a person approving."),
    S("governed_connectors", "enable", "Govern writes to your business systems",
      "Changes to connected business systems are previewed, approved and recorded with a way to undo them.",
      "toggle", "Security", False, "maverick.config", weaker=False,
      env=("MAVERICK_GOVERNED_CONNECTORS",),
      warning="Changes to connected business systems will no longer go through preview and approval."),
    S("governed_connectors", "restore_points", "Save a restore point before changes",
      "Read the current record before changing it so the change can be undone.",
      "toggle", "Security", True, "maverick.config", weaker=False,
      env=("MAVERICK_GOVERNED_RESTORE_POINTS",),
      warning="Changes to business systems will not be undoable, so each one will need a person."),
    S("residency", "region", "Where data must be stored",
      "The region your data is declared to live in, for example EU or US. Leave empty for no declared region.",
      "text", "Security", "", "maverick.residency", max_length=16, pattern=r"[A-Za-z0-9-]{0,16}",
      env=("MAVERICK_DATA_REGION",)),
    S("residency", "strict", "Enforce the storage region",
      "Refuse to store data outside the declared region.",
      "toggle", "Security", False, "maverick.residency", weaker=False, restart=True,
      env=("MAVERICK_RESIDENCY_STRICT",),
      warning="Data may be stored outside the declared region."),
    S("a2a", "enabled", "Let other agents send tasks here",
      "Other agents you approve may hand tasks to Lightwork. Set their password and limits under Requests from other agents, or issue an individual key in External agents. Restart the service after changing this switch.",
      "toggle", "Security", False, "maverick.a2a", weaker=True, restart=True, env=("MAVERICK_A2A_ENABLED",),
      warning="Other agents on the network will be able to send tasks that spend your budget."),

    # --------------------------------------------------------------- AI models
    S("routing", "cost_aware", "Pick the cheapest capable model",
      "Use the least expensive model that can do each task well.",
      "toggle", "AI models", False, "maverick.cost.router"),
    S("routing", "verify_ensemble", "Double-check with a second AI service",
      "Confirm important answers with models from more than one provider.",
      "toggle", "AI models", False, "maverick.verifier"),
    S("routing", "energy_aware", "Prefer lower-energy models",
      "Favour models that use less energy when they can do the task.",
      "toggle", "AI models", False, "maverick.energy_aware_router"),
    S("routing", "allowed_providers", "AI services agents may use for these choices",
      "Limit automatic model choices to these AI services. Leave empty to allow any service you have connected.",
      "multiselect", "AI models", [], "maverick.cost.router",
      choices=(("anthropic", "Anthropic (Claude)"), ("openai", "OpenAI"),
               ("gemini", "Google Gemini"), ("openrouter", "OpenRouter"),
               ("moonshot", "Moonshot"), ("deepseek", "DeepSeek"), ("xai", "xAI (Grok)"),
               ("ollama", "Ollama (self-hosted)"), ("vllm", "Self-hosted compatible service"),
               ("bedrock", "Amazon Bedrock"), ("azure", "Microsoft Azure"),
               ("vertex", "Google Cloud Vertex AI"))),
    S("verification", "risk_proportional", "Check risky work more carefully",
      "Spend more checking effort on work with bigger consequences.",
      "toggle", "AI models", False, "maverick.agent"),
    S("verification", "verify_chat_answers", "Check chat answers",
      "Verify answers in Chat before they are shown.",
      "toggle", "AI models", False, "maverick.agent"),
    S("chat", "stream_answers", "Show chat answers as they are written",
      "Show a live preview of each answer while it is being written.",
      "toggle", "AI models", True, "maverick.agent"),
    S("planning", "mode", "How agents plan",
      "Plan once, compare several plans before starting, or let Lightwork choose from past results.",
      "select", "AI models", "", "maverick.tree_of_thought",
      choices=(("", "Plan once (default)"), ("tree_of_thought", "Compare several plans first"),
               ("auto", "Choose automatically from past results")),
      env=("MAVERICK_TREE_OF_THOUGHT",)),
    S("search", "enable", "Draft several answers and keep the best",
      "Write a few candidate answers and keep the one the checker rates highest.",
      "toggle", "AI models", False, "maverick.config"),
    S("search", "n", "Number of candidate answers",
      "How many candidate answers to write when the option above is on.",
      "number", "AI models", 3, "maverick.config", minimum=1, maximum=10, integer=True,
      unit="answers"),
    S("adaptive_compute", "enable", "Spend effort where it is needed",
      "Use fewer parallel attempts when agents are confident and more when they are unsure.",
      "toggle", "AI models", False, "maverick.config"),
    S("effort", "enabled", "Adjust thinking effort per task",
      "Let Lightwork choose how much reasoning effort each task needs.",
      "toggle", "AI models", False, "maverick.effort", env=("MAVERICK_EFFORT_ENABLED",)),
    S("context", "compaction_strategy", "How long conversations are shortened",
      "The method used to shorten long conversations so they fit. Written summaries use "
      "extra AI calls within the task's spending limit, reuse the earlier summary in the same "
      "run, and add older turns at the configured summary interval. Their style learns from "
      "agents that returned a complete answer and continued turns; this does not measure "
      "answer accuracy or whether the team's final review accepted it.",
      "select", "AI models", "", "maverick.compaction.strategies",
      choices=(("", "Keep recent turns and trim long tool results (default)"),
               ("learned", "Written summary that learns from completed answers"),
               ("multimodal", "Replace large images and audio with short notes"),
               ("streaming", "Running summary for very long chats"),
               ("graph", "Summary of people, things and how they relate")),
      env=("MAVERICK_COMPACTION_STRATEGY",)),
    S("context", "compact", "Keep the most useful older turns",
      "Keep the most relevant older parts of long conversations instead of only the latest few.",
      "toggle", "AI models", False, "maverick.context_compactor"),
    S("context", "model_scaled", "Size memory to each model",
      "Fit conversation history to how much each model can read at once.",
      "toggle", "AI models", True, "maverick.context_scaling"),
    S("speculative", "enable", "Use a quick model for predictable steps",
      "Draft predictable steps with a cheaper model and keep the main model for new situations.",
      "toggle", "AI models", False, "maverick.config"),
    S("persona", "name", "Assistant name",
      "The name your agents use for themselves.",
      "text", "AI models", "", "maverick.persona", max_length=60,
      pattern=r"[^\n\r<>{}]{0,60}"),
    S("persona", "style", "Writing style",
      "Voice and detail in replies. " + " ".join(f"{label}: {STYLES[key]}"
          for key, label in style_choices() if key),
      "select", "AI models", "", "maverick.persona",
      choices=style_choices(), aliases="writing tone personality voice"),
    S("voice", "dashboard_commands", "Voice input in chat",
      "Show a microphone button in Chat that turns spoken requests into text.",
      "toggle", "AI models", True, "maverick_dashboard.voice_policy", env=("MAVERICK_VOICE_COMMANDS",)),
    S("domains", "discipline", "Department working rules",
      "Give each department's agents and specialists their department's working rules.",
      "toggle", "AI models", True, "maverick.config"),

    # ------------------------------------------------------- Spending & limits
    S("budget", "max_wall_seconds", "Time limit per task",
      "The longest a single task may run.",
      "number", "Spending & limits", None, "maverick.budget", minimum=60, maximum=604800,
      unit="seconds"),
    S("budget", "max_tool_calls", "Actions per task",
      "The most tool uses allowed in a single task.",
      "number", "Spending & limits", None, "maverick.budget", minimum=1, maximum=100000,
      integer=True, unit="actions", weaker="higher",
      warning="A single task will be able to take more actions before it is stopped."),
    S("budget", "max_output_tokens", "Words written per task",
      "The most text, in tokens (about three quarters of a word each), agents may write in one task.",
      "number", "Spending & limits", None, "maverick.budget", minimum=1000,
      maximum=100000000, integer=True, unit="tokens"),
    S("budget", "self_tuning", "Suggest a spending limit from past tasks",
      "Let Lightwork use past costs for similar tasks to set a task spending limit when you have not set one. Turn this on only if you want a learned limit; your own limit always wins.",
      "toggle", "Spending & limits", False, "maverick.self_tuning_budget",
      env=("MAVERICK_BUDGET_SELF_TUNING",)),
    S("budget", "strict_pricing", "Require known prices",
      "Stop a task when a model's price is unknown instead of guessing its cost.",
      "toggle", "Spending & limits", BOOLEAN_SETTINGS["budget.strict_pricing"].default,
      "maverick.budget", weaker=False, env=BOOLEAN_SETTINGS["budget.strict_pricing"].dashboard_env,
      warning="Spending on models with unknown prices will be estimated, so costs may be under-counted."),
    S("quotas", "enforce", "Daily limits per person",
      "Enforce the daily limits below for each person.",
      "toggle", "Spending & limits", False, "maverick.quotas", env=("MAVERICK_QUOTA_ENFORCE",),
      weaker=False,
      warning="People will be able to spend and use as much as they like each day."),
    S("quotas", "max_dollars_per_day", "Daily spending limit per person",
      "The most one person's tasks may spend in a day. Zero means no limit.",
      "number", "Spending & limits", 0.0, "maverick.quotas", minimum=0, maximum=1000000,
      unit="dollars per day", env=("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY",)),
    S("quotas", "max_tokens_per_day", "Daily text limit per person",
      "The most text, in tokens, one person's tasks may use in a day. Zero means no limit.",
      "number", "Spending & limits", 0, "maverick.quotas", minimum=0, maximum=10000000000,
      integer=True, unit="tokens per day", env=("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY",)),
    S("spending_limits", "alert_at", "Spending limit alerts",
      "Percentages of a workspace or per-person spending limit at which administrators, and the "
      "person for their own limit, get an in-app alert. Each one alerts once per day or month. "
      "Leave the list empty for no alerts; the limits still stop paid work at 100 percent.",
      "list", "Spending & limits", [50, 75, 100], "maverick.spending_alerts",
      max_items=10, max_length=4, item_label="Percent", item_hint="75",
      item_error="a whole number from 1 to 100"),
    S("spending_limits", "typical_cost_min_runs", "Past tasks needed for a typical cost",
      "How many finished tasks an agent or specialist needs in this workspace before Lightwork "
      "shows what its past tasks usually cost beside the task form. Below this, it says there "
      "are not enough past tasks yet. The range is recorded history, never a prediction.",
      "number", "Spending & limits", 10, "maverick.typical_cost", minimum=2, maximum=1000,
      integer=True, unit="finished tasks"),
    S("swarm", "max_total_spawns", "Helper agents per task",
      "The most helper agents one task may create.",
      "number", "Spending & limits", 64, "maverick.config", minimum=1, maximum=1000,
      integer=True, unit="agents", env=("MAVERICK_MAX_TOTAL_SPAWNS",)),
    S("swarm", "max_concurrent_model_calls", "Helpers thinking at once",
      "How many helper agents may wait on an AI service at the same time. Zero means no limit.",
      "number", "Spending & limits", 0, "maverick.config", minimum=0, maximum=256,
      integer=True, unit="at once"),
    S("credit", "max_children", "Largest team to score",
      "Skip scoring each agent's contribution in teams larger than this.",
      "number", "Spending & limits", 6, "maverick.config", minimum=2, maximum=64,
      integer=True, unit="agents"),
    S("commerce", "enable", "Shopping and store tools",
      "Give shopping and store agents their tools: search, compare, build carts and suggest store changes for approval.",
      "toggle", "Spending & limits", False, "maverick.config"),
    S("commerce", "max_session_spend", "Cart limit per session",
      "The most a single shopping session's cart may add up to.",
      "number", "Spending & limits", 500.0, "maverick.config", minimum=1, maximum=1000000,
      unit="store currency"),
    S("commerce", "max_line_quantity", "Quantity limit per item",
      "The most of one item a cart may hold.",
      "number", "Spending & limits", 10, "maverick.config", minimum=1, maximum=10000,
      integer=True, unit="items"),
    S("commerce", "max_cart_lines", "Different items per cart",
      "The most different items one cart may hold.",
      "number", "Spending & limits", 25, "maverick.config", minimum=1, maximum=1000,
      integer=True, unit="items"),
    S("billing.stripe", "enable", "Collect payments with Stripe",
      "Turn usage invoices into real Stripe charges with the Stripe keys set below or on the server.",
      "toggle", "Spending & limits", False, "maverick.billing_stripe", env=("MAVERICK_STRIPE_ENABLE",)),
    S("billing.stripe", "bill_metered_usage", "Charge for model usage",
      "Also charge customers for their model usage, not only the platform fee.",
      "toggle", "Spending & limits", False, "maverick.billing_stripe",
      env=("MAVERICK_STRIPE_BILL_METERED",)),
    S("billing.stripe", "currency", "Billing currency",
      "The three-letter currency code for charges, for example usd or eur.",
      "text", "Spending & limits", "usd", "maverick.config", max_length=3,
      pattern=r"[A-Za-z]{3}"),

    # ------------------------------------------------------- Memory & learning
    S("memory", "fact_tags", "Organize shared facts with tags",
      "Let operators add metadata tags to shared facts and filter by those tags. Tags never grant access.",
      "toggle", "Memory & learning", False, "maverick.fact_revision"),
    S("memory", "temporal", "Keep the history of every fact",
      "Remember what was believed on each date instead of only the latest value.",
      "toggle", "Memory & learning", False, "maverick.config", env=("MAVERICK_TEMPORAL_MEMORY",)),
    S("memory_guard", "enable", "Screen what agents remember",
      "Check everything written to memory for planted instructions and label where it came from.",
      "toggle", "Memory & learning", False, "maverick.config", weaker=False,
      env=("MAVERICK_MEMORY_GUARD",),
      warning="Memory will no longer be screened for planted instructions."),
    S("memory_guard", "min_recall_trust", "Memory agents may rely on",
      "The least trusted kind of memory agents may use while working.",
      "select", "Memory & learning", 1, "maverick.config",
      choices=(("3", "Only what people entered"), ("2", "Also what Lightwork learned"),
               ("1", "Also agents' own notes (default)"), ("0", "Everything, including outside content")),
      weaker=True, order=("3", "2", "1", "0"),
      warning="Agents will rely on less trusted memory, including content from outside sources."),
    S("domains", "memory", "Share department lessons",
      "Give agents and specialists the lessons their department has learned.",
      "toggle", "Memory & learning", True, "maverick.config"),
    S("cortex", "enable", "Company memory",
      "One governed place to look up knowledge, skills, lessons and past decisions, with every look-up recorded.",
      "toggle", "Memory & learning", True, "maverick.cortex"),
    S("knowledge", "reindex_jobs", "Bounded search index rebuilds",
      "Review collection size and limits, track rebuild progress, and cancel before publication. Paid adapters require verified cost admission.",
      "toggle", "Memory & learning", False, "maverick.knowledge_reindex_jobs"),
    S("knowledge", "reindex_max_chunks", "Maximum passages in a rebuild",
      "Refuse a rebuild above this collection size.", "number", "Memory & learning", 10000, "maverick.knowledge_reindex_jobs", minimum=1, maximum=100000, integer=True),
    S("knowledge", "reindex_max_wall_seconds", "Rebuild time limit in seconds",
      "Stop at a safe boundary after reaching this elapsed time; a batch already running finishes first.", "number", "Memory & learning", 300, "maverick.knowledge_reindex_jobs", minimum=1, maximum=3600, integer=True),
    S("knowledge", "reindex_max_dollars", "Rebuild provider cost limit",
      "Maximum USD reservation at reviewed standard embedding rates. Each batch is admitted before sending; uncertain paid requests are never retried automatically. Provider invoices remain authoritative.",
      "number", "Memory & learning", 5.0, "maverick.knowledge_reindex_jobs", minimum=0, maximum=1000, unit="USD"),
    S("knowledge", "enable", "Document search for agents",
      "Let agents search your uploaded documents by meaning and cite them.",
      "toggle", "Memory & learning", False, "maverick.config"),
    S("session_tree", "enable", "Keep the family tree of runs",
      "Record which runs were copied from which, so alternatives can be compared.",
      "toggle", "Memory & learning", True, "maverick.config"),
    S("calibration", "enforce", "Pause learning when the checker drifts",
      "Stop learning from results if the answer checker is no longer reliable.",
      "toggle", "Memory & learning", False, "maverick.config", weaker=False,
      warning="Learning will continue even when the answer checker is unreliable."),
    S("calibration", "min_samples", "Checked results before judging the checker",
      "How many checked results are needed before the checker's reliability is judged.",
      "number", "Memory & learning", 20, "maverick.config", minimum=1, maximum=100000,
      integer=True, unit="results"),
    S("assessments", "learn", "Learn from past assessments",
      "Suggest answers and precedents from your organisation's own past assessments. A person still reviews them.",
      "toggle", "Memory & learning", True, "maverick.config", env=("MAVERICK_ASSESS_LEARN",)),
    S("assessments", "doc_discovery", "Find related documents for assessments",
      "Search your connected document sources for contracts and agreements related to an assessment.",
      "toggle", "Memory & learning", True, "maverick.config", env=("MAVERICK_ASSESS_DISCOVERY",)),
    S("fairness_monitor", "enable", "Watch decisions for unfair outcomes",
      "Continuously compare decision outcomes between groups and warn when one falls behind.",
      "toggle", "Memory & learning", False, "maverick.config", env=("MAVERICK_FAIRNESS_MONITOR",)),
    S("fairness_monitor", "threshold", "Fairness warning level",
      "Warn when a group's approval rate falls below this share of the best group's rate.",
      "number", "Memory & learning", 0.8, "maverick.config", minimum=0.5, maximum=1.0,
      step=0.05, unit="share"),
    S("dreaming", "llm_consolidation", "Summarise lessons with an AI model",
      "Use a model to write up the lessons found in past work, instead of only simple pattern matching.",
      "toggle", "Memory & learning", False, "maverick.config"),

    # ----------------------------------------------------------------- Privacy
    S("privacy", "anonymous", "Anonymous records",
      "Leave names and personal details out of logs and activity records.",
      "toggle", "Privacy", False, "maverick.privacy", weaker=False, env=("MAVERICK_ANON",),
      warning="Names and personal details will be written to logs and records again."),
    S("telemetry", "donate_trajectories", "Share anonymous work patterns",
      "Contribute outline information about completed work, never its text, to improve models.",
      "toggle", "Privacy", False, "maverick.donation", weaker=True,
      warning="Outline information about your completed work will be shared."),
    S("analytics", "mcp_client_language", "Count which programming languages connect",
      "Keep a local count of the programming languages used by connected tools. Nothing leaves this computer.",
      "toggle", "Privacy", False, "maverick.mcp_analytics", env=("MAVERICK_MCP_ANALYTICS",)),
    S("analytics", "usability_survey", "Ask people how easy Lightwork is to use",
      "Offer each signed-in person a 10-question ease-of-use survey at most once a quarter, and one "
      "question after a few common tasks. One click hides it for the quarter. Answers stay on this "
      "server, are reported by the role people choose, never by name, and are never sent anywhere. "
      "Results are on People > Ease-of-use results.",
      "toggle", "Privacy", False, "maverick.usability_survey"),
    S("analytics", "web_vitals", "Measure page speed for real visitors",
      "Time how fast pages load, respond and stay steady (LCP, INP and CLS) in a sample of real visits, "
      "and show the 75th percentile for each page on phones and computers over the last 28 days. "
      "Only counts per page are kept: no names, addresses or browsing history. Nothing is sent anywhere. "
      "Results are on Settings > Page speed.",
      "toggle", "Privacy", False, "maverick.web_vitals"),
    S("analytics", "web_vitals_sample_rate", "Share of visits measured for page speed",
      "How many visits are measured when page speed measurement is on, from 0 (none) to 1 (every visit). "
      "0.5 measures about every other visit. More visits give results sooner; each one measured sends three numbers.",
      "number", "Privacy", 0.5, "maverick.web_vitals", minimum=0, maximum=1, step=0.05, unit="share"),
    S("analytics", "usage_measures", "Count first results and AI suggestions, without names",
      "Count whether new people see a finished result of their own task in their first session, and how often "
      "AI suggestions are shown, used or dismissed. People and suggestions are kept only as one-way codes, and "
      "nothing is sent anywhere. Results are on People > Ease-of-use results.",
      "toggle", "Privacy", False, "maverick.usage_measures"),
    S("immune", "twin_record", "Record tool results for replay",
      "Keep sealed copies of every task's tool results so the task can be replayed to test changes.",
      "toggle", "Privacy", False, "maverick.config", weaker=True,
      warning="Copies of tool results, which may include personal data, will be kept."),
    S("immune", "canaries", "Test reviewers with practice approvals",
      "Allow administrators to plant known-flawed practice approvals to measure whether reviewers catch them.",
      "toggle", "Privacy", False, "maverick.config"),
    S("attachments", "allow_any_mime", "Accept any kind of attachment",
      "Accept attachments of any declared type. Programs and archives are always refused.",
      "toggle", "Privacy", False, "maverick.attachments", weaker=True,
      warning="Unusual file types will be accepted as attachments."),
    S("attachments", "transcribe_media", "Transcribe audio and video",
      "Turn speech in attached audio and video into text for the task.",
      "toggle", "Privacy", True, "maverick.attachments", env=("MAVERICK_ATTACH_TRANSCRIBE",)),
    S("attachments", "extract_text", "Read text from documents",
      "Pull the text out of attached office documents for the task.",
      "toggle", "Privacy", True, "maverick.attachments", env=("MAVERICK_ATTACH_EXTRACT",)),
    S("voice", "auto_fetch_model", "Download the offline speech model",
      "Download a verified speech-to-text model so voice input works without an outside service.",
      "toggle", "Privacy", False, "maverick.voice_models", restart=True,
      env=("MAVERICK_VOICE_AUTO_FETCH",)),
    S("compliance", "disclosure_text", "AI disclosure message",
      "The sentence shown to people to tell them they are dealing with an AI system.",
      "text", "Privacy", "", "maverick.compliance", max_length=1000, env=("MAVERICK_AI_DISCLOSURE",),
      pattern=r"[^\x00-\x08\x0b\x0c\x0e-\x1f]{1,1000}"),

    S("paper_review", "use_model", "Let AI draft contract wording",
      "When reviewing a vendor's contract, let an AI model write the suggested clause changes. The findings are the same either way.",
      "toggle", "Privacy", True, "maverick.paper_review", weaker=True,
      warning="Vendor contracts will be sent to an AI model to draft wording."),
    S("paper_review", "org_name", "Your organisation's name in contracts",
      "The name used for your side when drafting contract language.",
      "text", "Privacy", "", "maverick.paper_review", max_length=120,
      pattern=r"[^\n\r<>{}]{0,120}"),
    S("privacy_ops", "enable", "Privacy program records",
      "Keep the records of processing, impact assessments and other privacy program records.",
      "toggle", "Privacy", True, "maverick.privacy_ops"),
    S("ediscovery", "enable", "Legal holds and matter export",
      "Let a records administrator place a legal hold on named people's records and export those records for counsel. While a hold applies, the matching records cannot be deleted.",
      "toggle", "Privacy", False, "maverick.ediscovery"),
    S("content_provenance", "claim_generator", "Name on content credentials",
      "The product name recorded in content credentials attached to generated media.",
      "text", "Privacy", "Lightwork", "maverick.content_provenance", max_length=128,
      pattern=r"[^\n\r<>{}]{1,128}"),

    # ---------------------------------------------------------- Data retention
    S("retention", "audit_days", "Keep the activity record for",
      "Activity record days older than this are removed. Leave unset to keep them forever.",
      "number", "Data retention", None, "maverick.audit.retention", minimum=1, maximum=3650,
      integer=True, unit="days", weaker="lower",
      warning="Older activity records will be permanently deleted at the next clean-up.",
      preview="retention"),
    S("retention", "episodes_days", "Keep finished work records for",
      "Records of finished work older than this are removed. Leave unset to keep them forever.",
      "number", "Data retention", None, "maverick.audit.retention", minimum=1, maximum=3650,
      integer=True, unit="days", weaker="lower",
      warning="Older work records will be permanently deleted at the next clean-up.",
      preview="retention"),
    S("retention", "events_days", "Keep task progress updates for",
      "Task progress updates older than this are removed. Leave unset to keep them forever.",
      "number", "Data retention", None, "maverick.audit.retention", minimum=1, maximum=3650,
      integer=True, unit="days", weaker="lower",
      warning="Older progress updates will be permanently deleted at the next clean-up.",
      preview="retention"),
    S("retention", "messages_days", "Keep messages for",
      "Messages older than this are removed. Leave unset to keep them forever.",
      "number", "Data retention", None, "maverick.audit.retention", minimum=1, maximum=3650,
      integer=True, unit="days", weaker="lower",
      warning="Older messages will be permanently deleted at the next clean-up.",
      preview="retention"),
    S("retention", "usage_days", "Keep usage tallies for",
      "Daily usage tallies older than this are removed. Leave unset to keep them forever.",
      "number", "Data retention", None, "maverick.audit.retention", minimum=1, maximum=3650,
      integer=True, unit="days", weaker="lower",
      warning="Older usage tallies will be permanently deleted at the next clean-up.",
      preview="retention"),
    S("work_details", "enable", "Business fields and stages",
      "Let your team set up named business fields and stages for tasks and security records. "
      "Every save is reviewed; these labels do not change execution or approval. Original results are retained for the latest 20 saves per record.",
      "toggle", "Work", True, "maverick.work_record_details"),
    S("durable", "enabled", "Resume tasks after a crash",
      "Save progress as tasks run so they can continue from the last step after an interruption.",
      "toggle", "Data retention", BOOLEAN_SETTINGS["durable.enabled"].default, "maverick.config"),
    S("durable", "keep_last", "Saved progress points per agent",
      "How many saved progress points to keep for each agent.",
      "number", "Data retention", INTEGER_SETTINGS["durable.keep_last"].default, "maverick.config",
      minimum=INTEGER_SETTINGS["durable.keep_last"].minimum,
      maximum=INTEGER_SETTINGS["durable.keep_last"].maximum, integer=True, unit="points"),
    S("workspace", "journal", "Keep a copy before files change",
      "Save a copy of each file before an agent changes it, so a task's changes can be undone.",
      "toggle", "Data retention", False, "maverick.workspace_journal"),

    # ------------------------------------------------------------ Integrations
    S("mobile_offline", "enabled", "Allow offline copies on mobile devices",
      "Let current policy-aware companions keep a bounded offline task copy. People can turn saving off; workspace policy can only narrow this installation ceiling.",
      "toggle", "Data retention", True, "maverick.mobile_offline_policy"),
    S("mobile_offline", "max_age_seconds", "Keep mobile offline copies for at most",
      "A cached copy expires after this time, even while the device is offline. Shorter workspace limits take precedence.",
      "number", "Data retention", 86400, "maverick.mobile_offline_policy", minimum=1, maximum=1440,
      scale=60, integer=True, unit="minutes"),
    S("mobile_offline", "max_bytes", "Largest mobile offline copy",
      "Refuse larger offline copies instead of silently dropping parts of them.",
      "number", "Data retention", 2097152, "maverick.mobile_offline_policy", minimum=1, maximum=2048,
      scale=1024, integer=True, unit="KB"),
    S("device_pairing", "enabled", "Allow personal companion pairing",
      "Let named members pair devices through an expiring code and explicit browser confirmation. Each credential is limited to its member's own tasks in one workspace. Disabling this denies existing devices on their next request.",
      "toggle", "People & access", False, "maverick_dashboard.device_pairing"),
    S("device_pairing", "credential_hours", "Paired-device credential lifetime",
      "Require protected renewal within this interval. All enrollments expire after 30 days and require new browser approval. Workspace policy can only shorten the organization lifetime.",
      "number", "People & access", 24, "maverick_dashboard.device_pairing", minimum=1, maximum=168, integer=True, unit="hours"),
    S("device_pairing", "allow_actions", "Allow reviewed own-task actions on companions",
      "Permit a separately opted-in device to submit a reviewed answer or Stop on its own tasks. Current role, current task state and explicit review still apply. Approvals and general administrative operations stay on the dashboard.",
      "toggle", "People & access", False, "maverick_dashboard.device_pairing"),
    S("notifications", "personal_alerts", "Show personal task alerts",
      "Let signed-in people see in the app (the bell) when their tasks finish, need an answer, or wait for their approval. On by default; email, Slack and Teams stay off until you set them up. Each person can choose alerts, quiet hours, daily digests and task mutes in Your notifications. Requires personal preferences.",
      "toggle", "Integrations", True, "maverick.personal_notifications"),
    S("notifications", "personal_critical_bypass", "Allow personal approval and deadline exceptions",
      "Let people explicitly allow approval and deadline alerts to bypass their personal quiet hours and summary timing. Organization operational alerts are unchanged.",
      "toggle", "Integrations", False, "maverick_dashboard.personal_notifications_api"),
    S("notifications", "metric_alerts", "Task performance and usage alerts",
      "Show each signed-in person an in-app alert when their recorded runs reach the thresholds below. "
      "Uses up to 5,000 of their latest runs completed in the last seven days that they can still open; "
      "older history is explicitly excluded. Finish rate measures completion, not answer accuracy. "
      "Recorded usage is not a complete provider invoice. Follows personal Needs attention alert choices, "
      "quiet hours and delivery settings; never changes spending limits. Off by default.",
      "toggle", "Integrations", False, "maverick.task_metric_alerts",
      subgroup="Task performance alerts", aliases="metric quality performance usage threshold alerts"),
    S("notifications", "metric_min_runs", "Runs needed before a finish-rate alert",
      "Require this many included completed runs before checking the finish-rate threshold. Usage alerts do not need this minimum.",
      "number", "Integrations", 10, "maverick.task_metric_alerts", minimum=1, maximum=1000,
      integer=True, unit="recorded runs", subgroup="Task performance alerts"),
    S("notifications", "metric_finish_below", "Alert below this finish rate",
      "Alert when fewer than this percentage of included runs finished successfully. Zero turns off this check. "
      "Stopped and failed completed runs lower the rate; this does not judge whether answers are correct.",
      "number", "Integrations", 80, "maverick.task_metric_alerts", minimum=0, maximum=100,
      integer=True, unit="percent", subgroup="Task performance alerts"),
    S("notifications", "metric_spend_above", "Alert at this recorded weekly spending",
      "Alert when included runs record at least this many US dollars. Zero turns off this check. "
      "Uses recorded usage, which may not include every provider charge; does not stop or authorize spending.",
      "number", "Integrations", 0.0, "maverick.task_metric_alerts", minimum=0, maximum=1000000,
      unit="US dollars", subgroup="Task performance alerts"),
    S("notifications", "metric_tokens_above", "Alert at this recorded weekly text usage",
      "Alert when included runs record at least this many text units (tokens) read and written. "
      "Zero turns off this check. This is recorded usage, not a complete invoice or a new spending limit.",
      "number", "Integrations", 0, "maverick.task_metric_alerts", minimum=0, maximum=10000000000,
      integer=True, unit="text units", subgroup="Task performance alerts"),
    S("notifications", "personal_background", "Refresh personal alerts while pages are closed",
      "Run a bounded dashboard observer for explicitly enrolled named accounts. It rechecks current identity and owned work, observes changes about every 30 seconds, and releases eligible digests while the dashboard is running.",
      "toggle", "Integrations", False, "maverick_dashboard.personal_notification_scheduler"),
    S("notifications", "personal_external", "Allow personal alerts to verified private conversations",
      "Let people opt into Slack or Telegram private delivery using their explicitly verified My data identities. Requires background observation, current membership and channel allowlists; organization webhook destinations are never reused.",
      "toggle", "Integrations", False, "maverick.personal_notification_delivery"),
    S("notifications", "personal_dashboard_url", "Dashboard address for personal notification links",
      "The HTTPS origin people use to sign in, without a path, query or credentials. Messages say why each alert was sent, what it needs and by when, with authenticated links, and never include task text.",
      "text", "Integrations", "", "maverick.personal_notification_delivery"),
    S("collaboration", "comments", "Comments and mentions",
      "Let people comment on tasks, workflow runs, approval requests and policy pages, and mention a "
      "colleague to notify them in their own notifications. Only people who can open the item can read "
      "its comments or be mentioned. On by default.",
      "toggle", "People & access", True, "maverick.comments",
      aliases="comment comments mention mentions discuss discussion thread collaborate"),
    S("collaboration", "suggestions", "Suggested edits to rules",
      "Let agents and colleagues suggest changes to AI use rules, data use rules and privacy notices. "
      "A suggestion shows exactly what it changes, who or what proposed it and why. Accepting it creates "
      "a draft that still goes through that document's own approval. On by default.",
      "toggle", "People & access", True, "maverick.policy_suggestions",
      aliases="suggest suggestion suggestions edit review accept reject tracked changes rules policy"),
    S("collaboration", "ai_suggestions", "AI-drafted suggestions",
      "Let the AI assistant draft a suggested edit to AI use rules when a person asks. Each draft "
      "uses the AI service within the spending cap for one task and is only a suggestion until a "
      "person accepts it. On by default.",
      "toggle", "People & access", True, "maverick.policy_suggestions",
      aliases="ai suggest draft assistant rules policy wording"),
    S("support", "status_page_url", "Service status page",
      "A public page that shows whether your Lightwork service is up and its incident history. When set, the Help menu on every page links to it, and so does the notice shown while an AI service is paused. Leave empty to show no link.",
      "text", "Integrations", "", "maverick.config", pattern=r"(" + _HTTPS + r")?",
      subgroup="Help and support", aliases="status page incident outage help menu"),
    S("support", "contact_email", "Support contact email",
      "Where \"Get help from a person\" requests go: your vendor's or help desk's address. People review the request and send it from their own email app; nothing is sent automatically. Leave empty to have people send requests to their Lightwork administrator.",
      "text", "Integrations", "", "maverick.config",
      pattern=r"([^@\s\"'<>,;]{1,64}@[^@\s\"'<>,;]{1,190}\.[A-Za-z]{2,24})?",
      subgroup="Help and support", aliases="help desk vendor support person contact"),
    S("notifications", "delivery_receipts", "Keep notification delivery history",
      "Keep content-free delivery results for seven days, up to 1,000 attempts. View history and send a test on Notification delivery in Settings.",
      "toggle", "Integrations", True, "maverick.notifications"),
    S("notifications", "backend", "Send organization alerts with",
      "Choose the shared channel for organization operational alerts. Personal task updates appear in Your notifications and can use separately verified private conversations.",
      "select", "Integrations", "ntfy", "maverick.notifications",
      choices=(("none", "Do not send alerts"), ("ntfy", "ntfy phone alerts"),
               ("slack", "Slack"), ("discord", "Discord"),
               ("pushover", "Pushover"), ("email", "Email"))),
    S("notifications", "ntfy_topic", "ntfy topic",
      "Your private ntfy topic name. Treat it like a password.",
      "secret", "Integrations", "", "maverick.notifications"),
    S("notifications", "ntfy_server", "ntfy server",
      "The ntfy server web address. Leave empty to use the public ntfy service.",
      "text", "Integrations", "", "maverick.notifications", max_length=300,
      pattern=r"(" + _HTTPS + r")?"),
    S("notifications", "slack_webhook", "Slack alert link",
      "The Slack incoming message link for alerts.",
      "secret", "Integrations", "", "maverick.notifications", pattern=_HTTPS),
    S("notifications", "discord_webhook", "Discord alert link",
      "The Discord message link for alerts.",
      "secret", "Integrations", "", "maverick.notifications", pattern=_HTTPS),
    S("notifications", "batch_window_seconds", "Group routine alerts",
      "Collect routine alerts and send them together this often. Urgent alerts are always sent at once. Zero sends each alert straight away.",
      "number", "Integrations", 0, "maverick.notification_batcher", minimum=0, maximum=86400,
      integer=True, unit="seconds", env=("MAVERICK_NOTIFY_BATCH_WINDOW",)),
    S("webhooks", "outbound", "Send task events to these addresses",
      "Web addresses that receive a signed message when tasks start and finish.",
      "list", "Integrations", [], "maverick.webhooks", max_items=10, pattern=_HTTPS,
      weaker="add",
      warning="Details of every task will be sent to the new address."),
    S("automation_import", "enable", "Import automations from other tools",
      "Bring in existing automations from tools such as n8n, Make, Workato, Power Automate or UiPath.",
      "toggle", "Integrations", BOOLEAN_SETTINGS["automation_import.enable"].default, "maverick.config",
      env=BOOLEAN_SETTINGS["automation_import.enable"].dashboard_env),
    S("automation_import", "create_schedules", "Recreate imported schedules",
      "When an imported automation ran on a schedule, offer to recreate that schedule here, "
      "reviewed once its draft is published.",
      "toggle", "Integrations", BOOLEAN_SETTINGS["automation_import.create_schedules"].default, "maverick.config"),
    S("event_triggers", "enable", "Start workflows from events",
      "Watch connected services and start the chosen workflow when something new arrives.",
      "toggle", "Integrations", False, "maverick.automation_events",
      env=("MAVERICK_EVENT_TRIGGERS",)),
    S("flows", "public_url", "Web address for approval links",
      "The address people use to reach this dashboard, used in Approve and Reject links sent to chat apps.",
      "text", "Integrations", "", "maverick_dashboard.automation_queue", max_length=300,
      pattern=r"(" + _HTTPS + r")?"),
    S("tax", "auto_update", "Update tax figures automatically",
      "Download signed updates to tax figures when an update address and trusted keys are set.",
      "toggle", "Integrations", True, "maverick.config"),
    S("tax", "check_hours", "Check for tax updates every",
      "How often to look for new tax figures.",
      "number", "Integrations", 20.0, "maverick.config", minimum=1, maximum=720, unit="hours"),
    S("shield", "federated_updates", "Receive shared threat updates",
      "Download signed updates to the threat checks when an update address and key are set.",
      "toggle", "Integrations", False, "maverick.shield_updates"),
    S("shoring", "enable", "Book of work and service levels",
      "Show the book of work, measured service levels and the exception desk.",
      "toggle", "Integrations", True, "maverick.shoring"),

    # ------------------------------------------------------------- Performance
    S("query_limits", "timeout_seconds", "Time limit for data look-ups",
      "How long a single look-up in a connected data source may take.",
      "number", "Performance", 30, "maverick.query_execution", minimum=1, maximum=300,
      unit="seconds"),
    S("connector_limits", "max_attempts", "Retries for connected services",
      "How many times a call to a connected service is tried before giving up.",
      "number", "Performance", 3, "maverick.connector_attempts", minimum=1, maximum=5,
      integer=True, unit="attempts"),
    S("flows", "max_node_retries", "Retries for each workflow step",
      "The most retries allowed for a failed step. Zero disables retries; steps configured above this limit must be adjusted before they can run.",
      "number", "Performance", 5, "maverick.config", minimum=0, maximum=10, integer=True,
      unit="retries", env=("MAVERICK_FLOW_MAX_NODE_RETRIES",)),
    S("cache", "prewarm", "Warm up AI connections",
      "Open connections to AI services early so the first reply is faster.",
      "toggle", "Performance", False, "maverick.llm"),
    S("latency", "hedge_ms", "Send a backup request after",
      "If an AI service has not answered after this long, send the same request again and use the first reply. Leave unset to never do this.",
      "number", "Performance", None, "maverick.llm", minimum=100, maximum=60000,
      integer=True, unit="milliseconds"),
    S("tools", "output_cache", "Reuse recent tool results",
      "Reuse the result of an identical recent tool call instead of repeating it.",
      "toggle", "Performance", False, "maverick.cache.tool"),
    S("tools", "hardware_sensors", "Read this computer's sensors",
      "Let agents read temperature, battery and similar sensors on this computer.",
      "toggle", "Performance", False, "maverick.tools"),
    S("dashboard", "compress", "Compress dashboard pages",
      "Send smaller pages to browsers. Turn off only if another server in front already does this.",
      "toggle", "Performance", True, "maverick_dashboard.app", restart=True,
      env=("MAVERICK_DASHBOARD_COMPRESS",)),
    S("rate_limits", "web_search", "Web searches allowed",
      "The most web searches allowed in a period of time. Clear it to use the installer's choice.",
      "rate", "Performance", None, "maverick.safety.rate_limiter", key_kind="tool",
      weaker="higher",
      warning="Agents will be able to search the web more often, or without any limit."),
    S("rate_limits", "http_fetch", "Web page reads allowed",
      "The most web page reads allowed in a period of time. Clear it to use the installer's choice.",
      "rate", "Performance", None, "maverick.safety.rate_limiter", key_kind="tool",
      weaker="higher",
      warning="Agents will be able to read web pages more often, or without any limit."),
    S("rate_limits", "shell", "Commands allowed",
      "The most commands allowed in a period of time. Clear it to use the installer's choice.",
      "rate", "Performance", None, "maverick.safety.rate_limiter", key_kind="tool",
      weaker="higher",
      warning="Agents will be able to run commands more often, or without any limit."),
)

# ====================================================================
# Settings that need more than one value per control, or a guided form:
# chat channels, publisher keys, the protected work area, document search,
# connected business systems, finance, the security suite, AI governance
# modules, the AI gateway, GRC sync, outside tool gateway, local models,
# plugin permissions and usage limits for any tool.
# ====================================================================

_PHONE = r"\+[0-9]{6,15}"
_DIGITS = r"-?[0-9]{1,20}"
_EMAIL = r"[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,24}"

# Channel name -> (label shown, on the Channels page already?, allow-list key,
# item word, item hint, item pattern, item error). Names match the channel
# adapter registry in maverick.server (``_WIRES``); a test pins that.
CHANNEL_ALLOWLISTS: dict[str, tuple[str, bool, str, str, str, str, str]] = {
    "telegram": ("Telegram", True, "allowed_user_ids", "Person", "123456789",
                 _DIGITS, "a Telegram person number"),
    "discord": ("Discord", True, "allowed_user_ids", "Person", "123456789012345678",
                _DIGITS, "a Discord person number"),
    "slack": ("Slack", True, "allowed_user_ids", "Person", "U01ABCDEF",
              r"[A-Z0-9]{5,24}", "a Slack member code, for example U01ABCDEF"),
    "whatsapp_cloud": ("WhatsApp (Cloud)", True, "allowed_user_ids", "Number", "14155551234",
                       r"[0-9]{6,15}", "a phone number written as digits only"),
    "sms": ("Text messages", True, "allowed_user_ids", "Number", "+14155551234",
            _PHONE, "a phone number starting with + and the country code"),
    "email": ("Email", True, "allowed_user_ids", "Address", "name@example.com",
              _EMAIL, "an email address"),
    "signal": ("Signal", False, "allowed_user_ids", "Number", "+14155551234",
               _PHONE, "a phone number starting with + and the country code"),
    "matrix": ("Matrix", False, "allowed_user_ids", "Account", "@name:matrix.org",
               r"@[^:\s]{1,255}:[^\s]{1,255}", "a Matrix account such as @name:matrix.org"),
    "bluesky": ("Bluesky", False, "allowed_user_ids", "Handle", "name.bsky.social",
                r"[A-Za-z0-9.:-]{3,253}", "a Bluesky handle"),
    "mastodon": ("Mastodon", False, "allowed_user_ids", "Account", "name@mastodon.social",
                 r"@?[^@\s]{1,64}@[^@\s]{1,253}", "an account such as name@mastodon.social"),
    "whatsapp": ("WhatsApp (Twilio)", False, "allowed_user_ids", "Number",
                 "whatsapp:+14155551234", r"whatsapp:\+[0-9]{6,15}",
                 "a number written as whatsapp:+ and the country code"),
    "threads": ("Threads", False, "allowed_user_ids", "Username", "name",
                r"[A-Za-z0-9._]{1,30}", "a Threads username"),
    "rcs": ("RCS messages", False, "allowed_user_ids", "Number", "+14155551234",
            _PHONE, "a phone number starting with + and the country code"),
    "imessage": ("iMessage", False, "allowed_user_ids", "Contact", "+14155551234",
                 r"(" + _PHONE + r"|" + _EMAIL + r")", "a phone number or email address"),
    "irc": ("IRC", False, "allowed_user_ids", "Account", "nickname",
            r"[^\s,]{1,64}", "a signed-in IRC account name"),
    "voice": ("Phone calls", False, "allowed_callers", "Number", "+14155551234",
              r"\+[1-9][0-9]{5,14}", "a full phone number starting with + and a country code"),
    "mattermost": ("Mattermost", True, "allowed_user_ids", "Person", "alice",
                   r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", "a Mattermost username or user id"),
    "teams": ("Microsoft Teams", True, "allowed_users", "Person",
              "12345678-abcd-abcd-abcd-1234567890ab", r"[0-9a-fA-F-]{36}",
              "a Microsoft Entra object ID (36 characters, from the person's Entra profile)"),
}


def _channel_settings() -> tuple[Setting, ...]:
    out: list[Setting] = []
    for name, (label, on_page, key, item, hint, pattern, error) in CHANNEL_ALLOWLISTS.items():
        section = f"channels.{name}"
        common = {"group": "Chat channels", "reader": "maverick.server", "subgroup": label,
                  "restart": True}
        if not on_page:
            out.append(S(section, "enabled", f"Use {label}",
                         f"Let people on the list below give agents work through {label}.",
                         "toggle", default=False, weaker=True,
                         warning=f"People on the {label} list will be able to give agents work.",
                         aliases=f"{name} channel chat", **common))
        noun = "callers" if key == "allowed_callers" else "people"
        access_help = (
            "Only numbers in the effective caller list can start work through calls. "
            "Enter each number with + and its country code. Saving a blank list "
            "denies everyone; use the inherited-value control to restore an inherited list. With no permitted callers, incoming calls "
            "cannot start work. Caller ID alone does not verify a person; sensitive "
            "actions still need approval."
            if name == "voice" else
            f"Only {noun} listed here can give agents work through {label}. When the "
            "list is empty and saved here, nobody can. Use the inherited-value control to restore an "
            "inherited installer or server list instead."
        )
        out.append(S(section, key, f"Who may use {label}",
                     access_help,
                     "list", default=[], weaker="grow", item_label=item, item_hint=hint,
                     pattern=pattern, item_error=error, empty_unset=False, max_items=200,
                     max_length=300,
                     warning=f"More people will be able to give agents work through {label}.",
                     aliases=f"{name} allow list allowed senders", **common))
        if name == "teams":
            out.append(S(section, "approvals_enabled", "Decide approvals in Microsoft Teams",
                         "Send approval requests to linked approvers as cards in Teams, where "
                         "they can approve, reject or send them back. Decisions use the same "
                         "record as the Approvals page.",
                         "toggle", default=False, weaker=True,
                         warning="People linked as approvers will be able to approve agent "
                                 "actions from Teams.",
                         aliases="teams approvals adaptive card", **common))
            out.append(S(section, "allowed_tenants", "Microsoft 365 organisations that may use Lightwork",
                         "Only messages from these organisation directory IDs reach the agent. "
                         "When empty, the directory ID on the Channels page is the only one allowed.",
                         "list", default=[], weaker="grow", item_label="Organisation",
                         item_hint="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", pattern=r"[0-9a-fA-F-]{36}",
                         item_error="a Microsoft Entra directory ID (36 characters)", empty_unset=True,
                         max_items=50,
                         warning="More organisations will be able to give agents work through Teams.",
                         **common))
        if name == "telegram":
            out.append(S(section, "allowed_chat_ids", "Telegram chats that may use Lightwork",
                         "Private chats listed here may also give agents work.",
                         "list", default=[], weaker="grow", item_label="Chat",
                         item_hint="123456789", pattern=_DIGITS,
                         item_error="a Telegram chat number", empty_unset=True, max_items=200,
                         warning="More Telegram chats will be able to give agents work.",
                         **common))
    return tuple(out)


def _https(_label: str) -> str:
    return r"(" + _HTTPS + r")?"


_CHANNEL_FIELDS: tuple[Setting, ...] = (
    # Signal
    S("channels.signal", "phone_number", "Signal number",
      "The phone number your Signal account uses, starting with + and the country code.",
      "text", "Chat channels", "", "maverick.server", subgroup="Signal", restart=True,
      pattern=r"(" + _PHONE + r")?", max_length=16),
    # Matrix
    S("channels.matrix", "homeserver", "Matrix server",
      "The web address of your Matrix server.", "text", "Chat channels", "",
      "maverick.server", subgroup="Matrix", restart=True, pattern=_https("x"), max_length=300),
    S("channels.matrix", "user_id", "Matrix account",
      "The account Lightwork signs in as, such as @lightwork:matrix.org.", "text",
      "Chat channels", "", "maverick.server", subgroup="Matrix", restart=True,
      pattern=r"(@[^:\s]{1,255}:[^\s]{1,255})?", max_length=300),
    S("channels.matrix", "access_token", "Matrix sign-in key",
      "The access key for that account. It is stored sealed and never shown again.",
      "secret", "Chat channels", "", "maverick.server", subgroup="Matrix", restart=True,
      max_length=500),
    # Bluesky
    S("channels.bluesky", "handle", "Bluesky handle",
      "The Bluesky account Lightwork uses, such as lightwork.bsky.social.", "text",
      "Chat channels", "", "maverick.server", subgroup="Bluesky", restart=True,
      pattern=r"[A-Za-z0-9.:-]{0,253}", max_length=253),
    S("channels.bluesky", "password", "Bluesky app password",
      "An app password created in Bluesky's settings. It is stored sealed and never shown again.",
      "secret", "Chat channels", "", "maverick.server", subgroup="Bluesky", restart=True,
      max_length=200),
    S("channels.bluesky", "poll_interval", "Check Bluesky every",
      "How often Lightwork looks for new messages.", "number", "Chat channels", 30,
      "maverick.server", subgroup="Bluesky", restart=True, minimum=10, maximum=3600,
      integer=True, unit="seconds"),
    # Mastodon
    S("channels.mastodon", "instance", "Mastodon server",
      "The web address of your Mastodon server.", "text", "Chat channels", "",
      "maverick.server", subgroup="Mastodon", restart=True, pattern=_https("x"), max_length=300),
    S("channels.mastodon", "access_token", "Mastodon sign-in key",
      "The access key for Lightwork's account. It is stored sealed and never shown again.",
      "secret", "Chat channels", "", "maverick.server", subgroup="Mastodon", restart=True,
      max_length=500),
    S("channels.mastodon", "poll_interval", "Check Mastodon every",
      "How often Lightwork looks for new messages.", "number", "Chat channels", 30,
      "maverick.server", subgroup="Mastodon", restart=True, minimum=10, maximum=3600,
      integer=True, unit="seconds"),
    # WhatsApp through Twilio
    S("channels.whatsapp", "account_sid", "Twilio account code",
      "Your Twilio account code, which starts with AC.", "text", "Chat channels", "",
      "maverick.server", subgroup="WhatsApp (Twilio)", restart=True,
      pattern=r"(AC[0-9a-fA-F]{32})?", max_length=34),
    S("channels.whatsapp", "auth_token", "Twilio sign-in key",
      "Your Twilio auth token. It is stored sealed and never shown again.", "secret",
      "Chat channels", "", "maverick.server", subgroup="WhatsApp (Twilio)", restart=True,
      max_length=200),
    S("channels.whatsapp", "from_number", "WhatsApp sending number",
      "The number messages come from, written as whatsapp:+ and the country code.", "text",
      "Chat channels", "", "maverick.server", subgroup="WhatsApp (Twilio)", restart=True,
      pattern=r"(whatsapp:\+[0-9]{6,15})?", max_length=30),
    S("channels.whatsapp", "port", "Port for incoming WhatsApp messages",
      "The port on this server that receives messages from Twilio.", "number",
      "Chat channels", 8765, "maverick.server", subgroup="WhatsApp (Twilio)", restart=True,
      minimum=1024, maximum=65535, integer=True, unit="port"),
    # Threads
    S("channels.threads", "access_token", "Threads sign-in key",
      "The access key for Lightwork's Threads account. It is stored sealed and never shown again.",
      "secret", "Chat channels", "", "maverick.server", subgroup="Threads", restart=True,
      max_length=500),
    S("channels.threads", "user_id", "Threads account number",
      "The number of the Threads account Lightwork uses.", "text", "Chat channels", "",
      "maverick.server", subgroup="Threads", restart=True, pattern=r"[0-9]{0,30}",
      max_length=30),
    S("channels.threads", "poll_seconds", "Check Threads every",
      "How often Lightwork looks for new replies.", "number", "Chat channels", 30,
      "maverick.server", subgroup="Threads", restart=True, minimum=10, maximum=3600,
      integer=True, unit="seconds"),
    # RCS
    S("channels.rcs", "agent_id", "RCS agent name",
      "The name of your RCS business messaging agent.", "text", "Chat channels", "",
      "maverick.server", subgroup="RCS messages", restart=True,
      pattern=r"[A-Za-z0-9._-]{0,128}", max_length=128),
    S("channels.rcs", "webhook_token", "RCS message check key",
      "The shared key that proves incoming RCS messages are genuine. It is stored sealed.",
      "secret", "Chat channels", "", "maverick.server", subgroup="RCS messages", restart=True,
      max_length=200),
    S("channels.rcs", "port", "Port for incoming RCS messages",
      "The port on this server that receives RCS messages.", "number", "Chat channels", 8768,
      "maverick.server", subgroup="RCS messages", restart=True, minimum=1024, maximum=65535,
      integer=True, unit="port"),
    # iMessage
    S("channels.imessage", "poll_interval", "Check iMessage every",
      "How often Lightwork looks for new messages on this Mac.", "number", "Chat channels", 5,
      "maverick.server", subgroup="iMessage", restart=True, minimum=1, maximum=600,
      integer=True, unit="seconds"),
    # IRC
    S("channels.irc", "server", "IRC server",
      "The name of the IRC server, such as irc.libera.chat.", "text", "Chat channels", "",
      "maverick.server", subgroup="IRC", restart=True,
      pattern=r"[A-Za-z0-9.-]{0,253}", max_length=253),
    S("channels.irc", "port", "IRC port", "The port of the IRC server.", "number",
      "Chat channels", 6697, "maverick.server", subgroup="IRC", restart=True, minimum=1,
      maximum=65535, integer=True, unit="port"),
    S("channels.irc", "tls", "Use an encrypted IRC connection",
      "Connect to the IRC server over an encrypted connection.", "toggle", "Chat channels",
      True, "maverick.server", subgroup="IRC", restart=True, weaker=False,
      warning="Messages to and from IRC will travel unencrypted."),
    S("channels.irc", "nick", "IRC name", "The name Lightwork uses on IRC.", "text",
      "Chat channels", "maverick", "maverick.server", subgroup="IRC", restart=True,
      pattern=r"[A-Za-z0-9\[\]\\`^{}|-]{1,30}", max_length=30),
    S("channels.irc", "channels", "IRC rooms to join",
      "The rooms Lightwork joins, such as #support.", "list", "Chat channels", [],
      "maverick.server", subgroup="IRC", restart=True, item_label="Room",
      item_hint="#support", pattern=r"[#&][^\s,]{1,49}", item_error="a room name starting with #",
      max_items=50),
    S("channels.irc", "password", "IRC password",
      "The password for Lightwork's IRC account. It is stored sealed and never shown again.",
      "secret", "Chat channels", "", "maverick.server", subgroup="IRC", restart=True,
      max_length=200),
    # Phone calls
    S("channels.voice", "provider", "Phone call service",
      "Vapi and Retell can ask Lightwork for an answer during a call. Bland supports outgoing calls only. Follow the Phone call setup guide above.", "select",
      "Chat channels", "vapi", "maverick.server", subgroup="Phone calls", restart=True,
      choices=(("vapi", "Vapi"), ("retell", "Retell"), ("bland", "Bland — outgoing calls only"))),
    S("channels.voice", "api_key", "Phone call service key",
      "The key for the service above. It is stored sealed and never shown again.", "secret",
      "Chat channels", "", "maverick.server", subgroup="Phone calls", restart=True,
      max_length=300),
    S("channels.voice", "phone_number", "Phone number",
      "The number people call, starting with + and the country code.", "text",
      "Chat channels", "", "maverick.server", subgroup="Phone calls", restart=True,
      pattern=r"(" + _PHONE + r")?", max_length=16),
    S("channels.voice", "assistant_id", "Saved call assistant",
      "Copy the saved assistant's ID from Vapi, or the saved agent's ID from Retell. Incoming calls must use this exact assistant.", "text",
      "Chat channels", "", "maverick.server", subgroup="Phone calls", restart=True,
      pattern=r"[A-Za-z0-9._:-]{0,128}", max_length=128),
    S("channels.voice", "webhook_token", "Call check key",
      "Set the same private key in the phone service's Authorization header. It checks the service connection, not the caller's identity. It is stored sealed.", "secret",
      "Chat channels", "", "maverick.server", subgroup="Phone calls", restart=True,
      max_length=300),
    S("channels.voice", "port", "Port for incoming calls",
      "The port on this server that receives call events.", "number", "Chat channels", 8770,
      "maverick.server", subgroup="Phone calls", restart=True, minimum=1024, maximum=65535,
      integer=True, unit="port"),
    # Mattermost (on the Channels page; how often to check is not)
    S("channels.mattermost", "poll_interval", "Check Mattermost every",
      "How often Lightwork looks for new Mattermost messages.", "number", "Chat channels", 10,
      "maverick.server", subgroup="Mattermost", restart=True, minimum=2, maximum=3600,
      integer=True, unit="seconds"),
    # Email (on the Channels page; how often to check is not)
    S("channels.email", "poll_interval", "Check email every",
      "How often Lightwork looks for new email.", "number", "Chat channels", 30,
      "maverick.server", subgroup="Email", restart=True, minimum=10, maximum=3600,
      integer=True, unit="seconds"),
)

_MORE: tuple[Setting, ...] = (
    # ------------------------------------------------ trusted skill publishers
    S("skills", "trusted_pubkeys", "Trusted skill publishers",
      "Skills signed by these publishers are trusted. Add a publisher by uploading or "
      "pasting their public key file; each one is shown by its fingerprint.",
      "keys", "Safety", [], "maverick.config", subgroup="Skill publishers", weaker="grow",
      warning="Skills signed by a newly trusted publisher will install and run, or, if the "
              "list is emptied, a signature from anyone will be accepted.",
      aliases="signed skills public key publisher"),

    # --------------------------------------------------- protected work area
    S("sandbox", "language", "Tools in the work area",
      "The set of programming tools the work area starts with.", "select",
      "Protected work area", "", "maverick.sandbox", subgroup="Work area",
      choices=(("", "Python (default)"), ("javascript", "JavaScript and TypeScript"),
               ("go", "Go"), ("rust", "Rust"), ("java", "Java and Kotlin"), ("ruby", "Ruby"))),
    S("sandbox", "image", "Custom work area image",
      "A specific container image to run commands in, instead of the one chosen by the tools "
      "above. Leave empty to use the standard one.", "text", "Protected work area", "",
      "maverick.sandbox", subgroup="Work area", max_length=255, weaker="change",
      pattern=r"([A-Za-z0-9][A-Za-z0-9._/:@-]{0,254})?",
      warning="Commands will run in a different image, which may include programs your team "
              "has not reviewed."),
    S("sandbox", "allow_network", "Let the work area reach the internet",
      "Commands may download packages and contact other computers.", "toggle",
      "Protected work area", False, "maverick.sandbox", subgroup="Work area", weaker=True,
      warning="Agent commands will be able to send data to, and download programs from, "
              "anywhere on the internet."),
    S("sandbox", "allow_root", "Run commands with full control of the work area",
      "Commands run as the all-powerful user inside the work area.", "toggle",
      "Protected work area", False, "maverick.sandbox", subgroup="Work area", weaker=True,
      warning="Agent commands will be able to change anything inside the work area, which "
              "makes breaking out of it easier."),
    S("sandbox", "memory", "Memory for the work area",
      "The most memory commands may use.", "select", "Protected work area", "4g",
      "maverick.sandbox", subgroup="Work area",
      choices=(("1g", "1 GB"), ("2g", "2 GB"), ("4g", "4 GB (default)"), ("8g", "8 GB"),
               ("16g", "16 GB"), ("32g", "32 GB"))),
    S("sandbox", "cpus", "Processors for the work area",
      "How many processors commands may use. Leave empty for the standard amount.", "number",
      "Protected work area", None, "maverick.sandbox", subgroup="Work area", minimum=0.5,
      maximum=64, step=0.5, unit="processors"),
    S("sandbox", "pids_limit", "Programs running at once",
      "The most programs commands may run at the same time.", "number",
      "Protected work area", 512, "maverick.sandbox", subgroup="Work area", minimum=16,
      maximum=65536, integer=True, unit="programs"),
    S("sandbox", "host", "Remote computer for commands",
      "When commands run on another computer, the name of that computer, such as "
      "builder@build-server. It must already trust this server.", "text",
      "Protected work area", "", "maverick.sandbox", subgroup="Remote computer",
      max_length=255, weaker="change",
      pattern=r"((?:[^\s@/:\\-][^\s@/:\\]{0,63}@)?[^\s@/\\-][^\s@/\\]{0,190})?",
      warning="Agent commands will run on a different computer."),
    S("sandbox", "host_key_checking", "Checking the remote computer",
      "How strictly the remote computer's identity is checked before commands run on it.",
      "select", "Protected work area", "accept-new", "maverick.sandbox",
      subgroup="Remote computer",
      choices=(("yes", "Only computers already known (strictest)"),
               ("accept-new", "Trust a new computer the first time, then check (default)"),
               ("no", "Do not check (not recommended)")),
      weaker=True, order=("yes", "accept-new", "no"),
      warning="Commands could be sent to an impostor computer without anyone noticing."),
    S("sandbox", "namespace", "Cluster area for commands",
      "When commands run in a cluster, the area (namespace) of that cluster they run in.",
      "text", "Protected work area", "default", "maverick.sandbox", subgroup="Cluster",
      max_length=63, weaker="change", pattern=r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?",
      warning="Agent commands will run in a different part of your cluster, which may have "
              "different network rules."),

    # ------------------------------------------------------ document search
    S("knowledge", "embedder", "How documents are indexed",
      "The service that turns document passages into searchable form. Changing it means "
      "documents are indexed again.", "select", "Memory & learning", "hosted",
      "maverick.config", subgroup="Document search",
      choices=(("hosted", "Voyage AI service (its key is set on the server)"),
               ("local", "On this server, no outside service"),
               ("deterministic", "Offline test mode (low quality)")),
      weaker="change",
      warning="Document text may be sent to a different service to be indexed."),
    S("knowledge", "store", "Where the search index is kept",
      "Where searchable passages are stored.", "select", "Memory & learning", "sqlite",
      "maverick.config", subgroup="Document search",
      choices=(("sqlite", "A file on this server (default)"),
               ("pgvector", "Your company database (connection set on the server)"),
               ("qdrant", "An existing Qdrant index (read and erase only)"))),
    S("knowledge", "model", "Indexing model",
      "The model name the indexing service uses, such as voyage-3.", "text",
      "Memory & learning", "voyage-3", "maverick.config", subgroup="Document search",
      pattern=r"[A-Za-z0-9._:/-]{1,128}", max_length=128),
    S("knowledge", "base_url", "Indexing service address",
      "The web address of the indexing service.", "text", "Memory & learning",
      "https://api.voyageai.com/v1", "maverick.config", subgroup="Document search",
      pattern=_HTTPS, max_length=300, weaker="change",
      warning="Document text will be sent to a different address to be indexed."),
    S("knowledge", "dim", "Index size per passage",
      "Must match the indexing model; change it only together with the model.", "number",
      "Memory & learning", 1024, "maverick.config", subgroup="Document search", minimum=64,
      maximum=8192, integer=True, unit="values"),
    S("knowledge", "url", "Qdrant index address",
      "The web address of an existing Qdrant index, when that is where passages are kept.",
      "text", "Memory & learning", "", "maverick.config", subgroup="Document search",
      pattern=r"(https?://[^\s\"'<>]{1,300})?", max_length=300, weaker="insecure",
      warning="Document passages will be sent without encryption, so others on the "
              "network could read them."),

    # ---------------------------------------------- connected business systems
    S("governed_connectors", "connectors", "Business systems whose changes are governed",
      "Changes agents make in these systems are previewed, approved and recorded.",
      "multiselect", "Security", [], "maverick.config", subgroup="Connected business systems",
      choices_from="governed_connectors", weaker="shrink",
      warning="Agent changes to the systems you remove will no longer be previewed and approved."),
    S("governed_connectors", "approver", "Standing approver for changes",
      "The person agent changes to connected business systems are approved against. With "
      "nobody chosen, those changes wait until someone approves them outside Lightwork.",
      "select", "Security", "", "maverick.governed_tools", subgroup="Connected business systems",
      choices_from="people", env=("MAVERICK_GOVERNED_APPROVER",), weaker="change",
      warning="A different person will be the approver of record for agent changes to your "
              "business systems."),

    # ---------------------------------------------------------------- finance
    S("governance.require_human_above", "*", "Pause payments above",
      "Any money movement larger than this waits for a person to approve it. Leave empty to "
      "not pause by amount.", "number", "Finance", None, "maverick.governance",
      subgroup="Approval limits", minimum=0, maximum=1000000000, unit="dollars",
      weaker="higher", warning="Larger payments will go ahead without a person approving."),
    S("governance.deny_above", "*", "Refuse payments above",
      "Any money movement larger than this is refused outright. Leave empty for no ceiling.",
      "number", "Finance", None, "maverick.governance", subgroup="Approval limits", minimum=0,
      maximum=1000000000, unit="dollars", weaker="higher",
      warning="Larger payments will be allowed to go ahead."),
    S("governance", "require_fresh_human_approval", "Ask every time",
      "A paused action always needs a new approval, even if a person chose remember this "
      "before.", "toggle", "Finance", False, "maverick.governance", subgroup="Approval limits",
      weaker=False,
      warning="An earlier remember this approval will let paused actions run without asking."),
    S("finance", "regimes", "Finance rules to enforce",
      "The strictest rule among those chosen applies to each money movement.", "multiselect",
      "Finance", [], "maverick.finance.regimes", subgroup="Rules",
      choices=(("sox", "SOX"), ("coso", "COSO"), ("gaap", "GAAP"), ("pci", "PCI DSS"),
               ("glba", "GLBA"), ("aml", "Anti-money laundering"), ("sec", "SEC rules"),
               ("irs", "IRS rules"), ("dora", "DORA"), ("basel_iii", "Basel III"),
               ("ifrs_17", "IFRS 17")),
      weaker="shrink", warning="Money movements will no longer be held to the rules you remove."),
    S("finance_operations", "federal_register_enable", "Watch the US Federal Register",
      "Check the official Federal Register for new finance rules.", "toggle", "Finance", True,
      "maverick.finance.status", subgroup="Regulatory monitoring"),
    S("finance_operations", "texas_register_enable", "Watch the Texas Register",
      "Check the Texas Register and queue each issue for review.", "toggle", "Finance", False,
      "maverick.finance.status", subgroup="Regulatory monitoring"),
    S("finance_operations", "eur_lex_enable", "Watch EU legislation",
      "Check new EU Parliament and Council legislation for review.", "toggle", "Finance", False,
      "maverick.finance.status", subgroup="Regulatory monitoring"),
    S("finance_operations", "edpb_enable", "Watch EU data protection guidance",
      "Check the European Data Protection Board's news for review.", "toggle", "Finance", False,
      "maverick.finance.status", subgroup="Regulatory monitoring"),
    S("finance_operations", "regulatory_domains", "Topics to send for review",
      "Which kinds of new rules go to the review queue.", "multiselect", "Finance",
      ["finance", "money_transmitter", "insurance_producer"],
      "maverick_dashboard.finance_scheduler", subgroup="Regulatory monitoring",
      choices=(("finance", "Finance"), ("money_transmitter", "Money transmission"),
               ("insurance_producer", "Insurance sales"), ("lending", "Lending"))),
    S("finance_operations", "regulatory_poll_seconds", "Check for new rules every",
      "How often the rule sources above are checked.", "number", "Finance", 3600,
      "maverick_dashboard.finance_scheduler", subgroup="Regulatory monitoring", minimum=5,
      maximum=10080, integer=True, scale=60, unit="minutes"),
    S("finance_operations", "control_test_interval_seconds", "Test finance controls every",
      "How often finance controls are tested and evidence is gathered.", "number", "Finance",
      86400, "maverick.finance.control_testing", subgroup="Control testing", minimum=1,
      maximum=744, integer=True, scale=3600, unit="hours"),
    S("finance_operations", "evidence_due_days", "Evidence is due within",
      "How long the control owner has to supply evidence after a test.", "number", "Finance",
      7, "maverick.finance.control_testing", subgroup="Control testing", minimum=1,
      maximum=365, integer=True, unit="days"),
    S("finance_operations", "control_owner", "Control owner",
      "Who is named as responsible for finance controls and evidence.", "text", "Finance",
      "Finance Control Owner", "maverick.finance.control_testing", subgroup="Control testing",
      pattern=r"[^\n\r<>{}]{1,256}", max_length=256),
    S("finance_operations", "anomaly_enable", "Look for unusual money movements",
      "Open a case when a payment pattern looks unusual.", "toggle", "Finance", True,
      "maverick.finance.control_testing", subgroup="Screening", weaker=False,
      warning="Unusual payment patterns will no longer open a case."),
    S("finance_operations", "sanctions_max_age_hours", "Oldest sanctions list allowed",
      "Screening fails a control test when the sanctions list is older than this.", "number",
      "Finance", 72, "maverick.finance.control_testing", subgroup="Screening", minimum=1,
      maximum=8760, integer=True, unit="hours", weaker="higher",
      warning="Payments may be screened against an older sanctions list without a warning."),

    # --------------------------------------------------------- security suite
    S("threat_hunt", "poll_seconds", "Run the platform hunter every",
      "How often the platform hunter looks for threats when it is on.", "number",
      "Security suite", 300, "maverick_dashboard.security_api", subgroup="Hunting schedule",
      minimum=0.5, maximum=1440, step=0.5, scale=60, unit="minutes", weaker="higher",
      warning="Threats may be found later."),
    S("env_hunt", "poll_seconds", "Run the environment hunter every",
      "How often the environment hunter gathers security events when it is on.", "number",
      "Security suite", 300, "maverick_dashboard.security_api", subgroup="Hunting schedule",
      minimum=0.5, maximum=1440, step=0.5, scale=60, unit="minutes", weaker="higher",
      warning="Threats may be found later."),
)

# Environment hunter event sources: name -> label. Names match
# maverick.env_hunt.tooling.CONNECTOR_NAMES (a test pins that).
ENV_HUNT_SOURCES: dict[str, str] = {
    "cloudtrail": "AWS CloudTrail",
    "guardduty": "AWS GuardDuty",
    "syslog": "System logs",
    "edr": "Device protection software",
    "splunk": "Splunk",
    "elastic": "Elastic",
    "sentinel": "Microsoft Sentinel",
    "kubernetes_audit": "Kubernetes activity log",
    "okta": "Okta",
    "entra": "Microsoft Entra",
}


def _env_hunt_settings() -> tuple[Setting, ...]:
    out: list[Setting] = []
    for name, label in ENV_HUNT_SOURCES.items():
        section = f"env_hunt.connectors.{name}"
        common = {"group": "Security suite", "reader": "maverick.env_hunt.tooling",
                  "subgroup": f"Event source: {label}", "aliases": f"{name} hunter connector"}
        out.append(S(section, "enable", f"Gather events from {label}",
                     f"The environment hunter reads security events from {label} using the "
                     "sign-in details set on your server.", "toggle", default=False, **common))
        out.append(S(section, "pivot_enable", f"Look up related {label} events",
                     "When something suspicious is found, fetch nearby events for context.",
                     "toggle", default=False, **common))
        out.append(S(section, "push_enable", f"Accept events sent in for {label}",
                     f"Let other systems send events that are recorded as coming from {label}.",
                     "toggle", default=False, weaker=True,
                     warning=f"Other systems will be able to submit events that are trusted as "
                             f"if they came from {label}.", **common))
    return tuple(out)


_GOVERNANCE: tuple[Setting, ...] = (
    # ------------------------------------------------------------ AI gateway
    S("llm_gateway", "enable", "Run the AI gateway",
      "AI agents built elsewhere can send their AI requests through Lightwork, where each one "
      "is checked, recorded and kept within budget. Its passwords are set on the server.",
      "toggle", "AI governance", False, "maverick.llm_gateway", subgroup="AI gateway",
      weaker=True,
      warning="Agents that hold the gateway password will be able to send AI requests through "
              "Lightwork, which spends your budget."),
    S("llm_gateway", "upstream_url", "AI service the gateway forwards to",
      "The secure web address of the AI service requests are passed on to, such as "
      "https://api.openai.com.", "text", "AI governance", "", "maverick.llm_gateway",
      subgroup="AI gateway", pattern=r"(" + _HTTPS + r")?", max_length=300, weaker="change",
      warning="Requests, and any data in them, will be sent to a different AI service."),
    S("llm_gateway", "anthropic_upstream_url", "Claude service the gateway forwards to",
      "Where requests written for Claude are passed on to. Leave empty to refuse them.",
      "text", "AI governance", "", "maverick.llm_gateway", subgroup="AI gateway",
      pattern=r"(" + _HTTPS + r")?", max_length=300, weaker="change",
      warning="Requests, and any data in them, will be sent to a different AI service."),
    S("llm_gateway", "allowed_models", "Models the gateway allows",
      "Only requests for these models are passed on. Leave all unticked to allow any model.",
      "multiselect", "AI governance", [], "maverick.llm_gateway", subgroup="AI gateway",
      choices_from="gateway_models", weaker="grow",
      warning="Requests for more models, which may cost more, will be passed on."),
    S("llm_gateway", "screen_prompts", "Screen requests for attacks",
      "Check each request for hidden instructions before passing it on.", "toggle",
      "AI governance", False, "maverick.llm_gateway", subgroup="AI gateway", weaker=False,
      warning="Requests will be passed on without being checked for hidden instructions."),
    S("llm_gateway", "redact_prompts", "Remove personal data from requests",
      "Mask personal details in requests before they leave Lightwork.", "toggle",
      "AI governance", False, "maverick.llm_gateway", subgroup="AI gateway", weaker=False,
      warning="Personal details in requests will be sent to the AI service."),
    S("llm_gateway", "redact_completions", "Remove personal data from answers",
      "Mask personal details in answers before they are returned.", "toggle",
      "AI governance", False, "maverick.llm_gateway", subgroup="AI gateway", weaker=False,
      warning="Personal details in answers will be returned as they are."),
    S("llm_gateway", "max_body_bytes", "Largest request",
      "Bigger requests are refused.", "number", "AI governance", 1048576,
      "maverick.llm_gateway", subgroup="AI gateway", minimum=4, maximum=4096, integer=True,
      scale=1024, unit="KB"),
    S("llm_gateway", "default_max_output_tokens", "Longest answer when none is asked for",
      "The answer length used when a request does not set one, in tokens.", "number",
      "AI governance", 4096, "maverick.llm_gateway", subgroup="AI gateway", minimum=1,
      maximum=1000000, integer=True, unit="tokens"),
    S("llm_gateway", "budget_window_seconds", "Gateway budget period",
      "The period the gateway's request and token limits below count over.", "number",
      "AI governance", 3600, "maverick.llm_gateway", subgroup="AI gateway", minimum=1,
      maximum=8784, integer=True, scale=3600, unit="hours"),
    S("llm_gateway.team_budgets.default", "max_requests", "Requests allowed per period",
      "The most requests callers may make in one budget period. Empty means no limit.",
      "number", "AI governance", None, "maverick.llm_gateway", subgroup="AI gateway",
      minimum=1, maximum=2000000000, integer=True, unit="requests", weaker="higher",
      warning="Callers will be able to send more requests and spend more."),
    S("llm_gateway.team_budgets.default", "max_completion_tokens",
      "Answer tokens allowed per period",
      "The most answer text, in tokens, callers may receive in one budget period. Empty means "
      "no limit.", "number", "AI governance", None, "maverick.llm_gateway",
      subgroup="AI gateway", minimum=1, maximum=2000000000, integer=True, unit="tokens",
      weaker="higher", warning="Callers will be able to spend more."),

    # ------------------------------------------------------- GRC record sync
    S("grc_sync", "enable", "Copy governance records to your GRC system",
      "Send model-risk findings, accepted risks and incidents to your governance, risk and "
      "compliance system as linked records. Evidence stays in Lightwork.", "toggle",
      "AI governance", False, "maverick.grc_sync", subgroup="GRC record sync", weaker=True,
      warning="Summaries of findings, accepted risks and incidents will be sent to your GRC "
              "system."),
    S("grc_sync", "connector", "Your GRC system",
      "The connected system records are sent to. Its address and key are set on the server.",
      "select", "AI governance", "servicenow", "maverick.grc_sync", subgroup="GRC record sync",
      choices_from="governed_connectors"),
    S("grc_sync", "findings_path", "Where findings go",
      "The table in your GRC system that receives findings. Your GRC administrator can give "
      "you this; it is the part of the table's web address after the system's name, starting "
      "with a slash.", "text",
      "AI governance", "", "maverick.grc_sync", subgroup="GRC record sync",
      pattern=r"(/[^\s?#]{0,511})?", max_length=512),
    S("grc_sync", "acceptances_path", "Where accepted risks go",
      "The table in your GRC system that receives accepted risks, in the same form.", "text",
      "AI governance", "", "maverick.grc_sync", subgroup="GRC record sync",
      pattern=r"(/[^\s?#]{0,511})?", max_length=512),
    S("grc_sync", "incidents_path", "Where incidents go",
      "The table in your GRC system that receives incidents, in the same form.", "text",
      "AI governance", "", "maverick.grc_sync", subgroup="GRC record sync",
      pattern=r"(/[^\s?#]{0,511})?", max_length=512),
    S("grc_sync", "backlink_base", "Link back to Lightwork",
      "The address people use to open this dashboard, added to each record so it links back.",
      "text", "AI governance", "", "maverick.grc_sync", subgroup="GRC record sync",
      pattern=r"(" + _HTTPS + r")?", max_length=512),

    # ------------------------------------------------------ outbound GRC sync
    S("grc_outbound_sync", "targets", "Governance systems for assurance records",
      "Where assurance results are sent when outbound GRC records are on.", "multiselect",
      "AI governance", [], "maverick.grc_outbound_sync", subgroup="Outbound assurance records",
      choices=(("servicenow_irm", "ServiceNow risk management"), ("archer", "Archer"))),
    S("grc_outbound_sync", "max_attempts_per_revision", "Tries per record",
      "How many times one record is sent before it waits for a person.", "number",
      "AI governance", 8, "maverick.grc_outbound_sync", subgroup="Outbound assurance records",
      minimum=1, maximum=100, integer=True, unit="tries"),

    # ------------------------------------------------------ drift monitoring
    S("drift_monitoring", "bins", "Groups used to compare results",
      "How finely results are grouped when they are compared with the starting point.",
      "number", "AI governance", 10, "maverick.drift_monitoring",
      subgroup="Model drift monitoring", minimum=2, maximum=64, integer=True, unit="groups"),
    S("drift_monitoring", "min_samples", "Results needed before judging drift",
      "How many new results are needed before drift is judged.", "number", "AI governance", 30,
      "maverick.drift_monitoring", subgroup="Model drift monitoring", minimum=2,
      maximum=50000, integer=True, unit="results", weaker="higher",
      warning="Drift will be reported later, after more results."),
    S("drift_monitoring", "psi_threshold", "Alert when the spread of results shifts by",
      "How far the overall spread of results may move before an alert (stability score).",
      "number", "AI governance", 0.2, "maverick.drift_monitoring",
      subgroup="Model drift monitoring", minimum=0, maximum=100, step=0.01, unit="score",
      weaker="higher", warning="Bigger changes in results will pass without an alert."),
    S("drift_monitoring", "js_threshold", "Alert when results differ by",
      "How different new results may be from the starting point before an alert, from 0 to 1.",
      "number", "AI governance", 0.1, "maverick.drift_monitoring",
      subgroup="Model drift monitoring", minimum=0, maximum=1, step=0.01, unit="score",
      weaker="higher", warning="Bigger changes in results will pass without an alert."),
    S("drift_monitoring", "kl_threshold", "Alert when information changes by",
      "A second measure of how much new results differ from the starting point.", "number",
      "AI governance", 0.1, "maverick.drift_monitoring", subgroup="Model drift monitoring",
      minimum=0, maximum=100, step=0.01, unit="score", weaker="higher",
      warning="Bigger changes in results will pass without an alert."),
    S("drift_monitoring", "ks_p_value_floor", "Confidence needed for number changes",
      "How unlikely a change in numbers must be to raise an alert. Smaller is stricter about "
      "proof, so fewer alerts.", "number", "AI governance", 0.01, "maverick.drift_monitoring",
      subgroup="Model drift monitoring", minimum=0, maximum=0.5, step=0.001, unit="chance",
      weaker="lower", warning="Fewer changes will raise an alert."),
    S("drift_monitoring", "chi2_p_value_floor", "Confidence needed for category changes",
      "How unlikely a change in categories must be to raise an alert.", "number",
      "AI governance", 0.01, "maverick.drift_monitoring", subgroup="Model drift monitoring",
      minimum=0, maximum=0.5, step=0.001, unit="chance", weaker="lower",
      warning="Fewer changes will raise an alert."),
    S("drift_monitoring", "embedding_cosine_threshold", "Alert when meaning shifts by",
      "How far the meaning of text results may move before an alert, from 0 to 2.", "number",
      "AI governance", 0.1, "maverick.drift_monitoring", subgroup="Model drift monitoring",
      minimum=0, maximum=2, step=0.01, unit="score", weaker="higher",
      warning="Bigger changes in meaning will pass without an alert."),
    S("drift_monitoring", "performance_decay_threshold", "Alert when accuracy drops by",
      "How much accuracy may fall before an alert, as a share from 0 to 1.", "number",
      "AI governance", 0.05, "maverick.drift_monitoring", subgroup="Model drift monitoring",
      minimum=0, maximum=1, step=0.01, unit="share", weaker="higher",
      warning="Bigger drops in accuracy will pass without an alert."),
    S("drift_monitoring", "evidence_validity_seconds", "Drift checks stay valid for",
      "How long a drift check counts as current evidence.", "number", "AI governance",
      2592000, "maverick.drift_monitoring", subgroup="Model drift monitoring", minimum=1,
      maximum=366, integer=True, scale=86400, unit="days", weaker="higher",
      warning="Older drift checks will still count as current evidence."),

    # ------------------------------------------------ shared governance inventory
    S("governance_inventory", "enable", "Shared governance inventory",
      "Keep one combined, versioned view of records across the governance modules.", "toggle",
      "AI governance", False, "maverick_dashboard.shared_governance_inventory_composition",
      subgroup="Shared governance inventory"),
    S("governance_inventory", "retention_seconds", "Keep inventory snapshots for",
      "How long saved inventory snapshots are kept.", "number", "AI governance", 31536000,
      "maverick_dashboard.shared_governance_inventory_composition",
      subgroup="Shared governance inventory", minimum=1, maximum=3650, integer=True,
      scale=86400, unit="days", weaker="lower",
      warning="Older inventory snapshots will be deleted sooner."),
    S("governance_inventory", "max_source_records", "Records read from each module",
      "The most records read from one module when the inventory is built.", "number",
      "AI governance", 10000, "maverick_dashboard.shared_governance_inventory_composition",
      subgroup="Shared governance inventory", minimum=1, maximum=100000, integer=True,
      unit="records"),
    S("governance_inventory", "max_entities", "Items in the inventory",
      "The most items one inventory may hold.", "number", "AI governance", 20000,
      "maverick_dashboard.shared_governance_inventory_composition",
      subgroup="Shared governance inventory", minimum=1, maximum=100000, integer=True,
      unit="items"),
    S("governance_inventory", "max_relationships", "Links in the inventory",
      "The most links between items one inventory may hold.", "number", "AI governance", 40000,
      "maverick_dashboard.shared_governance_inventory_composition",
      subgroup="Shared governance inventory", minimum=1, maximum=200000, integer=True,
      unit="links"),
    S("governance_inventory", "max_snapshots", "Snapshots kept",
      "The most inventory snapshots kept at once.", "number", "AI governance", 10000,
      "maverick_dashboard.shared_governance_inventory_composition",
      subgroup="Shared governance inventory", minimum=2, maximum=10000, integer=True,
      unit="snapshots"),

    # ------------------------------------------------------------ AI inventory
    S("ai_inventory", "connectors", "Where to find AI systems",
      "The platforms the AI inventory reads from, using sign-in details set on the server.",
      "multiselect", "AI governance", [], "maverick.ai_inventory", subgroup="AI inventory",
      choices=(("agentforce", "Salesforce Agentforce"), ("azure_ai_foundry", "Azure AI Foundry"),
               ("aws_sagemaker", "Amazon SageMaker"), ("bedrock", "Amazon Bedrock"),
               ("copilot_studio", "Microsoft Copilot Studio"),
               ("databricks_unity_catalog", "Databricks Unity Catalog"),
               ("hugging_face", "Hugging Face"), ("mlflow", "MLflow"), ("openai", "OpenAI"),
               ("replicate", "Replicate"), ("snowflake", "Snowflake"),
               ("snowflake_cortex", "Snowflake Cortex"), ("vertex_ai", "Google Vertex AI"))),
    S("ai_inventory", "poll_seconds", "Refresh the inventory every",
      "How often the platforms above are read again.", "number", "AI governance", 3600,
      "maverick_dashboard.ai_inventory_scheduler", subgroup="AI inventory", minimum=1,
      maximum=1440, integer=True, scale=60, unit="minutes"),
    S("ai_inventory", "page_cap", "Pages read per platform",
      "The most result pages read from one platform in one refresh.", "number",
      "AI governance", 100, "maverick.ai_inventory", subgroup="AI inventory", minimum=1,
      maximum=1000, integer=True, unit="pages"),
    S("ai_inventory", "retry_attempts", "Tries per platform",
      "How many times a platform is tried before the refresh gives up on it.", "number",
      "AI governance", 3, "maverick.ai_inventory", subgroup="AI inventory", minimum=1,
      maximum=10, integer=True, unit="tries"),
    S("ai_inventory", "timeout_seconds", "Time limit per platform request",
      "How long one request to a platform may take.", "number", "AI governance", 30.0,
      "maverick.ai_inventory", subgroup="AI inventory", minimum=0.1, maximum=300, step=0.1,
      unit="seconds"),

    # ----------------------------------------------------------- AI entity tasks
    S("ai_entity_tasks", "max_tasks", "Open AI system tasks",
      "The most follow-up tasks about AI systems kept at once.", "number", "AI governance",
      100000, "maverick_dashboard.ai_entity_tasks_composition", subgroup="AI system tasks",
      minimum=1, maximum=1000000, integer=True, unit="tasks"),
    S("ai_entity_tasks", "retention_seconds", "Keep finished tasks for",
      "How long finished tasks are kept.", "number", "AI governance", 31536000,
      "maverick_dashboard.ai_entity_tasks_composition", subgroup="AI system tasks",
      minimum=1, maximum=3650, integer=True, scale=86400, unit="days", weaker="lower",
      warning="Finished tasks will be deleted sooner."),

    # ---------------------------------------------------------- governance loop
    S("ai_governance_loop", "poll_seconds", "Check for governance work every",
      "How often the governance loop looks for new work.", "number", "AI governance", 300,
      "maverick_dashboard.ai_governance_loop_composition", subgroup="AI governance loop",
      minimum=5, maximum=3600, integer=True, unit="seconds"),
    S("ai_governance_loop", "batch_size", "Items handled at a time",
      "How many items the loop handles in one pass.", "number", "AI governance", 100,
      "maverick_dashboard.ai_governance_loop_composition", subgroup="AI governance loop",
      minimum=1, maximum=500, integer=True, unit="items"),
    S("ai_governance_loop", "max_attempts", "Tries per item",
      "How many times an item is tried before it waits for a person.", "number",
      "AI governance", 5, "maverick_dashboard.ai_governance_loop_composition",
      subgroup="AI governance loop", minimum=1, maximum=20, integer=True, unit="tries"),
    S("ai_governance_loop", "retry_base_seconds", "Wait before trying again",
      "How long to wait before the first retry; later retries wait longer.", "number",
      "AI governance", 30, "maverick_dashboard.ai_governance_loop_composition",
      subgroup="AI governance loop", minimum=1, maximum=86400, integer=True, unit="seconds"),
    S("ai_governance_loop", "max_lag_seconds", "Warn when work is behind by",
      "Show a warning when governance work falls this far behind.", "number", "AI governance",
      900, "maverick_dashboard.ai_governance_loop_composition", subgroup="AI governance loop",
      minimum=1, maximum=525600, integer=True, scale=60, unit="minutes", weaker="higher",
      warning="Delays in governance work will be flagged later."),

    # ---------------------------------------------------- model improvement
    S("model_improvement", "enable", "Train improved specialist models",
      "Allow training runs that improve specialist models from your reviewed work.", "toggle",
      "AI governance", False, "maverick.config", subgroup="Model improvement"),
    S("model_improvement", "allow_hosted", "Allow training on an outside service",
      "Training runs may use a hosted training service instead of this server.", "toggle",
      "AI governance", False, "maverick.config", subgroup="Model improvement", weaker=True,
      warning="Examples from your work will be sent to an outside training service."),
    S("model_improvement", "require_signed_receipt", "Require a signed training receipt",
      "An improved model is only used once its training run has a verified, signed receipt.",
      "toggle", "AI governance", True, "maverick.config", subgroup="Model improvement",
      weaker=False, warning="Improved models could be used without proof of how they were trained."),
    S("model_improvement", "minimum_train_families", "Different task kinds needed for training",
      "The fewest different kinds of task a training run must learn from.", "number",
      "AI governance", 20, "maverick.config", subgroup="Model improvement", minimum=20,
      maximum=1000000, integer=True, unit="kinds"),
    S("model_improvement", "minimum_holdout_families", "Different task kinds kept for testing",
      "The fewest different kinds of task kept aside to test an improved model.", "number",
      "AI governance", 20, "maverick.config", subgroup="Model improvement", minimum=20,
      maximum=1000000, integer=True, unit="kinds"),

    # -------------------------------------------- assessment evidence proposals
    S("assessment_evidence_autopopulation", "apply_enabled", "Let accepted answers fill assessments",
      "When a reviewer accepts a proposed answer, write it into the assessment.", "toggle",
      "AI governance", False,
      "maverick_dashboard.assessment_evidence_autopopulation_composition",
      subgroup="Assessment evidence proposals", weaker=True,
      warning="Accepted proposals will change assessment answers directly."),
    S("assessment_evidence_autopopulation", "min_confidence_bps", "Lowest confidence to propose",
      "Only propose an answer when the evidence supports it at least this strongly.", "number",
      "AI governance", 7000, "maverick_dashboard.assessment_evidence_autopopulation_composition",
      subgroup="Assessment evidence proposals", minimum=0.01, maximum=100, step=0.01,
      integer=True, scale=100, unit="percent", weaker="lower",
      warning="Answers backed by weaker evidence will be proposed."),
    S("assessment_evidence_autopopulation", "max_citations_per_answer", "Evidence cited per answer",
      "The most pieces of evidence cited for one proposed answer.", "number", "AI governance",
      8, "maverick_dashboard.assessment_evidence_autopopulation_composition",
      subgroup="Assessment evidence proposals", minimum=1, maximum=32, integer=True,
      unit="pieces"),
    S("assessment_evidence_autopopulation", "retention_seconds", "Keep proposals for",
      "How long proposals are kept.", "number", "AI governance", 31536000,
      "maverick_dashboard.assessment_evidence_autopopulation_composition",
      subgroup="Assessment evidence proposals", minimum=1, maximum=3660, integer=True,
      scale=86400, unit="days", weaker="lower", warning="Proposals will be deleted sooner."),

    # --------------------------------------------------------- AI vendor risk
    S("ai_vendor_risk", "portal_enable", "Vendor answer portal",
      "Let vendors answer AI risk questionnaires through a private link.", "toggle",
      "AI governance", False, "maverick.ai_vendor_portal", subgroup="AI vendor risk", weaker=True,
      warning="People outside your organisation will be able to submit answers through a link."),

    # ------------------------------------------------------ governance agents
    S("governance_agents", "enabled_agents", "Governance agents available",
      "Which governance specialists can be used when governance agents are on.", "multiselect",
      "AI governance", ["breach_response", "privacy_risk_assessment", "program_copilot",
                        "knowledgebase_governance", "third_party_risk"],
      "maverick.governance_agents", subgroup="Governance agents",
      choices=(("breach_response", "Breach response"),
               ("privacy_risk_assessment", "Privacy risk assessment"),
               ("program_copilot", "Program assistant"),
               ("knowledgebase_governance", "Knowledge base governance"),
               ("third_party_risk", "Third-party risk"))),

    # ---------------------------------------------------------- document vault
    S("governed_document_vault", "max_document_bytes", "Largest document",
      "Bigger documents are refused.", "number", "AI governance", 26214400,
      "maverick.governed_document_vault", subgroup="Document vault", minimum=1, maximum=100,
      integer=True, scale=1048576, unit="MB"),
    S("governed_document_vault", "max_documents", "Documents kept",
      "The most documents the vault holds.", "number", "AI governance", 100000,
      "maverick.governed_document_vault", subgroup="Document vault", minimum=1,
      maximum=1000000, integer=True, unit="documents"),
    S("governed_document_vault", "retention_seconds", "Keep documents for",
      "How long documents are kept.", "number", "AI governance", 31536000,
      "maverick.governed_document_vault", subgroup="Document vault", minimum=1, maximum=3650,
      integer=True, scale=86400, unit="days", weaker="lower",
      warning="Documents will be deleted sooner."),
    S("governed_document_vault", "grant_ttl_seconds", "Download links last",
      "How long a one-time download link works.", "number", "AI governance", 60,
      "maverick.governed_document_vault", subgroup="Document vault", minimum=5, maximum=300,
      integer=True, unit="seconds", weaker="higher",
      warning="Download links will work for longer if they are passed on."),

    # ------------------------------------------ administrator document access
    S("administration_document_access", "enable", "Administrator document access",
      "Let administrators open governed documents through short-lived, recorded links.",
      "toggle", "AI governance", False, "maverick.administration_document_access",
      subgroup="Administrator document access", weaker=True,
      warning="Administrators will be able to open governed documents."),
    S("administration_document_access", "default_ttl_seconds", "Access lasts by default",
      "How long an administrator's access to a document lasts unless they choose less.",
      "number", "AI governance", 300, "maverick.administration_document_access",
      subgroup="Administrator document access", minimum=30, maximum=3600, integer=True,
      unit="seconds", weaker="higher", warning="Document access will last longer."),
    S("administration_document_access", "max_ttl_seconds", "Longest access allowed",
      "The longest an administrator's access to a document may last.", "number",
      "AI governance", 900, "maverick.administration_document_access",
      subgroup="Administrator document access", minimum=30, maximum=3600, integer=True,
      unit="seconds", weaker="higher", warning="Document access will be allowed to last longer."),
    S("administration_document_access", "max_uses", "Opens per access",
      "How many times one access may open the document.", "number", "AI governance", 1,
      "maverick.administration_document_access", subgroup="Administrator document access",
      minimum=1, maximum=10, integer=True, unit="opens", weaker="higher",
      warning="One access will be able to open a document more times."),
    S("administration_document_access", "retention_seconds", "Keep access records for",
      "How long records of administrator access are kept.", "number", "AI governance", 604800,
      "maverick.administration_document_access", subgroup="Administrator document access",
      minimum=1, maximum=366, integer=True, scale=86400, unit="days", weaker="lower",
      warning="Records of who opened documents will be deleted sooner."),
)

_INTEGRATIONS_MORE: tuple[Setting, ...] = (
    # ------------------------------------------- outside tool gateway (sidecar)
    S("mcp_sidecar", "enable", "Offer reviewed tools to outside AI clients",
      "Outside AI clients with their own credentials may use the reviewed tools below, each "
      "checked, recorded and kept within budget.", "toggle", "Integrations", False,
      "maverick_mcp.sidecar", subgroup="Tool gateway for outside AI clients", weaker=True,
      restart=True,
      warning="Outside AI clients will be able to use the reviewed tools you list."),
    S("mcp_sidecar", "upstream_url", "Tool server the gateway fronts",
      "The secure web address of the tool server whose tools are offered.", "text",
      "Integrations", "", "maverick_mcp.sidecar", subgroup="Tool gateway for outside AI clients",
      pattern=r"(" + _HTTPS + r"|http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?(/[^\s\"'<>]*)?)?",
      max_length=300, restart=True, weaker="change",
      warning="Outside AI clients will reach a different tool server."),
    S("mcp_sidecar", "tools", "Reviewed tools",
      "Only these tools are offered, each with the risk level your team gave it. Type the "
      "tool's name exactly as the tool server lists it.", "table", "Integrations", {},
      "maverick_mcp.sidecar", subgroup="Tool gateway for outside AI clients", row_kind="risk",
      restart=True, weaker="grow",
      warning="More tools, or tools marked as less risky, will be offered to outside AI clients."),
    S("mcp_sidecar", "max_calls_per_window", "Calls allowed per client",
      "The most tool calls one client may make each hour. Zero means no count limit.",
      "number", "Integrations", 0, "maverick_mcp.sidecar",
      subgroup="Tool gateway for outside AI clients", minimum=0, maximum=1000000, integer=True,
      unit="calls per hour", restart=True),
    S("mcp_sidecar", "listen_port", "Gateway port",
      "The port on this server the gateway listens on.", "number", "Integrations", 8787,
      "maverick_mcp.sidecar", subgroup="Tool gateway for outside AI clients", minimum=1024,
      maximum=65535, integer=True, unit="port", restart=True),
    S("mcp_sidecar", "require_shield", "Require the safety checks",
      "Refuse to start the gateway when Lightwork's safety checks are not installed.", "toggle",
      "Integrations", True, "maverick_mcp.sidecar", subgroup="Tool gateway for outside AI clients",
      restart=True, weaker=False,
      warning="The gateway could run without screening tool calls for threats."),

    # ------------------------------------------------------------ local models
    S("system", "local_first", "Prefer AI models on this network",
      "When a local model is running, use it before an outside AI service.", "toggle",
      "Integrations", False, "maverick.provider_local_first", subgroup="Local AI models",
      env=("MAVERICK_LOCAL_FIRST",)),
    S("local_first", "model", "Local model to prefer",
      "The local model used when the option above is on.", "select", "Integrations", "",
      "maverick.provider_local_first", subgroup="Local AI models", choices_from="local_models"),
    S("local_runtime", "enabled", "Run a local model server",
      "Let Lightwork start and manage a model server on this computer.", "toggle",
      "Integrations", False, "maverick.local_runtime", subgroup="Local AI models", env=("MAVERICK_LOCAL_RUNTIME_ENABLED",)),
    S("local_runtime", "engine", "Model server program",
      "The program that serves the local model.", "select", "Integrations", "vllm",
      "maverick.local_runtime", subgroup="Local AI models",
      choices=(("vllm", "vLLM"), ("tgi", "Text Generation Inference"), ("llamacpp", "llama.cpp")), env=("MAVERICK_LOCAL_RUNTIME_ENGINE",)),
    S("local_runtime", "model", "Model to serve",
      "The model name or existing local model file or folder the server loads.", "text", "Integrations",
      "", "maverick.local_runtime", subgroup="Local AI models",
      pattern=r"[^\x00-\x1f\x7f]{0,1024}", max_length=1024, env=("MAVERICK_LOCAL_RUNTIME_MODEL",)),
    S("local_runtime", "port", "Local connection number",
      "Choose an unused connection number if another program is already using this one. Zero uses the model program's usual choice.",
      "number", "Integrations", 0, "maverick.local_runtime", subgroup="Local AI models",
      minimum=0, maximum=65535, integer=True, env=("MAVERICK_LOCAL_RUNTIME_PORT",)),
    S("local_runtime", "precision", "Model precision",
      "Lower precision uses less memory and may lower answer quality.", "select",
      "Integrations", "auto", "maverick.local_runtime", subgroup="Local AI models",
      choices=(("auto", "Automatic (default)"), ("bf16", "High (bf16)"), ("fp16", "High (fp16)"),
               ("int8", "Medium (8-bit)"), ("int4", "Low (4-bit)")), env=("MAVERICK_LOCAL_RUNTIME_PRECISION",)),
    S("local_runtime", "max_concurrent", "Requests served at once",
      "How many requests the server answers at the same time. Zero uses the program's choice.",
      "number", "Integrations", 0, "maverick.local_runtime", subgroup="Local AI models",
      minimum=0, maximum=4096, integer=True, unit="requests", env=("MAVERICK_LOCAL_RUNTIME_MAX_CONCURRENT",)),
    S("local_runtime", "kv_cache", "Reuse work between similar requests",
      "Keep the start of recent requests so similar ones answer faster.", "select",
      "Integrations", "", "maverick.local_runtime", subgroup="Local AI models",
      choices=(("", "Off (default)"), ("persistent", "On")), env=("MAVERICK_LOCAL_RUNTIME_KV_CACHE",)),
    S("local_runtime", "autoscale", "Add servers when busy",
      "Start more copies of the server when requests queue up.", "toggle", "Integrations",
      False, "maverick.local_runtime", subgroup="Local AI models", env=("MAVERICK_LOCAL_RUNTIME_AUTOSCALE",)),
    S("local_runtime", "min_replicas", "Fewest server copies",
      "The fewest copies of the model server kept running.", "number", "Integrations", 1,
      "maverick.local_runtime", subgroup="Local AI models", minimum=1, maximum=64,
      integer=True, unit="copies", env=("MAVERICK_LOCAL_RUNTIME_MIN_REPLICAS",)),
    S("local_runtime", "max_replicas", "Most server copies",
      "The most copies of the model server started when it is busy.", "number", "Integrations", 1,
      "maverick.local_runtime", subgroup="Local AI models", minimum=1, maximum=64,
      integer=True, unit="copies", env=("MAVERICK_LOCAL_RUNTIME_MAX_REPLICAS",)),

    # ------------------------------------------------------ plugin permissions
    S("plugins", "grant", "What plugins may do",
      "Permissions granted to every turned-on plugin that asks for them. Lightwork checks "
      "what a plugin declares before loading it; it does not stop a loaded plugin from "
      "doing more. Keep 'Where plugins run' on a separate program for a real boundary.",
      "multiselect",
      "Integrations", [], "maverick.plugins", subgroup="Plugin permissions",
      choices=(("network", "Use the internet"), ("fs_write", "Change files"),
               ("subprocess", "Run other programs")),
      weaker="grow", warning="Plugins will be able to do more on this server."),
    S("plugins", "enforce_permissions", "Skip plugins that ask for more",
      "A plugin asking for a permission not granted above is not loaded. This is a "
      "check on what the plugin declares, not a limit on what it can do once loaded.",
      "toggle",
      "Integrations", True, "maverick.plugins", subgroup="Plugin permissions", weaker=False,
      env=("MAVERICK_PLUGINS_ENFORCE",),
      warning="Plugins asking for permissions you have not granted will load anyway."),

    # ------------------------------------------------- usage limits, any tool
    S("rate_limits", "other", "Usage limits for other tools",
      "Add a limit for any other tool, or for every tool from outside tool servers at once.",
      "table", "Performance", {}, "maverick.safety.rate_limiter", key_kind="entries",
      row_kind="rate", choices_from="tools", subgroup="Usage limits for other tools",
      fixed_keys=("web_search", "http_fetch", "shell"), weaker="grow",
      warning="Tools will be able to run more often."),
)

C = Column
_RISK_CEILING = (("", "No extra limit"), ("low", "Low risk only"),
                 ("medium", "Up to medium risk"), ("high", "Up to high risk"))
_REF = r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}"
# Catalog addresses never carry query text (it can hold an access token that
# would otherwise be copied into the activity record).
_HTTPS_PLAIN = r"https://[^\s\"'<>?#]{1,300}"
_REVIEW_ENV = ("MAVERICK_REVIEW_CHECKPOINT_DOLLARS", "MAVERICK_REVIEW_CHECKPOINT_TOOL_CALLS",
               "MAVERICK_REVIEW_CHECKPOINT_WALL_SECONDS")

_POLICY: tuple[Setting, ...] = (
    # ------------------------------------------------ review pauses (safety)
    S("safety.review_checkpoint", "dollars", "Pause for a review after spending",
      "A long task stops for a person to review it each time it has spent this much more. "
      "Leave empty for no pause by amount.", "number", "Safety", None,
      "maverick.review_checkpoint", subgroup="Review pauses on long tasks", minimum=0.01,
      maximum=100000, unit="dollars", env=_REVIEW_ENV, weaker="higher", none_text="Off",
      warning="Long tasks will run further, or without stopping, before a person reviews them."),
    S("safety.review_checkpoint", "tool_calls", "Pause for a review after actions",
      "A long task stops for a person to review it each time it has taken this many more "
      "actions. Leave empty for no pause by count.", "number", "Safety", None,
      "maverick.review_checkpoint", subgroup="Review pauses on long tasks", minimum=1,
      maximum=100000, integer=True, unit="actions", env=_REVIEW_ENV, weaker="higher",
      none_text="Off",
      warning="Long tasks will run further, or without stopping, before a person reviews them."),
    S("safety.review_checkpoint", "wall_seconds", "Pause for a review after running",
      "A long task stops for a person to review it each time it has run this much longer. "
      "Leave empty for no pause by time.", "number", "Safety", None,
      "maverick.review_checkpoint", subgroup="Review pauses on long tasks", minimum=1,
      maximum=10080, unit="minutes", scale=60, env=_REVIEW_ENV, weaker="higher",
      none_text="Off",
      warning="Long tasks will run further, or without stopping, before a person reviews them."),

    # ------------------------------------------------------ approvals (safety)
    S("actions", "require_approval_at", "Actions in your systems that need a person",
      "Changes agents and outside agents make in your connected systems wait for a person "
      "from this risk level up.", "select", "Safety", "high", "maverick.governed_actions",
      subgroup="Approvals",
      choices=(("low", "Every change, whatever its risk"),
               ("medium", "Medium and high risk changes"),
               ("high", "High risk changes only (default)")),
      weaker=True, order=("low", "medium", "high"),
      warning="Riskier changes in your connected systems will go ahead without a person "
              "approving them."),
    S("actions", "enable", "Keep a traceable record of consequential actions",
      "Record each consequential action an agent takes, with what led to it, in a record "
      "that shows any later change.", "toggle", "Safety", False, "maverick.governed_actions",
      subgroup="Approvals", env=("MAVERICK_GOVERNED_ACTIONS",), weaker=False,
      warning="Consequential actions will no longer be recorded with what led to them."),
    S("approval", "delegation", "Suggest reviewers for approvals",
      "Add a suggested reviewer to matching approvals. Rules are checked from the top "
      "and the first match wins. Other authorized reviewers can still decide; this "
      "setting does not restrict decision authority.",
      "rules", "Safety", [], "maverick.approval_delegation", subgroup="Approvals",
      columns=(
          C("delegate_to", "Suggested reviewer", "select", choices_from="people_only", required=True),
          C("min_risk", "For risk", "select", default="",
            choices=(("", "Any risk"), ("low", "Low and above"), ("medium", "Medium and above"),
                     ("high", "High and above"), ("critical", "Critical only"))),
          C("tool_glob", "For tool", "pick", choices_from="tools_any", default="*",
            required=True),
      ),
      item_label="Rule", add_label="Add a rule",
      empty_text="No rules yet, so every approval goes to the shared queue.",
      empty_hint="Nobody has been added yet. Add people on the People page first.",
      weaker="change", warning="Approvals will be sent to different people than before."),

    # ------------------------------------------------- tools per chat app
    S("security", "channels", "Tools allowed in each chat app",
      "Limit what agents may do when work arrives from a particular chat app. Blocked tools "
      "are never used there; when you list allowed tools, only those are used; the risk "
      "limit leaves out riskier tools.", "table", "Security", {}, "maverick.safety.tool_acl",
      subgroup="Tools per chat app", row_kind="grid", choices_from="chat_channels",
      columns=(
          C("denied_tools", "Blocked tools", "picks", choices_from="tools", max_items=500),
          C("allowed_tools", "Only these tools", "picks", choices_from="tools", max_items=500),
          C("max_risk", "Riskiest tools allowed", "select", choices=_RISK_CEILING, default=""),
      ),
      row_label="Chat app", item_label="Chat app", add_label="Add rules for this app",
      empty_text="No chat app has its own tool rules yet.",
      empty_hint="No chat apps are set up yet. Set one up on the Channels page first.",
      weaker="acl",
      warning="Agents will be able to use more tools, or riskier tools, when work arrives "
              "from that chat app.", aliases="tool access channel telegram slack deny allow"),

    # ------------------------------------------ spending per AI service
    S("budget", "provider_caps", "Most to spend with each AI service",
      "Across every task, spending with an AI service stops for the rest of the period once "
      "it reaches its limit.", "table", "Spending & limits", {}, "maverick.provider_cost_cap",
      subgroup="Spending per AI service", row_kind="grid", choices_from="providers",
      scalar=True,
      columns=(C("cap", "Most to spend", "number", minimum=0.01, maximum=10000000,
                 unit="dollars", required=True),),
      row_label="AI service", item_label="AI service", add_label="Add a limit",
      empty_text="No AI service has a spending limit yet.",
      empty_hint="No AI services are set up yet. Add one under AI service keys on the "
                 "Settings page first.",
      weaker="cap", warning="More can be spent with that AI service, or its limit will be removed."),
    S("budget", "provider_caps_period", "Spending limits apply per",
      "Whether the limits above count spending for each day or each calendar month.",
      "select", "Spending & limits", "day", "maverick.provider_cost_cap",
      subgroup="Spending per AI service", env=("MAVERICK_PROVIDER_CAPS_PERIOD",),
      choices=(("day", "Day (default)"), ("month", "Calendar month")),
      weaker=True, order=("month", "day"),
      warning="The same limits will apply to a shorter period, so more can be spent in total."),

    # ------------------------------------------------ Ekko (privacy)
    S("ekko", "allowed_apps", "Apps Ekko may notice",
      "People can let Ekko notice their work only in the apps chosen here. With none "
      "chosen, the list set by your installer applies.", "multiselect", "Privacy", [],
      "maverick.config", subgroup="Work pattern discovery (Ekko)", choices_from="ekko_apps",
      weaker="grow", warning="Ekko will be able to notice work in more apps."),
    S("ekko", "blocked_apps", "Apps Ekko must never notice",
      "Blocked even if they are allowed above. Email, chat, customer and finance systems and "
      "databases are always blocked as well.", "multiselect", "Privacy", [], "maverick.config",
      subgroup="Work pattern discovery (Ekko)", choices_from="ekko_apps", weaker="shrink",
      warning="Ekko may notice work in the apps you remove from this list."),
    S("ekko", "capture_level", "How much Ekko records",
      "What Ekko writes down about work in an allowed app.", "select", "Privacy",
      "application_metadata", "maverick.config", subgroup="Work pattern discovery (Ekko)",
      choices=(("application_metadata", "Only which app is in use (recommended)"),
               ("guided", "The app, the action and the kind of document")),
      weaker=True, order=("application_metadata", "guided"),
      warning="Ekko will record more detail about what people do in each app."),
    S("ekko", "retention_days", "Days Ekko keeps what it notices",
      "How long observations stay before they are removed.", "number", "Privacy", 14,
      "maverick.config", subgroup="Work pattern discovery (Ekko)", minimum=2, maximum=30,
      integer=True, unit="days", weaker="higher",
      warning="What Ekko notices will be kept for longer."),
    S("ekko", "enrollment_days", "Longest a person can turn Ekko on for",
      "After this many days Ekko stops until the person turns it on again.", "number",
      "Privacy", 30, "maverick.config", subgroup="Work pattern discovery (Ekko)", minimum=1,
      maximum=90, integer=True, unit="days", weaker="higher",
      warning="People will be able to leave Ekko on for longer before it asks again."),
    S("ekko", "min_occurrences", "Repeats before a task is suggested",
      "How many times a pattern must be seen before Ekko suggests automating it.", "number",
      "Privacy", 3, "maverick.config", subgroup="Work pattern discovery (Ekko)", minimum=2,
      maximum=100, integer=True, unit="times"),
    S("ekko", "planning_enabled", "Save private Ekko opportunity plans",
      "Let each person save task descriptions, benefit assumptions and pilot results for their own device. "
      "Plans are encrypted, expire within the Ekko retention period and can be erased. This does not enable recording or run work.",
      "toggle", "Privacy", False, "maverick.config", subgroup="Work pattern discovery (Ekko)"),
    S("ekko", "build_enabled", "Let Ekko find and build workflow drafts",
      "Build private workflows from repeated business requests, reviewed activity and tasks the customer describes. "
      "Building starts no execution or schedule. Workflows must also be enabled.",
      "toggle", "Privacy", False, "maverick.config", subgroup="Work pattern discovery (Ekko)"),
    S("ekko", "min_distinct_days", "Days a pattern must appear on",
      "A pattern must be seen on at least this many different days before it is suggested.",
      "number", "Privacy", 2, "maverick.config", subgroup="Work pattern discovery (Ekko)",
      minimum=2, maximum=30, integer=True, unit="days"),

    # ------------------------------------ self-improving instructions (learning)
    S("approval_challenges", "enable", "Check fictional approval races locally",
      "Allow fictional approval practices and isolated checks of this installation’s safeguards. "
      "No customer work, credentials or AI calls are used. Each check and exact file export needs separate review; no live guard is activated.",
      "toggle", "Memory & learning", False, "maverick.approval_challenges", subgroup="Shareable approval practices"),
    S("instruction_capture", "enable", "Record instructions from authorized tasks",
      "Allow a person to record the instructions Lightwork gives the AI connection on one task's next successful call started after consent. "
      "Each task needs separate consent. This local installation keeps private instruction text; recording does not start work or enable learning.",
      "toggle", "Memory & learning", False, "maverick.instruction_capture", subgroup="Recorded instructions"),
    S("self_harness", "risk_limited", "Use the careful improvement profile",
      "Improvements to agent instructions must pass unseen tests, repeated checks and a trial "
      "on a small share of work before they are used.", "toggle", "Memory & learning", True,
      "maverick.config", subgroup="Self-improving instructions", partial_default=False,
      weaker=False, warning="Improvements to agent instructions could be adopted on weaker evidence."),
    S("self_harness", "auto_run", "Look for improvements every night",
      "Review recurring mistakes on the overnight learning schedule. Improvements are "
      "adopted only when the configured checks pass. See the last review on Learning.", "toggle",
      "Memory & learning", True, "maverick.config", subgroup="Self-improving instructions",
      partial_default=False),
    S("self_harness", "eval_budget_dollars", "Most to spend testing improvements",
      "The most one night's testing may cost. With the careful profile on, never more than "
      "5 dollars; with it off and nothing set, there is no limit.", "number", "Memory & learning", 5.0, "maverick.config",
      subgroup="Self-improving instructions", minimum=0.01, maximum=1000, unit="dollars",
      weaker="higher",
      warning="Testing improvements may cost more each night."),
    S("self_harness", "corpus_harvest", "Learn test cases from past tasks",
      "Turn tasks that failed and later succeeded into new test cases for improvements.",
      "select", "Memory & learning", "off", "maverick.config",
      subgroup="Self-improving instructions",
      choices=(("off", "Off (default)"), ("propose", "Suggest them for a person to review"),
               ("auto", "Add them without review")),
      weaker=True, order=("off", "propose", "auto"),
      warning="New test cases will be added without a person reviewing them."),
    S("self_harness", "transfer_auto", "Share proven improvements between models",
      "Each night, try improvements proven on one model with your other models, with the "
      "same tests and trial.", "toggle", "Memory & learning", False, "maverick.config",
      subgroup="Self-improving instructions"),
    S("knowledge_access", "enable", "Governed knowledge library",
      "Show your organisation's approved knowledge inside Lightwork, with correction, "
      "exclusion and deletion.", "toggle", "Memory & learning", True, "maverick.config",
      subgroup="Knowledge library", env=("MAVERICK_KNOWLEDGE_ACCESS",)),

    S("knowledge_access", "task_context", "Tasks that analyze selected approved sources",
      "Allow named workspace members to select exact source versions for tool-free AI analysis. "
      "Source permission is checked again before AI use, publication and opening the result.",
      "toggle", "Memory & learning", False, "maverick.knowledge_task_context",
      subgroup="Knowledge library"),

    # ----------------------------------------------------- AI governance
    S("eu_ai_incidents", "authorities", "People who decide serious AI incident reports",
      "Each person listed may make reporting decisions on serious AI incidents, in the role "
      "shown, for the authorities named. Separate several authorities with commas.", "rules",
      "AI governance", [], "maverick_dashboard.model_risk_api",
      subgroup="Serious AI incident reports",
      columns=(
          C("principal", "Person", "select", choices_from="people_only", required=True,
            unique=True),
          C("role", "Role", "select", required=True,
            choices=(("authorized_provider_representative", "Authorised representative"),
                     ("incident_commander", "Incident lead"),
                     ("legal_counsel", "Legal counsel"),
                     ("regulatory_compliance_officer", "Regulatory compliance officer"),
                     ("safety_officer", "Safety officer"))),
          C("authority_refs", "Authorities", "words", required=True, pattern=_REF,
            item_error="an authority reference of letters, numbers and dots or dashes"),
      ),
      item_label="Person", add_label="Add a person",
      empty_text="Nobody can decide incident reports yet.",
      empty_hint="Nobody has been added yet. Add people on the People page first.",
      weaker="grow",
      warning="The people you add or change will be able to make decisions on reports to "
              "authorities."),
    S("ai_cost_roi.aws", "enable", "Collect AI costs from Amazon Web Services",
      "Read AI spending from your AWS bill. Its account details and sign-in are set on your "
      "server.", "toggle", "AI governance", False, "maverick.ai_cost_collectors",
      subgroup="AI cost collection"),
    S("ai_cost_roi.azure", "enable", "Collect AI costs from Microsoft Azure",
      "Read AI spending from your Azure bill. Its account details and sign-in are set on "
      "your server.", "toggle", "AI governance", False, "maverick.ai_cost_collectors",
      subgroup="AI cost collection"),
    S("ai_cost_roi.gcp", "enable", "Collect AI costs from Google Cloud",
      "Read AI spending from your Google Cloud bill. Its account details and sign-in are set "
      "on your server.", "toggle", "AI governance", False, "maverick.ai_cost_collectors",
      subgroup="AI cost collection"),
    S("ai_cost_roi.openai", "enable", "Collect AI costs from OpenAI",
      "Read AI spending from your OpenAI organisation. Its details and sign-in are set on "
      "your server.", "toggle", "AI governance", False, "maverick.ai_cost_collectors",
      subgroup="AI cost collection"),
    S("ai_cost_roi", "collector_poll_seconds", "Collect costs every",
      "How often turned-on cost collection runs.", "number", "AI governance", 86400.0,
      "maverick.ai_cost_collectors", subgroup="AI cost collection", minimum=1, maximum=168,
      unit="hours", scale=3600),
    S("red_team_assurance", "enable", "Allow red-team test campaigns",
      "Let administrators run planned attack tests against your agents. Its signing key is "
      "set on your server.", "toggle", "AI governance", False, "maverick.red_team_assurance",
      subgroup="Red-team testing"),
    S("red_team_assurance", "max_cases", "Most test cases per campaign",
      "The most attack tests one campaign may run.", "number", "AI governance", 12,
      "maverick.red_team_assurance", subgroup="Red-team testing", minimum=1, maximum=32,
      integer=True, unit="tests"),
    S("red_team_assurance", "campaign_ttl_seconds", "Longest a campaign may run",
      "A campaign that is not finished by then is closed.", "number", "AI governance", 604800,
      "maverick.red_team_assurance", subgroup="Red-team testing", minimum=1, maximum=720,
      integer=True, unit="hours", scale=3600),
    S("red_team_assurance", "evidence_validity_seconds", "Test results count as current for",
      "After this, a campaign's results no longer count as proof that agents resist attacks.",
      "number", "AI governance", 7776000, "maverick.red_team_assurance",
      subgroup="Red-team testing", minimum=1, maximum=366, integer=True, unit="days",
      scale=86400, weaker="higher",
      warning="Older test results will keep counting as proof that agents resist attacks."),
    S("candidate_promotion", "enable", "Allow moving research results into use",
      "Named administrators may review a research result, try it on a small share of work, "
      "then put it into use or roll it back. It stays closed until your installation has a "
      "reviewed release setup.", "toggle", "AI governance", False, "maverick.config",
      subgroup="Moving research results into use", env=("MAVERICK_CANDIDATE_PROMOTION",),
      weaker=True,
      warning="Administrators will be able to change the running system with research results."),
    S("candidate_promotion", "review_ttl_seconds", "A review approval stays valid for",
      "How long a person's review of a research result can be used before it must be given "
      "again.", "number", "AI governance", 3600,
      "maverick_dashboard.candidate_promotion_composition",
      subgroup="Moving research results into use", minimum=1, maximum=10080, integer=True,
      unit="minutes", scale=60, weaker="higher",
      warning="A review approval will stay usable for longer before it must be given again."),
    S("vendor_onboarding", "reviewed_uploads", "Preview supplier uploads before use",
      "Office files and recordings suppliers send are previewed and reviewed inside "
      "Lightwork before they are used.", "toggle", "AI governance", True, "maverick.config",
      subgroup="Supplier onboarding", weaker=False,
      warning="Supplier files will no longer be previewed and reviewed before use."),

    # ------------------------------------------------------ integrations
    S("template_registries", "indexes", "Where to find task templates",
      "Web addresses of the catalogs task templates can be installed from. With none listed, "
      "the built-in catalog is used.", "list", "Integrations", [], "maverick.templates",
      subgroup="Template and tool server catalogs", pattern=_HTTPS_PLAIN, max_length=300,
      item_error="a secure web address without a question mark", empty_unset=True,
      weaker="add", warning="Templates from a new catalog will be offered for install."),
    S("mcp_registries", "indexes", "Where to find tool servers",
      "Web addresses of the catalogs outside tool servers can be added from. With none "
      "listed, the built-in catalog is used.", "list", "Integrations", [],
      "maverick.mcp_registry", subgroup="Template and tool server catalogs",
      pattern=_HTTPS_PLAIN, max_length=300,
      item_error="a secure web address without a question mark", empty_unset=True,
      weaker="add", warning="Tool servers from a new catalog will be offered to add."),
    S("provider_failover", "chains", "Backup AI models",
      "When a model's service fails, try these models next, in order.", "table",
      "Integrations", {}, "maverick.provider_failover", subgroup="Backup AI models",
      row_kind="grid", choices_from="models", scalar=True,
      columns=(C("fallbacks", "Try next, in order", "picks", choices_from="models",
                 required=True, max_items=8),),
      row_label="When this model fails", item_label="Model", add_label="Add backups",
      empty_text="No model has backups yet.", weaker="add",
      warning="Requests may go to another AI service when the first one fails."),
    S("providers.bedrock", "auth_mode", "How Lightwork signs in to Amazon Bedrock",
      "Amazon Bedrock can use your AWS sign-in or server role, or a Bedrock access key.",
      "select", "Integrations", "iam", "maverick.llm", subgroup="Amazon Bedrock",
      choices=(("iam", "AWS sign-in or server role (recommended)"),
               ("api_key", "A Bedrock access key"))),
    S("computer_use", "vision_min_confidence", "How sure agents must be before clicking",
      "Agents click an item they found by looking at the screen only when at least this sure.",
      "number", "Integrations", 0.5, "maverick.vision_click", subgroup="Computer control",
      minimum=1, maximum=100, unit="percent", scale=0.01, weaker="lower",
      warning="Agents will click on screen items they are less sure they have recognised."),

    # ------------------------------------------------------ people & access
    S("dashboard", "default_suites", "Departments a person may use by default",
      "People with no departments of their own can use only these. With none ticked, they "
      "can use no departments. Removing the setting entirely restores every department.", "multiselect", "People & access", [], "maverick.suite_grants",
      subgroup="Departments", choices_from="suites", weaker="widen",
      warning="People with no departments of their own will be able to use more departments, "
              "or all of them."),
    S("suites", "*", "Departments turned off",
      "Agents from a department turned off here cannot be hired or run. Every other department "
      "stays on.", "table", "People & access", {}, "maverick.domain", subgroup="Departments",
      key_kind="entries", row_kind="grid", choices_from="suites", scalar=True,
      columns=(C("on", "Turned on", "switch", default=False),),
      row_label="Department", item_label="Department", add_label="Add a department",
      empty_text="Every department is on."),
    S("dashboard", "group_roles", "Roles for sign-in groups",
      "Everyone in a group your sign-in provider shares gets this role, unless they have a "
      "role of their own.", "table", "People & access", {}, "maverick_dashboard.scim_groups",
      subgroup="Sign-in groups", row_kind="grid", choices_from="scim_groups", scalar=True,
      columns=(C("role", "Role", "select", choices_from="roles", required=True),),
      row_label="Group", item_label="Group", add_label="Add a group",
      empty_text="No groups give a role yet.",
      empty_hint="No groups have arrived from your sign-in provider yet.",
      weaker="grow", warning="Members of that group will get a different role, which may let "
                             "them do more."),
    S("dashboard", "group_suites", "Departments for sign-in groups",
      "Everyone in a group your sign-in provider shares may use these departments, unless "
      "they have departments of their own.", "table", "People & access", {},
      "maverick_dashboard.scim_groups", subgroup="Sign-in groups", row_kind="grid",
      choices_from="scim_groups", scalar=True,
      columns=(C("suites", "Departments", "picks", choices_from="suites", required=True),),
      row_label="Group", item_label="Group", add_label="Add a group",
      empty_text="No groups give departments yet.",
      empty_hint="No groups have arrived from your sign-in provider yet.",
      weaker="grow", warning="Members of that group will be able to use more departments."),
)

SETTINGS = (SETTINGS + _channel_settings() + _CHANNEL_FIELDS + _MORE + _env_hunt_settings()
            + _GOVERNANCE + _INTEGRATIONS_MORE + _POLICY)

# Rows kept in per-group modules (one module per group of settings).
from . import (  # noqa: E402 -- the row and column types must exist first
    settings_catalog_access,
    settings_catalog_budget_guidance,
    settings_catalog_features,
    settings_catalog_governance,
    settings_catalog_integrations,
    settings_catalog_learning,
    settings_catalog_personalization,
    settings_catalog_privacy,
    settings_catalog_runtime,
    settings_catalog_structured,
)

_GROUP_MODULES = (settings_catalog_access, settings_catalog_features, settings_catalog_runtime, settings_catalog_learning,
                  settings_catalog_privacy, settings_catalog_governance,
                  settings_catalog_integrations, settings_catalog_structured, settings_catalog_personalization, settings_catalog_budget_guidance)
for _group in _GROUP_MODULES:
    SETTINGS += tuple(_group.entries(S, C, Column))

BY_ID: dict[str, Setting] = {s.id: s for s in SETTINGS}

# Top-level tables the catalog may write; settings_store's allowlisted
# serializer emits exactly these (plus its own existing tables).
CATALOG_TOP_SECTIONS: tuple[str, ...] = tuple(sorted({s.top for s in SETTINGS}))

# Settings that must agree with another setting before the kernel accepts
# them, so the pair is validated together.
_REQUIRES_NONEMPTY: dict[str, str | tuple[str, ...]] = {
    # Strict residency refuses to start without a declared region.
    "residency.strict": "residency.region",
    # The gateway and the tool gateway refuse to start without somewhere to
    # forward to (and, for the tool gateway, reviewed tools).
    "llm_gateway.enable": "llm_gateway.upstream_url",
    "mcp_sidecar.enable": ("mcp_sidecar.upstream_url", "mcp_sidecar.tools"),
    "local_runtime.enabled": "local_runtime.model",
}
# GRC sync only runs when at least one destination table is named.
_REQUIRES_ANY: dict[str, tuple[str, ...]] = {
    "grc_sync.enable": ("grc_sync.findings_path", "grc_sync.acceptances_path",
                        "grc_sync.incidents_path"),
}
# Pairs the kernel rejects when the first is larger than the second.
_ORDERED: tuple[tuple[str, str], ...] = (
    ("administration_document_access.default_ttl_seconds",
     "administration_document_access.max_ttl_seconds"),
    ("local_runtime.min_replicas", "local_runtime.max_replicas"),
    # Ekko counts a pattern only on days it still keeps.
    ("ekko.min_distinct_days", "ekko.retention_days"),
)
# Settings that need others filled in only when they hold one chosen value
# (a choice of "shared queue" needs the queue's address and key).
_REQUIRES_VALUE: dict[tuple[str, str], tuple[str, ...]] = {}
# Group modules may declare the same kinds of pairs for their own rows
# (``REQUIRES_NONEMPTY``, ``REQUIRES_ANY``, ``ORDERED``, ``REQUIRES_VALUE``).
for _group in _GROUP_MODULES:
    _REQUIRES_NONEMPTY.update(getattr(_group, "REQUIRES_NONEMPTY", {}))
    _REQUIRES_ANY.update(getattr(_group, "REQUIRES_ANY", {}))
    _ORDERED += tuple(getattr(_group, "ORDERED", ()))
    _REQUIRES_VALUE.update(getattr(_group, "REQUIRES_VALUE", {}))


class SettingError(ValueError):
    """A value the catalog refuses, with a plain sentence for the page."""


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _storable(value: object) -> bool:
    """True when every piece of text in ``value`` can be saved and read back.

    The settings file cannot hold half of a broken character pair (text that
    is not valid UTF-8) or invisible control characters; one such value would
    make the whole file unreadable and every dashboard setting stop applying.
    """
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return not any(unicodedata.category(ch) == "Cc" for ch in value)
    if isinstance(value, (list, tuple)):
        return all(_storable(item) for item in value)
    if isinstance(value, dict):
        return all(_storable(key) and _storable(item) for key, item in value.items())
    return True


def coerce(setting: Setting, value: object) -> object:
    """Validate and normalize one submitted value for ``setting``.

    ``None`` is only accepted for numbers without a default (meaning "no
    limit"), which callers treat as removing the dashboard value.
    """
    if setting.id == "spending_limits.alert_at":
        from maverick.spending_alerts import validate_alert_at
        try:
            return validate_alert_at(value)
        except ValueError as exc:
            raise SettingError(str(exc)) from exc
    if setting.id == "budget.warning_thresholds":
        try:
            return settings_catalog_budget_guidance.thresholds(value)
        except ValueError as exc:
            raise SettingError(str(exc)) from exc
    result = _coerce_value(setting, value)
    if setting.id == "plugins.workbench_image":
        from maverick.sandbox.local_images import LocalImageUnavailable, validate_choice
        try:
            result = validate_choice(result)
        except LocalImageUnavailable as exc:
            raise SettingError(str(exc)) from exc
    if not _storable(result):
        raise SettingError(
            f"{setting.label}: remove the hidden or unusual characters from this value."
        )
    return result


def _coerce_value(setting: Setting, value: object) -> object:  # noqa: C901 - one branch per control
    control = setting.control
    label = setting.label
    if control == "toggle":
        if not isinstance(value, bool):
            raise SettingError(f"{label}: choose on or off.")
        return value
    if control == "select":
        allowed = {v for v, _ in setting.choices}
        text = str(value) if not isinstance(value, bool) and value is not None else None
        if text is None or text not in allowed:
            raise SettingError(f"{label}: choose one of the listed options.")
        if _is_number(setting.default):
            return int(text)
        return text
    if control == "multiselect":
        if not isinstance(value, list) or len(value) > len(setting.choices):
            raise SettingError(f"{label}: choose from the listed options.")
        allowed = [v for v, _ in setting.choices]
        picked = []
        for item in value:
            if not isinstance(item, str) or item not in allowed:
                raise SettingError(f"{label}: choose from the listed options.")
            if item not in picked:
                picked.append(item)
        # Nothing ticked means "stop setting this here": an empty list would
        # otherwise read as "allow none" to the kernel.
        return sorted(picked, key=allowed.index) or None
    if control == "number":
        if value is None or value == "":
            if setting.default is None:
                return None
            raise SettingError(f"{label}: enter a number.")
        if isinstance(value, str):
            try:
                value = float(value)
            except ValueError as exc:
                raise SettingError(f"{label}: enter a number.") from exc
        if not _is_number(value) or not math.isfinite(float(value)):
            raise SettingError(f"{label}: enter a number.")
        shown = float(value)
        if setting.minimum is not None and shown < setting.minimum:
            raise SettingError(f"{label}: enter at least {_fmt(setting.minimum)}.")
        if setting.maximum is not None and shown > setting.maximum:
            raise SettingError(f"{label}: enter at most {_fmt(setting.maximum)}.")
        number = shown * setting.scale
        if setting.scale != 1.0 and abs(number - round(number)) < 1e-6:
            number = float(round(number))
        if setting.integer:
            if number != int(number):
                raise SettingError(f"{label}: enter a whole number.")
            number = int(number)
        elif isinstance(setting.default, int) and not isinstance(setting.default, bool) \
                and number == int(number):
            number = int(number)
        return number
    if control == "path":
        return _coerce_path(setting, value)
    if control == "picks":
        return _coerce_picks(setting, value)
    if control == "fingerprint":
        text = "" if value is None else value
        if not isinstance(text, str):
            raise SettingError(f"{label}: upload the file to work out its fingerprint.")
        text = text.strip().lower()
        if text and not re.fullmatch(_FINGERPRINT_RE, text):
            raise SettingError(f"{label}: upload the file to work out its fingerprint.")
        return text or None
    if control == "document":
        from . import settings_documents

        return settings_documents.coerce(setting, value)
    if control == "text" and setting.workspace_segment:
        return _coerce_workspace_address(setting, value)
    if control in {"text", "secret"}:
        if not isinstance(value, str):
            raise SettingError(f"{label}: enter text.")
        text = value.strip()
        if len(text) > setting.max_length:
            raise SettingError(f"{label}: use at most {setting.max_length} characters.")
        if control == "secret" and not text:
            raise SettingError(f"{label}: enter a value, or use Reset to remove it.")
        if setting.pattern and not re.fullmatch(setting.pattern, text):
            raise SettingError(f"{label}: this value is not in the expected form.")
        # An emptied text box means "stop setting this here".
        return text or None
    if control == "rate":
        if value is None or value == "":
            return None
        if not isinstance(value, dict):
            raise SettingError(f"{label}: enter how many and how often.")
        count, seconds = value.get("count"), value.get("seconds")
        if not (_is_number(count) and _is_number(seconds)) or count != int(count) \
                or seconds != int(seconds) or not 1 <= count <= 100000 \
                or not 1 <= seconds <= 86400:
            raise SettingError(f"{label}: enter a whole number of times and a period.")
        return f"{int(count)}/{int(seconds)}"
    if control == "list":
        if not isinstance(value, list) or len(value) > setting.max_items:
            raise SettingError(f"{label}: use at most {setting.max_items} entries.")
        items: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise SettingError(f"{label}: each entry must be text.")
            item = raw.strip()
            if not item:
                continue
            if len(item) > setting.max_length or (
                setting.pattern and not re.fullmatch(setting.pattern, item)
            ):
                raise SettingError(f"{label}: each entry must be {setting.item_error}.")
            if item not in items:
                items.append(item)
        if not items and setting.empty_unset:
            return None
        return items
    if control == "keys":
        return _coerce_keys(setting, value)
    if control == "table":
        return _coerce_table(setting, value)
    if control == "rules":
        return _coerce_rules(setting, value)
    raise SettingError(f"{label}: this setting cannot be changed here.")  # pragma: no cover


WORKSPACE_SEGMENT = "{tenant_sha256}"


def _coerce_workspace_address(setting: Setting, value: object) -> str | None:
    """A secure address with one part that Lightwork fills in per workspace.

    The page sends the address with the workspace part already placed (the
    person picks where it goes); an address without one gets it at the end.
    The result is checked exactly as the kernel checks it before use."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SettingError(f"{setting.label}: enter a secure web address.")
    text = value.strip()
    if not text or text == "/" + WORKSPACE_SEGMENT:
        return None
    wrong = SettingError(f"{setting.label}: enter a secure web address that starts with "
                         "https://, with nothing after a ? or #.")
    if len(text) > setting.max_length or not re.fullmatch(
            r"https://[^\s\"'<>?#]{1,1800}", text):
        raise wrong
    base, _, rest = text[len("https://"):].partition("/")
    if not base or "{" in base or "}" in base:
        raise wrong
    parts = [part for part in rest.split("/") if part]
    if any(("{" in part or "}" in part) and part != WORKSPACE_SEGMENT for part in parts) \
            or parts.count(WORKSPACE_SEGMENT) > 1:
        raise wrong
    if WORKSPACE_SEGMENT not in parts:
        parts.append(WORKSPACE_SEGMENT)
    address = "https://" + base + "/" + "/".join(parts)
    from maverick.unified_audit_custody import (
        UnifiedAuditCustodyError,
        _validate_siem_template,
    )

    try:
        _validate_siem_template(address)
    except UnifiedAuditCustodyError as exc:
        raise wrong from exc
    return address


def workspace_address_parts(value: object) -> tuple[str, int]:
    """``(address without the workspace part, parts before it)`` for the page."""
    text = str(value or "")
    if not text.startswith("https://") or WORKSPACE_SEGMENT not in text:
        return text, -1
    base, _, rest = text[len("https://"):].partition("/")
    parts = [part for part in rest.split("/") if part]
    at = parts.index(WORKSPACE_SEGMENT) if WORKSPACE_SEGMENT in parts else len(parts)
    kept = [part for part in parts if part != WORKSPACE_SEGMENT]
    return "https://" + base + ("/" + "/".join(kept) if kept else ""), at


def workspace_address_shown(value: object) -> str:
    """The address in plain words, with the workspace part marked."""
    return str(value or "").replace("/" + WORKSPACE_SEGMENT, "/[workspace]")


def _coerce_picks(setting: Setting, value: object) -> list[str] | None:
    if value is None or value == "":
        return None if setting.empty_unset else []
    if not isinstance(value, list) or len(value) > setting.max_items:
        raise SettingError(f"{setting.label}: choose at most {setting.max_items}.")
    allowed = {v for v, _ in setting.choices}
    picked: list[str] = []
    for item in value:
        if not isinstance(item, str) or item not in allowed:
            raise SettingError(f"{setting.label}: choose each one from the list.")
        if item not in picked:
            picked.append(item)
    if not picked and setting.empty_unset:
        return None
    return picked


def _coerce_path(setting: Setting, value: object) -> str | None:
    """A server location: checked on the server where Lightwork runs."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SettingError(f"{setting.label}: enter a location on the server.")
    text = value.strip()
    if len(text) > setting.max_length:
        raise SettingError(f"{setting.label}: use at most {setting.max_length} characters.")
    if not text:
        return None  # an emptied box means "stop setting this here"
    if setting.id == "auth.saml.idp_metadata_file" and text.startswith("managed-saml:"):
        from fastapi import HTTPException

        from .company_saml_materials import resolve

        try:
            resolve(text)
        except (HTTPException, ValueError, OSError) as exc:
            raise SettingError("The protected uploaded provider files are unavailable. Review guided single sign-on setup.") from exc
        return text
    from . import settings_paths

    try:
        return settings_paths.check(text, kind=setting.path_kind,
                                    writable=setting.path_writable,
                                    private=setting.path_private,
                                    new_ok=setting.path_new, scope=setting.path_scope)
    except settings_paths.PathRefused as exc:
        raise SettingError(f"{setting.label}: {exc}") from exc


# --------------------------------------------------------- publisher keys
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_KEYS = 20


def parse_public_key(text: object) -> str:
    """A publisher's public key in any common file form -> the stored form.

    Accepts the plain hexadecimal form the kernel stores, an OpenSSH
    ``ssh-ed25519`` line, a PEM ``PUBLIC KEY`` block, or the bare base64 of
    the 32 key bytes. Raises :class:`SettingError` with a plain sentence.
    """
    import base64
    import binascii

    raw = str(text or "").strip()
    bad = SettingError(
        "That file is not a publisher key this page can read. Ask the publisher for their "
        "public key file."
    )
    if not raw or len(raw) > 4096:
        raise bad
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return raw.lower()
    try:
        if raw.startswith("ssh-ed25519 "):
            blob = base64.b64decode(raw.split()[1], validate=True)
            name_len = int.from_bytes(blob[:4], "big")
            if blob[4:4 + name_len] != b"ssh-ed25519":
                raise bad
            rest = blob[4 + name_len:]
            key_len = int.from_bytes(rest[:4], "big")
            key = rest[4:4 + key_len]
        elif "-----BEGIN PUBLIC KEY-----" in raw:
            body = raw.split("-----BEGIN PUBLIC KEY-----", 1)[1].split("-----END", 1)[0]
            der = base64.b64decode("".join(body.split()), validate=True)
            if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
                raise bad
            key = der[12:]
        else:
            key = base64.b64decode("".join(raw.split()), validate=True)
    except (binascii.Error, ValueError, IndexError) as exc:
        raise bad from exc
    if len(key) != 32:
        raise bad
    return key.hex()


def key_fingerprint(hex_key: str) -> str:
    """A short readable fingerprint of a stored key (never the key itself)."""
    import hashlib

    try:
        digest = hashlib.sha256(bytes.fromhex(str(hex_key))).hexdigest().upper()
    except ValueError:
        return "Unreadable key"
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4))


def _coerce_keys(setting: Setting, value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_KEYS:
        raise SettingError(f"{setting.label}: use at most {MAX_KEYS} keys.")
    keys: list[str] = []
    for item in value:
        parsed = parse_public_key(item)
        if parsed not in keys:
            keys.append(parsed)
    return keys


# ---------------------------------------------------------------- tables
RISK_LEVELS: tuple[tuple[str, str], ...] = (
    ("low", "Low risk"), ("medium", "Medium risk"), ("high", "High risk"),
)
_RISK_RANK = {"low": 0, "medium": 1, "high": 2}
MAX_TABLE_ROWS = 64


def _coerce_table(setting: Setting, value: object) -> dict:  # noqa: C901 - one branch per row kind
    label = setting.label
    if value is None or value == "":
        return {}
    most = setting.max_rows or MAX_TABLE_ROWS
    if not isinstance(value, list) or len(value) > most:
        raise SettingError(f"{label}: use at most {most} rows.")
    allowed = {v for v, _ in setting.choices}
    out: dict[str, object] = {}
    for row in value:
        if not isinstance(row, dict):
            raise SettingError(f"{label}: each row needs a name and a value.")
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        if name in out:
            raise SettingError(f"{label}: each row must be different.")
        if setting.row_kind == "rate":
            if name in setting.fixed_keys:
                raise SettingError(f"{label}: that tool has its own setting above.")
            if name not in allowed:
                raise SettingError(f"{label}: choose a tool from the list.")
            count, seconds = row.get("count"), row.get("seconds")
            if not (_is_number(count) and _is_number(seconds)) or count != int(count) \
                    or seconds != int(seconds) or not 1 <= count <= 100000 \
                    or not 1 <= seconds <= 86400:
                raise SettingError(f"{label}: enter a whole number of times and a period.")
            out[name] = f"{int(count)}/{int(seconds)}"
        elif setting.row_kind == "grid":
            if name not in allowed:
                raise SettingError(f"{label}: choose each {setting.item_label.lower()} from the list.")
            out[name] = _grid_spec(setting, row)
        elif setting.row_kind == "named":
            if setting.pattern and not re.fullmatch(setting.pattern, name):
                raise SettingError(f"{label}: each name must be {setting.item_error}.")
            if name in setting.fixed_keys:
                raise SettingError(f"{label}: “{name}” is already taken. Choose another name.")
            spec = _grid_spec(setting, row)
            if setting.scalar:
                out[name] = spec
            else:
                # An optional column left empty is left out, never stored empty.
                out[name] = {k: v for k, v in spec.items() if v not in ("", None)}
        elif setting.row_kind == "risk":
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) or "__" in name:
                raise SettingError(
                    f"{label}: a tool name uses letters, numbers, dots, dashes and single "
                    "underscores only."
                )
            risk = str(row.get("risk") or "")
            if risk not in _RISK_RANK:
                raise SettingError(f"{label}: choose a risk level for each tool.")
            out[name] = {"risk": risk}
        else:  # pragma: no cover - guarded by _assert_consistent
            raise SettingError(f"{label}: this setting cannot be changed here.")
    return out


def _coerce_cell(setting: Setting, column: Column, value: object) -> object:  # noqa: C901 - one branch per column kind
    """Validate one cell of a grid or rules row."""
    where = f"{setting.label}, {column.label.lower()}"
    kind = column.kind
    allowed = [v for v, _ in column.choices]
    if kind in {"select", "pick"}:
        if value is None:
            value = column.default if column.default is not None else ""
        text = value if isinstance(value, str) else None
        if text is None or text not in allowed and not (text == "" and not column.required):
            raise SettingError(f"{where}: choose one of the listed options.")
        if column.required and not text:
            raise SettingError(f"{where}: choose an option for each row.")
        return text
    if kind == "picks":
        if value is None:
            value = []
        if not isinstance(value, list) or len(value) > column.max_items:
            raise SettingError(f"{where}: choose at most {column.max_items}.")
        picked: list[str] = []
        for item in value:
            if not isinstance(item, str) or item not in allowed:
                raise SettingError(f"{where}: choose from the listed options.")
            if item not in picked:
                picked.append(item)
        if column.required and not picked:
            raise SettingError(f"{where}: choose at least one for each row.")
        return picked
    if kind == "switch":
        if value is None:
            value = bool(column.default)
        if not isinstance(value, bool):
            raise SettingError(f"{where}: choose on or off.")
        return value
    if kind == "number":
        if value is None or value == "":
            raise SettingError(f"{where}: enter a number for each row.")
        if not _is_number(value) or not math.isfinite(float(value)):
            raise SettingError(f"{where}: enter a number.")
        if column.minimum is not None and value < column.minimum:
            raise SettingError(f"{where}: enter at least {_fmt(column.minimum)}.")
        if column.maximum is not None and value > column.maximum:
            raise SettingError(f"{where}: enter at most {_fmt(column.maximum)}.")
        if column.integer:
            if value != int(value):
                raise SettingError(f"{where}: enter a whole number.")
            return int(value)
        return float(value)
    if kind in {"path", "program"}:
        # A file on the server (``program``: one Lightwork runs).
        text = "" if value is None else value
        if not isinstance(text, str):
            raise SettingError(f"{where}: enter a location on the server.")
        text = text.strip()
        if not text:
            if column.required:
                raise SettingError(f"{where}: fill this in for each row.")
            return ""
        from . import settings_paths

        try:
            return settings_paths.check(text, kind="file", program=kind == "program")
        except settings_paths.PathRefused as exc:
            raise SettingError(f"{where}: {exc}") from exc
    if kind == "color":
        text = "" if value is None else value
        if not isinstance(text, str) or (text and not re.fullmatch(_COLOR, text.strip())):
            raise SettingError(f"{where}: choose a colour.")
        if column.required and not text.strip():
            raise SettingError(f"{where}: choose a colour for each row.")
        return text.strip().lower()
    if kind in {"text", "secret"}:
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise SettingError(f"{where}: enter text.")
        text = value.strip()
        if len(text) > column.max_length:
            raise SettingError(f"{where}: use at most {column.max_length} characters.")
        if text and column.pattern and not re.fullmatch(column.pattern, text):
            raise SettingError(f"{where}: each entry must be {column.item_error}.")
        if kind == "text" and column.required and not text:
            raise SettingError(f"{where}: fill this in for each row.")
        return text  # an empty secret keeps the row's saved one (settings_all_page)
    if kind == "words":
        if value is None:
            value = ""
        if isinstance(value, str):
            value = value.split(",")
        if not isinstance(value, list) or len(value) > column.max_items:
            raise SettingError(f"{where}: use at most {column.max_items} entries.")
        words: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise SettingError(f"{where}: each entry must be text.")
            item = raw.strip()
            if not item:
                continue
            if len(item) > column.max_length or (
                column.pattern and not re.fullmatch(column.pattern, item)
            ):
                raise SettingError(f"{where}: each entry must be {column.item_error}.")
            if item not in words:
                words.append(item)
        if column.required and not words:
            raise SettingError(f"{where}: enter at least one for each row.")
        return words
    raise SettingError(f"{setting.label}: this setting cannot be changed here.")  # pragma: no cover


def _grid_spec(setting: Setting, row: dict) -> object:
    """What one grid row stores: the single value, or every column's value.

    Every column is written (an empty list or ``""`` included) so a value the
    installer set for the same row cannot show through underneath.
    """
    cells = {c.key: _coerce_cell(setting, c, row.get(c.key)) for c in setting.columns}
    if setting.scalar:
        return cells[setting.columns[0].key]
    return cells


def _coerce_rules(setting: Setting, value: object) -> list[dict]:
    label = setting.label
    if value is None or value == "":
        return []
    most = setting.max_rows or MAX_TABLE_ROWS
    if not isinstance(value, list) or len(value) > most:
        raise SettingError(f"{label}: use at most {most} rows.")
    out: list[dict] = []
    for row in value:
        if not isinstance(row, dict):
            raise SettingError(f"{label}: each row needs its values.")
        cells = {c.key: _coerce_cell(setting, c, row.get(c.key)) for c in setting.columns}
        cells = {c.key: cells[c.key] for c in setting.columns
                 if not (c.omit_empty and cells[c.key] in ([], "", None))}
        if cells in out:
            raise SettingError(f"{label}: each row must be different.")
        for column in setting.columns:
            if column.unique and any(r.get(column.key) == cells.get(column.key) for r in out):
                raise SettingError(
                    f"{label}: each {column.label.lower()} can be listed only once."
                )
        out.append(cells)
    return out


def _rank(value: object, order: tuple[str, ...]) -> int:
    try:
        return order.index(str(value or ""))
    except ValueError:
        return len(order)


def _acl_row(spec: object) -> tuple[list[str], list[str], str]:
    spec = spec if isinstance(spec, dict) else {}
    denied = [str(v) for v in spec.get("denied_tools") or [] if isinstance(v, str)]
    allowed = [str(v) for v in spec.get("allowed_tools") or [] if isinstance(v, str)]
    risk = spec.get("max_risk")
    return denied, allowed, risk if risk in {"low", "medium", "high"} else ""


def _acl_loosens(before: dict, after: dict) -> bool:
    ceiling = ("low", "medium", "high", "")  # "" = no ceiling of its own
    for name, spec in before.items():
        if name not in after:
            return True  # the app's own rules are removed
        old_denied, old_allowed, old_risk = _acl_row(spec)
        new_denied, new_allowed, new_risk = _acl_row(after[name])
        if any(tool not in new_denied for tool in old_denied):
            return True  # a blocked tool is unblocked
        if old_allowed and (not new_allowed or any(t not in old_allowed for t in new_allowed)):
            return True  # the allow list opened up
        if _rank(new_risk, ceiling) > _rank(old_risk, ceiling):
            return True  # riskier tools allowed
    return False


def _caps_loosen(before: dict, after: object) -> bool:
    """A row of limits where 0 means "no limit": raising or clearing one loosens."""
    now = after if isinstance(after, dict) else {}
    for key, was in before.items():
        if not _is_number(was) or was <= 0:
            continue  # there was no limit to loosen
        new = now.get(key, 0)
        if not _is_number(new) or new <= 0 or new > was:
            return True
    return False


def _grid_loosens(setting: Setting, before: dict, after: dict) -> bool:
    mode = setting.weaker
    if mode == "acl":
        return _acl_loosens(before, after)
    if mode == "cap":
        for name, cap in before.items():
            if name not in after:
                return True
            if isinstance(cap, dict):
                if _caps_loosen(cap, after[name]):
                    return True
            elif _is_number(cap) and _is_number(after[name]) and after[name] > cap:
                return True
        return False
    if mode == "floor":
        # A minimum (people who must approve): removing a row or lowering it.
        for name, floor in before.items():
            if name not in after:
                return True
            if _is_number(floor) and _is_number(after[name]) and after[name] < floor:
                return True
        return False
    if mode == "add":
        for name, items in after.items():
            old = before.get(name)
            old_items = old if isinstance(old, list) else []
            if name not in before or any(i not in old_items for i in items or []):
                return True
        return False
    if mode == "grow":
        return any(name not in before or before[name] != spec for name, spec in after.items())
    return before != after


RATE_PERIODS: tuple[tuple[int, str], ...] = (
    (60, "minute"), (3600, "hour"), (86400, "day"),
)


def parse_rate(value: object) -> tuple[int, int] | None:
    """``"10/60"`` -> ``(10, 60)``; anything else -> None."""
    match = re.fullmatch(r"\s*(\d{1,6})\s*/\s*(\d{1,6})\s*", str(value or ""))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _period_text(seconds: int) -> str:
    for size, name in RATE_PERIODS:
        if seconds == size:
            return name
    return f"{seconds} seconds"


def warning_lead(setting: Setting) -> str:
    """How the page introduces a setting's safety note."""
    if setting.control == "toggle":
        return "If you turn this on:" if setting.weaker is True else "If you turn this off:"
    if setting.weaker == "lower":
        return "If you lower this:"
    if setting.weaker == "higher":
        return "If you raise this:"
    if setting.weaker == "change":
        return "If you change this:"
    if setting.weaker in {"grow", "add", "widen"}:
        return "If you add to this:"
    if setting.weaker in {"acl", "cap"}:
        return "If you loosen this:"
    if setting.weaker == "insecure":
        return "If you use a web address that is not secure:"
    if setting.weaker == "shrink":
        return "If you remove from this:"
    return "If you loosen this:"


def _count(count: int, noun: str) -> str:
    if count == 1:
        return f"1 {noun}"
    plural = noun + "es" if noun.endswith(("s", "x", "sh", "ch")) else noun + "s"
    return f"{count} {plural}"


def _fmt(number: float) -> str:
    if float(number) == int(number):
        return f"{int(number):,}" if abs(number) >= 10000 else str(int(number))
    return str(number)


def valid_number(setting: Setting, value: object) -> bool:
    """Whether an effective numeric source meets this control's existing bounds."""
    if value is None or value == "":
        return setting.default is None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return False
    try:
        number = float(value)
        if not math.isfinite(number):
            return False
        _coerce_value(setting, number / setting.scale)
    except (SettingError, ValueError, TypeError, OverflowError):
        return False
    return True


def _number_weakens(setting: Setting, old: object, new: object) -> bool:
    old = None if old == "" else old
    new = None if new == "" else new
    if not valid_number(setting, new):
        raise SettingError(f"{setting.label}: choose a valid number or its product default before continuing.")
    if not valid_number(setting, old):
        return bool(setting.warning)  # An unknown prior limit cannot establish a safe relaxation.
    if not setting.warning or old == new:
        return False
    if setting.weaker == "lower":
        return new is not None and (old is None or float(new) < float(old))
    if setting.weaker == "higher":
        return old is not None and (new is None or float(new) > float(old))
    return setting.weaker == "change" and old != new


def weakens(setting: Setting, old: object, new: object) -> bool:
    """True when moving from the effective ``old`` to ``new`` lowers a protection."""
    if setting.control == "number":
        return _number_weakens(setting, old, new)
    if not setting.warning or old == new:
        return False
    if setting.control == "toggle":
        return new is setting.weaker and old is not setting.weaker
    if setting.control == "select" and setting.order:
        order = list(setting.order)
        try:
            return order.index(str(new)) > order.index(str(old))
        except ValueError:
            return str(new) != str(setting.order[0])
    if setting.weaker == "change":
        return old != new
    if setting.weaker == "insecure":
        # A plain http:// address sends the data without encryption.
        return isinstance(new, str) and new.strip().lower().startswith("http://")
    if setting.control == "rate" and setting.weaker == "higher":
        was, now = parse_rate(old), parse_rate(new)
        if was is None:
            return False  # there was no limit to loosen
        return now is None or now[0] / now[1] > was[0] / was[1]
    if setting.control in {"list", "multiselect", "keys", "picks"}:
        return _list_loosens(setting, old, new)
    if setting.control == "document":
        from . import settings_documents

        return settings_documents.loosens(setting, old, new)
    if setting.control == "table":
        return _table_loosens(setting, old, new)
    if setting.control == "rules":
        before = old if isinstance(old, list) else []
        after = new if isinstance(new, list) else []
        return any(row not in before for row in after) if setting.weaker == "grow" \
            else before != after
    return False


def _list_loosens(setting: Setting, old: object, new: object) -> bool:
    old_items = [str(v) for v in old] if isinstance(old, list) else []
    new_items = [str(v) for v in new] if isinstance(new, list) else []
    if setting.weaker == "add":
        # Only a new destination sends data somewhere new; removing one
        # sends less.
        return any(item not in old_items for item in new_items)
    if setting.weaker == "grow":
        added = any(item not in old_items for item in new_items)
        # Emptying hands the decision back to a broader default: an empty
        # publisher list trusts any signature, an empty model list allows
        # every model, an empty allow list falls back to the server's list.
        return added or (bool(old_items) and not new_items)
    if setting.weaker == "shrink":
        return any(item not in new_items for item in old_items)
    if setting.weaker == "widen":
        # An empty list places no restriction, so leaving it is tightening.
        if not old_items:
            return False
        return not new_items or any(item not in old_items for item in new_items)
    return False


def _table_loosens(setting: Setting, old: object, new: object) -> bool:
    before = old if isinstance(old, dict) else {}
    after = new if isinstance(new, dict) else {}
    if setting.row_kind == "grid":
        return _grid_loosens(setting, before, after)
    if setting.row_kind == "named":
        return False if setting.weaker is None else _grid_loosens(setting, before, after)
    if setting.row_kind == "rate":
        for name, spec in before.items():
            if name not in after:
                return True  # a limit was removed
            was, now = parse_rate(spec), parse_rate(after[name])
            if was and now and now[0] / now[1] > was[0] / was[1]:
                return True  # more calls allowed per second
        return False
    for name, row in after.items():
        if name not in before:
            return True  # a new tool is exposed
        was = before[name].get("risk") if isinstance(before[name], dict) else None
        now = row.get("risk") if isinstance(row, dict) else None
        if _RISK_RANK.get(str(now), 2) < _RISK_RANK.get(str(was), 2):
            return True  # a tool was marked as less risky
    return False


def cross_checks(effective: dict[str, object]) -> None:
    """Refuse combinations the kernel would reject as a broken configuration."""
    for setting_id, needs in _REQUIRES_NONEMPTY.items():
        if effective.get(setting_id) is not True:
            continue
        for needed in (needs if isinstance(needs, tuple) else (needs,)):
            if not effective.get(needed):
                first, second = BY_ID[setting_id], BY_ID[needed]
                raise SettingError(
                    f"{first.label}: fill in “{second.label}” first."
                    if second.control in {"text", "select", "table"}
                    else f"{first.label}: choose at least one option in “{second.label}” first."
                )
    for setting_id, options in _REQUIRES_ANY.items():
        if effective.get(setting_id) is True and not any(effective.get(o) for o in options):
            first = BY_ID[setting_id]
            names = ", ".join(f"“{BY_ID[o].label}”" for o in options)
            raise SettingError(f"{first.label}: fill in at least one of {names} first.")
    for (setting_id, wanted), needs in _REQUIRES_VALUE.items():
        if str(effective.get(setting_id)) != wanted:
            continue
        for needed in needs:
            if not effective.get(needed):
                first, second = BY_ID[setting_id], BY_ID[needed]
                chosen = dict(first.choices).get(wanted, wanted)
                raise SettingError(f"{first.label} “{chosen}”: fill in “{second.label}” first.")
    for low_id, high_id in _ORDERED:
        low, high = effective.get(low_id), effective.get(high_id)
        if _is_number(low) and _is_number(high) and float(low) > float(high):
            high_label = BY_ID[high_id].label
            raise SettingError(
                f"{BY_ID[low_id].label} can't be more than "
                f"{high_label[:1].lower() + high_label[1:]}."
            )
    # A group module may refuse its own combinations (``cross_checks``).
    for group in _GROUP_MODULES:
        check = getattr(group, "cross_checks", None)
        if check is not None:
            check(effective, BY_ID, SettingError)


def lookup(tree: object, path: tuple[str, ...]) -> tuple[bool, object]:
    """``(present, value)`` for a nested key path in a config mapping."""
    node = tree
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _structured_display(setting: Setting, value: object) -> str | None:
    """Plain words for the picks, fingerprint, document and address controls."""
    if setting.id == "auth.saml.idp_metadata_file" and str(value).startswith("managed-saml:"):
        return "Protected uploaded provider files"
    if setting.id == "plugins.workbench_image":
        from maverick.sandbox.local_images import cached_label
        return cached_label(value)
    if setting.control == "picks" and isinstance(value, list):
        labels = dict(setting.choices)
        shown = [labels.get(str(v), str(v)) for v in value[:3]]
        more = f" and {len(value) - 3} more" if len(value) > 3 else ""
        return ", ".join(shown) + more
    if setting.control == "fingerprint":
        text = str(value)
        return " ".join(text[i:i + 4] for i in range(0, 16, 4)).upper() + " …"
    if setting.control == "document":
        from . import settings_documents

        return settings_documents.describe(setting, value)
    if setting.workspace_segment:
        return workspace_address_shown(value) + " ([workspace] is each workspace's own part)"
    return None


def display_value(setting: Setting, value: object) -> str:
    """Plain words for a value (never a secret's content)."""
    if setting.secret:
        return "Set" if value else "Not set"
    if setting.control == "number" and not valid_number(setting, value):
        return "The current number is invalid. Review a replacement or its product default."
    if (value is None or value == "" or value == []) and setting.none_text:
        return setting.none_text
    if value is None or value == "" or value == []:
        if setting.control in {"number", "rate"}:
            return "No limit"
        if setting.control == "select":
            return dict(setting.choices).get("", "Not set")
        return "Not set"
    structured = _structured_display(setting, value)
    if structured is not None:
        return structured
    if setting.control == "toggle":
        return "On" if value is True else "Off"
    if setting.control in {"select", "multiselect"}:
        labels = dict(setting.choices)
        if setting.control == "multiselect" and isinstance(value, list):
            return ", ".join(labels.get(str(v), str(v)) for v in value) or "None"
        return labels.get(str(value), "Other value")
    if setting.control == "list" and isinstance(value, list):
        noun = setting.item_label.lower()
        if len(value) == 1:
            return f"1 {noun}"
        return f"{len(value)} {noun}es" if noun.endswith(("s", "x", "sh", "ch")) \
            else f"{len(value)} {noun}s"
    if setting.control == "keys" and isinstance(value, list):
        return f"{len(value)} trusted key" + ("" if len(value) == 1 else "s")
    if setting.control == "table" and isinstance(value, dict):
        if setting.row_kind in {"grid", "named"}:
            return _count(len(value), setting.item_label.lower()) if value else "None"
        noun = "limit" if setting.row_kind == "rate" else "tool"
        return f"{len(value)} {noun}" + ("" if len(value) == 1 else "s") if value else "None"
    if setting.control == "rules" and isinstance(value, list):
        return _count(len(value), setting.item_label.lower()) if value else "None"
    if setting.control == "rate":
        parsed = parse_rate(value)
        if parsed is None:
            return "Other value"
        count, seconds = parsed
        return f"{count} every {_period_text(seconds)}"
    if setting.control == "number" and _is_number(value):
        text = _fmt(round(float(value) / setting.scale, 4))
        return f"{text} {setting.unit}".strip()
    return str(value)


__all__ = [
    "BY_ID", "CATALOG_TOP_SECTIONS", "Column", "GROUPS", "GROUP_INTROS", "SETTINGS",
    "RATE_PERIODS", "RISK_LEVELS", "Setting", "SettingError", "coerce", "cross_checks",
    "display_value", "key_fingerprint", "lookup", "parse_public_key", "parse_rate",
    "warning_lead", "weakens",
]


def _assert_consistent() -> None:
    for s in SETTINGS:
        assert s.control in CONTROLS, s.id
        assert s.group in GROUPS, s.id
        if s.control in {"select", "multiselect"}:
            assert s.choices or s.choices_from, s.id
        if s.warning:
            assert s.weaker is not None, s.id
        if s.control == "table":
            assert s.row_kind in {"rate", "risk", "grid", "named"}, s.id
        if s.row_kind in {"grid", "named"} or s.control == "rules":
            assert s.columns and all(c.kind in COLUMN_KINDS for c in s.columns), s.id
            assert not s.scalar or len(s.columns) == 1, s.id
            for c in s.columns:
                if c.kind in {"select", "pick", "picks"}:
                    assert c.choices or c.choices_from, s.id
        if s.row_kind == "grid":
            assert s.choices or s.choices_from, s.id
        if s.control == "picks":
            assert s.choices or s.choices_from, s.id
        assert (s.control == "document") == bool(s.document), s.id
        assert not s.workspace_segment or s.control == "text", s.id
        assert not s.fingerprint_of or s.control == "fingerprint", s.id
        # A keep period previews its clean-up from the number box.
        assert not s.preview or s.control == "select" or (s.preview == "retention" and s.control == "number"), s.id
        if s.key_kind == "entries":
            assert s.control == "table", s.id
        assert s.scale > 0, s.id
        assert (s.control == "path") == bool(s.path_kind), s.id
        assert not s.path_kind or s.path_kind in PATH_KINDS, s.id
        assert not (s.path_new or s.path_scope) or s.control == "path", s.id
        assert s.path_scope in {"", "data"}, s.id
    for pairs in (_REQUIRES_NONEMPTY, _REQUIRES_VALUE):
        for first, needs in pairs.items():
            first_id = first[0] if isinstance(first, tuple) else first
            assert first_id in BY_ID, first_id
            for needed in (needs if isinstance(needs, tuple) else (needs,)):
                assert needed in BY_ID, needed


_assert_consistent()
