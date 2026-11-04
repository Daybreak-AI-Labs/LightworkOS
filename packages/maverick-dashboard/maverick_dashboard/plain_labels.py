"""Plain-language labels for administration pages.

Stored values such as model identifiers (``openai:gpt-5.4``), configuration
sources (``environment:ANTHROPIC_API_KEY``, ``config.toml``) and setting keys
(``code_exec``) are exact and must stay exact in forms and storage. This
module turns them into the words a person sees, so templates never print the
raw value. Every function is total: an unknown value still gets a readable
label rather than an error.
"""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone

_UPPER_WORDS = {"gpt": "GPT", "ai": "AI", "llm": "AI model", "vl": "VL", "api": "API",
                "sms": "SMS", "ros": "ROS", "ui": "UI", "pro": "Pro"}
_BRAND_WORDS = {"deepseek": "DeepSeek", "openai": "OpenAI", "xai": "xAI",
                "openrouter": "OpenRouter", "minimax": "MiniMax", "qwen3": "Qwen3",
                "qwen": "Qwen", "kimi": "Kimi", "llama": "Llama", "grok": "Grok",
                "gemini": "Gemini", "claude": "Claude", "moonshot": "Moonshot"}


def provider_name(provider: str) -> str:
    """Short provider name: ``anthropic`` -> ``Anthropic``."""
    try:
        from maverick.llm import PROVIDER_LABELS
        label = PROVIDER_LABELS.get(provider)
    except Exception:  # pragma: no cover -- labels are best effort
        label = None
    if not label:
        from . import settings_store
        label = next((p["label"] for p in settings_store.PROVIDERS if p["name"] == provider), "")
    if not label:
        label = _BRAND_WORDS.get(provider.lower(), provider.replace("_", " ").title())
    # "Anthropic (Claude)" -> "Anthropic"; "Ollama (self-hosted)" -> "Ollama".
    return re.sub(r"\s*\(.*\)\s*$", "", label).strip() or label


def _word(token: str) -> str:
    low = token.lower()
    if low in _UPPER_WORDS:
        return _UPPER_WORDS[low]
    if low in _BRAND_WORDS:
        return _BRAND_WORDS[low]
    if re.fullmatch(r"\d+(\.\d+)*[a-z]?", low):
        return token
    return token[:1].upper() + token[1:]


def _model_words(model_id: str) -> str:
    tail = model_id.rsplit("/", 1)[-1]
    if tail.lower().startswith("gpt-"):
        parts = tail.split("-")
        head = "GPT-" + parts[1] if len(parts) > 1 else "GPT"
        return " ".join([head] + [_word(p) for p in parts[2:]])
    parts = [p for p in re.split(r"[-_]", tail) if p]
    out: list[str] = []
    for part in parts:
        # Consecutive plain numbers are one version: claude-opus-4-8 -> 4.8.
        if part.isdigit() and out and re.fullmatch(r"\d+(\.\d+)*", out[-1]):
            out[-1] = out[-1] + "." + part
        else:
            out.append(_word(part))
    return " ".join(out) or model_id


def model_label(spec: object) -> str:
    """``openai:gpt-5.4`` -> ``GPT-5.4 · OpenAI``; ``claude-opus-4-8`` ->
    ``Claude Opus 4.8 · Anthropic``."""
    text = str(spec or "").strip()
    if not text:
        return ""
    provider, sep, model_id = text.partition(":")
    if not sep:
        provider, model_id = ("anthropic" if text.lower().startswith("claude") else ""), text
    words = _model_words(model_id)
    return f"{words} · {provider_name(provider)}" if provider else words


_SOURCE_LABELS = {
    "dashboard": "saved here in Settings",
    "config.toml": "set when Lightwork was installed",
    "operator overlay": "set by your organization's administrator",
    "tenant config": "set for this workspace",
}


def source_label(source: object) -> str:
    """Where a setting comes from, in words; never a file or variable name."""
    text = str(source or "").strip()
    if not text:
        return ""
    labels: list[str] = []
    for part in text.split(" + "):
        part = part.strip()
        if part.startswith("environment:"):
            label = "set on the computer running Lightwork"
        else:
            label = _SOURCE_LABELS.get(part, "set outside Lightwork")
        if label not in labels:
            labels.append(label)
    return " and ".join(labels)


CAPABILITY_LABELS = {
    "computer_use": "Control a desktop",
    "browser": "Browse websites",
    "web_search": "Search the web",
    "mobile_tools": "Use phones and tablets",
    "ros": "Work with connected robots",
    "code_exec": "Run code",
}

FEATURE_LABELS = {
    "employee_companions": "Employee companions",
    "workflow_readiness": "Workflow catalog",
    "project_reviews": "Project reviews",
    "deliverable_bundles": "Selected deliverable bundles",
    "project_workspaces": "Project workspaces",
    "task_handoffs": "Accepted task handoffs",
    "human_conversation_handoffs": "Human help in Chat",
    "outcome_measurement": "Outcome measurement",
    "commitment_viability": "Keep promises in view",
    "work_restructuring": "Share preparation safely",
    "portable_competence": "Share and qualify local rule structures",
    "private_task_computation": "Private task calculations",
    "semantic_rule_reuse": "Reuse complete rule-behavior evidence",
    "procedure_interactions": "Check local rules together",
    "operational_competence_acquisition": "Plan teaching questions",
    "request_program": "Prepare an answer for this request",
    "commitment_economic_alternatives": "Compare additional-work economics",
    "workflow_step_checks": "Try one workflow step",
    "applicability_regions": "Checked answer regions",
    "governed_rule_evolution": "Rewrite and check local rules",
    "recovery_visibility": "Understand a missing reply",
    "commitment_capability_learning": "Qualify additional work",
    "shared_decision_evidence": "Shared decision reviews",
    "guided_onboarding": "Guided first steps",
    "action_center": "Action center",
    "draft_recovery": "Recover unsaved drafts",
    "support_center": "Support reports",
    "record_search": "Search across records",
    "workspace_recovery": "Workspace backups",
    "signing_identity_transition": "Change of software publisher",
    "skills": "Skills library",
    "world_model": "Shared memory across tasks",
    "streaming": "Show replies as they are written",
    "pack_editing": "Edit agents and specialists",
    "role_editing": "Edit agent roles",
    "scheduling": "Scheduled workflows",
    "triggers": "Start workflows from other apps",
}

# Plain rewrites of the few help texts whose stored wording is technical.
FEATURE_HELP = {
    "workflow_readiness": "Show the ready-made workflows you can run and what each still needs before you rely on it.",
    "project_reviews": "Share finished task results with the reviewers you choose.",
    "deliverable_bundles": "Share selected files and result versions with a named colleague for review and offline use.",
    "project_workspaces": "Plan outcomes, milestones and current source context with explicitly chosen colleagues.",
    "task_handoffs": "Offer a named colleague an unstarted continuation with selected evidence and a spending ceiling; acceptance closes the original conversation to new execution.",
    "outcome_measurement": "Compare how long work took before and after Lightwork, using your own numbers.",
    "commitment_viability": "See whether reported capacity and stock can cover two accepted orders, and what needs a decision before an option closes.",
    "work_restructuring": "Check exact shared preparation across permitted original local cases, with separate complete results and deadlines.",
    "portable_competence": "Release only reviewed anonymous local rule structures. Qualify them against a target workflow and its own permitted cases before any local use.",
    "private_task_computation": "Check a bounded rule using a permitted task attachment and release only a separately approved fixed answer. Original data stays private.",
    "procedure_interactions": "Compare two owned local rules in both orders and check all supported starting values before any combined use.",
    "operational_competence_acquisition": "Plan questions from a rule's complete supported alternatives and current permitted effort reports. Teaching and publication remain separate reviews.",
    "request_program": "Check bounded arrangements of your existing taught rules against permitted original cases for one request. Nothing is published automatically.",
    "commitment_economic_alternatives": "Compare reported offer prices and full incremental costs with currently protected commitments. Results remain conditional on your stated facts.",
    "workflow_step_checks": "Check one owned taught step against ordinary entered values without running the whole workflow or any connected action.",
    "applicability_regions": "Check both local rule versions across every supported starting situation. Only current separately permitted expected answers can choose a version; unclear situations remain for review.",
    "governed_rule_evolution": "Build alternative local rules and a complete checking order from one owned published rule. Independently review every change before publication, and retain the exact previous release for restoration.",
    "recovery_visibility": "Practice with fictional sign-offs to see when identical visible status hides different original outcomes. No live approval or connected service is used.",
    "semantic_rule_reuse": "Check every supported input for a local Yes/No or bounded whole-number rule before reusing prior evidence across a rewrite. All checks count toward the reviewed work allowance.",
    "commitment_capability_learning": "Compare additional work, possible resource additions and reported trial outcomes while protecting accepted commitments.",
    "shared_decision_evidence": "Find information that can resolve several entered choices, with current sharing permission and a shared question limit.",
    "guided_onboarding": "Offer a step-by-step path to your first finished piece of work.",
    "action_center": "Collect approvals and reviews waiting for you in one list.",
    "draft_recovery": "Keep a private, encrypted copy of unfinished work so it survives a closed tab.",
    "support_center": "Let administrators prepare a support report to send to the Lightwork team. Nothing is sent automatically.",
    "record_search": "Find vendors, evidence, assessments, tasks and reports by name.",
    "workspace_recovery": "Let administrators make, check and restore backups of this computer's workspaces.",
    "signing_identity_transition": "Allow administrators to approve a change to who publishes Lightwork updates. Only used during recovery.",
    "world_model": "Tasks share one memory, so what Lightwork learns in one task carries to the next.",
}

# The core agent roles, as a title and one line on what each does.
AGENT_ROLES = {
    "orchestrator": ("Planner", "Breaks a task into steps and hands each step to the right agent or specialist."),
    "researcher": ("Researcher", "Finds and reads sources, and gathers the facts a task needs."),
    "coder": ("Coder", "Writes and changes code."),
    "coding": ("Coding assistant", "Helps with smaller coding steps inside a larger task."),
    "writer": ("Writer", "Drafts documents, emails and reports."),
    "analyst": ("Analyst", "Works through numbers and data and explains what they show."),
    "revisor": ("Editor", "Improves a draft after feedback."),
    "verifier": ("Checker", "Checks finished work against what was asked before it is handed over."),
    "reviewer": ("Reviewer", "Reviews work and points out problems to fix."),
    "summarizer": ("Summarizer", "Writes short summaries of long material."),
    "skill_distiller": ("Skill builder", "Turns work that went well into reusable skills."),
    "vision": ("Image reader", "Reads screenshots, photos and scanned documents."),
    "translator": ("Translator", "Translates text between languages."),
}

EFFORT_LABELS = {"low": "Low", "medium": "Medium", "high": "High", "xhigh": "Very high", "max": "Maximum"}


def agent_role_title(role: object) -> str:
    key = str(role or "")
    return AGENT_ROLES.get(key, (key.replace("_", " ").capitalize(), ""))[0]


def agent_role_help(role: object) -> str:
    return AGENT_ROLES.get(str(role or ""), ("", ""))[1]


# Chat-app setup fields: (label, help, advanced). Advanced fields sit in a
# collapsed "Advanced settings" section with sensible defaults.
CHANNEL_FIELDS = {
    ("email", "email_auth"): ("How email signs in", "Microsoft accounts use protected account sign-in. Other mail services can keep their password setup.", False),
    ("email", "oauth_account"): ("Connected Microsoft mailbox", "Connect your mailbox on Connections, then choose it here. A reconnected account must be chosen and saved again.", False),
    ("telegram", "bot_token"): ("Bot token", "From BotFather in Telegram after you create a bot.", False),
    ("discord", "bot_token"): ("Bot token", "From the Discord Developer Portal, under your app's Bot page.", False),
    ("slack", "app_token"): ("App token (starts with xapp-)", "From your Slack app's Basic Information page, under App-Level Tokens.", False),
    ("slack", "bot_token"): ("Bot token (starts with xoxb-)", "From your Slack app's OAuth & Permissions page.", False),
    ("slack", "signing_secret"): ("Signing secret", "From your Slack app's Basic Information page. Needed only when buttons and slash commands reach this server over the web (Interactivity URL) rather than Socket Mode.", True),
    ("slack", "approvals_channel"): ("Approvals channel", "The Slack channel id (starts with C) where new approval cards with Approve and Reject buttons are posted. Leave empty to post none.", True),
    ("whatsapp_cloud", "access_token"): ("Access token", "From Meta for Developers, WhatsApp > API Setup.", False),
    ("whatsapp_cloud", "phone_number_id"): ("Phone number ID", "Shown next to your WhatsApp business number on the same API Setup page.", False),
    ("whatsapp_cloud", "verify_token"): ("Verification word", "Any word you choose. Enter the same word in Meta's webhook settings.", False),
    ("whatsapp_cloud", "app_secret"): ("App secret", "From Meta for Developers, App settings > Basic.", False),
    ("whatsapp_cloud", "port"): ("Listening port", "Only change this if your IT team asks you to.", True),
    ("sms", "account_sid"): ("Account SID", "From your Twilio Console home page.", False),
    ("sms", "auth_token"): ("Auth token", "From your Twilio Console home page, next to the Account SID.", False),
    ("sms", "from_number"): ("Sending phone number", "Your Twilio number, with country code, like +15551234567.", False),
    ("sms", "port"): ("Listening port", "Only change this if your IT team asks you to.", True),
    ("email", "imap_host"): ("Incoming mail server", "For example imap.gmail.com. Choosing your email provider above fills this in.", False),
    ("email", "trusted_authserv_id"): ("Server that checks incoming mail", "Ask your mail administrator for the server name on its sender-check result. The server must remove sender-supplied results before mail reaches this inbox. Incoming email cannot start work until this is set and the sender check passes.", False),
    ("email", "imap_user"): ("Incoming mail username", "Usually the full email address.", False),
    ("email", "imap_password"): ("Incoming mail password", "Many providers need an app password rather than your normal password.", False),
    ("email", "smtp_host"): ("Outgoing mail server", "For example smtp.gmail.com.", False),
    ("email", "smtp_user"): ("Outgoing mail username", "Usually the full email address.", False),
    ("email", "smtp_password"): ("Outgoing mail password", "Often the same app password as incoming mail.", False),
    ("email", "smtp_port"): ("Outgoing mail port", "Usually 465. Some providers, such as Outlook, use 587.", True),
    ("mattermost", "url"): ("Server address", "The web address people use to open Mattermost, such as https://chat.example.com.", False),
    ("mattermost", "bot_token"): ("Bot access token", "From Mattermost's System Console, under Integrations > Bot Accounts, after you create a bot.", False),
    ("teams", "app_id"): ("App ID", "The Microsoft App ID of your Azure Bot, shown on the bot's Configuration page in the Azure portal.", False),
    ("teams", "app_password"): ("Client secret", "From the app registration in Microsoft Entra, under Certificates & secrets. Paste the secret value, not its id.", False),
    ("teams", "tenant_id"): ("Tenant ID", "Your Microsoft Entra tenant id (Directory ID). Leave blank only for a multi-tenant app registration.", False),
    ("teams", "port"): ("Listening port", "Only change this if your IT team asks you to. Your public HTTPS address must forward /webhook/teams to it.", True),
}

CHANNEL_HELP_LINKS = {
    "telegram": "https://core.telegram.org/bots#how-do-i-create-a-bot",
    "discord": "https://discord.com/developers/applications",
    "slack": "https://api.slack.com/apps",
    "whatsapp_cloud": "https://developers.facebook.com/docs/whatsapp/cloud-api/get-started",
    "sms": "https://console.twilio.com",
    "mattermost": "https://developers.mattermost.com/integrate/reference/bot-accounts/",
    "teams": "https://learn.microsoft.com/azure/bot-service/bot-service-quickstart-registration",
}


# "Where do I get a key?" links, by provider.
PROVIDER_KEY_HELP = {
    "anthropic": "https://console.anthropic.com/settings/keys",
    "openai": "https://platform.openai.com/api-keys",
    "gemini": "https://aistudio.google.com/apikey",
    "openrouter": "https://openrouter.ai/keys",
    "moonshot": "https://platform.moonshot.ai/console/api-keys",
    "deepseek": "https://platform.deepseek.com/api_keys",
    "xai": "https://console.x.ai",
    "ollama": "https://ollama.com/download",
}


def capability_label(key: object) -> str:
    k = str(key or "")
    return CAPABILITY_LABELS.get(k) or k.replace("_", " ").capitalize()


def feature_label(key: object) -> str:
    k = str(key or "")
    return FEATURE_LABELS.get(k) or k.replace("_", " ").capitalize()


def feature_help(key: object, fallback: str = "") -> str:
    return FEATURE_HELP.get(str(key or ""), fallback)


def slugify(name: object, *, max_len: int = 48) -> str:
    """A stable identifier made from a display name: ``Acme — EU`` -> ``acme-eu``."""
    text = unicodedata.normalize("NFKD", str(name or "")).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return text[:max_len].strip("-")


def unique_slug(name: object, taken, *, fallback: str = "item", max_len: int = 48) -> str:
    """``slugify`` made unique against ``taken`` by appending -2, -3, ..."""
    base = slugify(name, max_len=max_len - 4) or fallback
    if not base[0].isalpha():
        base = f"{fallback}-{base}"[: max_len - 4]
    taken = set(taken or ())
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def day_text(day) -> str:
    """A calendar day the way browsers write it on English pages: "4 Oct 2026",
    "30 Sept 2026" (en-GB spells September "Sept")."""
    month = day.strftime("%b")
    return f"{day.day} {'Sept' if month == 'Sep' else month} {day.year}"


def datetime_text(value: object, *, seconds: bool = False, date_only: bool = False) -> str:
    """Epoch seconds as the shared server-side text: "4 Oct 2026, 14:01 UTC".

    The |datetime filter wraps this text in a <time> the browser rewrites in the
    viewer's zone; plain strings (option labels, chat replies, printed reports)
    use it directly. ``seconds`` adds ":05" where two moments a minute apart must
    stay distinct; ``date_only`` gives "4 Oct 2026". "" when unreadable.
    """
    if isinstance(value, bool):
        return ""
    try:
        when = datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return ""
    if date_only:
        return day_text(when)
    return f"{day_text(when)}, {when.strftime('%H:%M:%S' if seconds else '%H:%M')} UTC"


def money(value: object, decimals: int = 2, currency: str = "USD") -> str:
    """Money the way every page shows it (``mvMoney`` in lightwork-ui.js too):
    "$1,234.56" or "-$5.00", tiny non-zero amounts as "under $0.01".

    ``decimals=4`` is only for a labelled per-unit price ("$0.0030 per 1K
    tokens"). Another currency shows its code ("EUR 75.00").
    """
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        amount = 0.0
    smallest = 10.0 ** -decimals
    if 0 < abs(amount) < smallest / 2:
        return "under " + money(smallest, decimals, currency)
    number = f"{abs(amount):,.{decimals}f}"
    sign = "-" if amount < 0 else ""
    code = str(currency or "USD").upper()
    return f"{sign}${number}" if code == "USD" else f"{sign}{code} {number}"


def percent(value: object) -> str:
    """A percentage with at most one decimal: 0 -> "0%", 37.46 -> "37.5%"."""
    try:
        amount = float(value or 0)
    except (TypeError, ValueError):
        amount = 0.0
    return f"{amount:,.1f}".removesuffix(".0") + "%"


def size(num_bytes: object) -> str:
    """Bytes as KB / MB / GB."""
    try:
        n = float(num_bytes or 0)
    except (TypeError, ValueError):
        return "0 KB"
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "bytes":
                return f"{int(n)} bytes"
            return f"{n:,.1f} {unit}".replace(".0 ", " ")
        n /= 1024
    return f"{n:,.1f} TB"  # pragma: no cover


def risk_label(goal) -> dict | None:
    """``{"tier", "reasons"}`` when a task's wording looks medium or high risk.

    The same lexical check the task-start gate uses; it reads only the words,
    so the page calls it "looks ... risk" and never claims more."""
    try:
        from maverick.safety.goal_risk import classify_goal, plain_reasons
        found = classify_goal(getattr(goal, "title", "") or "", getattr(goal, "description", "") or "")
    except Exception:  # a label, never a reason for a page to fail
        return None
    if found.tier not in ("medium", "high"):
        return None
    return {"tier": found.tier, "reasons": plain_reasons(found.signals)}


def register(env) -> None:
    """Install the label filters on a Jinja environment (idempotent)."""
    env.filters.setdefault("risk_label", risk_label)
    env.filters.setdefault("model_label", model_label)
    env.filters.setdefault("source_label", source_label)
    env.filters.setdefault("capability_label", capability_label)
    env.filters.setdefault("feature_label", feature_label)
    env.filters.setdefault("money", money)
    env.filters.setdefault("percent", percent)
    env.filters.setdefault("agent_role", agent_role_title)
    env.filters.setdefault("agent_role_help", agent_role_help)
    env.filters.setdefault("effort_label", lambda v: EFFORT_LABELS.get(str(v or ""), str(v or "").capitalize()))
    env.filters.setdefault("filesize", size)
    env.filters.setdefault("fill_placeholders", fill_placeholders)
    env.filters.setdefault("pack_label", lambda d: pack_display_name(
        getattr(d, "name", ""), getattr(d, "persona", ""), getattr(d, "description", "")))


_PERSONA_TITLE = re.compile(
    r"^You are (?:the |an |a )?(?P<title>.+?)"
    r"(?=\s+for\s+(?:this|the|your|a|an)\b|\s+--|\s+—|:|,|\.|\s*\(|\s+(?:at|on|who|inside|within|in)\s)",
    re.DOTALL,
)


def _title_case(text: str) -> str:
    """Capitalise lowercase words; keep acronyms and brand casing as written."""
    small = {"and", "or", "of", "the", "for", "to", "in", "on", "a", "an", "&"}
    words = text.split()
    out = []
    for index, word in enumerate(words):
        if word.islower() and (index == 0 or word not in small):
            word = word[:1].upper() + word[1:]
        out.append(word)
    return " ".join(out)


def pack_display_name(name: object, persona: object = "", description: object = "") -> str:
    """Readable name for a specialist pack.

    ``aero_airworthiness`` -> ``Airworthiness Specialist``, read from the
    pack's own "You are the ... specialist" introduction when it has one,
    else its one-line description, else the humanized pack name.
    """
    match = _PERSONA_TITLE.match(str(persona or "").strip())
    if match:
        title = re.sub(r"\s+", " ", match.group("title")).strip(" -—")
        if 2 <= len(title) <= 60 and "_" not in title:
            return _title_case(title)
    summary = re.sub(r"\s+", " ", str(description or "")).strip().rstrip(".")
    if summary and len(summary) <= 60 and "_" not in summary:
        return _title_case(summary)
    return _title_case(str(name or "").replace("_", " ").replace("-", " ").strip()) or "Agent"


_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_\-]+)\s*\}\}")


def fill_placeholders(text: object) -> str:
    """Show template blanks as readable markers.

    ``Compare {{option_a}} vs {{option_b}}`` -> ``Compare [Option A] vs [Option B]``.
    """
    def label(match: re.Match) -> str:
        words = re.split(r"[_\-]+", match.group(1))
        return "[" + " ".join(w[:1].upper() + w[1:] for w in words if w) + "]"

    return _PLACEHOLDER.sub(label, str(text or ""))
