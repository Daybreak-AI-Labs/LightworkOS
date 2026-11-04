"""All-settings catalog rows for the integrations group.

Kept apart from settings_catalog.py so each group can be extended without
editing the shared catalog. entries receives the catalog's own row and
column types (a plain import would be circular).

Covers the tools agents use to reach email, calendars, an ERP system, GitHub
and Obsidian; issue-tracker and webhook delivery settings and their sealed
secrets; the sealed Stripe, Pushover and Microsoft 365 keys; alert batching and
operational alerts; tax-figure updates; billing plans, Stripe prices and
refunds; vendor-onboarding read retries; and voice input. Every row names the
kernel module that reads it, and each environment variable in ``env`` still
wins over the value saved here.
"""
from __future__ import annotations

_HTTPS = r"https://[^\s\"'<>]{1,300}"
_LOCAL_HTTP = r"http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/[^\s\"'<>]{0,300})?"
# A web address: secure, or plain only when it stays on this computer.
_ADDRESS = r"(" + _HTTPS + r"|" + _LOCAL_HTTP + r")?"
_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST = r"(" + _LABEL + r"(\." + _LABEL + r")*)?"
_EMAIL = r"[^@\s<>\"']{1,64}@[^@\s<>\"']{1,190}\.[A-Za-z]{2,24}"
_ACCOUNT = r"[^\s<>\"'{}]{0,254}"
_LINE = r"[^\n\r<>{}\"]{0,256}"
_MODEL_ID = r"[A-Za-z0-9._:/-]{0,128}"
# A folder on this server: absolute (or in the home folder), no ".." steps.
_FOLDER = (r"((?!.*(^|[\\/])\.\.([\\/]|$))(~?/|[A-Za-z]:[\\/])"
           r"[^\x00-\x1f<>\"|?*]{0,500})?")

_PLANS = (("free", "Free"), ("pro", "Pro"), ("enterprise", "Enterprise"))
_FEATURE_WORDS = {
    "core": "Core platform",
    "channels": "Chat channels",
    "audit_export": "Activity record export",
    "grpc": "Connections from other software",
    "sso": "Single sign-on",
    "self_host": "Run on your own servers",
}


def _plan_features() -> tuple[tuple[str, str], ...]:
    """Every feature a plan can include, in plain words."""
    from maverick.billing import DEFAULT_PLANS, gateable_features
    from maverick.departments import department_title

    names = list(dict.fromkeys([*gateable_features(),
                                *(f for plan in DEFAULT_PLANS.values() for f in plan.features)]))
    out = []
    for name in names:
        if name.startswith("department:"):
            out.append((name, "Department: " + department_title(name.split(":", 1)[1])))
        else:
            out.append((name, _FEATURE_WORDS.get(name, name.replace("_", " ").capitalize())))
    return tuple(out)


def _whisper_models() -> tuple[tuple[str, str], ...]:
    from maverick.voice_models import KNOWN_MODELS

    words = {"tiny": "Tiny (fastest, least accurate)", "base": "Base",
             "small": "Small", "medium": "Medium",
             "large": "Large (slowest, most accurate)"}
    out = [("", "Automatic (recommended)")]
    for name in KNOWN_MODELS:
        stem, _, lang = name.partition(".")
        label = words.get(stem.split("-")[0], stem.replace("-", " ").capitalize())
        if stem.startswith("large") and stem != "large":
            label = "Large, " + stem.split("-", 1)[1].replace("-", " ")
        out.append((name, label + (", English only" if lang == "en" else "")))
    return tuple(out)


def voice_choices(source: str) -> list[tuple[str, str]]:
    """Live options for the voice engine rows: only the programs and model
    files the kernel approves right now (see ``maverick.voice_models``). The
    value is the file name; the kernel finds it again inside its own folder
    and re-checks it before use, so no path is typed or shown."""
    from maverick import voice_models

    if source == "voice_programs":
        return [("", "Find it automatically (default)"),
                *((p.name, "Speech program " + p.name) for p in voice_models.approved_programs())]
    words = dict(_whisper_models())
    by_file = {filename: words.get(name, name)
               for name, (filename, _sha, _size) in voice_models.KNOWN_MODELS.items()}
    return [("", "Follow the speech model setting above (default)"),
            *((p.name, by_file.get(p.name, "Added by hand: " + p.name))
              for p in voice_models.approved_model_files())]


def specialist_choices() -> list[tuple[str, str]]:
    """The enabled specialist packs a routing rule can send messages to,
    named by department and job (the kernel re-checks the pack at intake)."""
    from maverick.departments import department_title
    from maverick.domain import SUITE_PREFIXES, enabled_domains, suite_for

    from .identity_format import humanize

    out = []
    for name in sorted(enabled_domains()):
        suite = suite_for(name)
        prefix = max((p for p in SUITE_PREFIXES if name.startswith(p)), key=len, default="")
        job = humanize(name[len(prefix):] or name)
        out.append((name, f"{department_title(suite)}: {job}" if suite else job))
    return sorted(out, key=lambda choice: choice[1].lower())


_ROUTE_URGENCY = (("", "Any"), ("normal", "Normal or more urgent"), ("high", "High or critical"),
                  ("critical", "Critical only"))
_ROUTE_FILES = (("image", "Picture"), ("audio", "Sound recording"), ("video", "Video"),
                ("pdf", "PDF"), ("text", "Text file"), ("file", "Other file"))


def _contact_centre_rows(S) -> tuple:
    """Where a conversation goes outside Lightwork when a person takes it over. Off by default."""
    group, sub = "Integrations", "Contact centre"
    return (
        S("contact_centre", "provider", "Send handed-off conversations to",
          "Off sends nothing. Zendesk creates a support ticket with the reason, the customer and "
          "the recent messages. A signed webhook posts the same details to your own system. "
          "Each handoff is sent once; a send that cannot be confirmed is shown as not confirmed "
          "and is not sent again.",
          "select", group, "off", "maverick.config", subgroup=sub,
          choices=(("off", "Off: do not send anything"),
                   ("zendesk", "Zendesk: create a support ticket"),
                   ("webhook", "Signed webhook: post to your own system")),
          aliases="contact centre zendesk ticket handoff webhook"),
        S("contact_centre", "zendesk_subdomain", "Zendesk subdomain",
          "The part before .zendesk.com in your Zendesk address, such as acme-support.",
          "text", group, "", "maverick.config", subgroup=sub, max_length=63,
          pattern=r"[a-z0-9][a-z0-9-]{0,62}", aliases="zendesk account"),
        S("contact_centre", "zendesk_email", "Zendesk agent email",
          "The email address of the Zendesk agent whose access token is used. Tickets are created "
          "as that agent.",
          "text", group, "", "maverick.config", subgroup=sub, max_length=254,
          pattern=_EMAIL),
        S("contact_centre", "zendesk_api_token", "Zendesk access token",
          "The access token for the agent above, created in Zendesk under Apps and integrations, "
          "then APIs. It is stored sealed and never shown again. A value set on the server is "
          "used instead.",
          "secret", group, "", "maverick.contact_centre", subgroup=sub, max_length=300,
          pattern=r"[^\s\"'<>]{8,300}", env=("MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN",),
          aliases="zendesk token password"),
        S("contact_centre", "webhook_url", "Webhook address",
          "A secure web address (https) that receives the signed message.",
          "text", group, "", "maverick.config", subgroup=sub, max_length=300, pattern=_HTTPS,
          aliases="signed webhook contact centre"),
        S("contact_centre", "webhook_secret", "Webhook signing secret",
          "The secret that signs each message, so your system can check it came from Lightwork. "
          "It is stored sealed and never shown again. A value set on the server is used instead. "
          "Without it, nothing is sent to the webhook.",
          "secret", group, "", "maverick.contact_centre", subgroup=sub, max_length=300,
          pattern=r"[^\s\"'<>]{8,300}", env=("MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET",),
          aliases="webhook signing secret"),
        S("contact_centre", "dashboard_url", "Lightwork web address",
          "The secure web address people use to open Lightwork. Each ticket or message links back "
          "to the conversation there. Leave empty to send without a link.",
          "text", group, "", "maverick.config", subgroup=sub, max_length=300, pattern=_HTTPS),
        S("contact_centre", "max_messages", "Recent messages to include",
          "How many of the latest messages of the conversation are sent. Each message is "
          "shortened to 2,000 characters.",
          "number", group, 20, "maverick.config", subgroup=sub, minimum=1, maximum=50,
          integer=True, unit="messages"),
    )


def entries(S, C, Column) -> tuple:  # noqa: ARG001 -- Column is C
    from maverick.image_edit_models import CHOICES, MAX_MODEL_LENGTH, MODEL_PATTERN

    plan_cells = (
        C("features", "What the plan includes", "picks", choices=_plan_features(),
          max_items=128),
        C("max_daily_dollars", "Daily spending limit (0 means no limit)", "number",
          minimum=0, maximum=1000000, unit="dollars", default=0),
        C("max_concurrent_goals", "Tasks at once (0 means no limit)", "number",
          minimum=0, maximum=10000, integer=True, unit="tasks", default=0),
    )
    return (
        *_contact_centre_rows(S),
        *(S("image_edit", field, label,
            "Copy the model name from its Replicate page, with a version if you want to "
            "keep using that version. Leave empty to keep the built-in choice. A choice "
            "set on the server takes priority. Hosted image edits use your connected "
            "Replicate account and may cost money; saving this choice makes no image.",
            "text", "AI models", "", "maverick.image_edit_models", subgroup="Images",
            env=(env,), pattern=MODEL_PATTERN, max_length=MAX_MODEL_LENGTH,
            aliases="image picture edit inpaint variation upscale replicate")
          for field, env, label in CHOICES),
        # ------------------------------------------------ plans and billing
        S("billing", "enforce_plan_caps", "Hold workspaces to their plan's daily limit",
          "A workspace without a daily spending limit of its own uses the daily limit of its "
          "billing plan. When this is off, such a workspace has no daily limit.",
          "toggle", "Spending & limits", False, "maverick.tenant.registry",
          subgroup="Plans and billing", env=("MAVERICK_ENFORCE_PLAN_CAPS",), weaker=False,
          warning="Workspaces without their own daily limit will be able to spend without "
                  "a daily limit.",
          aliases="plan cap entitlement tenant workspace"),
        S("billing", "plans", "Billing plans",
          "What each plan includes and its limits. A plan with no row here keeps its built-in "
          "features and limits: Free has the core platform, 5 dollars a day and 1 task at a "
          "time; Pro adds chat channels and connections from other software, 100 dollars a "
          "day and 5 tasks at a time; Enterprise has everything with no limits.",
          "table", "Spending & limits", {}, "maverick.billing", subgroup="Plans and billing",
          row_kind="grid", choices=_PLANS, columns=plan_cells, item_label="Plan",
          row_label="Plan", add_label="Change a plan",
          empty_text="Every plan uses its built-in features and limits.", weaker="change",
          warning="Workspaces on a changed plan get exactly what is listed: a feature left "
                  "out is taken away, and a higher limit or 0 lets them spend more.",
          aliases="entitlements plan caps pricing tiers"),
        S("billing.stripe.prices", "pro", "Stripe price for the Pro plan",
          "The Stripe price code charged every month for the Pro plan, the one starting "
          "with price. Leave empty to charge no platform fee for it.",
          "text", "Spending & limits", "", "maverick.config", subgroup="Plans and billing",
          pattern=r"(price_[A-Za-z0-9]{1,200})?", max_length=210, weaker="change",
          warning="Workspaces on this plan will be charged the new price from their next "
                  "bill.",
          aliases="stripe price subscription fee"),
        S("billing.stripe.prices", "enterprise", "Stripe price for the Enterprise plan",
          "The Stripe price code charged every month for the Enterprise plan, the one "
          "starting with price. Leave empty to charge no platform fee for it.",
          "text", "Spending & limits", "", "maverick.config", subgroup="Plans and billing",
          pattern=r"(price_[A-Za-z0-9]{1,200})?", max_length=210, weaker="change",
          warning="Workspaces on this plan will be charged the new price from their next "
                  "bill.",
          aliases="stripe price subscription fee"),
        S("billing.stripe", "secret_key", "Stripe secret key",
          "The secret key of the Stripe account that collects payments, from the Stripe "
          "dashboard's developer settings. It is stored sealed and never shown again. A key "
          "set on the server is used instead.",
          "secret", "Spending & limits", "", "maverick.billing_stripe",
          subgroup="Plans and billing", pattern=r"(sk|rk)_(test|live)_[A-Za-z0-9]{8,250}",
          max_length=260, env=("MAVERICK_STRIPE_SECRET_KEY",),
          aliases="stripe api key billing credentials"),
        S("billing.stripe", "webhook_secret", "Stripe message signing secret",
          "The signing secret of the Stripe webhook that tells Lightwork about failed or "
          "recovered payments. It is stored sealed and never shown again. A secret set on "
          "the server is used instead.",
          "secret", "Spending & limits", "", "maverick.billing_stripe",
          subgroup="Plans and billing", pattern=r"whsec_[A-Za-z0-9+/=]{8,250}",
          max_length=260, env=("MAVERICK_STRIPE_WEBHOOK_SECRET",),
          aliases="stripe webhook signing secret"),
        S("commerce", "stripe_refunds", "Let agents issue Stripe refunds",
          "Agents using the Stripe tool may send real refunds from your Stripe account once "
          "a request is confirmed. When off, they can only prepare a refund for a person.",
          "toggle", "Spending & limits", False, "maverick.tools.stripe_tool",
          env=("MAVERICK_STRIPE_ENABLE_REFUNDS",), weaker=True,
          warning="Agents will be able to send money back to customers from your Stripe "
                  "account.",
          aliases="stripe refund payments"),

        # ---------------------------------------------------- email for agents
        S("email", "disable", "Stop all outgoing email",
          "While this is on, agents cannot send email and Lightwork sends none of its own, "
          "such as invitations.",
          "toggle", "Integrations", False, "maverick.mailer", subgroup="Email for agents",
          env=("MAVERICK_EMAIL_DISABLE",), weaker=False,
          warning="Agents and Lightwork will be able to send email again.",
          aliases="email kill switch block sending"),
        S("email", "provider", "Send email through",
          "The service that sends email for agents and for Lightwork.",
          "select", "Integrations", "smtp", "maverick.mailer", subgroup="Email for agents",
          choices=(("smtp", "Your email account (default)"),
                   ("ses", "Amazon Simple Email Service")),
          env=("EMAIL_PROVIDER",), aliases="smtp ses mail"),
        S("email", "user", "Email account",
          "The account that signs in to send and read email, usually its address.",
          "text", "Integrations", "", "maverick.tools.email_tool", subgroup="Email for agents",
          pattern=_ACCOUNT, max_length=254, env=("EMAIL_USER",)),
        S("email", "app_password", "Email app password",
          "An app password made for Lightwork in your email account's security settings, "
          "not your normal password. It is stored sealed and never shown again.",
          "secret", "Integrations", "", "maverick.tools.email_tool",
          subgroup="Email for agents", max_length=500, env=("EMAIL_APP_PASSWORD",)),
        S("email", "from", "Send email as",
          "The address email comes from. Leave empty to use the email account above.",
          "text", "Integrations", "", "maverick.mailer", subgroup="Email for agents",
          pattern=r"(" + _EMAIL + r")?", max_length=254, env=("EMAIL_FROM",)),
        S("email", "smtp_host", "Outgoing mail server",
          "The server that sends email, such as smtp.gmail.com.",
          "text", "Integrations", "smtp.gmail.com", "maverick.tools.email_tool",
          subgroup="Email for agents", pattern=_HOST, max_length=253,
          env=("EMAIL_SMTP_HOST",), weaker="change",
          warning="Your email account and app password will be sent to the new server."),
        S("email", "smtp_port", "Outgoing mail server port",
          "Usually 465 for a secure connection, or 587.",
          "number", "Integrations", 465, "maverick.tools.email_tool",
          subgroup="Email for agents", minimum=1, maximum=65535, integer=True, unit="port",
          env=("EMAIL_SMTP_PORT",)),
        S("email", "imap_host", "Incoming mail server",
          "The server agents read email from, such as imap.gmail.com.",
          "text", "Integrations", "imap.gmail.com", "maverick.tools.email_tool",
          subgroup="Email for agents", pattern=_HOST, max_length=253,
          env=("EMAIL_IMAP_HOST",), weaker="change",
          warning="Your email account and app password will be sent to the new server."),

        # ------------------------------------------------- calendar for agents
        S("calendar", "url", "Calendar server address",
          "The web address of your calendar account, such as https://caldav.icloud.com.",
          "text", "Integrations", "", "maverick.tools.calendar_tool", subgroup="Calendar",
          pattern=_ADDRESS, max_length=300, env=("CALDAV_URL",), weaker="change",
          warning="Your calendar account and password will be sent to the new address."),
        S("calendar", "user", "Calendar account",
          "The account name or email address that signs in to the calendar.",
          "text", "Integrations", "", "maverick.tools.calendar_tool", subgroup="Calendar",
          pattern=_ACCOUNT, max_length=254, env=("CALDAV_USER",)),
        S("calendar", "password", "Calendar app password",
          "An app password made for Lightwork in your calendar account. It is stored sealed "
          "and never shown again.",
          "secret", "Integrations", "", "maverick.tools.calendar_tool", subgroup="Calendar",
          max_length=500, env=("CALDAV_PASSWORD",)),
        S("calendar", "calendar", "Calendar to use",
          "The name of the calendar agents use. Leave empty to use the first one.",
          "text", "Integrations", "", "maverick.tools.calendar_tool", subgroup="Calendar",
          pattern=_LINE, max_length=256, env=("CALDAV_CALENDAR",)),

        # -------------------------------------------------------- ERP system
        S("erp", "base_url", "Business system address",
          "The web address of your ERP system's data service, such as your NetSuite or SAP "
          "address.",
          "text", "Integrations", "", "maverick.tools.erp_tool", subgroup="Business system (ERP)",
          pattern=_ADDRESS, max_length=300, env=("ERP_BASE_URL",), weaker="change",
          warning="The business system sign-in key will be sent to the new address."),
        S("erp", "token", "Business system sign-in key",
          "The access key agents use to read from your ERP system. It is stored sealed and "
          "never shown again.",
          "secret", "Integrations", "", "maverick.tools.erp_tool",
          subgroup="Business system (ERP)", max_length=4000, env=("ERP_TOKEN",)),
        S("erp", "system", "Business system name",
          "The name agents use for your ERP system in their answers, such as NetSuite.",
          "text", "Integrations", "", "maverick.tools.erp_tool",
          subgroup="Business system (ERP)", pattern=r"[A-Za-z0-9 ._&()-]{0,64}",
          max_length=64, env=("ERP_SYSTEM",)),

        # ------------------------------------------------------------- GitHub
        S("github", "token", "GitHub access key",
          "A GitHub access key agents use to search code and read issues. Without one, only "
          "public projects can be read. It is stored sealed and never shown again.",
          "secret", "Integrations", "", "maverick.tools.github_search", subgroup="GitHub",
          max_length=500, env=("GITHUB_TOKEN", "GH_TOKEN")),
        # Sharing a task's history as a private gist (task history page).
        S("github", "share_token", "GitHub key for sharing task histories",
          "A GitHub access key allowed to create gists. It is used when someone shares a "
          "task's history as a private gist from its history page. It is stored sealed and "
          "never shown again. A key set on the server is used instead.",
          "secret", "Integrations", "", "maverick.run_share", subgroup="GitHub",
          max_length=500, env=("GITHUB_TOKEN", "GH_TOKEN"),
          aliases="github gist share task history key token"),
        S("github", "app_webhook_secret", "GitHub app message secret",
          "The webhook secret of the Lightwork GitHub app. Messages from GitHub are refused "
          "unless they are signed with it. It is stored sealed and never shown again. A "
          "secret set on the server is used instead.",
          "secret", "Integrations", "", "maverick.github_app", subgroup="GitHub",
          max_length=500, env=("MAVERICK_GH_APP_WEBHOOK_SECRET",),
          aliases="github webhook signing secret"),
        S("github", "trigger_labels", "GitHub issue trigger labels",
          "Issue-to-PR automation is currently unavailable until checkout isolation is "
          "implemented. These labels identify events; leave empty to use maverick, "
          "automate and ai-fix.",
          "list", "Integrations", [], "maverick.github_app", subgroup="GitHub",
          item_label="Label", item_hint="automate", pattern=r"[^\s,<>\"'{}]{1,50}",
          item_error="a label without spaces or commas", empty_unset=True, max_items=20,
          max_length=50, env=("MAVERICK_GH_TRIGGER_LABELS",)),

        # ----------------------------------------------------- issue trackers
        S("webhooks", "linear_bot_id", "Linear account that gets the work",
          "Linear issues assigned to this account start a task. Use the account's Linear "
          "user number or email address.",
          "text", "Integrations", "", "maverick.issue_webhooks", subgroup="Issue trackers",
          pattern=_ACCOUNT, max_length=254, env=("MAVERICK_BOT_LINEAR_ID",),
          weaker="change", warning="Issues assigned to this account will start paid tasks."),
        S("webhooks", "jira_bot_id", "Jira account that gets the work",
          "Jira issues assigned to this account start a task. Use the account's Jira account "
          "number or email address.",
          "text", "Integrations", "", "maverick.issue_webhooks", subgroup="Issue trackers",
          pattern=_ACCOUNT, max_length=254, env=("MAVERICK_BOT_JIRA_ACCOUNT_ID",),
          weaker="change", warning="Issues assigned to this account will start paid tasks."),
        S("webhooks", "gitlab_bot_username", "GitLab account that gets the work",
          "GitLab issues assigned to this username start a task.",
          "text", "Integrations", "", "maverick.issue_webhooks", subgroup="Issue trackers",
          pattern=r"[A-Za-z0-9._-]{0,255}", max_length=255,
          env=("MAVERICK_BOT_GITLAB_USERNAME",), weaker="change",
          warning="Issues assigned to this account will start paid tasks."),

        S("webhooks", "gitlab_token", "GitLab message token",
          "The secret token set on your GitLab webhook. Messages from GitLab without it are "
          "refused. It is stored sealed and never shown again. A token set on the server is "
          "used instead.",
          "secret", "Integrations", "", "maverick.issue_webhooks", subgroup="Issue trackers",
          max_length=500, env=("MAVERICK_GITLAB_WEBHOOK_TOKEN",),
          aliases="gitlab webhook token"),
        S("data_map", "graph_token", "Microsoft 365 access key",
          "The access key the data map and data requests use to count a person's Microsoft "
          "365 mail, files and SharePoint sites. It is stored sealed and never shown again. "
          "A key set on the server is used instead.",
          "secret", "Privacy", "", "maverick.data_map", subgroup="Data map",
          max_length=8000, env=("MAVERICK_GRAPH_TOKEN",),
          aliases="microsoft graph token sharepoint onedrive outlook"),

        # ----------------------------------------------------------- Obsidian
        S("obsidian", "vault_path", "Obsidian notes folder",
          "The folder on this server that holds your Obsidian notes, written from the top of "
          "the drive. Agents with the notes tool can read and change the notes in it.",
          "text", "Integrations", "", "maverick.tools.obsidian", subgroup="Obsidian notes",
          pattern=_FOLDER, max_length=500, weaker="change",
          warning="Agents will be able to read and change the notes in the new folder.",
          aliases="vault notes markdown"),

        # ------------------------------------------------------- notifications
        S("notifications", "batch_max", "Send grouped alerts once there are",
          "When routine alerts are grouped, send the group as soon as it holds this many, "
          "without waiting for the time above.",
          "number", "Integrations", 10, "maverick.notification_batcher", minimum=1,
          maximum=1000, integer=True, unit="alerts", env=("MAVERICK_NOTIFY_BATCH_MAX",)),
        S("notifications", "user_key", "Pushover user key",
          "Your Pushover user or group key, the 30 letters and numbers shown on your "
          "Pushover dashboard. It is stored sealed and never shown again. A key set on the "
          "server is used instead.",
          "secret", "Integrations", "", "maverick.notifications", pattern=r"[A-Za-z0-9]{30}",
          max_length=30, env=("PUSHOVER_USER_KEY",), aliases="pushover phone alerts"),
        S("notifications", "app_token", "Pushover app token",
          "The token of the Pushover app Lightwork sends alerts through, 30 letters and "
          "numbers. It is stored sealed and never shown again. A token set on the server is "
          "used instead.",
          "secret", "Integrations", "", "maverick.notifications", pattern=r"[A-Za-z0-9]{30}",
          max_length=30, env=("PUSHOVER_APP_TOKEN",), aliases="pushover phone alerts"),
        S("notifications.email", "host", "Mail server for alerts",
          "The outgoing mail server for alerts and daily summaries, such as smtp.example.com. "
          "Leave empty to send them through the email account under Email for agents.",
          "text", "Integrations", "", "maverick.notifications", subgroup="Email alerts",
          pattern=_HOST, max_length=253),
        S("notifications.email", "port", "Mail server port",
          "Usually 587 for STARTTLS or 465 for SSL.",
          "number", "Integrations", 587, "maverick.notifications", subgroup="Email alerts",
          minimum=1, maximum=65535, integer=True),
        S("notifications.email", "user", "Mail sign-in name",
          "The account name the mail server expects. Leave empty when the server needs none.",
          "text", "Integrations", "", "maverick.notifications", subgroup="Email alerts",
          pattern=_ACCOUNT, max_length=254),
        S("notifications.email", "password", "Mail password",
          "The password or app password for that account. It is stored sealed and never shown "
          "again. A password set on the server is used instead.",
          "secret", "Integrations", "", "maverick.notifications", subgroup="Email alerts",
          max_length=500, env=("MAVERICK_SMTP_PASSWORD",)),
        S("notifications.email", "from_address", "Send alerts as",
          "The address alerts and summaries come from.",
          "text", "Integrations", "", "maverick.notifications", subgroup="Email alerts",
          pattern=r"(" + _EMAIL + r")?", max_length=254),
        S("notifications.email", "tls", "Connection security",
          "How the mail server connection is protected.",
          "select", "Integrations", "starttls", "maverick.notifications", subgroup="Email alerts",
          choices=(("starttls", "STARTTLS (usual on port 587)"), ("ssl", "SSL (usual on port 465)"),
                   ("none", "None (only inside a trusted network)")),
          weaker="none", order=("ssl", "starttls", "none"),
          warning="Mail, including alert contents, would travel unprotected."),
        S("notifications.email", "to", "Send finished-task alerts to",
          "The address that receives finished-task alerts when Email is the alert service.",
          "text", "Integrations", "", "maverick.notifications", subgroup="Email alerts",
          pattern=r"(" + _EMAIL + r")?", max_length=254),
        S("channels.slack", "signing_secret", "Slack signing secret",
          "From your Slack app's Basic Information page. Needed when buttons and slash commands "
          "reach this server over the web instead of Socket Mode. Stored sealed.",
          "secret", "Chat channels", "", "maverick_dashboard.me_api", subgroup="Slack",
          max_length=200, env=("SLACK_SIGNING_SECRET",)),
        S("channels.slack", "approvals_channel", "Post new approval requests in",
          "The Slack channel id (starts with C) where new requests appear as cards with Approve "
          "and Reject buttons. Leave empty to post none.",
          "text", "Chat channels", "", "maverick.channel_approvals", subgroup="Slack",
          pattern=r"([A-Z0-9]{5,24})?", max_length=24, env=("SLACK_APPROVALS_CHANNEL",)),
        S("my_work", "digest_enable", "Send a daily summary",
          "Send each person a summary of what is waiting for them, once a day at their own "
          "hour, through their linked chat apps and email.",
          "toggle", "Integrations", False, "maverick.config", subgroup="Daily summary",
          env=("MAVERICK_DAILY_DIGEST",)),
        S("my_work", "digest_hour", "Usual summary hour",
          "The local hour the summary goes out unless a person picks their own on My work.",
          "number", "Integrations", 8, "maverick.config", subgroup="Daily summary",
          minimum=0, maximum=23, integer=True, unit="o'clock"),
        S("my_work", "digest_poll_seconds", "Check for due summaries every",
          "How often Lightwork looks for people whose summary is due.",
          "number", "Integrations", 300, "maverick.config", subgroup="Daily summary",
          minimum=30, maximum=3600, integer=True, unit="seconds", restart=True),
        S("my_work", "send_when_empty", "Send empty summaries",
          "Send the summary even when nothing is waiting, unless a person chooses otherwise.",
          "toggle", "Integrations", False, "maverick.config", subgroup="Daily summary"),
        S("my_work", "monthly_spend_limit_dollars", "Monthly spending limit per person",
          "The figure each person's spending this month is compared with on My work and in "
          "the summary. Zero shows no limit.",
          "number", "Integrations", 0, "maverick.config", subgroup="Daily summary",
          minimum=0, maximum=1000000, unit="dollars"),
        S("alerts", "enabled", "Alert me about problems with Lightwork itself",
          "Send an urgent alert with the service chosen above when, for example, the "
          "emergency stop trips, a spending limit runs out or the activity record breaks.",
          "toggle", "Integrations", False, "maverick.ops_alert", env=("MAVERICK_ALERTS",),
          aliases="operations alerts paging on-call"),

        # ------------------------------------------------ task event delivery
        S("webhooks", "workers", "Deliver task events in parallel",
          "How many task event messages are sent to your addresses at the same time.",
          "number", "Integrations", 4, "maverick.webhooks", subgroup="Task event delivery",
          minimum=1, maximum=64, integer=True, unit="at once", restart=True,
          env=("MAVERICK_WEBHOOK_WORKERS",)),
        S("webhooks", "max_inflight", "Most task events waiting to be sent",
          "Task event messages beyond this many are dropped and recorded, so a slow "
          "receiving address cannot use up this server's memory.",
          "number", "Integrations", None, "maverick.webhooks", subgroup="Task event delivery",
          minimum=1, maximum=10000, integer=True, unit="messages", restart=True,
          none_text="Automatic (16 for each parallel delivery)", weaker="higher",
          env=("MAVERICK_WEBHOOK_MAX_INFLIGHT",),
          warning="More unsent messages can pile up in memory when a receiving address is "
                  "slow."),
        S("webhooks", "max_age_seconds", "Accept signed messages for",
          "Signed messages from other systems older than this are refused, so a copied "
          "message cannot be sent again later.",
          "number", "Integrations", 300, "maverick.webhooks", subgroup="Task event delivery",
          minimum=30, maximum=86400, integer=True, unit="seconds", weaker="higher",
          env=("MAVERICK_WEBHOOK_MAX_AGE_SECONDS",),
          warning="Older signed messages will be accepted, so a copied message can be sent "
                  "again for longer."),
        S("webhooks", "body_limit", "Largest incoming chat message",
          "Messages sent to this server by chat apps larger than this are refused before "
          "they are checked.",
          "number", "Integrations", 1048576, "maverick_channels.base",
          subgroup="Task event delivery", minimum=16, maximum=102400, integer=True,
          scale=1024, unit="KB", restart=True, weaker="higher",
          env=("MAVERICK_WEBHOOK_BODY_LIMIT",),
          warning="Anyone who can reach the chat app ports can make this server read "
                  "larger messages before they are checked."),

        # ---------------------------------------------------------- automations
        S("automation_import", "max_steps", "Steps kept from an imported automation",
          "Imported automations with more steps than this are shortened, so their "
          "instructions stay a sensible length for every run.",
          "number", "Integrations", 200, "maverick.automation_import.ir", minimum=1,
          maximum=5000, integer=True, unit="steps", weaker="higher",
          env=("MAVERICK_IMPORT_MAX_STEPS",),
          warning="Longer imported automations make longer instructions, which cost more on "
                  "every run."),

        # ------------------------------------------------------ tax figures
        S("tax", "update_url", "Where tax figure updates come from",
          "The web address Lightwork checks for signed updates to tax figures. Updates are "
          "used only when they are signed by a trusted publisher below.",
          "text", "Integrations", "", "maverick.config", pattern=_ADDRESS, max_length=300,
          aliases="tax constants update channel"),
        S("tax", "trusted_constants_pubkeys", "Trusted tax figure publishers",
          "Tax figure updates signed by these publishers are used. Add a publisher by "
          "uploading or pasting their public key file; each one is shown by its fingerprint.",
          "keys", "Integrations", [], "maverick.config", weaker="grow",
          warning="Tax figures signed by a newly trusted publisher will be used in tax work.",
          aliases="tax signed updates public key publisher"),

        # --------------------------------------------------------- chat apps
        S("channels.routing", "rules", "Send chat messages to an agent or specialist",
          "Rules are checked in order for every message that arrives through a chat app; "
          "the first one that matches decides which agent or specialist handles it. Messages that "
          "match no rule go to the general assistant, as they do with no rules at all.",
          "rules", "Chat channels", [], "maverick.channel_autorouting",
          subgroup="Message routing",
          columns=(
              C("any_keyword", "Contains any of these words", "words", max_items=20,
                max_length=60, pattern=r"[^,<>{}\"\n\r]{1,60}",
                item_error="a word or short phrase"),
              C("urgency", "How urgent it sounds", "select", choices=_ROUTE_URGENCY, default=""),
              C("attachments", "Has a file of this kind", "picks", choices=_ROUTE_FILES),
              C("min_length", "At least this many characters (0 means any)", "number",
                minimum=0, maximum=100000, integer=True, default=0, unit="characters"),
              C("specialist", "Send to", "pick", choices_from="specialists", required=True),
          ),
          item_label="Rule", add_label="Add a rule",
          empty_text="Every chat message goes to the general assistant.", weaker="change",
          warning="Matching chat messages will be handled by the chosen agent or specialist, "
                  "with its tools and permissions.",
          aliases="routing rules agent specialist department triage"),
        S("channels", "rich_render", "Show formulas and diagrams as a page",
          "When a reply contains formulas or diagrams, also send a page that shows them "
          "properly. The page is saved on this server.",
          "toggle", "Chat channels", False, "maverick_channels.rich_render",
          subgroup="Every chat app", restart=True, env=("MAVERICK_CHANNELS_RICH_RENDER",),
          aliases="math mermaid render"),
        S("channels", "max_intake_records", "Saved chat message capacity",
          "The number of saved message receipts each workspace can hold across all chat apps. "
          "Lightwork clears delivered messages after their retention window; messages needing "
          "review stay saved. Raise this before capacity is full.",
          "number", "Chat channels", 20000, "maverick_channels.delivery",
          subgroup="Every chat app", minimum=1000, maximum=100000, integer=True,
          unit="messages", restart=True, weaker="higher",
          warning="A higher limit retains more message receipts on this server."),

        # ---------------------------------------------------- vendor onboarding
        S("vendor_onboarding", "safe_read_attempts", "Tries for each vendor document read",
          "How many times Lightwork tries to read a vendor document or ticket before it "
          "stops and asks a person.",
          "number", "AI governance", 3, "maverick.vendor_onboarding_setup",
          subgroup="Vendor onboarding", minimum=1, maximum=5, integer=True, unit="tries"),
        S("vendor_onboarding", "safe_read_backoff_seconds", "Wait between those tries",
          "How long to wait before trying a vendor document or ticket read again.",
          "number", "AI governance", 0.25, "maverick.vendor_onboarding_setup",
          subgroup="Vendor onboarding", minimum=0, maximum=5, step=0.05, unit="seconds"),

        # -------------------------------------------------------------- voice
        S("voice", "stt_backend", "Turn speech into text using",
          "Where spoken requests are turned into text.",
          "select", "AI models", "auto", "maverick.tools.voice", subgroup="Voice",
          choices=(("local", "Only this computer (recordings stay here)"),
                   ("auto", "Automatic: an outside service when one is set up (default)"),
                   ("openai", "OpenAI"), ("groq", "Groq")),
          order=("local", "auto", "openai", "groq"), weaker=True,
          env=("MAVERICK_VOICE_STT_BACKEND",),
          warning="Recordings of spoken requests may be sent to an outside service.",
          aliases="speech to text transcription whisper"),
        S("voice", "stt_model", "Speech model on this computer",
          "The speech-to-text model used on this computer. Larger models are more accurate "
          "and slower.",
          "select", "AI models", "", "maverick.voice_models", subgroup="Voice",
          choices=_whisper_models(), env=("MAVERICK_WHISPER_MODEL",),
          aliases="whisper model size"),
        S("voice", "whisper_cpp_bin", "Speech program on this computer",
          "The whisper.cpp program that turns speech into text on this computer. Only "
          "programs in Lightwork's own programs folder are offered, and the choice is "
          "checked again each time it runs.",
          "select", "AI models", "", "maverick.tools.voice", subgroup="Voice",
          choices_from="voice_programs", env=("MAVERICK_WHISPER_CPP",), weaker="change",
          warning="Lightwork will run a different program on this server to turn speech "
                  "into text.",
          aliases="whisper cpp binary program"),
        S("voice", "whisper_cpp_model", "Speech model file on this computer",
          "The speech model file that program loads. Only files in Lightwork's speech model "
          "folder are offered, and the choice is checked again each time it is loaded.",
          "select", "AI models", "", "maverick.voice_models", subgroup="Voice",
          choices_from="voice_model_files", env=("MAVERICK_WHISPER_CPP_MODEL",),
          weaker="change",
          warning="A different speech model file will be loaded to turn speech into text.",
          aliases="whisper ggml model file"),
        S("voice", "stt_openai_model", "OpenAI speech model",
          "The OpenAI model that turns speech into text. Leave empty for whisper-1.",
          "text", "AI models", "", "maverick.tools.voice", subgroup="Voice",
          pattern=_MODEL_ID, max_length=128, env=("MAVERICK_WHISPER_OPENAI_MODEL",)),
        S("voice", "stt_groq_model", "Groq speech model",
          "The Groq model that turns speech into text. Leave empty for "
          "whisper-large-v3-turbo.",
          "text", "AI models", "", "maverick.tools.voice", subgroup="Voice",
          pattern=_MODEL_ID, max_length=128, env=("MAVERICK_WHISPER_GROQ_MODEL",)),
        S("voice", "tts_openai_model", "OpenAI voice for spoken replies",
          "The OpenAI model that reads replies aloud. Leave empty for tts-1.",
          "text", "AI models", "", "maverick.tools.voice", subgroup="Voice",
          pattern=_MODEL_ID, max_length=128, env=("MAVERICK_TTS_OPENAI_MODEL",)),
        S("voice", "tts_elevenlabs_model", "ElevenLabs voice for spoken replies",
          "The ElevenLabs model that reads replies aloud. Leave empty for their fast "
          "turbo model.",
          "text", "AI models", "", "maverick.tools.voice", subgroup="Voice",
          pattern=_MODEL_ID, max_length=128, env=("MAVERICK_TTS_ELEVENLABS_MODEL",)),
        S("voice", "max_upload_bytes", "Longest voice recording accepted",
          "Voice recordings sent from Chat larger than this are refused.",
          "number", "AI models", 26214400, "maverick_dashboard.api", subgroup="Voice",
          minimum=1, maximum=200, integer=True, scale=1048576, unit="MB", weaker="higher",
          env=("MAVERICK_VOICE_MAX_BYTES",),
          warning="Larger recordings will be accepted, which uses more of this server's "
                  "memory."),
        S("voice", "transcribe_concurrency", "Recordings turned into text at once",
          "How many voice recordings are turned into text at the same time.",
          "number", "AI models", 2, "maverick_dashboard.api", subgroup="Voice", minimum=1,
          maximum=16, integer=True, unit="at once",
          env=("MAVERICK_VOICE_TRANSCRIBE_CONCURRENCY",)),
        S("attachments", "audio_max_bytes", "Largest sound file agents study",
          "Sound files larger than this are refused by the listening tool, so one file "
          "cannot use up this server's memory.",
          "number", "AI models", 67108864, "maverick.tools.audio_understanding",
          subgroup="Voice", minimum=1, maximum=2048, integer=True, scale=1048576,
          unit="MB", weaker="higher", env=("MAVERICK_AUDIO_MAX_BYTES",),
          warning="Larger sound files will be accepted, which uses more of this server's "
                  "memory."),
    ) + _finance_profile_rows(S, C)


# ------------------------------------------------ finance operating profile
# The Finance Operating Profile (maverick.finance.profile, finance-agent-suite
# §3.8). Values match the installer's finance step. Every row takes effect only
# while finance operations are turned on.
_FINANCE_SUBGROUP = "How agents handle finance work"
_LEVELS = (("draft", "Prepare only: a person carries it out"),
           ("approve", "Act after a person approves"),
           ("auto_threshold", "Act alone under the approval limit"),
           ("straight_through", "Act alone"))
_ALWAYS_A_PERSON = ("Payments, journal postings, payroll, bank-detail and supplier-record "
                    "changes, period close, chart-of-accounts changes, tax payments and "
                    "filings always wait for a person, whatever is chosen here.")


def _finance_actions() -> tuple[tuple[str, str], ...]:
    from maverick.finance.profile import FINANCE_ACTIONS

    return tuple(sorted(FINANCE_ACTIONS.items(), key=lambda item: item[1]))


def _finance_profile_rows(S, C) -> tuple:
    return (
        S("finance", "framework", "Accounting framework",
          "The accounting standards your books follow. Lightwork adds that framework's rules "
          "to agent actions: under US GAAP, reversing an impairment write-down or revaluing "
          "an asset upward is refused; under IFRS, those wait for a person and LIFO stock "
          "costing is refused. Posting, period close and accounting-policy changes wait for "
          "a person under both. Applies while finance operations are turned on.",
          "select", "Finance", "", "maverick.finance.profile", subgroup="Rules",
          choices=(("", "Not set"), ("us_gaap", "US GAAP"), ("ifrs", "IFRS")),
          weaker="change",
          warning="Different accounting rules will apply: some agent actions that were "
                  "refused may go ahead once a person approves them.",
          aliases="gaap ifrs accounting standards"),
        S("finance", "materiality", "Materiality",
          "The amount at which a finance matter is significant. A duplicate payment, a "
          "payment just under or split around an approval limit, or one made out of hours "
          "that adds up to this much or more needs a second, independent reviewer before "
          "its case can close. A finance action set to act alone under the approval limit "
          "waits for a person above this amount. Leave empty for no materiality. "
          "Applies while finance operations are turned on.",
          "number", "Finance", None, "maverick.finance.profile", subgroup=_FINANCE_SUBGROUP,
          minimum=1, maximum=1000000000, unit="dollars", weaker="higher",
          warning="Fewer unusual payment patterns will need a second reviewer, and agents "
                  "may act alone on larger amounts.",
          aliases="materiality flux review threshold"),
        S("finance.automation", "default", "How far agents go on finance actions",
          "What agents may do on finance actions such as approving expenses or sending "
          "invoices. Act alone under the approval limit uses the lower of Pause payments "
          "above and Materiality; with neither set, each action waits for a person. "
          + _ALWAYS_A_PERSON + " Applies while finance operations are turned on.",
          "select", "Finance", "", "maverick.finance.profile", subgroup=_FINANCE_SUBGROUP,
          choices=(("", "Not set: only the approval limits and rules apply"), *_LEVELS),
          weaker=True, order=("draft", "approve", "auto_threshold", "straight_through", ""),
          warning="Agents will be able to do more on finance actions without a person.",
          aliases="automation level ladder draft approve straight through"),
        S("finance.automation", "*", "Finance actions with their own level",
          "Give one finance action its own level instead of the one above. "
          + _ALWAYS_A_PERSON + " Applies while finance operations are turned on.",
          "table", "Finance", {}, "maverick.finance.profile", subgroup=_FINANCE_SUBGROUP,
          key_kind="entries", fixed_keys=("default",), row_kind="grid",
          choices=_finance_actions(), scalar=True,
          columns=(C("level", "How far agents go", "select", choices=_LEVELS,
                     required=True),),
          row_label="Finance action", item_label="Action", add_label="Add an action",
          empty_text="Every finance action uses the level above.", weaker="change",
          warning="The actions you changed will follow their new level; a looser level "
                  "lets agents do more without a person.",
          aliases="automation per action class"),
        S("finance.sod", "mode", "When one agent could do incompatible finance duties",
          "Recording, approving, moving money and reconciling must not sit with one agent. "
          "When an agent about to act holds an incompatible duty, Lightwork can block the "
          "action, or record the conflict and ask a person to approve it instead. A "
          "conflict on a payment, posting or other always-approved action is blocked "
          "either way. Applies while finance operations are turned on.",
          "select", "Finance", "", "maverick.finance.profile", subgroup=_FINANCE_SUBGROUP,
          choices=(("", "Not checked when an action runs"), ("enforce", "Block the action"),
                   ("warn", "Record it and ask a person")),
          weaker=True,
          order=("enforce", "warn", ""),
          warning="Actions by an agent holding incompatible finance duties will no "
                  "longer be blocked.",
          aliases="segregation of duties sod"),
        S("finance.approvals", "timeout", "When nobody answers a finance approval",
          "What happens to a finance action when nobody decides on the Approvals page "
          "within the approval wait (Safety, Approvals). Lightwork refuses the action and "
          "takes the request off the page; an automatic approval setting or an earlier "
          "remember this approval never counts. Refusing is the only choice because a "
          "finance action must never go ahead without a person's decision. Applies while "
          "finance operations are turned on.",
          "select", "Finance", "", "maverick.finance.profile", subgroup=_FINANCE_SUBGROUP,
          choices=(("", "Not set: the general approval rules apply"),
                   ("fail_closed", "Refuse the action")),
          weaker=True,
          order=("fail_closed", ""),
          warning="Finance approvals will follow the general approval rules again: an "
                  "earlier remember this approval can let them run, and unanswered "
                  "requests stay on the Approvals page.",
          aliases="approval timeout fail closed"),
    )


def cross_checks(effective: dict, by_id: dict, error: type[Exception]) -> None:
    """Refuse finance levels the kernel would refuse to build (hard floors)."""
    from maverick.finance.profile import HARD_FLOOR_ACTIONS

    rows = effective.get("finance.automation.*")
    lowered = sorted(
        action for action, level in (rows if isinstance(rows, dict) else {}).items()
        if action in HARD_FLOOR_ACTIONS and level in {"auto_threshold", "straight_through"}
    )
    if lowered:
        setting = by_id["finance.automation.*"]
        label = dict(setting.choices).get(lowered[0], lowered[0])
        raise error(
            f"{setting.label}: “{label}” always waits for a person, so choose prepare "
            "only or act after a person approves."
        )
