"""Best-effort grouping of the flow designer's connector/tool catalog.

The live registry is a flat list of ~3,300 tools (built-ins + every enabled SaaS
connector) with no category metadata of their own. A flat 3,300-name typeahead
is hard to browse, so the designer's picker groups results into a small, stable
set of buckets. This module is the single source of that mapping: a pure,
offline, keyword classifier over a tool's name + description.

It is deliberately coarse and first-match-wins -- the goal is "put slack, teams,
and gmail together under Communication", not a perfect taxonomy. Anything that
matches nothing lands in ``OTHER`` (better an honest catch-all than a wrong
label). Ordering matters: more specific buckets are checked before broad ones.
"""
from __future__ import annotations

OTHER = "Other"

# (category, keywords). First bucket with a keyword found in "<name> <desc>"
# (lowercased) wins, so order = priority. Keywords are plain substrings.
_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Communication", (
        "slack", "microsoft teams", "msteams", "ms_teams", " teams ", "gmail",
        "outlook", "email", "e-mail", "smtp", "imap", "sms", "twilio", "discord",
        "zoom", "webex", "telegram", "whatsapp", "messeng", "mattermost",
        "chat ", "chatwork", "ringcentral", "vonage", "dialpad", "aircall",
    )),
    ("Support & Ticketing", (
        "zendesk", "freshdesk", "freshservice", "helpdesk", "help desk",
        "ticket", "intercom", "servicenow", "service desk", "front app",
        "gorgias", "kayako", "helpscout", "help scout", "support",
    )),
    ("Dev & Code", (
        "github", "gitlab", "bitbucket", "jira", "jenkins", "circleci",
        "sentry", "pagerduty", "datadog", "opsgenie", "sonarqube", "snyk",
        "terraform", "kubernetes", "docker", "npm", "pypi", "artifactory",
        "repository", " repo ", "pull request", "ci/cd", "sourcegraph",
    )),
    ("Security & IT", (
        "okta", "auth0", "onelogin", "sso", "identity", "siem", "splunk",
        "crowdstrike", "firewall", "endpoint", "vulnerab", "pentest",
        "burp", "qualys", "tenable", "abuseipdb", "cloudflare", " mdm ",
        "jamf", "intune", "active directory",
    )),
    ("Finance & Payments", (
        "stripe", "paypal", "payment", "invoice", "billing", "quickbooks",
        "xero", "netsuite", "freshbooks", "accounting", "payroll", "ledger",
        "chargebee", "recurly", "braintree", "adyen", "square ", "bank",
        "expense", "coupa", "ariba", "tax", "carta",
    )),
    ("CRM & Sales", (
        "salesforce", "hubspot", "pipedrive", "zoho", "close.io", "close_io",
        "copper", "insightly", "crm", "lead", " deal", "sales", "outreach",
        "salesloft", "gong", "apollo",
    )),
    ("Marketing", (
        "mailchimp", "klaviyo", "sendgrid", "marketo", "campaign", "hootsuite",
        "buffer", "sprout", "google ads", "facebook ads", "adroll", "seo",
        "marketing", "eloqua", "pardot", "customer.io", "braze",
    )),
    ("HR & People", (
        "workday", "bamboohr", "bamboo hr", "greenhouse", "lever", "recruit",
        "gusto", "rippling", "namely", "adp", "personio", "hibob", " hris",
        "applicant", "onboarding", "lucca",
    )),
    ("Files & Storage", (
        "google drive", "gdrive", "dropbox", " box ", "onedrive", "sharepoint",
        "s3", "blob storage", "ftp", "file store", "object storage",
        "cloud storage",
    )),
    ("Data & Analytics", (
        "bigquery", "snowflake", "redshift", "databricks", "looker", "tableau",
        "metabase", "power bi", "segment", "mixpanel", "amplitude", "warehouse",
        "analytics", "sql", "database", "postgres", "mysql", "mongodb",
    )),
    ("Productivity", (
        "notion", "asana", "trello", "monday.com", "clickup", "airtable",
        "smartsheet", "todoist", "calendar", "google sheet", "spreadsheet",
        "confluence", "coda", "basecamp", "wrike", "smartsuite",
    )),
    ("AI & Agents", (
        "openai", "anthropic", "llm", "embedding", "vector", " rag ",
        "hugging face", "huggingface", "cohere", "eval", "inference",
        "prompt", "agent",
    )),
    # Kernel built-ins the flow engine reaches for directly. Checked last among
    # the specific buckets so a connector named e.g. "http_*" still classifies
    # by its SaaS keyword first.
    ("Core", (
        "sandbox", "shell", "world model", "knowledge", "budget", "memory",
        "http request", "http_json", "webhook", "read file", "write file",
        "python", "browser", "self_capability", "deliverable",
    )),
)


def categorize(name: str, description: str = "") -> str:
    """Return the coarse category for a tool, or ``OTHER`` if nothing matches."""
    hay = f"{name or ''} {description or ''}".lower()
    for category, keywords in _RULES:
        for kw in keywords:
            if kw in hay:
                return category
    return OTHER


def categories() -> list[str]:
    """The stable category names in display order, with ``OTHER`` last."""
    return [c for c, _ in _RULES] + [OTHER]


__all__ = ["categorize", "categories", "OTHER"]
