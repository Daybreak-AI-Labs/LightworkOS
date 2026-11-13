"""All-settings catalog rows for the privacy group.

Kept apart from settings_catalog.py so each group can be extended without
editing the shared catalog. entries receives the catalog's own row and
column types (a plain import would be circular).

The rows cover the value settings of the consent preferences, privacy
automation and data use governance modules (their on/off switches live on the
Modules list), the consent register, the data map, outbound prompt redaction,
compliance profiles and how long an action waits for a dashboard approval.
(The data map's Microsoft 365 key is handled with the integrations rows.)
Each row mirrors the bounds and formats its kernel reader enforces, so a saved
value never makes a module's configuration invalid on its own; combinations the
readers refuse are caught by :func:`cross_checks` before anything is written.

Addresses are exact https origins of the service each module talks to (no
path, query, credentials, address numbers or local names), so a setting can
never point a connection at an internal machine. Names of server-held keys are
sealed secrets, and each must carry the word its module's keys use (CONSENT,
DATA_USE, RIGHTS), so a key meant for one service can never be pointed
at an unrelated server credential and sent elsewhere.

Settings whose readers do not exist yet, per-scan or per-destination values
that live on the module pages, and values that need a control kind the catalog
does not have are listed in the WP4 report rather than offered here.
"""
from __future__ import annotations

import math

from maverick.config_contracts import BOOLEAN_SETTINGS, CHOICE_SETTINGS, INTEGER_SETTINGS

_P = "Privacy"

# An exact https origin on a public host name: letters in the last part (so no
# address numbers), no local-only names, an optional port and nothing after.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_PUBLIC_ORIGIN = (
    r"https://(?:" + _LABEL + r"\.)+"
    r"(?!(?i:localhost|local|internal|lan|home|arpa|test|invalid|example)(?:[:/]|$))"
    r"[A-Za-z]{2,63}(?::[0-9]{1,5})?/?"
)
# A public https address that may carry a path (sign-in issuers do).
_PUBLIC_URL = _PUBLIC_ORIGIN[:-2] + r"(?:/[^\s\"'<>?#]{0,300})?"


def _optional(pattern: str) -> str:
    return r"(?:" + pattern + r")?"


def _suffix_origin(*suffixes: str, port: bool = True) -> str:
    """An https origin whose host ends with one of ``suffixes`` (a vendor's)."""
    hosts = "|".join(s.replace(".", r"\.") for s in suffixes)
    tail = r"(?::443)?/?" if port else r"/?"
    return r"https://(?:" + _LABEL + r"\.)+(?:" + hosts + r")" + tail


def _exact_origin(host: str) -> str:
    return r"https://" + host.replace(".", r"\.") + r"(?::443)?/?"


def _env_name(word: str, upper: int = 127) -> str:
    """An upper-case server key name that contains ``word``."""
    return r"(?=[A-Z0-9_]*" + word + r")[A-Z][A-Z0-9_]{2," + str(upper) + r"}"


_ID = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"
_PROVIDER_FIELD = r"[A-Za-z_][A-Za-z0-9_]{0,127}"
_KEY_REF = r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}"
_WORKSPACE = r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9_-])?"

_DAY = 86400
_HOUR = 3600
_MINUTE = 60
_KB = 1024
_MB = 1024 * 1024

_DESTINATIONS = (
    ("salesforce", "Salesforce"),
    ("marketo", "Marketo"),
    ("adobe_experience_platform", "Adobe Experience Platform"),
    ("snowflake", "Snowflake"),
)
# Fields each destination needs before it can be chosen (the reader refuses
# a chosen destination with any of them missing).
_DESTINATION_FIELDS = {
    "salesforce": ("destination_id", "origin", "credential_secret_ref", "credential_revision",
                   "api_version", "object_api_name", "external_id_field",
                   "payload_digest_field"),
    "marketo": ("destination_id", "origin", "credential_secret_ref", "credential_revision",
                "custom_object_name", "dedupe_field", "payload_digest_field"),
    "adobe_experience_platform": ("destination_id", "origin", "credential_secret_ref",
                                  "credential_revision", "connection_id", "flow_id",
                                  "dataset_id", "schema_id", "ims_org_id"),
    "snowflake": ("destination_id", "origin", "credential_secret_ref", "credential_revision",
                  "database", "schema", "table", "warehouse", "role"),
}
_RIGHTS_SOURCES = (
    ("microsoft_graph_users", "Microsoft 365 users", _exact_origin("graph.microsoft.com"),
     "https://graph.microsoft.com"),
    ("google_workspace_users", "Google Workspace users", _exact_origin("admin.googleapis.com"),
     "https://admin.googleapis.com"),
    ("salesforce_contacts", "Salesforce contacts", _suffix_origin("salesforce.com"),
     "https://yourcompany.my.salesforce.com"),
    ("servicenow_users", "ServiceNow users", _suffix_origin("service-now.com"),
     "https://yourcompany.service-now.com"),
)
_DISCOVERY_SOURCES = (
    ("aws_s3", "Amazon S3"),
    ("azure_blob", "Azure Blob Storage"),
    ("google_cloud_storage", "Google Cloud Storage"),
    ("snowflake_metadata", "Snowflake (table descriptions only)"),
    ("servicenow_cmdb", "ServiceNow configuration database"),
    ("entra_assets", "Microsoft Entra"),
)
_COMPLIANCE_PROFILES = (
    ("hipaa", "HIPAA (health data, needs enterprise mode)"),
    ("gdpr", "GDPR (EU personal data)"),
    ("eu_ai_act", "EU AI Act"),
    ("nist_ai_rmf", "NIST AI Risk Management Framework"),
    ("iso_42001", "ISO 42001"),
    ("soc2", "SOC 2 (needs enterprise mode)"),
    ("sr_11_7", "SR 11-7 (bank model risk)"),
)

_CP = "consent_preferences"
_DEST = "consent_preferences.delivery.destinations"
_DU = "data_use_governance"
_PA = "privacy_automation"
_SOURCES = "privacy_automation.rights_orchestration.source_adapters"
_REMEDIATION = "privacy_automation.data_discovery.remediation"


def _sub(module: str, part: str) -> str:
    return f"{module} \N{EM DASH} {part}"


def entries(S, C, Column) -> tuple:  # noqa: ARG001 -- rows only
    return (
        *_consent_rows(S),
        *_destination_rows(S),
        *_consent_more_rows(S),
        *_data_use_rows(S),
        *_automation_rows(S),
        *_rights_rows(S),
        *_other_rows(S),
        *_deadline_alert_rows(S),
        *_consent_limit_rows(S),
        *_data_use_limit_rows(S),
        *_publication_trust_rows(S),
        *_consent_storage_rows(S),
        *_data_use_check_rows(S),
    )


# ------------------------------------------------------- consent preferences
def _consent_rows(S) -> tuple:
    signals = _sub("Consent preferences", "privacy signals")
    publishing = _sub("Consent preferences", "publishing")
    scanner = _sub("Consent preferences", "website scanner")
    apps = _sub("Consent preferences", "app scanner")
    identity = _sub("Consent preferences", "sign-in for people")
    native = "maverick_dashboard.consent_native_composition"
    return (
        S(f"{_CP}.standards", "gpc", "Global Privacy Control signal",
          "Include the Global Privacy Control browser signal in the privacy-signal rules your "
          "phone and TV consent apps follow. Apps set up under different rules must refresh "
          "them before they can send signals again.",
          "toggle", _P, False, native, subgroup=signals, aliases="gpc opt out"),
        S(f"{_CP}.standards", "dnt", "Do Not Track signal",
          "Include the Do Not Track browser signal in the privacy-signal rules your phone and "
          "TV consent apps follow.",
          "toggle", _P, False, native, subgroup=signals, aliases="dnt"),
        S(f"{_CP}.standards", "gpp", "Global Privacy Platform consent strings",
          "Accept Global Privacy Platform consent strings from phone and TV apps. Your server "
          "team must install a certified checker for these strings first.",
          "toggle", _P, False, native, subgroup=signals, aliases="gpp advertising"),
        S(f"{_CP}.standards", "tcf", "IAB Transparency and Consent Framework strings",
          "Accept Transparency and Consent Framework strings from phone and TV apps. Your "
          "server team must install a certified checker for these strings first.",
          "toggle", _P, False, native, subgroup=signals, aliases="tcf iab advertising"),
        S(f"{_CP}.standards", "google_consent_mode", "Google Consent Mode",
          "Include Google Consent Mode in the privacy-signal rules your phone and TV consent "
          "apps follow.",
          "toggle", _P, False, native, subgroup=signals, aliases="google advertising"),

        S(f"{_CP}.publishing.web_settings", "max_history", "Website settings versions kept",
          "How many earlier versions of your published website consent settings are kept.",
          "number", _P, 250, "maverick.consent_web_publish_settings", subgroup=publishing,
          minimum=1, maximum=1000, integer=True, unit="versions"),
        S(f"{_CP}.publishing.web_settings", "retention_seconds",
          "Keep website settings history for",
          "Earlier versions of your website consent settings older than this are removed.",
          "number", _P, 365 * _DAY, "maverick.consent_web_publish_settings",
          subgroup=publishing, minimum=1, maximum=3660, integer=True, scale=_DAY, unit="days",
          weaker="lower",
          warning="Older website settings history will be permanently deleted sooner."),

        S(f"{_CP}.scanner", "allow_authenticated_scans", "Allow scans that sign in to your sites",
          "Let website scans use stored sign-in details to check pages that are behind a "
          "sign-in.", "toggle", _P, False, "maverick.consent_scan_inventory",
          subgroup=scanner, weaker=True,
          warning="Scans will sign in to your websites with stored sign-in details and look at "
                  "pages behind the sign-in."),
        S(f"{_CP}.scanner.scheduler", "enable", "Run scheduled website scans",
          "Start website scans that are due automatically in the background. Turning this on "
          "takes effect after a restart.", "toggle", _P, False,
          "maverick_dashboard.consent_scan_scheduler", subgroup=scanner, restart=True),
        S(f"{_CP}.scanner.scheduler", "poll_seconds", "Check for due scans every",
          "How often the background runner looks for scans that are due.", "number", _P, 60,
          "maverick_dashboard.consent_scan_scheduler", subgroup=scanner, minimum=5,
          maximum=3600, integer=True, unit="seconds"),
        S(f"{_CP}.scanner.scheduler", "enqueue_limit", "Scans queued per check",
          "The most due scans queued each time the runner checks.", "number", _P, 100,
          "maverick_dashboard.consent_scan_scheduler", subgroup=scanner, minimum=1,
          maximum=500, integer=True, unit="scans"),
        S(f"{_CP}.scanner.scheduler", "claim_limit", "Scans run at the same time",
          "The most scans the runner works on at once.", "number", _P, 4,
          "maverick_dashboard.consent_scan_scheduler", subgroup=scanner, minimum=1,
          maximum=100, integer=True, unit="scans"),
        S(f"{_CP}.scanner.scheduler", "tenant_limit", "Workspaces checked each time",
          "The most workspaces the runner looks at in one check.", "number", _P, 1000,
          "maverick_dashboard.consent_scan_scheduler", subgroup=scanner, minimum=1,
          maximum=10000, integer=True, unit="workspaces"),

        S(f"{_CP}.application_scanner", "max_records", "App scan records kept",
          "The most phone and TV app scan records kept. New scans are refused once this many "
          "are kept.", "number", _P, 25000,
          "maverick_dashboard.consent_application_scanner_composition", subgroup=apps,
          minimum=1, maximum=1000000, integer=True, unit="records", weaker="higher",
          warning="More app scan records will be kept."),
        S(f"{_CP}.application_scanner", "retention_seconds", "Keep app scan records for",
          "App scan records older than this are removed.", "number", _P, 365 * _DAY,
          "maverick_dashboard.consent_application_scanner_composition", subgroup=apps,
          minimum=1, maximum=3650, integer=True, scale=_DAY, unit="days", weaker="lower",
          warning="Older app scan records will be permanently deleted sooner."),

        S(f"{_CP}.identity", "enable", "Let people sign in to manage their consent",
          "People can sign in through your own sign-in provider to see and change their "
          "consent choices. Fill in the three provider details below first.", "toggle", _P,
          False, "maverick.consent_identity_federation", subgroup=identity, weaker=True,
          warning="People signed in through the provider below will be able to see and change "
                  "their consent records."),
        S(f"{_CP}.identity", "issuer", "Sign-in provider address",
          "The address your sign-in provider writes into its sign-in tokens, starting with "
          "https.", "text", _P, "", "maverick.consent_identity_federation", subgroup=identity,
          pattern=_optional(_PUBLIC_URL), max_length=400, weaker="change",
          warning="Sign-ins from a different provider will be trusted."),
        S(f"{_CP}.identity", "audience", "Lightwork's name at the sign-in provider",
          "The name your sign-in provider gave Lightwork when you registered it.", "text", _P,
          "", "maverick.consent_identity_federation", subgroup=identity,
          pattern=r"(?:[^\s<>\"'{}]{1,256})?", max_length=256, weaker="change",
          warning="Sign-in tokens made for a different application will be accepted."),
        S(f"{_CP}.identity", "jwks_origin", "Where the provider publishes its signing keys",
          "The secure web address, with nothing after the host name, where your sign-in "
          "provider publishes the keys that prove its tokens are genuine.", "text", _P, "",
          "maverick.consent_identity_federation", subgroup=identity,
          pattern=_optional(_PUBLIC_ORIGIN), max_length=300, weaker="change",
          warning="Sign-in tokens will be checked against keys from a different address."),
        S(f"{_CP}.identity", "token_ttl_seconds", "Oldest sign-in token accepted",
          "Sign-in tokens older than this are refused.", "number", _P, 600,
          "maverick.consent_identity_federation", subgroup=identity, minimum=1, maximum=1440,
          integer=True, scale=_MINUTE, unit="minutes", weaker="higher",
          warning="Older sign-in tokens will still be accepted."),
        S(f"{_CP}.identity", "link_lifecycle_retention_seconds", "Keep sign-in link history for",
          "How long the history of links between sign-ins and consent records is kept.",
          "number", _P, 90 * _DAY, "maverick.consent_identity_federation", subgroup=identity,
          minimum=1, maximum=3650, integer=True, scale=_DAY, unit="days", weaker="lower",
          warning="Older sign-in link history will be permanently deleted sooner."),
    )


def _destination_rows(S) -> tuple:
    head = _sub("Consent preferences", "delivery to outside services")
    reader = "maverick.consent_delivery_destinations"
    rows = [
        S(_DEST, "enable", "Send consent changes to outside services",
          "Send each consent change to the services chosen below. Fill in a service's details "
          "before you choose it. Turning this off stops all sending, even for services "
          "that stay ticked.", "toggle", _P, False, reader, subgroup=head, weaker=True,
          warning="Consent changes will be sent to the services chosen below."),
        S(_DEST, "enabled_providers", "Services to send to",
          "The outside services that receive consent changes.", "multiselect", _P, [], reader,
          subgroup=head, choices=_DESTINATIONS, weaker="add",
          warning="Consent changes will also be sent to the added service."),
        S(_DEST, "timeout_seconds", "Wait for a service's answer up to",
          "How long to wait for an outside service to answer before trying again later.",
          "number", _P, 10.0, reader, subgroup=head, minimum=0.1, maximum=60, step=0.1,
          unit="seconds"),
        S(_DEST, "max_response_bytes", "Largest answer accepted",
          "Bigger answers from an outside service are refused.", "number", _P, 64 * _KB,
          reader, subgroup=head, minimum=1, maximum=1024, integer=True, scale=_KB, unit="KB",
          weaker="higher", warning="Bigger answers from outside services will be accepted."),
    ]
    origins = {
        "salesforce": (_suffix_origin("salesforce.com", "force.com"),
                       "https://yourcompany.my.salesforce.com"),
        "marketo": (_suffix_origin("mktorest.com"), "https://123-ABC-456.mktorest.com"),
        "adobe_experience_platform": (_suffix_origin("adobedc.net"), "https://dcs.adobedc.net"),
        "snowflake": (_suffix_origin("snowflakecomputing.com"),
                      "https://account.region.snowflakecomputing.com"),
    }
    for provider, name in _DESTINATIONS:
        section = f"{_DEST}.{provider}"
        sub = _sub("Consent preferences", f"{name} delivery")
        pattern, example = origins[provider]
        rows += [
            S(section, "destination_id", f"{name} delivery name",
              "A short name for this delivery, such as the service's name. Letters, numbers, "
              "dots, dashes and colons.", "text", _P, "", reader, subgroup=sub,
              pattern=_optional(_ID), max_length=128),
            S(section, "origin", f"{name} address",
              f"Your {name} address, such as {example}. Only {name} addresses are accepted.",
              "text", _P, "", reader, subgroup=sub, pattern=_optional(pattern), max_length=300,
              weaker="change",
              warning=f"Consent changes will be sent to a different {name} address."),
            S(section, "credential_secret_ref", f"{name} sign-in key name",
              f"The name your server keeps the {name} sign-in key under, written with a "
              "dollar sign in front. The key stays on the server; the name must include the "
              "word CONSENT. It is stored sealed and never shown again.", "secret", _P, "",
              reader, subgroup=sub,
              pattern=r"\$(?:\{" + _env_name("CONSENT", 127) + r"\}|"
                      + _env_name("CONSENT", 127) + r")",
              max_length=140),
            S(section, "credential_revision", f"{name} sign-in key version",
              f"Start at 1 and raise it by one each time the {name} sign-in key is replaced.",
              "number",
              _P, None, reader, subgroup=sub, minimum=1, maximum=2147483647, integer=True,
              unit="", none_text="Not set"),
        ]
        rows += _destination_fields(S, provider, name, section, sub, reader)
    return tuple(rows)


def _destination_fields(S, provider, name, section, sub, reader) -> list:
    def field(key, label, help_text, pattern=_PROVIDER_FIELD, default="", max_length=128):
        return S(section, key, label, help_text, "text", _P, default, reader, subgroup=sub,
                 pattern=_optional(pattern), max_length=max_length)

    ident = "Letters, numbers and underscores."
    if provider == "salesforce":
        return [
            field("api_version", "Salesforce version", "The Salesforce version to use, such "
                  "as v65.0.", pattern=r"v[0-9]{2}\.[0-9]", max_length=5),
            field("object_api_name", "Salesforce record type for consent changes",
                  f"The name of the custom record type that receives consent changes. {ident}"),
            field("external_id_field", "Salesforce field for the change reference",
                  f"The field that holds Lightwork's reference for each change. {ident}"),
            field("payload_digest_field", "Salesforce field for the change fingerprint",
                  f"The field that holds each change's fingerprint. {ident}"),
        ]
    if provider == "marketo":
        return [
            field("custom_object_name", "Marketo record type for consent changes",
                  f"The name of the custom record type that receives consent changes. {ident}"),
            field("dedupe_field", "Marketo field used to spot repeats",
                  f"The field Marketo uses to avoid saving the same change twice. {ident}"),
            field("message_id_field", "Marketo field for the change reference",
                  f"The searchable field that holds Lightwork's reference for each change. "
                  f"{ident}", default="lightworkMessageId"),
            field("payload_digest_field", "Marketo field for the change fingerprint",
                  f"The field that holds each change's fingerprint. {ident}"),
        ]
    if provider == "adobe_experience_platform":
        aep = r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
        return [
            field("connection_id", "Adobe streaming connection", "The ID of the streaming "
                  "connection in Adobe Experience Platform.", pattern=aep, max_length=256),
            field("flow_id", "Adobe data flow", "The ID of the data flow in Adobe Experience "
                  "Platform.", pattern=aep, max_length=256),
            field("dataset_id", "Adobe dataset", "The ID of the dataset that receives consent "
                  "changes.", pattern=aep, max_length=256),
            field("schema_id", "Adobe data model", "The ID of the Adobe data model the "
                  "dataset uses.", pattern=aep, max_length=256),
            field("ims_org_id", "Adobe organisation", "Your Adobe organisation ID, such as "
                  "ABC123@AdobeOrg.", pattern=r"[A-Za-z0-9][A-Za-z0-9._@-]{1,255}",
                  max_length=256),
        ]
    return [
        field("database", "Snowflake database", f"The database that holds the consent "
              f"table. {ident}"),
        field("schema", "Snowflake database area", f"The area inside the database that "
              f"holds the table, such as CONSENT. {ident}"),
        field("table", "Snowflake table", f"The table that receives consent changes. {ident}"),
        field("warehouse", "Snowflake warehouse", f"The warehouse that runs the writes. "
              f"{ident}"),
        field("role", "Snowflake role", f"The role Lightwork uses. Give it only the rights "
              f"it needs to add rows to the table. {ident}"),
    ]


def _consent_more_rows(S) -> tuple:
    native = _sub("Consent preferences", "phone and TV apps")
    index = _sub("Consent preferences", "custom search")
    bulk = _sub("Consent preferences", "bulk changes")
    brand = _sub("Consent preferences", "Trust Center branding")
    opt_out = _sub("Consent preferences", "Global Opt-Out")
    nr = "maverick_dashboard.consent_native_composition"
    ir = "maverick_dashboard.consent_custom_index_composition"
    br = "maverick_dashboard.consent_bulk_jobs_composition"
    tr = "maverick.trust_center_branding"
    gr = "maverick.consent_global_opt_out"
    return (
        S(f"{_CP}.native_sdk", "receipt_key_id", "Receipt signing key name",
          "The name written on consent receipts signed for phone and TV apps. Letters, "
          "numbers, dots, dashes and colons.", "text", _P, "", nr, subgroup=native,
          pattern=_optional(_ID), max_length=128),
        S(f"{_CP}.native_sdk", "receipt_key_revision", "Receipt signing key version",
          "Raise this by one each time the receipt signing key is replaced.", "number", _P, 1,
          nr, subgroup=native, minimum=1, maximum=1000000, integer=True),
        S(f"{_CP}.native_sdk", "receipt_key_secret_ref", "Receipt signing key location",
          "The name your server keeps the receipt signing key under. The key stays on the "
          "server; the name must include the word CONSENT. It is stored sealed and never "
          "shown again.", "secret", _P, "", nr, subgroup=native,
          pattern=_env_name("CONSENT"), max_length=128),
        S(f"{_CP}.native_sdk", "max_applications", "Apps that can be registered",
          "The most phone and TV apps that can be registered.", "number", _P, 1000, nr,
          subgroup=native, minimum=1, maximum=100000, integer=True, unit="apps",
          weaker="higher", warning="More apps will be able to register."),
        S(f"{_CP}.native_sdk", "max_devices", "Devices that can be registered",
          "The most phones and TVs that can be registered.", "number", _P, 100000, nr,
          subgroup=native, minimum=1, maximum=10000000, integer=True, unit="devices",
          weaker="higher", warning="More devices will be able to register."),
        S(f"{_CP}.native_sdk", "max_requests", "App requests kept on record",
          "Once this many app requests are on record, new ones are refused.", "number", _P,
          1000000, nr, subgroup=native, minimum=1, maximum=100000000, integer=True,
          unit="requests", weaker="higher", warning="More app requests will be kept."),
        S(f"{_CP}.native_sdk", "requests_per_minute", "Requests per minute from each app",
          "Requests beyond this from one app in a minute are refused.", "number", _P, 120, nr,
          subgroup=native, minimum=1, maximum=10000, integer=True, unit="per minute",
          weaker="higher", warning="Apps will be able to send more requests each minute."),
        S(f"{_CP}.native_sdk", "require_profile_linking", "Link app consent to a verified person",
          "Every consent choice from an app must be linked to a person whose identity was "
          "checked. Your server team must connect the linking step first.", "toggle", _P,
          False, nr, subgroup=native, weaker=False,
          warning="Consent from apps will be accepted without linking it to a verified person."),
        S(f"{_CP}.native_sdk", "require_rights_requests", "Require the privacy request step in apps",
          "Apps must offer the privacy request step. Your server team must connect it first.",
          "toggle", _P, False, nr, subgroup=native, weaker=False,
          warning="Apps will be able to work without offering the privacy request step."),

        S(f"{_CP}.profile_data.custom_index", "key_secret_ref", "Search key location",
          "The name your server keeps the key that scrambles searchable values under. The key "
          "stays on the server; the name must include the word CONSENT. It is stored sealed "
          "and never shown again.", "secret", _P, "MAVERICK_CONSENT_CUSTOM_INDEX_KEY", ir,
          subgroup=index, pattern=_env_name("CONSENT"), max_length=128),
        S(f"{_CP}.profile_data.custom_index", "key_version", "Search key version",
          "Raise this by one when the search key is replaced.", "number", _P, 1, ir,
          subgroup=index, minimum=1, maximum=1000000, integer=True, weaker="change",
          warning="Existing search lists will stop matching until they are rebuilt with the "
                  "new key version."),
        S(f"{_CP}.profile_data.custom_index", "max_indexes", "Search lists allowed",
          "The most custom search lists each workspace can create.", "number", _P, 256, ir,
          subgroup=index, minimum=1, maximum=10000, integer=True, unit="lists",
          weaker="higher", warning="More custom search lists can be created."),
        S(f"{_CP}.profile_data.custom_index", "max_page_size", "Search results per page",
          "The most people returned by one search.", "number", _P, 100, ir, subgroup=index,
          minimum=1, maximum=500, integer=True, unit="results"),
        S(f"{_CP}.profile_data.custom_index", "retention_seconds", "Keep search list history for",
          "Search list records older than this are removed.", "number", _P, 365 * _DAY, ir,
          subgroup=index, minimum=1, maximum=1825, integer=True, scale=_DAY, unit="days",
          weaker="lower", warning="Older search list history will be permanently deleted sooner."),

        S(f"{_CP}.bulk_jobs", "initial_credits", "Starting credits for each workspace",
          "How many items a workspace can process in bulk changes before it needs more credits.",
          "number", _P, 10000, br, subgroup=bulk, minimum=0, maximum=1000000000, integer=True,
          unit="credits", weaker="higher", warning="Workspaces will start with more credits."),
        S(f"{_CP}.bulk_jobs", "max_jobs", "Bulk changes kept", "The most bulk changes kept for each "
          "workspace.", "number", _P, 10000, br, subgroup=bulk, minimum=1, maximum=1000000,
          integer=True, unit="changes", weaker="higher", warning="More bulk changes will be kept."),
        S(f"{_CP}.bulk_jobs", "max_items_per_job", "Items in one bulk change",
          "The most people one bulk change can cover.", "number", _P, 10000, br, subgroup=bulk,
          minimum=1, maximum=100000, integer=True, unit="items", weaker="higher",
          warning="One bulk change will be able to change more people's consent at once."),
        S(f"{_CP}.bulk_jobs", "max_artifact_bytes", "Largest bulk export file",
          "Bulk export files bigger than this are refused.", "number", _P, 16 * _MB, br,
          subgroup=bulk, minimum=1, maximum=256, integer=True, scale=_MB, unit="MB",
          weaker="higher", warning="Bigger export files of consent records will be made."),
        S(f"{_CP}.bulk_jobs", "lease_seconds", "Time a worker holds a bulk change",
          "How long one worker keeps a bulk change before another may take it over.", "number", _P,
          60, br, subgroup=bulk, minimum=5, maximum=3600, integer=True, unit="seconds"),
        S(f"{_CP}.bulk_jobs", "retention_seconds", "Keep bulk changes for",
          "Bulk changes and their files older than this are removed.", "number", _P, 365 * _DAY,
          br, subgroup=bulk, minimum=1, maximum=3650, integer=True, scale=_DAY, unit="days",
          weaker="lower", warning="Older bulk changes and files will be permanently deleted sooner."),
        S(f"{_CP}.bulk_jobs", "worker_batch_size", "Items handled per step",
          "How many items a worker handles in one step of a bulk change.", "number", _P, 100, br,
          subgroup=bulk, minimum=1, maximum=500, integer=True, unit="items"),

        S(f"{_CP}.trust_center.branding", "enable", "Custom logos and web addresses",
          "Let each workspace show its own logo in the Trust Center and prove it owns a custom "
          "web address.", "toggle", _P, False,
          "maverick_dashboard.trust_center_branding_composition", subgroup=brand),
        S(f"{_CP}.trust_center.branding", "max_asset_bytes", "Largest logo file",
          "Logo files bigger than this are refused.", "number", _P, 2048 * _KB, tr,
          subgroup=brand, minimum=1, maximum=10240, integer=True, scale=_KB, unit="KB",
          weaker="higher", warning="Bigger logo files will be accepted."),
        S(f"{_CP}.trust_center.branding", "max_assets", "Logos kept", "The most logo files "
          "kept for each workspace.", "number", _P, 1000, tr, subgroup=brand, minimum=1,
          maximum=100000, integer=True, unit="logos"),
        S(f"{_CP}.trust_center.branding", "max_width", "Widest logo",
          "Logos wider than this are refused.", "number", _P, 4096, tr, subgroup=brand,
          minimum=16, maximum=16384, integer=True, unit="pixels"),
        S(f"{_CP}.trust_center.branding", "max_height", "Tallest logo",
          "Logos taller than this are refused.", "number", _P, 4096, tr, subgroup=brand,
          minimum=16, maximum=16384, integer=True, unit="pixels"),
        S(f"{_CP}.trust_center.branding", "max_pixels", "Most pixels in a logo",
          "Logos with more pixels than this are refused. It can't be more than the widest "
          "times the tallest logo.", "number", _P, 8388608, tr, subgroup=brand, minimum=256,
          maximum=64000000, integer=True, unit="pixels"),
        S(f"{_CP}.trust_center.branding", "max_domains", "Custom web addresses",
          "The most custom web addresses each workspace can claim.", "number", _P, 100, tr,
          subgroup=brand, minimum=1, maximum=10000, integer=True, unit="addresses"),
        S(f"{_CP}.trust_center.branding", "challenge_ttl_seconds",
          "Time to prove a web address",
          "How long the check that proves you own a web address stays open.", "number", _P,
          60 * _MINUTE, tr, subgroup=brand, minimum=5, maximum=1440, integer=True,
          scale=_MINUTE, unit="minutes"),
        S(f"{_CP}.trust_center.branding", "verification_ttl_seconds",
          "Web address proof lasts for",
          "How long a proven web address stays proven before it is checked again.", "number",
          _P, 7 * 24 * _HOUR, tr, subgroup=brand, minimum=1, maximum=2160, integer=True,
          scale=_HOUR, unit="hours", weaker="higher",
          warning="Web addresses will stay proven for longer before they are checked again."),
        S(f"{_CP}.trust_center.branding", "retention_seconds", "Keep old logos for",
          "Replaced logos and old web address records are removed after this.", "number", _P,
          90 * _DAY, tr, subgroup=brand, minimum=1, maximum=3650, integer=True, scale=_DAY,
          unit="days", weaker="lower",
          warning="Old logos and web address records will be permanently deleted sooner."),
        S(f"{_CP}.trust_center.branding", "key_ref", "Logo sealing key location",
          "Where the key that seals stored logos is kept, written as env, vault or secret, a "
          "colon and a name. Keep the standard location unless your server team set up "
          "another key store. It is stored sealed and never shown again.", "secret", _P,
          "env:MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY", tr, subgroup=brand, pattern=_KEY_REF,
          max_length=128),
        S(f"{_CP}.trust_center.branding", "key_revision", "Logo sealing key version",
          "Raise this by one each time the logo sealing key is replaced.", "number", _P, 1,
          tr, subgroup=brand, minimum=1, maximum=2147483647, integer=True),

        S(f"{_CP}.global_opt_out", "max_records", "Opt-out records kept",
          "The most Global Opt-Out records kept for each workspace.", "number", _P, 10000, gr,
          subgroup=opt_out, minimum=1, maximum=100000, integer=True, unit="records",
          weaker="higher", warning="More opt-out records will be kept."),
        S(f"{_CP}.global_opt_out", "retention_seconds", "Keep opt-out records for",
          "Global Opt-Out records older than this are removed.", "number", _P, 365 * _DAY, gr,
          subgroup=opt_out, minimum=1, maximum=3650, integer=True, scale=_DAY, unit="days",
          weaker="lower", warning="Older opt-out records will be permanently deleted sooner."),
        S(f"{_CP}.global_opt_out", "submission_ttl_seconds", "Time to finish an opt-out",
          "How long a person has to finish an opt-out they started.", "number", _P,
          15 * _MINUTE, gr, subgroup=opt_out, minimum=1, maximum=1440, integer=True,
          scale=_MINUTE, unit="minutes"),

        S("consent_registry", "subject_salt", "Consent register scrambling value",
          "A private value, 16 to 256 characters, used to scramble each person's reference "
          "before it is stored. It is stored sealed and never shown again.", "secret", _P, "",
          "maverick.consent_registry", subgroup="Consent register", pattern=r".{16,256}",
          max_length=256, weaker="change",
          warning="Records already kept can no longer be matched to the people they belong to."),
        S("consent_registry", "webhook_enable", "Accept consent updates from other tools",
          "Other consent tools can send signed consent updates to the register.", "toggle", _P,
          False, "maverick.consent_registry", subgroup="Consent register", weaker=True,
          warning="Outside consent tools holding the shared key will be able to add consent "
                  "records."),
        S("consent_registry", "webhook_secret_env", "Shared key location",
          "The name your server keeps the shared key for signed consent updates under. The "
          "name must include the word CONSENT. It is stored sealed and never shown again.",
          "secret", _P, "MAVERICK_CONSENT_WEBHOOK_SECRET", "maverick.consent_registry",
          subgroup="Consent register", pattern=_env_name("CONSENT", 63), max_length=64),
    )


# ------------------------------------------------------ data use governance
def _data_use_rows(S) -> tuple:
    runtime = "maverick_dashboard.data_use_provider_runtime"
    rows = [
        S(f"{_DU}.enforcement", "max_attempts", "Tries for each change in a data platform",
          "How many times a data rule change is tried in Snowflake or Databricks before it "
          "waits for a person.", "number", _P, 3, runtime,
          subgroup=_sub("Data use governance", "enforcement"), minimum=1, maximum=5,
          integer=True, unit="tries"),
    ]
    platforms = (
        ("snowflake", "Snowflake", _suffix_origin("snowflakecomputing.com", port=False),
         "https://account.snowflakecomputing.com", 1),
        ("databricks", "Databricks",
         _suffix_origin("cloud.databricks.com", "azuredatabricks.net", "gcp.databricks.com",
                        port=False),
         "https://workspace.cloud.databricks.com", 5),
    )
    for key, name, pattern, example, low in platforms:
        sub = _sub("Data use governance", name)
        section = f"{_DU}.{key}"
        rows += [
            S(section, "origin", f"{name} address",
              f"Your {name} address, such as {example}. Only {name} addresses are accepted.",
              "text", _P, "", "maverick_dashboard.data_use_provider_api", subgroup=sub,
              pattern=_optional(pattern), max_length=300, weaker="change",
              warning=f"Data rules will be applied in a different {name} account."),
            S(section, "credential_secret_ref", f"{name} sign-in key name",
              f"The name your server keeps the {name} sign-in key under, written with a "
              "dollar sign in front. The name must include the words DATA and USE joined by "
              "an underscore. It is stored sealed and never shown again.", "secret", _P, "",
              runtime, subgroup=sub,
              pattern=r"\$(?:\{" + _env_name("DATA_USE", 127) + r"\}|"
                      + _env_name("DATA_USE", 127) + r")",
              max_length=140),
            S(section, "credential_revision", f"{name} sign-in key version",
              f"Raise this by one each time the {name} sign-in key is replaced, then enroll "
              "each connection again.", "number", _P, 1, runtime, subgroup=sub, minimum=1,
              maximum=2147483647, integer=True, weaker="change",
              warning=f"{name} connections enrolled with the old version stop working until "
                      "they are enrolled again."),
            S(section, "timeout_seconds", f"Wait for {name} up to",
              f"How long to wait for {name} to answer.", "number", _P, 10, runtime,
              subgroup=sub, minimum=low, maximum=60 if key == "snowflake" else 50,
              step=0.1, unit="seconds"),
            S(section, "max_response_bytes", f"Largest answer from {name}",
              f"Bigger answers from {name} are refused.", "number", _P, 64 * _KB, runtime,
              subgroup=sub, minimum=1, maximum=128, integer=True, scale=_KB, unit="KB",
              weaker="higher", warning=f"Bigger answers from {name} will be accepted."),
        ]
    audit = _sub("Data use governance", "platform audit logs")
    ac = "maverick_dashboard.data_use_provider_audit_composition"
    at = "maverick_dashboard.data_use_provider_audit_transport"
    rows += [
        S(f"{_DU}.provider_audit", "enable", "Check platform audit logs",
          "Read Snowflake or Databricks audit logs to confirm each change really happened. "
          "Changes then need a current permission to read those logs.", "toggle", _P, False,
          at, subgroup=audit),
        S(f"{_DU}.provider_audit", "audit_window_seconds", "Time allowed for a change to show",
          "How long Lightwork keeps looking in the audit logs for a change.", "number", _P,
          _HOUR, ac, subgroup=audit, minimum=1, maximum=168, integer=True, scale=_HOUR,
          unit="hours"),
        S(f"{_DU}.provider_audit", "retention_seconds", "Keep audit log checks for",
          "Audit log check records older than this are removed. It must be at least the time "
          "allowed above.", "number", _P, 365 * _DAY, ac, subgroup=audit, minimum=1,
          maximum=3660, integer=True, scale=_DAY, unit="days", weaker="lower",
          warning="Older audit log checks will be permanently deleted sooner."),
        S(f"{_DU}.provider_audit", "max_attempts", "Tries for each audit log check",
          "How many times one check is tried before it waits for a person.", "number", _P, 5,
          ac, subgroup=audit, minimum=1, maximum=20, integer=True, unit="tries"),
        S(f"{_DU}.provider_audit", "cursor_overlap_seconds", "Overlap between log reads",
          "Each read starts a little before the last one ended, so late entries are not "
          "missed.", "number", _P, 5 * _MINUTE, at, subgroup=audit, minimum=1, maximum=60,
          integer=True, scale=_MINUTE, unit="minutes"),
        S(f"{_DU}.provider_audit", "max_pages_per_read", "Log pages per read",
          "The most pages of audit log read at once.", "number", _P, 20, at, subgroup=audit,
          minimum=1, maximum=100, integer=True, unit="pages"),
        S(f"{_DU}.provider_audit", "snowflake_latency_watermark_seconds",
          "Snowflake audit log delay",
          "How far behind Snowflake's audit log can run. Leave empty to not wait for it.",
          "number", _P, None, at, subgroup=audit, minimum=3, maximum=168, integer=True,
          scale=_HOUR, unit="hours", none_text="Not used"),
    ]
    sched = _sub("Data use governance", "audit log schedule")
    sr = "maverick_dashboard.data_use_provider_audit_scheduler"
    section = f"{_DU}.provider_audit.scheduler"
    rows += [
        S(section, "enable", "Check audit logs on a schedule",
          "Recover and confirm changes automatically in the background. Turning this on takes "
          "effect after a restart.", "toggle", _P, False, sr, subgroup=sched, restart=True),
        S(section, "poll_seconds", "Run every", "How often the background check runs.",
          "number", _P, 60, sr, subgroup=sched, minimum=5, maximum=3600, integer=True,
          unit="seconds"),
        S(section, "claim_limit", "Checks run at the same time",
          "The most checks worked on at once.", "number", _P, 10, sr, subgroup=sched,
          minimum=1, maximum=100, integer=True, unit="checks"),
        S(section, "tenant_limit", "Workspaces checked each time",
          "The most workspaces looked at in one run.", "number", _P, 1000, sr, subgroup=sched,
          minimum=1, maximum=10000, integer=True, unit="workspaces"),
        S(section, "lease_seconds", "Time a worker holds a check",
          "How long one worker keeps a check before another may take it over.", "number", _P,
          120, sr, subgroup=sched, minimum=30, maximum=86400, integer=True, unit="seconds"),
        S(section, "event_limit", "Log entries per run", "The most audit log entries handled "
          "in one run.", "number", _P, 100, sr, subgroup=sched, minimum=1, maximum=500,
          integer=True, unit="entries"),
        S(section, "retry_backoff_seconds", "Wait before retrying", "How long to wait after a "
          "failed check before trying again.", "number", _P, 30, sr, subgroup=sched,
          minimum=0, maximum=86400, integer=True, unit="seconds"),
        S(section, "purge_limit", "Old records removed per run",
          "The most expired records removed in one run.", "number", _P, 100, sr,
          subgroup=sched, minimum=1, maximum=500, integer=True, unit="records"),
    ]
    return tuple(rows)


# ------------------------------------------------------- privacy automation
def _automation_rows(S) -> tuple:
    found = _sub("Privacy automation", "personal data discovery")
    fixes = _sub("Privacy automation", "discovery fixes")
    sched = _sub("Privacy automation", "discovery fix schedule")
    ar = "maverick.privacy_data_discovery_adapters"
    rr = "maverick_dashboard.privacy_data_discovery_adapters_composition"
    adapters = f"{_PA}.data_discovery.adapters"
    return (
        S(adapters, "enable", "Look for personal data in connected services",
          "Connect to the services chosen below to look for personal data. Each place still "
          "has to be enrolled on the Data discovery page.", "toggle", _P, False, ar,
          subgroup=found, weaker=True,
          warning="Lightwork will connect to the chosen services to look for personal data."),
        S(adapters, "enabled_providers", "Services to look in",
          "The storage and directory services discovery can connect to.", "multiselect", _P,
          [], ar, subgroup=found, choices=_DISCOVERY_SOURCES, weaker="add",
          warning="Lightwork will also connect to the added service."),
        S(adapters, "timeout_seconds", "Wait for a service up to",
          "How long to wait for a service to answer.", "number", _P, 15.0, ar, subgroup=found,
          minimum=0.1, maximum=60, step=0.1, unit="seconds"),
        S(adapters, "max_response_bytes", "Largest answer read",
          "Bigger answers from a service are refused.", "number", _P, 8 * _MB, ar,
          subgroup=found, minimum=1, maximum=64, integer=True, scale=_MB, unit="MB",
          weaker="higher", warning="Bigger answers from services will be read."),
        S(adapters, "page_size", "Items asked for at a time",
          "How many items are asked for in each request.", "number", _P, 250, ar,
          subgroup=found, minimum=1, maximum=1000, integer=True, unit="items"),
        S(adapters, "max_pages", "Pages read per place", "The most pages read from one place "
          "in one scan.", "number", _P, 500, ar, subgroup=found, minimum=1, maximum=10000,
          integer=True, unit="pages", weaker="higher",
          warning="Each scan will read more from each place."),
        S(adapters, "max_attempts", "Tries for each request",
          "How many times a failed request is tried.", "number", _P, 3, ar, subgroup=found,
          minimum=1, maximum=5, integer=True, unit="tries"),
        S(adapters, "max_polls", "Checks for a slow answer",
          "How many times Lightwork checks back for an answer that takes a while.", "number",
          _P, 8, ar, subgroup=found, minimum=1, maximum=100, integer=True, unit="checks"),
        S(f"{_PA}.discovery_data_use_bridge", "enable", "Send reviewed findings to data use",
          "Reviewed discovery findings can update how a data use asset is classified. Needs "
          "data use governance to be on.", "toggle", _P, False,
          "maverick.privacy_discovery_data_use_bridge", subgroup=found),

        S(_REMEDIATION, "enable", "Fix findings through approved fixes",
          "Approved fixes for discovery findings are queued and recorded in the data "
          "map. Turn this on together with the data map record below.", "toggle", _P, False,
          rr, subgroup=fixes),
        S(_REMEDIATION, "max_attempts", "Tries for each fix", "How many times a fix is "
          "tried before it waits for a person.", "number", _P, 5, rr, subgroup=fixes,
          minimum=1, maximum=20, integer=True, unit="tries"),
        S(_REMEDIATION, "retention_seconds", "Keep finished fixes for",
          "Finished fixes older than this are removed.", "number", _P, 30 * _DAY, rr,
          subgroup=fixes, minimum=1, maximum=3660, integer=True, scale=_DAY, unit="days",
          weaker="lower", warning="Older fixes will be permanently deleted sooner."),
        S(f"{_REMEDIATION}.data_map", "enable", "Record fixes in the data map",
          "Keep a record of each approved fix in the data map. Turn this on together with "
          "fixing findings above.", "toggle", _P, False, rr, subgroup=fixes),
        S(f"{_REMEDIATION}.data_map", "retention_seconds", "Keep data map fix records for",
          "Data map fix records older than this are removed.", "number", _P, 365 * _DAY, rr,
          subgroup=fixes, minimum=1, maximum=3660, integer=True, scale=_DAY, unit="days",
          weaker="lower", warning="Older data map fix records will be permanently deleted "
                                  "sooner."),

        S(f"{_REMEDIATION}.scheduler", "enable", "Run fixes on a schedule",
          "Retry and check fixes automatically in the background. Turning this on takes "
          "effect after a restart.", "toggle", _P, False, rr, subgroup=sched, restart=True),
        S(f"{_REMEDIATION}.scheduler", "interval_seconds", "Run every",
          "How often the background runner works.", "number", _P, 60, rr, subgroup=sched,
          minimum=5, maximum=86400, integer=True, unit="seconds"),
        S(f"{_REMEDIATION}.scheduler", "jitter_seconds", "Random extra wait",
          "A small random wait added to each run so many servers do not run at once. It "
          "can't be more than the time between runs.", "number", _P, 10, rr, subgroup=sched,
          minimum=0, maximum=3600, integer=True, unit="seconds"),
        S(f"{_REMEDIATION}.scheduler", "retry_max_seconds", "Longest wait between retries",
          "The longest the runner waits after repeated failures.", "number", _P, 300, rr,
          subgroup=sched, minimum=5, maximum=86400, integer=True, unit="seconds"),
        S(f"{_REMEDIATION}.scheduler", "tenant_limit", "Workspaces handled each run",
          "The most workspaces handled in one run.", "number", _P, 1000, rr, subgroup=sched,
          minimum=1, maximum=10000, integer=True, unit="workspaces"),
        S(f"{_REMEDIATION}.scheduler", "worker_limit", "Fixes run each time",
          "The most fixes run in one go.", "number", _P, 10, rr, subgroup=sched, minimum=1,
          maximum=100, integer=True, unit="fixes"),
        S(f"{_REMEDIATION}.scheduler", "reconcile_limit", "Unclear fixes checked each time",
          "The most fixes with an unclear result that are checked again in one go.", "number",
          _P, 10, rr, subgroup=sched, minimum=1, maximum=100, integer=True, unit="fixes"),
        S(f"{_REMEDIATION}.scheduler", "lease_seconds", "Time a worker holds a fix",
          "How long one worker keeps a fix before another may take it over.", "number", _P,
          60, rr, subgroup=sched, minimum=1, maximum=3600, integer=True, unit="seconds"),
        *_drop_and_notice_rows(S),
        *_public_rights_form_rows(S),
    )


def _public_rights_form_rows(S) -> tuple:
    group = _sub("Privacy automation", "rights request form")
    reader = "maverick.public_rights_form"
    section = f"{_PA}.public_rights_form"
    return (
        S(section, "verification_ttl_hours", "Confirmation link works for",
          "How long the email link that confirms a requester's address stays valid.",
          "number", _P, 24, reader, subgroup=group, minimum=1, maximum=168, integer=True,
          unit="hours", weaker="higher",
          warning="A link that stays valid longer can be used by someone who finds it later."),
        S(section, "status_ttl_days", "Progress link works for",
          "How long the link a requester uses to follow their request stays valid.",
          "number", _P, 90, reader, subgroup=group, minimum=1, maximum=730, integer=True,
          unit="days", weaker="higher",
          warning="A progress link that stays valid longer can be used by someone who finds it later."),
        S(section, "requests_per_ip_per_hour", "Requests per connection per hour",
          "How many submissions one internet address may make in an hour before it is asked "
          "to wait.", "number", _P, 5, reader, subgroup=group, minimum=1, maximum=1000,
          integer=True, weaker="higher",
          warning="A higher limit lets one connection submit more, including automated abuse."),
        S(section, "requests_per_email_per_day", "Requests per email address per day",
          "How many submissions one email address may make in a day.", "number", _P, 3,
          reader, subgroup=group, minimum=1, maximum=100, integer=True, weaker="higher",
          warning="A higher limit lets one address be flooded with confirmation emails."),
        S(section, "internal_target_days", "Target when the law sets no deadline",
          "Used for laws that require an answer 'without delay' but fix no number of days "
          "(for example Japan). Shown to the team as an internal target, never as a legal "
          "deadline.", "number", _P, 30, reader, subgroup=group, minimum=1, maximum=365,
          integer=True, unit="days"),
        S(section, "max_message_chars", "Longest message a requester may write",
          "The size of the free-text box on the public form.", "number", _P, 4000, reader,
          subgroup=group, minimum=200, maximum=20000, integer=True, unit="characters"),
    )


def _drop_and_notice_rows(S) -> tuple:
    drop = _sub("Privacy automation", "California DROP")
    notice = _sub("Privacy automation", "privacy notice publishing")
    dr = "maverick_dashboard.privacy_drop_management_composition"
    nr = "maverick_dashboard.privacy_notice_publication_composition"
    ds = f"{_PA}.drop_management"
    ns = f"{_PA}.notice_governance.publication_runtime"
    return (
        S(ds, "principal_binding_key_ref", "Person-link key location",
          "Where the key that links deletion requests to people is kept, written as env, a "
          "colon and a name, or as a key store address. Keep the standard location unless "
          "your server team set up another key store. It is stored sealed and never shown "
          "again.", "secret", _P, "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY", dr, subgroup=drop,
          pattern=r"env:[A-Z][A-Z0-9_]{0,127}|(?:kms|secret|vault|aws-kms|azure-keyvault|"
                  r"gcp-kms)://[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,239}",
          max_length=260),
        S(ds, "retention_seconds", "Keep DROP records for",
          "California DROP deletion and opt-out records older than this are removed.",
          "number", _P, 365 * _DAY, dr, subgroup=drop, minimum=1, maximum=3650, integer=True,
          scale=_DAY, unit="days", weaker="lower",
          warning="Older DROP records will be permanently deleted sooner."),
        S(ds, "scheduler_enable", "Run DROP upkeep on a schedule",
          "Check and tidy DROP records automatically in the background. Changes here take "
          "effect after a restart.", "toggle", _P, False, dr, subgroup=drop, restart=True),
        S(ds, "scheduler_interval_seconds", "Run DROP upkeep every",
          "How often the background upkeep runs.", "number", _P, _HOUR, dr, subgroup=drop,
          minimum=1, maximum=1440, integer=True, scale=_MINUTE, unit="minutes", restart=True),
        S(ds, "scheduler_jitter_seconds", "Random extra wait for DROP upkeep",
          "A small random wait added to each run. It must be less than the time between "
          "runs.", "number", _P, 60, dr, subgroup=drop, minimum=0, maximum=3600, integer=True,
          unit="seconds", restart=True),
        S(ds, "scheduler_retry_max_seconds", "Longest wait after DROP upkeep fails",
          "The longest the upkeep waits after repeated failures.", "number", _P, 15 * _MINUTE,
          dr, subgroup=drop, minimum=1, maximum=1440, integer=True, scale=_MINUTE,
          unit="minutes", restart=True),

        S(ns, "enable", "Publish approved privacy notices",
          "Approved privacy notices are published to your consent publishing store. Needs "
          "the publishing targets your installer set up.", "toggle", _P, False, nr,
          subgroup=notice),
        S(ns, "scheduler_enable", "Publish notices on a schedule",
          "Publish approved notices automatically in the background. Turning this on takes "
          "effect after a restart.", "toggle", _P, False, nr, subgroup=notice, restart=True),
        S(ns, "active_tenants", "Workspaces that publish notices",
          "Only these workspaces publish notices. Each needs a publishing target from your "
          "installer.", "list", _P, [], nr, subgroup=notice, max_items=50,
          pattern=_WORKSPACE, max_length=128, item_label="Workspace", item_hint="default",
          item_error="a workspace name made of letters, numbers, dots, dashes or underscores",
          weaker="grow", warning="More workspaces will publish privacy notices."),
        S(ns, "poll_seconds", "Check for notices every", "How often the background publisher "
          "looks for approved notices.", "number", _P, 30, nr, subgroup=notice, minimum=5,
          maximum=86400, integer=True, unit="seconds"),
        S(ns, "retry_delay_seconds", "Wait before retrying a notice",
          "How long to wait after a failed publish before trying again.", "number", _P, 60, nr,
          subgroup=notice, minimum=0, maximum=604800, integer=True, unit="seconds"),
        S(ns, "retry_max_seconds", "Longest wait between retries",
          "The longest the publisher waits after repeated failures.", "number", _P, 300, nr,
          subgroup=notice, minimum=5, maximum=86400, integer=True, unit="seconds"),
        S(ns, "tenant_limit", "Workspaces handled each time",
          "The most workspaces the publisher handles in one go.", "number", _P, 100, nr,
          subgroup=notice, minimum=1, maximum=1000, integer=True, unit="workspaces"),
        S(ns, "lease_seconds", "Time a worker holds a notice",
          "How long one worker keeps a notice before another may take it over.", "number", _P,
          60, nr, subgroup=notice, minimum=1, maximum=3600, integer=True, unit="seconds"),
    )


def _rights_rows(S) -> tuple:
    intake = _sub("Privacy automation", "privacy requests from people")
    delivery = _sub("Privacy automation", "delivering answers to people")
    tv = _sub("Privacy automation", "TV and streaming apps")
    sources = _sub("Privacy automation", "systems searched for requests")
    ir = "maverick_dashboard.privacy_rights_intake_composition"
    dr = "maverick_dashboard.privacy_rights_consumer_delivery_composition"
    sr = "maverick_dashboard.privacy_rights_source_composition"
    ref = r"(?:env|vault|secret):[A-Z][A-Z0-9_]{0,95}"
    rows = [
        S(f"{_PA}.rights_consumer_intake", "enable", "Let people send privacy requests",
          "People signed in to the Trust Center can ask to see or delete their data.",
          "toggle", _P, False, ir, subgroup=intake),
        S(f"{_PA}.rights_consumer_intake", "max_active_requests", "Open requests allowed",
          "The most open privacy requests a workspace can have at once.", "number", _P, 1000,
          ir, subgroup=intake, minimum=1, maximum=10000, integer=True, unit="requests",
          weaker="higher", warning="More privacy requests can be open at once."),
        S(f"{_PA}.rights_consumer_intake", "max_active_requests_per_subject",
          "Open requests per person",
          "The most open privacy requests one person can have. It can't be more than the "
          "limit above.", "number", _P, 25, ir, subgroup=intake, minimum=1, maximum=10000,
          integer=True, unit="requests", weaker="higher",
          warning="One person will be able to have more requests open at once."),
        S(f"{_PA}.rights_consumer_intake", "request_ttl_seconds", "Time to finish a request",
          "How long a person has to finish a request they started.", "number", _P, 24 * _HOUR,
          ir, subgroup=intake, minimum=1, maximum=720, integer=True, scale=_HOUR,
          unit="hours"),
        S(f"{_PA}.rights_consumer_intake", "retention_seconds", "Keep request records for",
          "Privacy request records older than this are removed.", "number", _P, 365 * _DAY, ir,
          subgroup=intake, minimum=1, maximum=3660, integer=True, scale=_DAY, unit="days",
          weaker="lower", warning="Older privacy request records will be permanently deleted "
                                  "sooner."),

        S(f"{_PA}.rights_consumer_delivery", "digest_key_ref", "Delivery check key location",
          "Where the key used to check answer packages is kept, written as env, vault or "
          "secret, a colon and a name in capitals. It is stored sealed and never shown again.",
          "secret", _P, "", dr, subgroup=delivery, pattern=ref, max_length=110),
        S(f"{_PA}.rights_consumer_delivery", "export_signing_key_ref",
          "Delivery signing key location",
          "Where the key that signs answer packages is kept, in the same form. It is stored "
          "sealed and never shown again.", "secret", _P, "", dr, subgroup=delivery,
          pattern=ref, max_length=110),
        S(f"{_PA}.rights_consumer_delivery", "package_encryption_key_ref",
          "Delivery sealing key location",
          "Where the key that seals answer packages is kept, in the same form. It is stored "
          "sealed and never shown again.", "secret", _P, "", dr, subgroup=delivery,
          pattern=ref, max_length=110),
        S(f"{_PA}.rights_consumer_delivery", "server_grant_ttl_seconds",
          "Download link lasts for", "How long a one-time download of an answer package "
          "stays usable.", "number", _P, 30, dr, subgroup=delivery, minimum=5, maximum=120,
          integer=True, unit="seconds", weaker="higher",
          warning="Download links for answer packages will stay usable for longer."),
        S(f"{_PA}.rights_consumer_delivery", "max_package_bytes", "Largest answer package",
          "Answer packages bigger than this are refused.", "number", _P, 16 * _MB, dr,
          subgroup=delivery, minimum=1, maximum=16, integer=True, scale=_MB, unit="MB"),

        S(f"{_PA}.ott_ctv_rights", "enable", "Privacy requests from TV and streaming apps",
          "TV and streaming apps can pass on people's requests to see or delete their data. "
          "Needs sign-in for people and the Trust Center.", "toggle", _P, False,
          "maverick.privacy_rights_ott_ctv", subgroup=tv),

        S(_SOURCES, "enable", "Search connected systems for requests",
          "When a privacy request is approved, Lightwork finds, copies or deletes the "
          "person's records in the systems below.", "toggle", _P, False, sr, subgroup=sources,
          weaker=True,
          warning="Lightwork will connect to the systems below to find, copy and delete "
                  "people's records when a request is approved."),
        S(_SOURCES, "timeout_seconds", "Wait for a system up to",
          "How long to wait for a system to answer.", "number", _P, 15.0, sr,
          subgroup=sources, minimum=0.1, maximum=60, step=0.1, unit="seconds"),
        S(_SOURCES, "max_response_bytes", "Largest answer read",
          "Bigger answers from a system are refused.", "number", _P, 1024 * _KB, sr,
          subgroup=sources, minimum=1, maximum=4096, integer=True, scale=_KB, unit="KB",
          weaker="higher", warning="Bigger answers from systems will be read."),
        S(_SOURCES, "max_retrieval_bytes", "Largest copy of a person's data",
          "Copies of a person's data bigger than this are refused. It must be at least the "
          "largest answer above.", "number", _P, 8192 * _KB, sr, subgroup=sources, minimum=1,
          maximum=32768, integer=True, scale=_KB, unit="KB", weaker="higher",
          warning="Bigger copies of people's data will be made."),
        S(_SOURCES, "max_records", "Records per person", "The most records found for one "
          "person in one system.", "number", _P, 200, sr, subgroup=sources, minimum=1,
          maximum=1000, integer=True, unit="records", weaker="higher",
          warning="More of each person's records will be handled at once."),
        S(_SOURCES, "batch_size", "Requests handled each time",
          "How many requests a worker handles in one go.", "number", _P, 10, sr,
          subgroup=sources, minimum=1, maximum=100, integer=True, unit="requests"),
        S(_SOURCES, "lease_seconds", "Time a worker holds a request",
          "How long one worker keeps a request before another may take it over. It must be "
          "at least twice \"Wait for a system up to\", plus 5 seconds.", "number", _P, 60, sr,
          subgroup=sources, minimum=1, maximum=3600, integer=True, unit="seconds"),
        S(_SOURCES, "retry_delay_seconds", "Wait before retrying",
          "How long to wait after a failure before trying again.", "number", _P, 30, sr,
          subgroup=sources, minimum=0, maximum=604800, integer=True, unit="seconds"),
        S(_SOURCES, "claim_history_retention_seconds", "Keep worker history for",
          "Records of which worker handled what are removed after this.", "number", _P,
          24 * _HOUR, sr, subgroup=sources, minimum=1, maximum=720, integer=True, scale=_HOUR,
          unit="hours", weaker="lower",
          warning="Worker history will be permanently deleted sooner."),
        S(_SOURCES, "target_custody_retention_seconds", "Keep deletion targets for",
          "Sealed records of what is due to be deleted are removed after this.", "number", _P,
          30 * _DAY, sr, subgroup=sources, minimum=1, maximum=3650, integer=True, scale=_DAY,
          unit="days", weaker="lower",
          warning="Records of what is due to be deleted will be removed sooner."),
    ]
    capabilities = (("discover", "Find records"), ("retrieve", "Copy records"),
                    ("delete", "Delete records"), ("verify_delete", "Check deletions"))
    for key, name, pattern, example in _RIGHTS_SOURCES:
        section = f"{_SOURCES}.providers.{key}"
        sub = _sub("Privacy automation", f"{name} for requests")
        rows += [
            S(section, "enable", f"Search {name}",
              f"Include {name} when handling approved privacy requests. Fill in the details "
              "below first.", "toggle", _P, False, sr, subgroup=sub, weaker=True,
              warning=f"Lightwork will connect to {name} for privacy requests."),
            S(section, "source_id", f"{name} name in Lightwork",
              "A short name for this system. Letters, numbers, dots, dashes and colons.",
              "text", _P, "", sr, subgroup=sub, pattern=_optional(_ID), max_length=128),
            S(section, "origin", f"{name} address",
              f"The {name} address, such as {example}.", "text", _P, "", sr, subgroup=sub,
              pattern=_optional(pattern), max_length=300, weaker="change",
              warning=f"Requests will go to a different {name} address."),
            S(section, "credential_ref", f"{name} sign-in key location",
              "Where the sign-in key is kept, written as env, vault or secret, a colon and a "
              "name in capitals that includes the word RIGHTS. It is stored sealed and never "
              "shown again.", "secret", _P, "", sr, subgroup=sub,
              pattern=r"(?:env|vault|secret):" + _env_name("RIGHTS", 127), max_length=140),
            S(section, "capabilities", f"What Lightwork may do in {name}",
              "The actions allowed in this system.", "multiselect", _P, [], sr, subgroup=sub,
              choices=capabilities, weaker="grow",
              warning="Lightwork will be able to do more in that system, such as deleting "
                      "records."),
        ]
    return tuple(rows)


# ---------------------------------------------------------------- the rest
def _other_rows(S) -> tuple:
    return (
        S("privacy", "redact_egress", "Remove personal data before it goes to AI services",
          "Strip personal details and secrets from requests before they are sent to a cloud "
          "AI service. Requests to AI models on your own servers are left as they are.",
          "toggle", _P, False, "maverick.privacy_egress", weaker=False,
          env=("MAVERICK_REDACT_EGRESS",),
          warning="Personal details and secrets in requests will be sent to cloud AI services."),
        S("compliance", "profiles", "Compliance profiles",
          "The regulations Lightwork enforces. Each adds its own protections, such as asking "
          "a person before high-risk actions. HIPAA and SOC 2 also switch on enterprise mode, "
          "so they can only be chosen here once dashboard sign-in and a client binding are "
          "set up on the server. Your server's own settings can add more. With none ticked, "
          "your installer's choice applies.",
          "multiselect", "AI governance", [], "maverick.compliance_profiles",
          subgroup="Compliance profiles", choices=_COMPLIANCE_PROFILES, weaker="shrink",
          warning="Protections the removed regulation requires, such as asking a person "
                  "before high-risk actions, may stop applying."),
        S("approval", "dashboard_wait_seconds", "Wait for a dashboard approval up to",
          "How long an agent waits for someone to approve a risky action on the Approvals "
          "page. After 10 minutes the people who can decide get one in-app reminder. With "
          "no answer in time, the action is refused.", "number", "Safety",
          30 * _MINUTE, "maverick.safety.consent", subgroup="Approvals", minimum=1, maximum=60,
          integer=True, scale=_MINUTE, unit="minutes",
          env=("MAVERICK_CONSENT_DASHBOARD_TIMEOUT",)),
        S("approval", "undo_grace_seconds", "Allow undo after a decision for",
          "How long a person can undo an approve or reject on the Approvals page. "
          "The agent waits this long before acting on the decision. 0 turns undo off "
          "and lets the agent act at once.", "number", "Safety",
          INTEGER_SETTINGS["approval.undo_grace_seconds"].default, "maverick.safety.consent",
          subgroup="Approvals", minimum=INTEGER_SETTINGS["approval.undo_grace_seconds"].minimum,
          maximum=INTEGER_SETTINGS["approval.undo_grace_seconds"].maximum,
          integer=True, unit="seconds", weaker="higher",
          warning="Approved actions will wait longer before they start.",
          env=INTEGER_SETTINGS["approval.undo_grace_seconds"].dashboard_env),
        S("approval", "require_acknowledgement", "Confirm high-risk approvals",
          "Approving a high or critical risk request needs an explicit confirmation: a "
          "ticked box for high risk, and typing APPROVE for critical risk. Turning this "
          "off makes those approvals one click.", "toggle", "Safety",
          BOOLEAN_SETTINGS["approval.require_acknowledgement"].default, "maverick.safety.consent",
          subgroup="Approvals", weaker=False,
          warning="High-risk actions can be approved with a single click, without "
                  "restating what they will do.",
          env=BOOLEAN_SETTINGS["approval.require_acknowledgement"].dashboard_env),
        S("approval", "separate_approver", "Who approves a risky action someone asked for",
          "Whether the person who asked for a high or critical risk action may approve it "
          "themselves. By default someone else must, whenever another person can decide "
          "it; where nobody else can, the person who asked may approve it and the record "
          "says so. Always means someone else, even if the request then waits until it "
          "expires and the action is refused.", "select", "Safety",
          CHOICE_SETTINGS["approval.separate_approver"].default,
          "maverick.safety.dual_control", subgroup="Approvals",
          choices=(("when_available", "Someone else, when another approver is available (default)"),
                   ("always", "Always someone else"),
                   ("never", "The person who asked may approve it")),
          weaker=True, order=("always", "when_available", "never"),
          env=CHOICE_SETTINGS["approval.separate_approver"].dashboard_env,
          aliases="self approval approve own request second approver four eyes "
                  "segregation of duties",
          warning="People will be able to approve high-risk actions they asked for "
                  "themselves while someone else could decide them."),
        S("approval", "record_checks", "Keep a record of approval checks",
          "Each time Lightwork checks whether an action needs approval, it records when, the "
          "risk level, the kind of action, the agent or specialist and whether it was allowed, "
          "sent to a person or refused. Never the content or the command. The record lets you "
          "see later what a different approval threshold would have done.", "toggle", "Safety",
          BOOLEAN_SETTINGS["approval.record_checks"].default, "maverick.approval_checks", subgroup="Approvals",
          aliases="approval history threshold preview record of approval checks"),
        S("approval", "check_retention_days", "Keep approval checks for",
          "How long the record of approval checks is kept. Older entries are removed a few "
          "hundred at a time.", "number", "Safety",
          INTEGER_SETTINGS["approval.check_retention_days"].default, "maverick.approval_checks",
          subgroup="Approvals", minimum=INTEGER_SETTINGS["approval.check_retention_days"].minimum,
          maximum=INTEGER_SETTINGS["approval.check_retention_days"].maximum, integer=True, unit="days"),
    )


# --------------------------------------------------------- deadline alerts
_DA = "deadline_alerts"
_DA_SUB = "Deadline alerts"
_DA_READER = "maverick.deadline_alerts"
_LEAD_ITEM = r"[1-9][0-9]{0,2}"


def _lead_row(S, table, key, label, help_text, default, unit):
    return S(f"{_DA}.{table}", key, label, help_text, "list", _P, default, _DA_READER,
             subgroup=_DA_SUB, item_label=f"{unit} before", item_hint="7",
             item_error="a whole number of " + unit, pattern=_LEAD_ITEM, max_items=6,
             empty_unset=True)


def _deadline_alert_rows(S) -> tuple:
    return (
        S(_DA, "enabled", "Alert people about deadlines",
          "Send a notification when a data request, incident notification clock, assessment "
          "renewal, vendor contract renewal or approval is close to its deadline, due today or "
          "missed. Uses the notification backends set up under Notifications. On by default "
          "while the privacy register is on.",
          "toggle", _P, True, _DA_READER, subgroup=_DA_SUB, weaker=False,
          warning="Nobody will be told when a request, incident or renewal is due or missed."),
        S(_DA, "mode", "How alerts are sent",
          "One message per deadline is sent as soon as it is reached, or one summary per person "
          "per check listing everything that needs attention.",
          "select", _P, "immediate", _DA_READER, subgroup=_DA_SUB,
          choices=(("immediate", "One message per deadline"), ("digest", "One summary per person"))),
        S(_DA, "poll_seconds", "Check deadlines every",
          "How often the workspace's deadlines are checked.",
          "number", _P, 15 * _MINUTE, _DA_READER, subgroup=_DA_SUB, minimum=1, maximum=1440,
          integer=True, scale=_MINUTE, unit="minutes"),
        S(_DA, "quiet_hours", "Quiet hours",
          "A daily window, in the server's local time, during which non-urgent alerts wait "
          "(for example 22:00-07:00). Incident clock alerts always go through. Leave empty for none.",
          "text", _P, "", _DA_READER, subgroup=_DA_SUB, max_length=11,
          pattern=r"(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]"),
        S(_DA, "owner", "Who is alerted when a record has no assignee",
          "The name of the privacy or governance owner named in alerts for records nobody is "
          "assigned to.",
          "text", _P, "the privacy owner", _DA_READER, subgroup=_DA_SUB, max_length=200,
          pattern=r"[A-Za-z0-9][A-Za-z0-9 .,'@()_/-]{0,199}"),
        _lead_row(S, "lead_days", "dsar", "Data requests: warn this many days before",
                  "Each number sends one warning that many days before a data request is due.",
                  ["7", "2"], "days"),
        _lead_row(S, "lead_days", "assessment", "Assessments: warn this many days before",
                  "Warnings before an assessment renewal or review date.", ["30", "7"], "days"),
        _lead_row(S, "lead_days", "vendor", "Vendor contracts: warn this many days before",
                  "Warnings before a vendor contract renewal date.", ["30", "7"], "days"),
        _lead_row(S, "lead_hours", "incident", "Incidents: warn this many hours before",
                  "Warnings before the 72-hour breach notification clock runs out.", ["24", "4"], "hours"),
        _lead_row(S, "lead_hours", "approval", "Approvals: warn this many hours before",
                  "Warnings before an approval card expires unanswered.", ["24", "4"], "hours"),
    )


# ------------------------------------------------------------ cross checks
def cross_checks(effective: dict, by_id: dict, error: type) -> None:
    """Refuse privacy combinations the kernel readers reject as invalid."""
    _check_identity(effective, by_id, error)
    _check_destinations(effective, by_id, error)
    _check_discovery(effective, by_id, error)
    _check_rights(effective, by_id, error)
    _check_ordered(effective, by_id, error)
    _check_profiles(effective, by_id, error)
    _check_storage(effective, by_id, error)


def _label(by_id: dict, setting_id: str) -> str:
    return by_id[setting_id].label


def _require(effective, by_id, error, switch_id: str, needed: tuple[str, ...]) -> None:
    if effective.get(switch_id) is not True:
        return
    for needed_id in needed:
        value = effective.get(needed_id)
        if value is False or value in (None, "", []):
            raise error(f"{_label(by_id, switch_id)}: fill in “{_label(by_id, needed_id)}” "
                        "first.")


def _check_identity(effective, by_id, error) -> None:
    base = f"{_CP}.identity"
    _require(effective, by_id, error, f"{base}.enable",
             (f"{base}.issuer", f"{base}.audience", f"{base}.jwks_origin"))


def _check_destinations(effective, by_id, error) -> None:
    switch = f"{_DEST}.enable"
    chosen = effective.get(f"{_DEST}.enabled_providers") or []
    if effective.get(switch) is True and not chosen:
        raise error(f"{_label(by_id, switch)}: choose at least one option in "
                    f"“{_label(by_id, _DEST + '.enabled_providers')}” first.")
    names: set[str] = set()
    if effective.get(switch) is not True:
        return  # off: listed services are kept but nothing is bound or sent
    for provider in chosen:
        for key in _DESTINATION_FIELDS.get(str(provider), ()):
            setting_id = f"{_DEST}.{provider}.{key}"
            if effective.get(setting_id) in (None, ""):
                raise error(f"{_label(by_id, _DEST + '.enabled_providers')}: fill in "
                            f"“{_label(by_id, setting_id)}” first.")
        name = effective.get(f"{_DEST}.{provider}.destination_id")
        if name in names:
            raise error("Each outside service needs its own delivery name.")
        names.add(name)


def _check_discovery(effective, by_id, error) -> None:
    adapters = f"{_PA}.data_discovery.adapters"
    if effective.get(f"{adapters}.enable") is True and \
            not effective.get(f"{adapters}.enabled_providers"):
        raise error(f"{_label(by_id, adapters + '.enable')}: choose at least one option in "
                    f"“{_label(by_id, adapters + '.enabled_providers')}” first.")
    fixes, data_map = f"{_REMEDIATION}.enable", f"{_REMEDIATION}.data_map.enable"
    if (effective.get(fixes) is True) != (effective.get(data_map) is True):
        raise error(f"“{_label(by_id, fixes)}” and “{_label(by_id, data_map)}” must be turned "
                    "on or off together.")
    _require(effective, by_id, error, f"{_REMEDIATION}.scheduler.enable", (fixes,))
    notice = f"{_PA}.notice_governance.publication_runtime"
    _require(effective, by_id, error, f"{notice}.scheduler_enable", (f"{notice}.enable",))
    _require(effective, by_id, error, f"{notice}.enable", (f"{notice}.active_tenants",))
    _check_notice_targets(effective, by_id, error, notice)


def _check_notice_targets(effective, by_id, error, notice: str) -> None:
    """Workspaces that publish and publishing targets must match one to one
    (targets are set on the Privacy notices page)."""
    tenants = effective.get(f"{notice}.active_tenants")
    if not isinstance(tenants, list):
        return
    try:
        from maverick.config import load_config

        node = load_config() or {}
        for part in notice.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        bindings = node.get("bindings") if isinstance(node, dict) else None
    except Exception:  # an unreadable config is reported by the module itself
        return
    targets = {row.get("tenant_id") for row in (bindings or {}).values() if isinstance(row, dict)}
    label = _label(by_id, f"{notice}.active_tenants")
    missing = sorted(t for t in tenants if t not in targets)
    if missing:
        raise error(f"{label}: add a publishing target for “{missing[0]}” on the Privacy "
                    "notices page first.")
    orphaned = sorted(t for t in targets if isinstance(t, str) and t not in tenants)
    if orphaned:
        raise error(f"{label}: “{orphaned[0]}” still has a publishing target; remove it on the "
                    "Privacy notices page first.")


def _check_rights(effective, by_id, error) -> None:
    enabled = []
    for key, _name, _pattern, _example in _RIGHTS_SOURCES:
        base = f"{_SOURCES}.providers.{key}"
        _require(effective, by_id, error, f"{base}.enable",
                 (f"{base}.source_id", f"{base}.origin", f"{base}.credential_ref",
                  f"{base}.capabilities"))
        if effective.get(f"{base}.enable") is True:
            enabled.append(effective.get(f"{base}.source_id"))
    if effective.get(f"{_SOURCES}.enable") is True and not enabled:
        raise error(f"{_label(by_id, _SOURCES + '.enable')}: turn on at least one system "
                    "below first.")
    if len(set(enabled)) != len(enabled):
        raise error("Each system searched for requests needs its own name in Lightwork.")
    timeout = effective.get(f"{_SOURCES}.timeout_seconds")
    lease = effective.get(f"{_SOURCES}.lease_seconds")
    if _number(timeout) and _number(lease) and lease < math.ceil(float(timeout) * 2) + 5:
        raise error(f"{_label(by_id, _SOURCES + '.lease_seconds')} must be at least "
                    f"{math.ceil(float(timeout) * 2) + 5} seconds with the current wait.")


# (smaller, larger, strict): the kernel refuses the smaller one being larger
# (or, when strict, equal).
_ORDERED = (
    (f"{_CP}.identity.token_ttl_seconds", f"{_CP}.identity.link_lifecycle_retention_seconds",
     False),
    (f"{_DU}.provider_audit.audit_window_seconds", f"{_DU}.provider_audit.retention_seconds",
     False),
    (f"{_REMEDIATION}.scheduler.jitter_seconds", f"{_REMEDIATION}.scheduler.interval_seconds",
     False),
    (f"{_PA}.drop_management.scheduler_jitter_seconds",
     f"{_PA}.drop_management.scheduler_interval_seconds", True),
    (f"{_PA}.rights_consumer_intake.max_active_requests_per_subject",
     f"{_PA}.rights_consumer_intake.max_active_requests", False),
    (f"{_SOURCES}.max_response_bytes", f"{_SOURCES}.max_retrieval_bytes", False),
    (f"{_CP}.delivery.retry_base_seconds", f"{_CP}.delivery.retry_max_seconds", False),
    (f"{_DU}.enforcement.retry_base_seconds", f"{_DU}.enforcement.retry_max_seconds", False),
)


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_ordered(effective, by_id, error) -> None:
    for low_id, high_id, strict in _ORDERED:
        low, high = effective.get(low_id), effective.get(high_id)
        if _number(low) and _number(high) and (low >= high if strict else low > high):
            words = "must be less than" if strict else "can't be more than"
            high_label = _label(by_id, high_id)
            raise error(f"{_label(by_id, low_id)} {words} "
                        f"{high_label[:1].lower() + high_label[1:]}.")
    brand = f"{_CP}.trust_center.branding"
    width, height, pixels = (effective.get(f"{brand}.{k}")
                             for k in ("max_width", "max_height", "max_pixels"))
    if _number(width) and _number(height) and _number(pixels) and pixels > width * height:
        raise error(f"{_label(by_id, brand + '.max_pixels')} can't be more than the widest "
                    "times the tallest logo.")


def _check_profiles(effective, by_id, error) -> None:
    """Lock-out guard: a profile that needs the egress lock turns on
    enterprise mode, which closes the no-sign-in dashboard and requires a
    client binding. Choosing one here is refused unless enterprise mode is
    already on (so sign-in and the binding already work)."""
    chosen = effective.get("compliance.profiles") or []
    from maverick.compliance_profiles import FLOOR_EGRESS_LOCK, PROFILES

    locking = [key for key in chosen
               if key in PROFILES and FLOOR_EGRESS_LOCK in PROFILES[key].required_floors]
    if not locking:
        return
    from maverick.enterprise import enterprise_enabled

    if not enterprise_enabled():
        raise error(f"{_label(by_id, 'compliance.profiles')}: HIPAA and SOC 2 switch on "
                    "enterprise mode, which needs dashboard sign-in and a client binding set "
                    "up on the server first.")


# -------------------------------- installation defaults and caps
def _consent_limit_rows(S) -> tuple:
    reports = _sub("Consent preferences", "reports")
    delivery = _sub("Consent preferences", "delivery tries")
    scans = _sub("Consent preferences", "website scan limits")
    public = _sub("Consent preferences", "public consent service")
    admin = _sub("Consent preferences", "consent records screens")
    pr = "maverick_dashboard.consent_public_api"
    return (
        S(f"{_CP}.analytics", "min_cohort_size", "Smallest group shown in consent reports",
          "Groups with fewer people than this are hidden from consent reports. A report can "
          "ask for bigger groups but never smaller ones. When not set, reports hide groups "
          "under 10 unless they ask for as few as 2.", "number", _P, 2,
          "maverick.consent_analytics", subgroup=reports, minimum=2, maximum=100000,
          integer=True, unit="people", weaker="lower",
          warning="Consent reports will be able to show smaller groups, which makes people "
                  "easier to single out."),
        S(f"{_CP}.analytics", "retention_days", "How far back consent reports can look",
          "Reports only count consent records from this many days back. Leave empty for no "
          "limit.", "number", _P, None, "maverick.consent_analytics", subgroup=reports,
          minimum=1, maximum=3650, integer=True, unit="days", weaker="higher",
          none_text="No limit", warning="Consent reports will be able to include older records."),

        S(f"{_CP}.delivery.worker", "enable", "Run automatic consent delivery",
          "Runs only separately reviewed future-delivery subscriptions saved on Consent delivery. "
          "Turning this on does not authorize any destination or replay an unconfirmed send.",
          "toggle", _P, False, "maverick_dashboard.consent_delivery_managed_api", subgroup=delivery),
        S(f"{_CP}.delivery", "max_attempts", "Tries before a delivery stops",
          "How many times each consent change is sent to a delivery destination before it "
          "stops and is flagged. It is also the most a destination may choose, and it applies "
          "to existing destinations too.", "number", _P, 6, "maverick.consent_delivery",
          subgroup=delivery, minimum=1, maximum=20, integer=True, unit="tries",
          weaker="higher", warning="Failed consent changes will be sent more times."),
        S(f"{_CP}.delivery", "retry_base_seconds", "First wait before trying again",
          "How long to wait after the first failed delivery. Each later wait doubles, up to "
          "the longest wait below. Destinations added from now on use it unless they choose "
          "their own.", "number", _P, 5, "maverick.consent_delivery", subgroup=delivery,
          minimum=1, maximum=3600, integer=True, unit="seconds"),
        S(f"{_CP}.delivery", "retry_max_seconds", "Longest wait between tries",
          "The longest wait between two delivery tries, for destinations added from now on "
          "that do not choose their own.", "number", _P, 3600, "maverick.consent_delivery",
          subgroup=delivery, minimum=1, maximum=86400, integer=True, unit="seconds"),

        S(f"{_CP}.scanner", "max_pages", "Most pages in one website scan",
          "The most pages one scan may open. Scans that ask for more are held to it.",
          "number", _P, 100, "maverick.consent_scanner", subgroup=scans, minimum=1,
          maximum=10000, integer=True, unit="pages", weaker="higher",
          warning="Website scans will be able to open more pages."),
        S(f"{_CP}.scanner", "max_depth", "Most clicks deep a scan follows",
          "How many links deep a scan may follow from its start pages.", "number", _P, 4,
          "maverick.consent_scanner", subgroup=scans, minimum=0, maximum=20, integer=True,
          unit="clicks", weaker="higher", warning="Website scans will reach deeper pages."),
        S(f"{_CP}.scanner", "page_timeout_seconds", "Longest wait for one page",
          "How long a scan waits for one page to load.", "number", _P, 30,
          "maverick.consent_scanner", subgroup=scans, minimum=1, maximum=300, integer=True,
          unit="seconds", weaker="higher", warning="Website scans will wait longer on each page."),
        S(f"{_CP}.scanner", "max_network_events", "Most connections recorded per page",
          "The most network connections a scan records on one page.", "number", _P, 5000,
          "maverick.consent_scanner", subgroup=scans, minimum=1, maximum=100000,
          integer=True, unit="connections", weaker="higher",
          warning="Website scans will record more connections on each page."),
        S(f"{_CP}.scanner", "interval_seconds", "Shortest time between scheduled scans",
          "Scheduled scans of the same site never run more often than this, and schedules "
          "that name no interval use it.", "number", _P, 300, "maverick.consent_scanner",
          subgroup=scans, minimum=5, maximum=43200, integer=True, scale=_MINUTE,
          unit="minutes", weaker="lower",
          warning="Your websites will be able to be scanned more often."),

        S(f"{_CP}.edge_cache", "enable", "Let networks cache the consent script",
          "The consent script your websites load can be cached for the time below and served "
          "from cache if Lightwork cannot be reached. Consent settings and people's choices "
          "are never cached. When off, browsers keep the script for 5 minutes.", "toggle", _P,
          False, pr, subgroup=public),
        S(f"{_CP}.edge_cache", "max_age_seconds", "Keep the consent script for",
          "How long a cached copy of the consent script is used.", "number", _P, 300, pr,
          subgroup=public, minimum=0, maximum=1440, integer=True, scale=_MINUTE,
          unit="minutes"),
        S(f"{_CP}.edge_cache", "stale_if_error_seconds",
          "Use an old copy while Lightwork is unreachable for up to",
          "How long an expired cached copy may still be used when Lightwork cannot be "
          "reached. Zero never uses an expired copy.", "number", _P, 0, pr, subgroup=public,
          minimum=0, maximum=168, integer=True, scale=_HOUR, unit="hours"),
        S(f"{_CP}.public_api", "max_request_bytes", "Largest request from a website or app",
          "Bigger requests to the public consent service are refused.", "number", _P,
          64 * _KB, pr, subgroup=public, minimum=1, maximum=1024, integer=True, scale=_KB,
          unit="KB", weaker="higher",
          warning="Websites and apps will be able to send bigger requests."),
        S(f"{_CP}.public_api", "max_response_bytes", "Largest answer to a website or app",
          "Answers bigger than this are withheld.", "number", _P, 256 * _KB, pr,
          subgroup=public, minimum=1, maximum=4096, integer=True, scale=_KB, unit="KB",
          weaker="higher", warning="Bigger answers will be sent to websites and apps."),
        S(f"{_CP}.public_api", "requests_per_minute", "Requests per minute from each site or app",
          "Requests beyond this from one website or app in a minute are refused.", "number",
          _P, 120, pr, subgroup=public, minimum=1, maximum=10000, integer=True,
          unit="per minute", weaker="higher",
          warning="Websites and apps will be able to send more requests each minute."),

        S(f"{_CP}.limits", "profile_page_size", "People listed per page",
          "How many consent profiles one page of the list shows, and the most a request may "
          "ask for.", "number", _P, 100, "maverick_dashboard.consent_preferences_api",
          subgroup=admin, minimum=1, maximum=500, integer=True, unit="people"),
        S(f"{_CP}.limits", "receipt_page_size", "Consent records in one export",
          "How many consent records one person's export includes, and the most a request may "
          "ask for.", "number", _P, 500, "maverick_dashboard.consent_preferences_api",
          subgroup=admin, minimum=1, maximum=500, integer=True, unit="records"),
        S(f"{_CP}.limits", "request_body_bytes", "Largest change sent to the consent records",
          "Bigger requests to the consent records screens are refused. Leave empty for no "
          "extra limit.", "number", _P, None, "maverick_dashboard.consent_preferences_api",
          subgroup=admin, minimum=1, maximum=1024, integer=True, scale=_KB, unit="KB",
          weaker="higher", none_text="No extra limit",
          warning="Bigger requests will be accepted by the consent records screens."),
    )


def _data_use_limit_rows(S) -> tuple:
    rules = _sub("Data use governance", "rule limits")
    records = _sub("Data use governance", "catalog limits")
    enforcement = _sub("Data use governance", "enforcement")
    return (
        S(f"{_DU}.compiler", "max_operations", "Most changes one decision may make",
          "A decision that would change more fields than this is refused. Leave empty for no "
          "limit.", "number", _P, None, "maverick.data_use_policy_compiler", subgroup=rules,
          minimum=1, maximum=10000, integer=True, unit="changes", weaker="higher",
          none_text="No limit", warning="Decisions will be able to change more at once."),
        S(f"{_DU}.compiler", "max_row_filter_nodes", "Most parts in a row filter",
          "Row filters with more parts than this are refused. The data platforms accept at "
          "most 256.", "number", _P, 256, "maverick.data_use_policy_compiler", subgroup=rules,
          minimum=1, maximum=256, integer=True, unit="parts", weaker="higher",
          warning="More complex row filters will be accepted."),
        S(f"{_DU}.limits", "max_assets", "Data sets per workspace",
          "The most data sets a workspace may register. Leave empty for no limit.", "number",
          _P, None, "maverick.data_use_governance", subgroup=records, minimum=1,
          maximum=1000000, integer=True, unit="data sets", weaker="higher",
          none_text="No limit", warning="Workspaces will be able to register more data sets."),
        S(f"{_DU}.limits", "max_fields", "Fields per workspace",
          "The most fields a workspace may register. Leave empty for no limit.", "number", _P,
          None, "maverick.data_use_governance", subgroup=records, minimum=1,
          maximum=10000000, integer=True, unit="fields", weaker="higher",
          none_text="No limit", warning="Workspaces will be able to register more fields."),
        S(f"{_DU}.limits", "max_lineage_edges", "Data links per workspace",
          "The most links between fields a workspace may record. Leave empty for no limit.",
          "number", _P, None, "maverick.data_use_governance", subgroup=records, minimum=1,
          maximum=20000000, integer=True, unit="links", weaker="higher",
          none_text="No limit", warning="Workspaces will be able to record more data links."),
        S(f"{_DU}.limits", "max_context_age_seconds", "Oldest a decision fact may be",
          "Facts behind a data use decision (purpose, rules, consent, what the data holds) "
          "stop counting once they are this old, even if their source said they last longer. "
          "Leave empty to go by each source.", "number", _P, None,
          "maverick.data_use_governance", subgroup=records, minimum=1, maximum=365,
          integer=True, scale=_DAY, unit="days", weaker="higher", none_text="No limit",
          warning="Older facts will still count when data use is decided."),
        S(f"{_DU}.enforcement", "require_four_eyes", "Second person approves data platform changes",
          "Each change Lightwork makes in Snowflake or Databricks waits until a second, "
          "different person approves it on the Approvals page. People must sign in.",
          "toggle", _P, False, "maverick_dashboard.data_use_provider_api",
          subgroup=enforcement, weaker=False,
          warning="Changes in Snowflake and Databricks will run without a second person "
                  "approving them."),
        S(f"{_DU}.enforcement", "retry_base_seconds", "First wait before retrying a change",
          "When a request to the data platform did not go out, Lightwork waits this long "
          "before the next try, doubling each time.", "number", _P, 0.25,
          "maverick_dashboard.data_use_provider_runtime", subgroup=enforcement, minimum=0.05,
          maximum=10, step=0.05, unit="seconds"),
        S(f"{_DU}.enforcement", "retry_max_seconds", "Longest wait between retries",
          "The longest wait between two tries of the same change.", "number", _P, 1.0,
          "maverick_dashboard.data_use_provider_runtime", subgroup=enforcement, minimum=0.25,
          maximum=60, step=0.05, unit="seconds"),
    )


# ------------------------------------ consent publication signing and sessions
def _publication_trust_rows(S) -> tuple:
    """Signed consent publishing and short-lived visitor sessions.

    Both were promised by the configuration but had no reader; they are built
    in maverick.consent_publication_signing (signing key custody, publish-time
    signatures) and maverick_dashboard.consent_public_api (signed answers and
    visitor sessions). The signing key itself is made on the Banner and
    Preference Center page, never typed here.
    """
    publishing = _sub("Consent preferences", "publishing")
    public = _sub("Consent preferences", "public consent service")
    return (
        S(f"{_CP}.publishing", "require_signed_publications", "Sign published consent settings",
          "Sign every banner, preference center and privacy notice you publish, so websites "
          "that check signatures can prove the settings came from Lightwork unchanged. Create "
          "the signing key on the Banner and Preference Center page first: publishing is "
          "refused until it exists. Settings published earlier are sent unsigned until you "
          "publish them again.", "toggle", _P, False, "maverick.consent_publication_signing",
          subgroup=publishing, weaker=False, aliases="signature signing key ed25519",
          warning="Published consent settings will no longer be signed, and websites that "
                  "check signatures will stop showing your banner."),
        S(f"{_CP}.public_api", "token_ttl_seconds", "Visitor sessions last",
          "Websites and apps swap their site key for a short visitor session before they "
          "read or save consent, and renew it before it ends. Leave empty to keep sending "
          "the site key alone with every request. Websites that load the consent script from "
          "Lightwork switch over by themselves; apps that call the consent service directly "
          "must support sessions before you turn this on.", "number", _P, None,
          "maverick_dashboard.consent_public_api", subgroup=public, minimum=1, maximum=1440,
          integer=True, scale=_MINUTE, unit="minutes", none_text="Not used",
          weaker="higher", aliases="session token lifetime",
          warning="Visitor sessions will last longer, or the site key alone will be "
                  "accepted again."),
    )


def _consent_storage_rows(S) -> tuple:
    store = _sub("Consent preferences", "where records are kept")
    reader = "maverick.consent_storage"
    return (
        S(f"{_CP}.storage", "backend", "Where consent records are kept",
          "Consent choices, receipts and the other consent records live in files on this "
          "server, or in a shared PostgreSQL database that several servers can use. Switching "
          "doesn't move records already kept: after Lightwork restarts, copy them in Settings, "
          "Maintenance.", "select", _P, "sqlite", reader, subgroup=store,
          choices=(("sqlite", "In files on this server"),
                   ("postgres", "In a shared PostgreSQL database")),
          restart=True, env=("MAVERICK_CONSENT_STORAGE_BACKEND",), weaker="change",
          warning="Consent records kept in the other place won't be shown until they are "
                  "copied in Settings, Maintenance.",
          aliases="consent database postgres storage backend"),
        S(f"{_CP}.storage", "dsn", "Shared consent database connection",
          "How to reach the PostgreSQL database for consent records, including its password "
          "if it needs one. It is stored sealed and never shown again. A connection set on "
          "the server is used instead.", "secret", _P, "", reader, subgroup=store,
          max_length=4000, pattern=r"postgres(?:ql)?://\S+|\w+=\S+(?:\s+\w+=\S+)*",
          restart=True, test="server", env=("MAVERICK_CONSENT_PG_DSN",),
          weaker="change",
          warning="Consent records will be read from a different database, and records in "
                  "the old one won't be shown.",
          aliases="consent dsn connection string postgres"),
        S(f"{_CP}.storage", "dsn_secret_ref", "Server setting holding the connection",
          "The name of the server setting that holds the consent database connection; the "
          "name must include the word CONSENT. When that setting is present on the server it "
          "is used instead of the connection saved here. Leave empty to use Lightwork's "
          "standard name. It is stored sealed and never shown again.", "secret", _P, "",
          reader, subgroup=store, pattern=r"\$?" + _env_name("CONSENT", 63), max_length=65,
          restart=True, weaker="change",
          warning="Lightwork will look for the consent database connection somewhere else.",
          aliases="consent dsn environment variable secret reference"),
    )


def _check_storage(effective, by_id, error) -> None:
    """The shared consent database needs a connection and its driver."""
    import os

    from maverick import consent_storage

    backend = f"{_CP}.storage.backend"
    if os.environ.get(consent_storage.BACKEND_ENV, "").strip():
        return  # chosen on the server, which wins over this page
    if effective.get(backend) != "postgres":
        return
    ref = str(effective.get(f"{_CP}.storage.dsn_secret_ref") or "").strip().lstrip("$")
    name = ref or consent_storage.DEFAULT_DSN_ENV
    if not os.environ.get(name, "").strip() and not effective.get(f"{_CP}.storage.dsn"):
        raise error(f"{_label(by_id, backend)}: fill in "
                    f"“{_label(by_id, f'{_CP}.storage.dsn')}” first.")
    if not consent_storage.driver_available():
        raise error(f"{_label(by_id, backend)}: the database driver isn't installed with this "
                    "copy of Lightwork.")


def _data_use_check_rows(S) -> tuple:
    checks = _sub("Data use governance", "background checks")
    reader = "maverick.data_use_checks"
    return (
        S(f"{_DU}.scheduler", "enable", "Run data-use checks in the background",
          "On a schedule, re-check every workspace with data use governance on: that the "
          "record of changes is intact, which allowing decisions no longer match current "
          "facts, and which policy exceptions have ended. Nothing is changed and nothing is "
          "sent to a data platform. Takes effect after a restart.", "toggle", _P, False,
          reader, subgroup=checks, restart=True, weaker=False,
          warning="Data use problems will only be found when someone checks by hand.",
          aliases="data use scheduler background checks"),
        S(f"{_DU}.scheduler", "poll_seconds", "How often the checks run",
          "Time between two runs of the background checks.", "number", _P, 3600, reader,
          subgroup=checks, minimum=5, maximum=3600, integer=True, unit="seconds",
          weaker="higher", warning="Problems will be found later."),
        S(f"{_DU}.scheduler", "lease_seconds", "Longest one server holds a run",
          "When several servers share this installation, one runs the checks at a time. If "
          "it stops before finishing, another takes over after this long.", "number", _P,
          900, reader, subgroup=checks, minimum=30, maximum=86400, integer=True,
          unit="seconds"),
        S(f"{_DU}.scheduler", "history_limit", "Past check results kept",
          "How many past runs of the background checks are kept to look back on.", "number",
          _P, 50, reader, subgroup=checks, minimum=1, maximum=1000, integer=True,
          unit="runs", weaker="lower", warning="Fewer past check results will be kept."),
    )

