#!/usr/bin/env python3
"""Canonical secret-bearing environment registry for the GitHub Action.

This module deliberately has no Lightwork imports.  The public composite
action loads it with the isolated standard-library-only Python interpreter
before and after untrusted work runs.

``SECRET_ENV_NAMES`` records concrete credential consumers found in the
platform.  ``is_secret_env_name`` additionally covers generated connector
credentials (for example ``<CONNECTOR>_TOKEN``) and future names that follow
the reviewed credential naming convention.  Public configuration names that
contain security-adjacent words must be explicitly reviewed below.
"""

from __future__ import annotations

import re

# Concrete provider, connector, platform, and transitive SDK credentials.
# Keep this list explicit and reviewable even when the generic classifier
# would also recognize a name: the security contract scans runtime consumers
# and fails when a new concrete credential is absent from this registry.
SECRET_ENV_NAMES = (
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "AIRTABLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "ASANA_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_SECRET",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_OPENAI_AD_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "AZURE_PASSWORD",
    "BEDROCK_API_KEY",
    "BIGQUERY_ACCESS_TOKEN",
    "BITBUCKET_ACCESS_TOKEN",
    "BITBUCKET_APP_PASSWORD",
    "BLUESKY_PASSWORD",
    "BRAVE_API_KEY",
    "CALENDLY_TOKEN",
    "CCH_AXCESS_SUBSCRIPTION_KEY",
    "CLICKUP_API_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "CODEX_ACCESS_TOKEN",
    "COHERE_API_KEY",
    "CONFLUENCE_API_TOKEN",
    "DATABASE_URL",
    "DATABRICKS_TOKEN",
    "DATADOG_API_KEY",
    "DATADOG_APP_KEY",
    "DEEPL_API_KEY",
    "DEEPSEEK_API_KEY",
    "DISCORD_BOT_TOKEN",
    "DISCORD_NOTIFY_WEBHOOK_URL",
    "DROPBOX_ACCESS_TOKEN",
    "DYNAMICS_TOKEN",
    "E2B_API_KEY",
    "ELEVENLABS_API_KEY",
    "ERP_TOKEN",
    "ES_API_KEY",
    "ES_PASSWORD",
    "GA4_ACCESS_TOKEN",
    "GA4_API_SECRET",
    "GDRIVE_ACCESS_TOKEN",
    "GEMINI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "GMAIL_ACCESS_TOKEN",
    "GOOGLE_API_KEY",
    "GROK_API_KEY",
    "GROQ_API_KEY",
    "HASS_TOKEN",
    "HUBSPOT_TOKEN",
    "HUGGINGFACE_API_TOKEN",
    "IDENTITY_HEADER",
    "IRC_PASSWORD",
    "JIRA_API_TOKEN",
    "LIBRETRANSLATE_API_KEY",
    "LINEAR_API_KEY",
    "MAKE_TOKEN",
    "MASTODON_ACCESS_TOKEN",
    "MATRIX_ACCESS_TOKEN",
    "MATTERMOST_BOT_TOKEN",
    "MAVERICK_A2A_TOKEN",
    "MAVERICK_AUDIT_SIGNING_KEY",
    "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED",
    "MAVERICK_BACKUP_SIGNING_KEY",
    "MAVERICK_BENCH_SECRET",
    "MAVERICK_CONSENT_EXPERIMENT_KEY",
    "MAVERICK_CONSENT_PG_DSN",
    "MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY",
    "MAVERICK_DASHBOARD_SESSION_SECRET",
    "MAVERICK_DASHBOARD_TOKEN",
    "MAVERICK_DATADOG_API_KEY",
    "MAVERICK_DESKTOP_OAUTH_TICKET_KEY",
    "MAVERICK_EMBED_API_KEY",
    "MAVERICK_ENCRYPTION_KEY",
    "MAVERICK_EXECUTOR_KUBECONFIG_SECRET",
    "MAVERICK_FLOW_APPROVAL_SECRET",
    "MAVERICK_GH_APP_WEBHOOK_SECRET",
    "MAVERICK_GH_TOKEN",
    "MAVERICK_GITLAB_WEBHOOK_TOKEN",
    "MAVERICK_INBOUND_WEBHOOK_SECRET",
    "MAVERICK_JIRA_WEBHOOK_SECRET",
    "MAVERICK_LINEAR_WEBHOOK_SECRET",
    "MAVERICK_GRAPH_TOKEN",
    "MAVERICK_GRPC_BEARER_TOKEN",
    "MAVERICK_KNOWLEDGE_DSN",
    "MAVERICK_MCP_TOKEN",
    "MAVERICK_OIDC_CLIENT_SECRET",
    "MAVERICK_OIDC_SESSION_SECRET",
    "MAVERICK_PG_DSN",
    "MAVERICK_PRM_API_KEY",
    "MAVERICK_PRIVACY_DISCOVERY_DATA_USE_BRIDGE_DIGEST_KEY",
    "MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY",
    "MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
    "MAVERICK_PRIVACY_RIGHTS_INTAKE_SIGNING_KEY",
    "MAVERICK_PRIVACY_RIGHTS_OTT_CTV_SIGNING_KEY",
    "MAVERICK_PROXY_CLIENT_TOKEN",
    "MAVERICK_PROXY_KEY",
    "MAVERICK_QDRANT_API_KEY",
    "MAVERICK_QUEUE_REDIS_DSN",
    "MAVERICK_QUEUE_REDIS_KEYFILE",
    "MAVERICK_QUEUE_SIGNING_KEY",
    "MAVERICK_RECEIPT_KEY",
    "MAVERICK_RELAY_SECRET",
    "MAVERICK_RELAY_TOKEN",
    "MAVERICK_SCIM_TOKEN",
    "MAVERICK_SCREENSHOT_KEY",
    "MAVERICK_SENTINEL_CLIENT_SECRET",
    "MAVERICK_SENTRY_DSN",
    "MAVERICK_SIEM_TOKEN",
    "MAVERICK_STRIPE_SECRET_KEY",
    "MAVERICK_STRIPE_WEBHOOK_SECRET",
    "MAVERICK_THIRD_PARTY_PORTAL_ROUTING_KEY",
    "MAVERICK_TOOL_CACHE_REDIS_URL",
    "MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY",
    "MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY",
    "MAVERICK_VAULT_KEY",
    "MAVERICK_WEAVIATE_API_KEY",
    "MAVERICK_WEBHOOK_SECRET",
    "MISTRAL_API_KEY",
    "MIXPANEL_PROJECT_TOKEN",
    "MIXPANEL_SERVICE_SECRET",
    "MODERN_TREASURY_TOKEN",
    "MONGODB_URI",
    "MOONSHOT_API_KEY",
    "MSGRAPH_ACCESS_TOKEN",
    "MSI_SECRET",
    "N8N_API_KEY",
    "NEWSAPI_KEY",
    "NOTION_TOKEN",
    "OCTOPUS_TOKEN",
    "ONETRUST_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_COMPATIBLE_API_KEY",
    "OPENROUTER_API_KEY",
    "ORACLE_ORDS_TOKEN",
    "PAGERDUTY_API_TOKEN",
    "PAGERDUTY_EVENTS_KEY",
    "PLAID_SECRET",
    "PLAUSIBLE_API_KEY",
    "POSTHOG_API_KEY",
    "POSTHOG_PERSONAL_API_KEY",
    "POWER_AUTOMATE_TOKEN",
    "PUSHOVER_APP_TOKEN",
    "PUSHOVER_USER_KEY",
    "QDRANT_API_KEY",
    "RCS_SERVICE_ACCOUNT_JSON",
    "RCS_WEBHOOK_TOKEN",
    "REDIS_PASSWORD",
    "REDIS_URL",
    "REPLICATE_API_TOKEN",
    "SALESFORCE_ACCESS_TOKEN",
    "SAP_TOKEN",
    "SEMANTIC_SCHOLAR_API_KEY",
    "SENTRY_AUTH_TOKEN",
    "SERPAPI_API_KEY",
    "SERVICENOW_TOKEN",
    "SFCC_TOKEN",
    "SHOPIFY_ACCESS_TOKEN",
    "SLACK_APP_TOKEN",
    "SLACK_BOT_TOKEN",
    "SLACK_NOTIFY_WEBHOOK_URL",
    # Path to a live SSH agent socket: whoever can reach it can authenticate
    # as the operator, so its value is redacted like a credential.
    "SSH_AUTH_SOCK",
    "SNOWFLAKE_TOKEN",
    "SPOTIFY_ACCESS_TOKEN",
    "STRIPE_SECRET_KEY",
    "TAVILY_API_KEY",
    "TEAMS_WEBHOOK_URL",
    "TEAMS_APP_PASSWORD",
    "TELEGRAM_BOT_TOKEN",
    "TGI_API_KEY",
    "THREADS_ACCESS_TOKEN",
    "TRELLO_KEY",
    "TRELLO_TOKEN",
    "TWILIO_AUTH_TOKEN",
    "UIPATH_TOKEN",
    "UMBRELLA_TOKEN",
    "VAPI_WEBHOOK_TOKEN",
    "VAULT_TOKEN",
    "VENDOR_CONSOLE_SECRET",
    "VENDOR_CONSOLE_SIGNING_KEY",
    "VERCEL_TOKEN",
    "VERTEX_ACCESS_TOKEN",
    "VLLM_API_KEY",
    "VOYAGE_API_KEY",
    "WHATSAPP_CLOUD_ACCESS_TOKEN",
    "WHATSAPP_CLOUD_APP_SECRET",
    "WHATSAPP_CLOUD_VERIFY_TOKEN",
    "WORKATO_TOKEN",
    "WORKDAY_TOKEN",
    "XAI_API_KEY",
    "ZOOM_OAUTH_TOKEN",
)

# Environment values that point at files whose bytes can authenticate a
# caller.  The sanitizer snapshots both the path value and bounded file bytes.
SECRET_FILE_ENV_NAMES = (
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_FEDERATED_TOKEN_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "MAVERICK_OAUTH_OUT",
    "MAVERICK_QUEUE_REDIS_KEYFILE",
)

# These are concrete environment reads that an independent contract scan
# recognizes as security-adjacent but that contain public identifiers,
# endpoints, modes, limits, public keys, or paths rather than credentials.
# Adding an exception requires an explicit review in the same change.
REVIEWED_NON_SECRET_ENV_NAMES = frozenset(
    {
        "AZURE_AUTHORITY_HOST",
        "AZURE_CLIENT_ID",
        "AZURE_OPENAI_AUTH",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_TOKEN_SCOPE",
        "AZURE_TENANT_ID",
        "AZURE_TOKEN_CREDENTIALS",
        # Bedrock provider mode selector (for example "api_key" or "iam");
        # the credential itself is AWS_BEARER_TOKEN_BEDROCK.
        "BEDROCK_AUTH_MODE",
        "CALENDLY_USER_URI",
        "EMAIL_TRUSTED_AUTHSERV_ID",
        "MAVERICK_A2A_ALLOW_UNAUTHENTICATED",
        "MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR",
        "MAVERICK_AGENT_MAX_TOKENS",
        "MAVERICK_APPROVER_KEYS",
        "MAVERICK_WEBHOOK_SUBSCRIPTIONS",
        "MAVERICK_APPROVER_KEYS_DIR",
        "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY",
        "MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS",
        "MAVERICK_COMPACT_TIKTOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_ENCRYPTION_KEY_DIGEST",
        "MAVERICK_ENERGY_WH_PER_1K_TOKENS",
        "MAVERICK_FETCH_ALLOW_PRIVATE",
        "MAVERICK_HISTORY_TOKENS",
        "MAVERICK_KMS_KEY_ID",
        "MAVERICK_MCP_MAX_RESOURCE_SESSIONS",
        "MAVERICK_OAUTH_VAULT",
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT",
        "MAVERICK_OIDC_JWKS_URI",
        "MAVERICK_OIDC_REDIRECT_URI",
        "MAVERICK_OIDC_TOKEN_ENDPOINT",
        # Boolean policy switch for per-tenant BYOK provider keys ([providers]
        # per_tenant_keys). Trips the "KEYS" segment heuristic but carries no
        # credential -- the tenant key itself lives under a distinct, pattern-
        # redacted MAVERICK_TENANT_<digest>_<PROVIDER>_API_KEY name.
        "MAVERICK_PER_TENANT_KEYS",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_PROXY_AUTH_HEADER",
        "MAVERICK_PROXY_AUTH_STYLE",
        "MAVERICK_QUEUE_REDIS_CERTFILE",
        "MAVERICK_QUOTA_MAX_TOKENS_PER_DAY",
        "MAVERICK_RELEASE_PUBKEYS",
        "MAVERICK_ROUTER_THRESHOLD_TOKENS",
        "MAVERICK_SECRETS_BACKEND",
        "MAVERICK_SECRETS_DIR",
        "MAVERICK_SECURITY_AUTOFIX",
        "MAVERICK_TOOL_TOKEN_TTL",
        "MAVERICK_TOOL_TOKENS",
        "MAVERICK_TUI_KEYS",
        "MAVERICK_WEBHOOK_BODY_LIMIT",
        "MAVERICK_WEBHOOK_MAX_AGE_SECONDS",
        "MAVERICK_WEBHOOK_MAX_INFLIGHT",
        "MAVERICK_WEBHOOK_WORKERS",
        "SNOWFLAKE_TOKEN_TYPE",
    }
)

_SECRET_ENV_NAME_SET = frozenset(SECRET_ENV_NAMES) | frozenset(
    SECRET_FILE_ENV_NAMES
)
_CREDENTIAL_NAME_RE = re.compile(
    r"(?:^|_)(?:"
    r"API_?KEY|ACCESS_?KEY(?:_ID)?|APP_?KEY|AUTH_?TOKEN|BEARER_?TOKEN|"
    r"CLIENT_?SECRET|CREDENTIALS?|ENCRYPTION_?KEY|JWT|KEYFILE|NETRC|"
    r"PASSPHRASE|PASSWD|PASSWORD|PRIVATE_?KEY|SESSION_?SECRET|"
    r"SIGNING_?KEY|SECRET|TOKEN"
    r")(?:_|$)"
)
_SECRET_CONNECTION_RE = re.compile(
    r"(?:^|_)(?:DATABASE|MONGO(?:DB)?|POSTGRES|QDRANT|REDIS|SENTRY)"
    r"(?:_[A-Z0-9]+)*(?:_DSN|_URI|_URL)$"
)
_SECRET_WEBHOOK_RE = re.compile(
    r"(?:^|_)WEBHOOK(?:_[A-Z0-9]+)*(?:_SECRET|_TOKEN|_URL)$"
)


def is_secret_env_name(name: str) -> bool:
    """Return whether an inherited environment value must be exact-redacted."""
    if not isinstance(name, str):
        return False
    normalized = name.upper()
    if normalized in REVIEWED_NON_SECRET_ENV_NAMES:
        return False
    return (
        normalized in _SECRET_ENV_NAME_SET
        or bool(_CREDENTIAL_NAME_RE.search(normalized))
        or bool(_SECRET_CONNECTION_RE.search(normalized))
        or bool(_SECRET_WEBHOOK_RE.search(normalized))
        or normalized.endswith("_DSN")
        or normalized.endswith("_API_SECRET")
        or normalized.endswith("_APP_PASSWORD")
        or normalized.endswith("_KEY")
    )
