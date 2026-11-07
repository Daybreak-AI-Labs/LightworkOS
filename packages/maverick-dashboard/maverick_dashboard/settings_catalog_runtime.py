"""All-settings catalog rows for the runtime group.

Kept apart from settings_catalog.py so each group can be extended without
editing the shared catalog. entries receives the catalog's own row and
column types (a plain import would be circular).

This group covers how agents run: AI services and models, planning and
thinking, conversation length, tools and their caches, the protected work
area, safety checks, plugins, document search and memory back ends, and the
diagnostics a running server reads. Every row names the kernel module that
reads it; a value the environment sets (``env``) wins over this page.
"""
from __future__ import annotations

from maverick.config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS, TEXT_SETTINGS

from .settings_catalog_patterns import HTTPS as _HTTPS

# An address that is secure, or plain http only on this computer.
_ADDRESS = (r"(" + _HTTPS + r"|http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?"
            r"(/[^\s\"'<>?#]{0,300})?)?")
# A file on the server: an absolute path or one under the home folder.
_SERVER_PATH = r"((/|~/|[A-Za-z]:\\)[^\x00-\x1f\"'<>|?*]{0,500})?"
_HOST = r"[A-Za-z0-9*?.\[\]:-]{1,253}"
_ROLES = (("orchestrator", "Lead agent"), ("researcher", "Researcher"), ("coder", "Coder"),
          ("writer", "Writer"), ("analyst", "Analyst"), ("revisor", "Reviser"),
          ("verifier", "Answer checker"), ("summarizer", "Summariser"),
          ("skill_distiller", "Skill writer"), ("vision", "Image reader"),
          ("translator", "Translator"), ("coding", "Coding helper"),
          ("reviewer", "Reviewer"), ("shield_judge", "Safety second opinion"),
          ("cascade_draft", "Low-cost first try"))
_RISKS = (("low", "Low risk"), ("medium", "Medium risk"), ("high", "High risk"))
_SEVERITIES = (("medium", "Medium"), ("high", "High (default)"), ("critical", "Critical"))


def entries(S, C, Column) -> tuple:  # noqa: ARG001 -- Column kept for the shared signature
    return (_models(S, C) + _providers(S) + _work_area(S, C) + _safety(S, C)
            + _tools(S, C) + _memory(S) + _diagnostics(S, C) + _switches(S)
            + _wired(S, C) + _background(S) + _startup_limits(S) + _tool_server(S))


def cross_checks(effective: dict, by_id: dict, error: type) -> None:
    """Refuse values the kernel would reject or cannot honour yet."""
    if effective.get("ekko.provider_egress") is True:
        raise error("Send Ekko's findings to an AI service: this can't be turned on yet. Ekko "
                    "has no reviewed way to send what it notices off this computer, so it "
                    "stays off.")
    keys = effective.get("tui.keys")
    if isinstance(keys, dict) and keys:
        from maverick import keymap

        if keymap.validate({**keymap.DEFAULTS, **{k: str(v).lower() for k, v in keys.items()}}):
            raise error("Keys in the terminal view: two actions can't share one key.")
    _voice_unlock_check(effective, by_id, error)


def _voice_unlock_check(effective: dict, by_id: dict, error: type) -> None:
    """Voice unlock can't be turned on until it can actually check voices."""
    if effective.get("voice.biometric_unlock") is not True:
        return
    from maverick import voice_unlock

    if voice_unlock.enabled():
        return  # already on: other saves are not held up by it
    reason = voice_unlock.readiness(str(effective.get("voice.speaker_model_path") or ""))
    if reason:
        raise error(f"{by_id['voice.biometric_unlock'].label}: {reason}")


def _models(S, C) -> tuple:
    return (
        # ------------------------------------------------ effort and planning
        S("adaptive_compute", "low_uncertainty", "Use fewer attempts below this uncertainty",
          "When agents are this sure or surer, fewer parallel attempts are made, down to the "
          "fewest below. From 0 (never) to 1 (always).", "number", "AI models", 0.2,
          "maverick.config", subgroup="Effort and planning", minimum=0, maximum=1, step=0.05,
          unit="share"),
        S("adaptive_compute", "min_width", "Fewest attempts when agents are sure",
          "The fewest parallel attempts made when agents are confident.", "number",
          "AI models", 1, "maverick.config", subgroup="Effort and planning", minimum=1,
          maximum=16, integer=True, unit="attempts"),
        S("planning", "candidates", "Plans compared before starting",
          "How many plans are written and compared when agents compare several plans first. "
          "Each plan is one extra request to the AI service.", "number", "AI models", 3,
          "maverick.tree_of_thought", subgroup="Effort and planning", minimum=1, maximum=10,
          integer=True, unit="plans", env=("MAVERICK_TOT_CANDIDATES",)),
        S("thinking", "budget", "Thinking allowance for the lead agent",
          "How much private reasoning, in tokens, the lead agent and the reviser may use on "
          "each step. Thinking is billed like written text.", "number", "AI models", 8000,
          "maverick.agent", subgroup="Effort and planning", minimum=1024, maximum=128000,
          integer=True, unit="tokens"),
        S("thinking", "adaptive", "Adjust thinking to past results",
          "Use less thinking where recent work succeeded easily and more where it struggled.",
          "toggle", "AI models", False, "maverick.thinking_budget",
          subgroup="Effort and planning"),
        S("speculative", "draft_model", "Quick model for predictable steps",
          "The cheaper model that drafts predictable steps when that option is on.", "select",
          "AI models", "", "maverick.config", subgroup="Effort and planning",
          choices_from="models"),
        S("persona", "addendum", "Extra instruction for every agent",
          "A sentence added to every agent's instructions, for example: Always cite your "
          "sources.", "text", "AI models", "", "maverick.persona",
          subgroup="Effort and planning", max_length=500, pattern=r"[^\n\r<>{}]{0,500}"),
        S("agent_factory", "jd_hiring", "Hire agents from a job description",
          "Offer the page that turns a written job description into a new agent.", "toggle",
          "AI models", True, "maverick.jd_hiring", subgroup="Effort and planning"),
        S("agent_factory", "require_passing_tests", "Require passing tests before publishing instructions",
          "Changed instructions for an agent or specialist are published only after every saved test "
          "passes on exactly those instructions. Someone can still publish without a passing run by "
          "giving a reason, which is written to the activity record.", "toggle",
          "AI models", True, "maverick.agent_publish_policy", subgroup="Effort and planning", weaker=False,
          warning="Changed instructions could be published without any test run.",
          aliases="publish gate test set test cases agent tests answer checks"),
        S("agent_tests", "max_cases_per_specialist", "Saved answer checks per specialist",
          "How many saved answer checks one specialist can keep, and how many one run checks at once. "
          "Lowering it keeps the checks already saved, but a set larger than the limit cannot pass "
          "a full run.", "number", "AI models", INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].default,
          "maverick.agent_tests_policy", subgroup="Effort and planning",
          minimum=INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].minimum,
          maximum=INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].maximum, integer=True, unit="checks",
          aliases="test cases answer checks test set limit"),
        S("agent_tests", "require_for_new_specialists", "Require a passing run before a new specialist is published",
          "A specialist that has never been published needs at least one saved check, and a full run of "
          "every saved check on its exact draft must pass, before it can be published. A reason does not "
          "skip this.", "toggle", "AI models", BOOLEAN_SETTINGS["agent_tests.require_for_new_specialists"].default, "maverick.agent_tests_policy",
          subgroup="Effort and planning", weaker=False,
          warning="A new specialist could be published without any test run.",
          aliases="new agent publish gate test cases answer checks"),
        S("agent_tests", "bypass_requires_second_person", "Second administrator approves publishing without passing tests",
          "When changed instructions are published without a passing run, a different administrator must "
          "approve the reason first. The person who asked cannot approve their own reason.", "toggle",
          "AI models", BOOLEAN_SETTINGS["agent_tests.bypass_requires_second_person"].default, "maverick.agent_tests_policy",
          subgroup="Effort and planning", weaker=False,
          warning="A reason alone is enough to publish changed instructions without a passing run.",
          aliases="four eyes approval reason publish gate test cases answer checks"),
        S("agent_tests", "tool_checks", "Saved answer checks may test which tools a specialist calls",
          "A saved check can say which tools a specialist must call, must not call, and what the call must "
          "include. Each tool is replaced by a test stub that records the call and answers with a fixed result, "
          "so no real tool, file, network call or shell command runs. Checks that use tools are skipped while this is off.",
          "toggle", "AI models", BOOLEAN_SETTINGS["agent_tests.tool_checks"].default, "maverick.agent_tests_policy",
          subgroup="Effort and planning", aliases="tool use tool calls stub test checks answer checks"),
        S("agent_tests", "canary_percent", "Share of new goals that try a changed specialist first",
          "0 publishes changed instructions straight away, as today. From 1 to 50, a changed specialist "
          "is first tried on that share of new goals, chosen by goal, while the rest keep the current "
          "version. Goals already running are not changed. Promote the new version for everyone, or roll it back, "
          "in Workforce.", "number", "AI models", INTEGER_SETTINGS["agent_tests.canary_percent"].default,
          "maverick.agent_tests_policy", subgroup="Effort and planning",
          minimum=INTEGER_SETTINGS["agent_tests.canary_percent"].minimum,
          maximum=INTEGER_SETTINGS["agent_tests.canary_percent"].maximum, integer=True, unit="percent", weaker="higher",
          warning="Some new goals would use changed instructions before everyone does.",
          aliases="canary gradual rollout trial share percent candidate changed instructions"),
        S("agent_tests", "canary_auto_rollback", "Roll back a trial version that fails clearly more often",
          "After at least 10 finished goals on the trial version, roll it back automatically when its share of "
          "failed goals is more than 20 percentage points above the current version. It needs a finished goal on "
          "the current version to compare with. The roll back is recorded.",
          "toggle", "AI models", BOOLEAN_SETTINGS["agent_tests.canary_auto_rollback"].default, "maverick.agent_tests_policy",
          subgroup="Effort and planning", weaker=False,
          warning="A trial version that fails more often would stay live until someone rolls it back.",
          aliases="canary automatic rollback trial failures"),

        # ------------------------------------------------ conversation length
        S("context", "max_output_tokens", "Longest reply per step",
          "The most text, in tokens, an agent may write in one step. Leave empty to size it "
          "to each model.", "number", "AI models", None, "maverick.context_scaling",
          subgroup="Conversation length", minimum=1024, maximum=128000, integer=True,
          unit="tokens", none_text="Sized to each model", env=("MAVERICK_AGENT_MAX_TOKENS",)),
        S("context", "window_override", "Treat every model as reading at most",
          "Use this reading limit, in tokens, for every model instead of each model's known "
          "limit. Leave empty to use the known limits.", "number", "AI models", None,
          "maverick.context_scaling", subgroup="Conversation length", minimum=8000,
          maximum=10000000, integer=True, unit="tokens", none_text="Known limit of each model",
          env=("MAVERICK_MODEL_CONTEXT_WINDOW",)),
        S("context", "model_windows", "Reading limits for particular models",
          "Tell Lightwork how much a model can read at once when it does not know, for "
          "example a model you run yourself.", "table", "AI models", {}, "maverick.preflight",
          subgroup="Conversation length", row_kind="grid", choices_from="models", scalar=True,
          columns=(C("window", "Reading limit", "number", minimum=1000, maximum=10000000,
                     integer=True, unit="tokens", required=True),),
          row_label="Model", item_label="Model", add_label="Add a limit",
          empty_text="No model has its own reading limit."),
        S("context", "preflight", "Check each request fits the model",
          "Before a request is sent, estimate whether it fits what the model can read.",
          "select", "AI models", "warn", "maverick.llm", subgroup="Conversation length",
          choices=(("strict", "Refuse requests that won't fit"),
                   ("warn", "Send them and record a warning (default)"),
                   ("off", "Don't check")),
          weaker=True, order=("strict", "warn", "off"), env=("MAVERICK_PREFLIGHT",),
          warning="Requests too long for the model will be sent unchecked, spending money "
                  "on calls that fail."),
        S("context", "history_tokens", "Shorten conversations to about",
          "When a conversation is shortened, aim for this much text, in tokens. Leave empty "
          "to size it to each model.", "number", "AI models", None,
          "maverick.context_compactor", subgroup="Conversation length", minimum=500,
          maximum=2000000, integer=True, unit="tokens", none_text="Sized to each model",
          env=("MAVERICK_HISTORY_TOKENS",)),
        S("context", "history_window", "Recent turns considered when shortening",
          "How many recent turns are looked at when a conversation is shortened. Leave empty "
          "to size it to each model.", "number", "AI models", None,
          "maverick.context_compactor", subgroup="Conversation length", minimum=2,
          maximum=10000, integer=True, unit="turns", none_text="Sized to each model",
          env=("MAVERICK_HISTORY_WINDOW",)),
        S("context", "router_threshold_tokens", "Read a document in parts above",
          "Documents longer than this, in tokens, are read in parts when that option is on. "
          "Leave empty to size it to each model.", "number", "AI models", None,
          "maverick.long_context_router", subgroup="Conversation length", minimum=1000,
          maximum=10000000, integer=True, unit="tokens", none_text="Sized to each model",
          env=("MAVERICK_ROUTER_THRESHOLD_TOKENS",)),
        S("context", "router_top_k", "Parts of a long document kept",
          "How many of the most relevant parts are given to agents.", "number", "AI models",
          12, "maverick.long_context_router", subgroup="Conversation length", minimum=1,
          maximum=200, integer=True, unit="parts", env=("MAVERICK_ROUTER_TOP_K",)),
        S("context", "async_compaction", "Reuse work when shortening conversations",
          "Keep counts from earlier shortening so long conversations shorten faster. Works "
          "together with keeping the most useful older turns.", "toggle", "AI models", False,
          "maverick.async_compaction", subgroup="Conversation length",
          env=("MAVERICK_ASYNC_COMPACTION",)),
        S("context", "compaction_stream_ttl_days", "Remove unused running summaries after",
          "Running summaries of very long chats that nobody has used for this long are "
          "removed.", "number", "AI models", 30, "maverick.compaction.streaming",
          subgroup="Conversation length", minimum=1, maximum=3650, integer=True, unit="days",
          weaker="higher", warning="Summaries of old conversations will be kept for longer."),
        S("context", "retrieval_router", "Read very long pasted documents in parts",
          "When a task includes a very long document, give agents only the parts that "
          "matter to each step.", "toggle", "AI models", False,
          "maverick.long_context_router", subgroup="Conversation length",
          env=("MAVERICK_RETRIEVAL_ROUTER",)),
        S("compaction", "hybrid", "Learn which shortening method works best",
          "Try the shortening methods on real conversations and prefer the one that works "
          "best. A method chosen above always wins.", "toggle", "AI models", False,
          "maverick.compaction.hybrid", subgroup="Conversation length",
          env=("MAVERICK_COMPACTION_HYBRID",)),

        # ------------------------------------------------------- model routing
        S("models", "guidance", "Show model choice guidance",
          "Show provider-reported capabilities and dated pricing evidence alongside model choices. Unknown details remain unknown.",
          "toggle", "AI models", True, "maverick.model_guidance", subgroup="Model choices"),
        S("models", "capability_tests", "Allow bounded model generation tests",
          "Let administrators review and explicitly confirm one synthetic model call, capped at USD 0.05 and 64 output tokens or lower workspace limits. Cancellation cannot retract a sent request; uncertain calls are never retried.",
          "toggle", "AI models", False, "maverick.model_tests", subgroup="Model choices"),
        S("models", "catalog", "Extra models to offer",
          "Models that are not in the built-in list, so they can be chosen everywhere. Write "
          "each as the service name, a colon and the model name.", "list", "AI models", [],
          "maverick_dashboard.model_pickers", subgroup="Model choices", item_label="Model",
          item_hint="vllm:my-model", pattern=r"[a-z0-9_]{1,32}:[A-Za-z0-9._:/@-]{1,160}",
          item_error="a service name, a colon and a model name", max_items=50,
          max_length=200),
        S("models", "discovery_ttl_minutes", "Refresh model lists every",
          "How long a list of models fetched from an AI service is used before it is fetched "
          "again.", "number", "AI models", 60, "maverick.model_discovery",
          subgroup="Model choices", minimum=1, maximum=1440, integer=True, unit="minutes"),
        S("routing", "max_error_rate", "Skip an AI service that fails more than",
          "When picking the cheapest model, leave out services whose recent requests failed "
          "at least this often.", "number", "AI models", 0.5, "maverick.cost.router",
          subgroup="Model choices", minimum=5, maximum=100, scale=0.01,
          unit="percent", env=("MAVERICK_ROUTING_MAX_ERROR_RATE",)),
        S("routing", "bandit", "Learn which AI service works best",
          "When picking the cheapest model, try the suitable services and learn which one "
          "gives the most successful answers for the money for each kind of work.",
          "toggle", "AI models", False, "maverick.cost.bandit", subgroup="Model choices",
          env=("MAVERICK_ROUTING_BANDIT",)),
        S("models", "cascade", "Start with a lower-cost model",
          "Agents without a model of their own start on the low-cost first-try model and "
          "move to their usual model when an answer is rejected or a task gets long.",
          "toggle", "AI models", False, "maverick.routing", subgroup="Model choices",
          env=("MAVERICK_CASCADE_ROUTING",)),
        S("models", "cascade_escalate_below", "Move to the usual model when the checker is less sure than",
          "With a lower-cost start, an answer the checker rejects with less confidence "
          "than this moves the agent to its usual model.", "number", "AI models", 0.6,
          "maverick.routing", subgroup="Model choices", minimum=1, maximum=100, scale=0.01,
          unit="percent", env=("MAVERICK_ESCALATE_BELOW",)),
        S("models", "cascade_escalate_tool_depth", "Move to the usual model after",
          "With a lower-cost start, an agent that has taken more actions than this on one "
          "task moves to its usual model.", "number", "AI models", 3, "maverick.routing",
          subgroup="Model choices", minimum=1, maximum=100, integer=True, unit="actions",
          env=("MAVERICK_ESCALATE_TOOL_DEPTH",)),
        S("routing", "battery_threshold_pct", "Prefer lower-energy models below",
          "On battery, switch to the lower-energy model once the charge falls below this.",
          "number", "AI models", 20, "maverick.energy_aware_router", subgroup="Model choices",
          minimum=1, maximum=100, integer=True, unit="percent"),
        S("routing", "roles", "Model rules for each kind of agent",
          "Limit which AI services each kind of agent may use when models are picked "
          "automatically, and how capable its model must be.", "table", "AI models", {},
          "maverick.cost.router", subgroup="Model choices", row_kind="grid", choices=_ROLES,
          columns=(
              C("providers", "Only these services", "picks", choices_from="providers",
                max_items=20),
              C("deny_providers", "Never these services", "picks", choices_from="providers",
                max_items=20),
              C("tier", "Model level", "select", default="",
                choices=(("", "Any level"), ("cheap", "Low cost"), ("base", "Standard"),
                         ("premium", "Most capable"))),
          ),
          row_label="Kind of agent", item_label="Kind of agent", add_label="Add rules",
          empty_text="Every kind of agent may use any connected service.",
          empty_hint="No AI services are set up yet. Add one under AI service keys on the "
                     "Settings page first."),
    )


def _providers(S) -> tuple:
    return (
        S("providers.anthropic", "base_url", "Claude service address",
          "Send Claude requests through this address instead of Anthropic's own, for example "
          "a regional gateway. Leave empty for the standard address.", "text", "Integrations",
          "", "maverick.config", subgroup="AI service addresses", pattern=_ADDRESS,
          max_length=320, weaker="change",
          warning="Claude requests, and the task text in them, will go to a different "
                  "address."),
        S("providers.openai_compatible", "base_url", "Compatible AI service address",
          "The address of an AI service that speaks the OpenAI request format, such as your "
          "own model server or a company gateway.", "text", "Integrations", "",
          "maverick.config", subgroup="AI service addresses", pattern=_ADDRESS,
          max_length=320, weaker="change",
          warning="Requests, and the task text in them, will go to a different address."),
        S("providers.openai_compatible", "api_key", "Compatible AI service key",
          "The key for the service above. It is stored sealed and never shown again.",
          "secret", "Integrations", "", "maverick.config", subgroup="AI service addresses",
          max_length=500),
        S("providers.azure", "base_url", "Microsoft Azure address",
          "The address of your Azure OpenAI resource.", "text", "Integrations", "",
          "maverick.config", subgroup="Microsoft Azure", pattern=r"(" + _HTTPS + r")?",
          max_length=320, weaker="change",
          warning="Azure requests, and the task text in them, will go to a different "
                  "address."),
        S("providers.azure", "api_key", "Microsoft Azure key",
          "The key for your Azure OpenAI resource. It is stored sealed and never shown again.",
          "secret", "Integrations", "", "maverick.config", subgroup="Microsoft Azure",
          max_length=500),
        S("providers.azure", "auth_mode", "How Lightwork signs in to Azure",
          "Use the key above, or the server's Microsoft sign-in.", "select", "Integrations",
          "", "maverick.config", subgroup="Microsoft Azure",
          choices=(("", "Decide from what is set (default)"), ("api_key", "The key above"),
                   ("entra_id", "The server's Microsoft sign-in"))),
        S("providers.azure", "deployment", "Azure model deployment",
          "The name of the model deployment in your Azure resource.", "text", "Integrations",
          "", "maverick.llm", subgroup="Microsoft Azure", pattern=r"[A-Za-z0-9._-]{0,64}",
          max_length=64),
        S("providers.azure", "api_version", "Azure service version",
          "The Azure OpenAI version date to use. Leave empty for the standard one.", "text",
          "Integrations", "", "maverick.llm", subgroup="Microsoft Azure",
          pattern=r"(20[0-9]{2}-[0-9]{2}-[0-9]{2}(-preview)?)?", max_length=20),
        S("providers.bedrock", "region", "Amazon Bedrock region",
          "The AWS region your Bedrock models run in, such as us-east-1.", "text",
          "Integrations", "", "maverick.llm", subgroup="Amazon Bedrock",
          pattern=r"([a-z]{2}(-gov)?-[a-z]+-[0-9])?", max_length=20),
        S("providers.bedrock", "endpoint", "Amazon Bedrock service",
          "Which Bedrock service Lightwork calls.", "select", "Integrations", "mantle",
          "maverick.llm", subgroup="Amazon Bedrock",
          choices=(("mantle", "Current service (default)"), ("legacy", "Older runtime service"))),
        S("providers.bedrock", "api_key", "Amazon Bedrock access key",
          "The Bedrock access key, when Lightwork signs in with one. It is stored sealed and "
          "never shown again.", "secret", "Integrations", "", "maverick.llm",
          subgroup="Amazon Bedrock", max_length=500),
        S("providers.vertex", "project_id", "Google Cloud project",
          "The Google Cloud project whose Vertex AI access Lightwork uses.", "text",
          "Integrations", "", "maverick.llm", subgroup="Google Cloud Vertex AI",
          pattern=r"([A-Za-z0-9][A-Za-z0-9.:_-]{0,127})?", max_length=128),
        S("providers.vertex", "region", "Vertex AI region",
          "The Vertex AI region for your Claude models, such as us-east5.", "text",
          "Integrations", "", "maverick.llm", subgroup="Google Cloud Vertex AI",
          pattern=r"([a-z0-9][a-z0-9-]{0,62})?", max_length=63),
        S("providers.vertex", "model_id", "Claude model on Vertex AI",
          "The model ID exactly as shown in the Vertex AI Model Garden.", "text",
          "Integrations", "", "maverick.llm", subgroup="Google Cloud Vertex AI",
          pattern=r"([A-Za-z0-9][A-Za-z0-9._@-]{0,119})?", max_length=120),
        S("providers", "per_tenant_keys", "Let each workspace use its own AI service key",
          "A workspace that has its own key for an AI service uses it instead of the shared "
          "one.", "toggle", "Integrations", False, "maverick.config",
          subgroup="AI service addresses", env=("MAVERICK_PER_TENANT_KEYS",), weaker=True,
          warning="Workspaces with their own key will send their work to the AI service "
                  "under that key instead of the shared one."),
        S("providers", "test_receipt_max_age_days", "Trust a passing connection test for",
          "How long a passing AI service connection test counts as \"Connected\". After this, "
          "the service reads \"not tested yet\" again until you test it.", "number",
          "Integrations", 30, "maverick.config", subgroup="AI service addresses", minimum=1,
          maximum=365, integer=True, unit="days", env=("MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS",),
          weaker="higher",
          warning="A longer period means a key that stopped working can show as connected for longer."),
        S("provider_failover.policy", "failover_on", "Move to a backup model after",
          "The kinds of failure that send a request on to the backup models. With none "
          "ticked, every failure except a wrong key or a bad request does.", "multiselect",
          "Integrations", [], "maverick.failover_policy", subgroup="Backup AI models",
          choices=(("rate_limit", "The service is busy"), ("timeout", "No reply in time"),
                   ("network", "The connection failed"), ("server", "A service fault"),
                   ("auth", "A wrong or expired key"),
                   ("bad_request", "The request was refused"), ("other", "Anything else")),
          weaker="grow",
          warning="Requests will move to your backup AI services in more situations, "
                  "which may send task text to another service."),
        S("provider_failover.policy", "cooldown_s", "Rest a failing model for",
          "After repeated failures a model is skipped for this long. Zero never rests it.",
          "number", "Integrations", 0, "maverick.failover_policy", subgroup="Backup AI models",
          minimum=0, maximum=3600, integer=True, unit="seconds"),
        S("provider_failover.policy", "cooldown_after", "Failures before resting a model",
          "How many failures in a row make a model rest.", "number", "Integrations", 2,
          "maverick.failover_policy", subgroup="Backup AI models", minimum=1, maximum=20,
          integer=True, unit="failures"),
        # ------------------------------------------------------------ AI gateway
        S("llm_gateway", "gateway_token", "Gateway password for callers",
          "The password agents built elsewhere send to use the gateway. It is stored sealed "
          "and never shown again.", "secret", "AI governance", "", "maverick.llm_gateway",
          subgroup="AI gateway", max_length=500, weaker="change",
          env=("MAVERICK_GATEWAY_TOKEN",),
          warning="Callers using the old password will be refused, and anyone with the new "
                  "one can send requests that spend your budget."),
        S("llm_gateway", "upstream_token", "Key for the AI service behind the gateway",
          "The key the gateway uses with the AI service it forwards to. It is stored sealed "
          "and never shown again.", "secret", "AI governance", "", "maverick.llm_gateway",
          subgroup="AI gateway", max_length=500),
        S("llm_gateway", "anthropic_upstream_token", "Key for the Claude service behind the gateway",
          "The key used for requests written for Claude. It is stored sealed and never shown "
          "again.", "secret", "AI governance", "", "maverick.llm_gateway",
          subgroup="AI gateway", max_length=500),
        S("llm_gateway", "anthropic_version", "Claude request version",
          "The version date sent with requests written for Claude. Leave empty for the "
          "standard one.", "text", "AI governance", "", "maverick.llm_gateway",
          subgroup="AI gateway", pattern=r"(20[0-9]{2}-[0-9]{2}-[0-9]{2})?", max_length=10),
    )


def _work_area(S, C) -> tuple:
    group = "Protected work area"
    return (
        S("sandbox", "workdir", "Folder for agent files",
          "The folder on the server where agents keep the files they work on.", "text", group,
          "~/maverick-workspace", "maverick.sandbox", subgroup="Work area", pattern=_SERVER_PATH, max_length=500,
          weaker="change",
          warning="Agents will read and write files in a different folder on the server."),
        S("sandbox", "require_container", "Never run commands directly on the server",
          "Refuse to run agent commands outside a container, even when no container program "
          "is chosen.", "toggle", group, False, "maverick.sandbox", subgroup="Work area",
          env=("MAVERICK_REQUIRE_CONTAINER_BACKEND",), weaker=False,
          warning="Agent commands may run directly on the server when no container is "
                  "available."),
        S("sandbox", "reuse_container", "Keep one container for a whole task",
          "Start the work area once per task instead of once per command, which is faster.",
          "toggle", group, False, "maverick.sandbox", subgroup="Work area"),
        S("sandbox", "cross_run_pool", "Keep ready work areas between tasks",
          "Keep a clean work area ready so the next task starts faster.", "toggle", group,
          False, "maverick.sandbox", subgroup="Work area"),
        S("sandbox", "runtime", "Stronger isolation program",
          "The name of the isolation program used when the work area type is the stronger "
          "isolation option.", "text", group, "runsc", "maverick.sandbox",
          subgroup="Work area", pattern=r"[A-Za-z0-9._/-]{0,128}", max_length=128,
          weaker="change",
          warning="Commands will run under a different isolation program."),
        S("sandbox", "ssh_args", "Extra options for the remote computer",
          "Extra connection options used when commands run on another computer, one per "
          "entry.", "list", group, [], "maverick.sandbox", subgroup="Remote computer",
          item_label="Option", item_hint="-p2222", pattern=r"-[A-Za-z0-9][A-Za-z0-9=._:/,-]{0,120}",
          item_error="a connection option starting with a dash", max_items=20,
          weaker="change",
          warning="Commands will reach the remote computer with different connection "
                  "options."),
        S("sandbox", "context", "Cluster to use",
          "The named cluster connection to use, when your cluster settings file lists more "
          "than one. Leave empty for its default.", "text", group, "", "maverick.sandbox",
          subgroup="Cluster", pattern=r"[A-Za-z0-9@._:/-]{0,200}", max_length=200,
          weaker="change", warning="Agent commands will run in a different cluster."),
        S("sandbox", "kubeconfig", "Cluster settings file",
          "Where the cluster settings file is on the server. Leave empty for the standard "
          "one.", "text", group, "", "maverick.sandbox", subgroup="Cluster",
          pattern=_SERVER_PATH, max_length=500, weaker="change",
          warning="Agent commands will run with different cluster settings."),
        S("sandbox", "run_as_user", "User number inside the cluster",
          "The user number cluster commands run as. Zero is the all-powerful user.", "number",
          group, 1000, "maverick.sandbox", subgroup="Cluster", minimum=0, maximum=2147483647,
          integer=True, unit="", weaker="lower",
          warning="Cluster commands may run as a more powerful user."),
        S("sandbox", "extra_kubectl_args", "Extra cluster options",
          "Extra options added to every cluster command, one per entry.", "list", group, [],
          "maverick.sandbox", subgroup="Cluster", item_label="Option",
          item_hint="--request-timeout=30s",
          pattern=r"--[a-z][a-z0-9-]{0,60}(=[A-Za-z0-9._:/,@-]{1,120})?",
          item_error="an option starting with two dashes", max_items=20, weaker="change",
          warning="Cluster commands will run with different options."),
        S("sandbox", "project_dir", "Project folder for development containers",
          "The folder whose development container settings are used for that work area "
          "type.", "text", group, "", "maverick.sandbox", subgroup="Development container",
          pattern=_SERVER_PATH, max_length=500, weaker="change",
          warning="Commands will run in a container built from a different project."),
        S("sandbox", "memory_mb", "Memory for cloud work areas",
          "The most memory a cloud work area may use. Leave empty for the service's choice.",
          "number", group, None, "maverick.sandbox", subgroup="Cloud work areas",
          minimum=256, maximum=262144, integer=True, unit="MB",
          none_text="The service's choice"),
        S("sandbox", "provider", "Where micro-machines run",
          "Run micro-machine work areas on this server, or with the E2B hosted service.",
          "select", group, "local", "maverick.sandbox", subgroup="Cloud work areas",
          choices=(("local", "On this server (default)"), ("e2b", "E2B hosted service")),
          weaker="change", warning="Agent commands and their files will run on an outside "
                                   "service."),
        S("sandbox", "api_key", "E2B key",
          "The key for the E2B hosted service. It is stored sealed and never shown again.",
          "secret", group, "", "maverick.sandbox", subgroup="Cloud work areas",
          max_length=500),
        S("sandbox", "network", "Internet for micro-machines",
          "Whether micro-machine work areas may reach the internet.", "select", group,
          "egress-deny", "maverick.sandbox", subgroup="Cloud work areas",
          choices=(("egress-deny", "No internet (default)"),
                   ("egress-allow", "Allow the internet")),
          weaker=True, order=("egress-deny", "egress-allow"),
          warning="Agent commands will be able to send data to, and download programs from, "
                  "anywhere on the internet."),
        S("sandbox", "warm", "Keep a hosted micro-machine running",
          "Reuse one hosted micro-machine between commands instead of starting a new one "
          "each time.", "toggle", group, False, "maverick.sandbox",
          subgroup="Cloud work areas"),
        # ----------------------------------------------------- locked-down mode
        S("containment", "enabled", "Locked-down mode for every task",
          "Run every task with nothing leaving and nothing kept: the tools that send data "
          "out are removed, commands get no internet, work happens in a throwaway folder "
          "and each task has a time limit. Use it while handling untrusted material.",
          "toggle", group, False, "maverick.containment", subgroup="Locked-down mode",
          env=("MAVERICK_CONTAINMENT",), weaker=False,
          warning="Tasks will again be able to send data out and keep their files.",
          aliases="containment untrusted quarantine"),
        S("containment", "no_network", "No internet in locked-down mode",
          "Commands get no internet while locked-down mode is on.", "toggle", group, True,
          "maverick.containment", subgroup="Locked-down mode", weaker=False,
          warning="Commands in locked-down mode will be able to reach the internet."),
        S("containment", "ephemeral_workspace", "Throwaway folder in locked-down mode",
          "Tasks work in a private folder that is deleted afterwards, so nothing they write "
          "is kept.", "toggle", group, True, "maverick.containment",
          subgroup="Locked-down mode", weaker=False,
          warning="Files written by tasks in locked-down mode will be kept."),
        S("containment", "max_wall_seconds", "Time limit in locked-down mode",
          "The longest a task may run while locked-down mode is on.", "number", group, 1800,
          "maverick.containment", subgroup="Locked-down mode", minimum=1, maximum=1440,
          scale=60, unit="minutes", weaker="higher",
          warning="Tasks in locked-down mode will be able to run for longer."),
        S("containment", "deny_tools", "More tools to remove in locked-down mode",
          "Tools removed in addition to the built-in list of tools that send data out, "
          "which is always removed.", "list", group, [], "maverick.containment",
          subgroup="Locked-down mode", item_label="Tool", item_hint="github_issues",
          pattern=r"[A-Za-z0-9_.-]{1,128}", item_error="a tool name", max_items=100,
          weaker="shrink",
          warning="The tools you remove from this list will be usable in locked-down mode."),
        S("sandbox", "tool", "Websites each web tool may reach",
          "Limit the addresses the web tools may contact. Blocked addresses always win; "
          "when you list allowed addresses, only those can be reached. A star matches any "
          "part of a name.", "table", group, {}, "maverick.sandbox.network_policy",
          subgroup="Web tool addresses", row_kind="grid",
          choices=(("http_fetch", "Reading web pages"), ("browser", "Web browser"),
                   ("websocket", "Live connections")),
          columns=(
              C("allow_egress", "Only these addresses", "words", pattern=_HOST,
                max_items=100, item_error="an address such as api.example.com"),
              C("deny_egress", "Never these addresses", "words", pattern=_HOST,
                max_items=100, item_error="an address such as api.example.com"),
          ),
          row_label="Web tool", item_label="Web tool", add_label="Add rules",
          empty_text="The web tools may reach any address the rules below allow.",
          weaker="change",
          warning="The web tools will be able to reach a different set of addresses."),
    )


def _safety(S, C) -> tuple:
    return (
        S("safety", "consent_mode", "Actions that can't be undone",
          "What happens when an agent wants to take an action that deletes, sends or "
          "changes something for good.", "select", "Safety", "", "maverick.safety.consent",
          subgroup="Destructive actions",
          choices=(("", "Ask for risky ones, allow the rest (default)"),
                   ("dashboard", "Wait on the Approvals page"),
                   ("ask", "Ask a person each time"),
                   ("auto-deny", "Refuse them all"),
                   ("auto-approve", "Allow them all")),
          weaker=True, order=("auto-deny", "dashboard", "ask", "", "auto-approve"),
          env=("MAVERICK_CONSENT_MODE",),
          aliases="approval approvals approve risky irreversible undo undone permanent threshold",
          warning="Actions that can't be undone will go ahead with less oversight.",
          preview="approval_checks"),
        S("safety", "constitution", "Your own phrases to block",
          "Requests and answers containing any of these words or phrases are treated as a "
          "threat of the level you choose. Separate phrases with commas.", "rules", "Safety",
          [], "maverick_shield.guard", subgroup="Destructive actions",
          columns=(
              C("phrases", "Words or phrases", "words", required=True,
                pattern=r"[^,<>{}\n\r]{1,80}", max_items=50, max_length=80,
                item_error="a word or phrase without commas"),
              C("severity", "Treat as", "select", default="high", choices=_SEVERITIES),
          ),
          item_label="Rule", add_label="Add phrases",
          empty_text="Only the built-in checks apply.", weaker="change",
          warning="Phrases you remove or lower will no longer be stopped."),
        S("safety", "cascade", "Second opinion on suspicious text",
          "Every request and answer gets the ordinary safety check. Text that still looks "
          "suspicious also goes to an AI model for a second opinion, charged to the task.",
          "toggle", "Safety", False, "maverick_shield.cascade", subgroup="Safety checks",
          env=("MAVERICK_CASCADE_SHIELD",), weaker=False,
          warning="Suspicious text will get only the ordinary safety check."),
        S("shield", "probe_model", "Trained model for spotting suspicious text",
          "A file with a trained model that helps decide which text gets a second opinion. "
          "It can only add suspicion, never remove it.", "path", "Safety", "",
          "maverick_shield.probe_model", subgroup="Safety checks", path_kind="file",
          max_length=400, env=("MAVERICK_SHIELD_PROBE_MODEL",)),
        S("safety", "shield_rate_limit", "Safety checks allowed per task",
          "The most safety checks one task may run in a period of time. Text over the limit "
          "is refused, never let through unchecked. Clear it for no limit.", "rate", "Safety",
          None, "maverick.safety.shield_rate_limit", subgroup="Safety checks",
          env=("MAVERICK_SHIELD_RATE_LIMIT",), weaker="higher",
          warning="A runaway task will be able to run many more safety checks, which slows "
                  "Lightwork and can cost more."),
        S("shield", "update_url", "Where shared threat updates come from",
          "The web address of the signed threat check updates to download.", "text",
          "Safety", "", "maverick.shield_updates", subgroup="Shared threat updates",
          max_length=300, pattern=r"(" + _HTTPS + r")?"),
        S("shield", "update_pubkey", "Publisher key for threat updates",
          "The publisher's signing key, 64 letters and digits. Updates signed with any other "
          "key are refused.", "text", "Safety", "", "maverick.shield_updates",
          subgroup="Shared threat updates", max_length=64, pattern=r"([0-9a-fA-F]{64})?",
          weaker="change", warning="Threat check updates from a different publisher will "
                                   "be trusted."),
        S("shield", "update_interval_hours", "Check for threat updates every",
          "How often to look for new signed threat check updates.", "number", "Safety", 24,
          "maverick_dashboard.shield_update_scheduler", subgroup="Shared threat updates",
          minimum=1, maximum=168, integer=True, unit="hours"),
        S("safety", "quorum_required", "Approvals needed to change protected settings",
          "How many other administrators must approve a change to a protected setting "
          "before it is saved. The person asking can't approve their own change.", "select",
          "Safety", "", "maverick.quorum", subgroup="Changing protected settings",
          choices=(("", "None: one administrator can save (default)"),
                   ("2", "Two other administrators"), ("3", "Three other administrators"),
                   ("4", "Four other administrators"), ("5", "Five other administrators")),
          weaker=True, order=("5", "4", "3", "2", ""), env=("MAVERICK_QUORUM_REQUIRED",),
          warning="Protected settings will change with fewer approvals, or with none."),
        S("safety", "quorum_protected_keys", "Protected settings",
          "The settings that need other administrators' approval to change. With none "
          "ticked, the four marked as default are protected.", "multiselect", "Safety",
          ["budget.max_dollars", "governance.*", "plugins.*", "safety.*"], "maverick.quorum",
          subgroup="Changing protected settings",
          choices=(("safety.*", "Safety settings (default)"),
                   ("governance.*", "Governance settings (default)"),
                   ("plugins.*", "Plugin settings (default)"),
                   ("budget.max_dollars", "Spending limit per task (default)"),
                   ("budget.*", "All spending limits"), ("security.*", "Security settings"),
                   ("shield.*", "Shared threat updates"), ("auth.*", "Sign-in settings"),
                   ("audit.*", "Activity record settings")),
          weaker="shrink", warning="The settings you remove will change without anyone "
                                   "else's approval."),
        S("safety", "quorum_ttl_days", "Approvals stay usable for",
          "How long an approved change to a protected setting can still be saved. At most "
          "7 days, because a request can only be approved for a week.", "number",
          "Safety", 7, "maverick.quorum", subgroup="Changing protected settings", minimum=1,
          maximum=7, integer=True, unit="days", weaker="higher",
          warning="Approved changes will stay usable for longer after they are approved."),
        S("safety", "require_shield", "Require the safety checks",
          "Refuse outside messages and agent requests when Lightwork's safety checks are not "
          "installed, instead of letting them through.", "toggle", "Safety", False,
          "maverick.shield_policy", subgroup="Destructive actions",
          env=("MAVERICK_REQUIRE_SHIELD",), weaker=False,
          warning="Outside messages will be let through unchecked if the safety checks "
                  "are missing."),
        S("embedded", "allow_flash", "Let agents reprogram connected devices",
          "Agents may write new software onto, or reset, circuit boards connected to this "
          "server.", "toggle", "Safety", False, "maverick.tools.embedded_device",
          subgroup="Destructive actions", weaker=True,
          warning="Agents will be able to overwrite the software on connected devices."),
        S("capabilities", "enforce", "Give each agent only what it was granted",
          "Each agent and its helpers may use only the tools and limits handed to them.",
          "toggle", "Safety", False, "maverick.capability", subgroup="Agent permissions",
          env=("MAVERICK_ENFORCE_CAPABILITIES",), weaker=False,
          warning="Helper agents will be able to use tools their lead agent was not given."),
        S("capabilities", "per_call_tokens", "Check a fresh pass for every tool use",
          "Each tool use needs a short-lived pass tied to that one call. Works with the "
          "option above.", "toggle", "Safety", False, "maverick.tool_token",
          subgroup="Agent permissions", env=("MAVERICK_TOOL_TOKENS",), weaker=False,
          warning="Tool uses will no longer need their own pass."),
        S("repl", "max_output_chars", "Output kept from each code step",
          "The most characters of output kept from one step of agent code.", "number",
          "Safety", 8000, "maverick.config", subgroup="Agent permissions", minimum=256,
          maximum=1000000, integer=True, unit="characters"),
        S("repl", "max_state_bytes", "Memory kept between code steps",
          "How much data agent code may carry from one step to the next.", "number", "Safety",
          262144, "maverick.config", subgroup="Agent permissions", minimum=1, maximum=1024,
          integer=True, scale=1024, unit="KB"),
        S("repl", "max_statements", "Code steps per session",
          "The most steps of code an agent may run in one session.", "number", "Safety", 200,
          "maverick.config", subgroup="Agent permissions", minimum=1, maximum=10000,
          integer=True, unit="steps", weaker="higher",
          warning="Agents will be able to run more code in one session."),
        S("ifc", "allow_sinks", "Tools that may carry sensitive data out",
          "These tools are not checked when labelled sensitive data is about to leave through "
          "them.", "multiselect", "Safety", [], "maverick.config",
          subgroup="Agent permissions",
          choices=(("web_search", "Web search"), ("web_archive", "Web archive"),
                   ("browser", "Web browser"), ("computer", "Computer control"),
                   ("email", "Email"), ("gmail", "Gmail"), ("ses", "Amazon email"),
                   ("sns", "Amazon notifications"), ("twilio", "Text messages"),
                   ("slack_bot", "Slack"), ("discord_bot", "Discord"), ("teams", "Teams"),
                   ("notify", "Notifications"), ("calendar", "Calendar"),
                   ("github_issues", "GitHub issues"), ("git_advanced", "Code pushes")),
          weaker="grow",
          warning="Sensitive data will be able to leave through these tools unchecked."),
        # ------------------------------------------------------------- security
        S("security", "max_risk", "Riskiest tools agents may use",
          "Tools above this risk level are removed for every agent.", "select", "Security", "",
          "maverick.safety.tool_acl", subgroup="Tool access",
          choices=(("", "Up to high risk with secure defaults (default)"),
                   ("low", "Low risk only"), ("medium", "Up to medium risk"),
                   ("high", "Up to high risk")),
          weaker=True, order=("low", "medium", "high", ""),
          warning="Agents will be able to use riskier tools."),
        S("security", "tool_risk", "Risk level of particular tools",
          "Change the risk level Lightwork gives a tool. The level decides which approvals "
          "and limits apply to it.", "table", "Security", {}, "maverick.safety.tool_risk",
          subgroup="Tool access", row_kind="grid", choices_from="tools", scalar=True,
          columns=(C("risk", "Risk level", "select", choices=_RISKS, required=True),),
          row_label="Tool", item_label="Tool", add_label="Set a risk level",
          empty_text="Every tool has its built-in risk level.", weaker="change",
          warning="Tools marked as less risky will need fewer approvals and pass more "
                  "limits."),
        S("security", "isolate_parsers", "Open uploaded files in a separate process",
          "Read uploaded documents in a separate, limited program, so a harmful file cannot "
          "reach the rest of Lightwork.", "toggle", "Security", False,
          "maverick.parser_isolation", subgroup="Tool access",
          env=("MAVERICK_ISOLATE_PARSERS",), weaker=False,
          warning="Uploaded files will be read inside Lightwork itself."),
        S("tools", "database_allow_url_arg", "Let agents choose which database to open",
          "Agents may give the database tool an address of their own, instead of only the "
          "one set on the server.", "toggle", "Security", False,
          "maverick.tools.database_tool", subgroup="Tool access",
          env=("MAVERICK_DATABASE_ALLOW_URL_ARG",), weaker=True,
          warning="Agents will be able to connect to any database they can reach."),
        S("egress", "deny", "Addresses no tool may reach",
          "Tools and connections refuse these addresses. A star matches any part of a name; "
          "a single star blocks everything not allowed below.", "list", "Security", [],
          "maverick.tenant.egress", subgroup="Outbound connections",
          item_label="Address", item_hint="169.254.169.254", pattern=_HOST,
          item_error="an address such as api.example.com", max_items=200,
          weaker="shrink", warning="Tools will be able to reach the addresses you remove."),
        S("egress", "allow", "Only these addresses",
          "When this list has entries, tools may reach only these addresses.", "list",
          "Security", [], "maverick.tenant.egress", subgroup="Outbound connections",
          item_label="Address", item_hint="api.example.com", pattern=_HOST,
          item_error="an address such as api.example.com", max_items=200, weaker="grow",
          warning="Tools will be able to reach more addresses, or any address once the list "
                  "is empty."),
        S("safety", "supply_chain_pinning", "Check installed software on start",
          "When the server starts, record the installed software packages the first time "
          "and warn in the server log if any of them change later.", "toggle", "Security",
          False, "maverick.supply_chain", subgroup="Signing keys", restart=True,
          env=("MAVERICK_SUPPLY_CHAIN_PINNING",), weaker=False,
          warning="Changed or swapped software packages will no longer be noticed."),
        S("safety", "receipt_key", "Key for signed spending receipts",
          "A long secret phrase used to sign each task's spending receipt. It is stored "
          "sealed and never shown again; keep a copy to check receipts later.", "secret",
          "Security", "", "maverick.budget_receipts", subgroup="Signing keys",
          env=("MAVERICK_RECEIPT_KEY",), max_length=500),
        S("safety", "screenshot_key", "Key for sealed screenshots",
          "A long secret phrase used to seal the screenshots agents take as evidence. It is "
          "stored sealed and never shown again.", "secret", "Security", "",
          "maverick.screenshot_seal", subgroup="Signing keys",
          env=("MAVERICK_SCREENSHOT_KEY",), max_length=500),
        # -------------------------------------------------------------- plugins
        S("plugins", "require_signing", "Only load signed plugins",
          "Refuse plugins that are not signed by your plugin signing authority.", "toggle",
          "Integrations", False, "maverick.plugins", subgroup="Plugin safety", weaker=False,
          warning="Unsigned plugins will load and run."),
        S("plugins", "ca_root_pubkey", "Plugin signing authority",
          "Paste the contents of your plugin signing authority's public key file. Setting it "
          "turns signature checks on.", "text", "Integrations", "", "maverick.plugins",
          subgroup="Plugin safety", pattern=r"([0-9a-fA-F]{64})?", max_length=64,
          weaker="change",
          warning="Plugins signed by a different authority will be trusted."),
        S("plugins", "ca_revoked", "Withdrawn plugin signatures",
          "Signatures listed here are refused even though the authority issued them.",
          "list", "Integrations", [], "maverick.plugins", subgroup="Plugin safety",
          item_label="Signature number", item_hint="3f2a9c...",
          pattern=r"[0-9a-fA-F-]{8,64}", item_error="a signature number", max_items=500,
          weaker="shrink", warning="Plugins with the signatures you remove will load again."),
        S("plugins", "isolation", "Where plugins run",
          "Run plugins inside Lightwork, or apart from it so a faulty plugin can't affect "
          "the rest.", "select", "Integrations", "", "maverick.plugin_isolation",
          subgroup="Plugin safety",
          choices=(("", "Apart under enterprise protections, otherwise inside (default)"),
                   ("subprocess", "In a separate program"),
                   ("subinterpreter", "In a separate area of Lightwork"),
                   ("none", "Inside Lightwork")),
          weaker=True, order=("subprocess", "subinterpreter", "", "none"),
          env=("MAVERICK_PLUGIN_ISOLATION",),
          warning="Plugins will run with more access to the rest of Lightwork."),
        S("plugins", "lock_policy", "When a plugin's version changes",
          "What happens when an installed plugin no longer matches the recorded version.",
          "select", "Integrations", "", "maverick.plugin_lock", subgroup="Plugin safety",
          choices=(("", "Refuse under enterprise protections, otherwise nothing (default)"),
                   ("enforce", "Refuse to load it"), ("warn", "Load it and record a warning"),
                   ("off", "Do nothing")),
          weaker=True, order=("enforce", "", "warn", "off"),
          env=("MAVERICK_PLUGIN_LOCK_POLICY",),
          warning="Plugins that changed since they were checked will load."),
        S("plugins", "telemetry", "Count plugin use",
          "Keep a local count of how often each plugin tool is used. Nothing leaves this "
          "server.", "toggle", "Integrations", False, "maverick.plugin_telemetry",
          subgroup="Plugin safety", env=("MAVERICK_PLUGIN_TELEMETRY",)),
    )


def _tools(S, C) -> tuple:
    subgroup = "Connected services"
    return (
        S("connector_limits", "attempt_seconds", "Time limit for each try",
          "How long one try at a connected service may take.", "number", "Performance", 30.0,
          "maverick.connector_attempts", subgroup=subgroup, minimum=1, maximum=120,
          unit="seconds"),
        S("connector_limits", "total_seconds", "Time limit for a call with its retries",
          "How long a call to a connected service may take in total.", "number",
          "Performance", 60.0, "maverick.connector_attempts", subgroup=subgroup, minimum=1,
          maximum=300, unit="seconds"),
        S("connector_limits", "wire_bytes", "Largest reply from a service",
          "Bigger replies from a connected service are refused.", "number", "Performance",
          2097152, "maverick.connector_attempts", subgroup=subgroup, minimum=1, maximum=64,
          integer=True, scale=1048576, unit="MB"),
        S("connector_limits", "decoded_bytes", "Largest unpacked reply",
          "Bigger replies, once unpacked, are refused.", "number", "Performance", 4194304,
          "maverick.connector_attempts", subgroup=subgroup, minimum=1, maximum=64,
          integer=True, scale=1048576, unit="MB"),
        S("connector_limits", "json_depth", "Deepest nesting in a reply",
          "Replies nested deeper than this are refused.", "number", "Performance", 64,
          "maverick.connector_attempts", subgroup=subgroup, minimum=1, maximum=128,
          integer=True, unit="levels"),
        S("connector_limits", "json_items", "Most items in a reply",
          "Replies with more items than this are refused.", "number", "Performance", 100000,
          "maverick.connector_attempts", subgroup=subgroup, minimum=1, maximum=1000000,
          integer=True, unit="items"),
        S("tools", "output_cache_size", "Recent tool results kept",
          "How many recent tool results are kept for reuse.", "number", "Performance", 256,
          "maverick.cache.tool", subgroup="Reusing tool results", minimum=1, maximum=100000,
          integer=True, unit="results"),
        S("tools", "output_cache_ttl_s", "Reuse a tool result for up to",
          "How long a kept result may be reused. Leave empty to keep it until newer results "
          "push it out.", "number", "Performance", None, "maverick.cache.tool",
          subgroup="Reusing tool results", minimum=1, maximum=604800, integer=True,
          unit="seconds", none_text="Until newer results replace it"),
        S("tools", "output_cache_snapshot", "Keep reusable results after a restart",
          "Save kept tool results to disk so they can be reused after Lightwork restarts.",
          "toggle", "Performance", False, "maverick.cache.tool",
          subgroup="Reusing tool results", env=("MAVERICK_TOOL_CACHE_SNAPSHOT",)),
        S("tools", "output_cache_backend", "Share reusable results between servers",
          "Also keep reusable tool results in a shared Redis store, so every server of this "
          "installation can reuse them. Works with reusing recent tool results.", "select",
          "Performance", "", "maverick.cache.redis_tool", subgroup="Reusing tool results",
          choices=(("", "Only on each server (default)"), ("redis", "Also in a shared Redis store")),
          env=("MAVERICK_TOOL_CACHE_BACKEND",), weaker="change",
          warning="Tool results will be stored on the shared Redis server."),
        S("tools", "output_cache_redis_url", "Shared Redis store address",
          "The address of the shared Redis store, including its password if it has one. It "
          "is stored sealed and never shown again.", "secret", "Performance", "",
          "maverick.cache.redis_tool", subgroup="Reusing tool results", max_length=500,
          env=("MAVERICK_TOOL_CACHE_REDIS_URL",)),
        S("tools", "latency_budget_ms", "Flag tool uses slower than",
          "Record a warning for any tool use that takes longer than this. The tool still "
          "finishes.", "number", "Performance", None, "maverick.latency_budget",
          subgroup="Reusing tool results", minimum=100, maximum=600000, integer=True,
          unit="milliseconds", none_text="Off", env=("MAVERICK_TOOL_LATENCY_BUDGET_MS",)),
        S("tools", "exposure", "Tools described on each request",
          "When Use a short tool list is on, choose the starting list described to the AI. The short "
          "list fits the agent's role, and a specialist pack sees its own tools; agents can "
          "look up any other permitted tool when they need it. Models with a smaller tool "
          "limit keep key actions and let agents look up the rest.", "select", "Performance", "core",
          "maverick.config", subgroup="Reusing tool results",
          choices=(("core", "A short list, and agents look up the rest (recommended)"),
                   ("full", "A longer list, up to the model's limit (costs more)")),
          env=("MAVERICK_TOOL_EXPOSURE",), aliases="tool catalog exposure context tokens"),
        S("tools", "core_extra", "Tools always described",
          "When Use a short tool list is on, describe these tools too, by tool name.",
          "list", "Performance", [], "maverick.config", subgroup="Reusing tool results",
          item_label="Tool name", item_hint="scan_finance_anomalies",
          pattern=r"[a-z0-9_]{1,80}", item_error="a tool name such as read_file",
          max_items=50),
        S("capabilities", "deferred_tools", "Use a short tool list",
          "Describe a smaller set of tools to the AI, and let it find other permitted tools "
          "when needed. Turn off to describe the longer list. Tool permissions and the AI's "
          "own tool limit still apply. Saving here replaces an earlier tool-loading choice.",
          "toggle", "Performance", True, "maverick.agent", partial_default=True,
          subgroup="Reusing tool results", env=("MAVERICK_DEFERRED_TOOLS",),
          aliases="deferred loading connectors core tool catalog"),
        S("capabilities", "web_search", "Let agents and specialists search the web",
          "Allow agents and specialists whose work calls for current web information to use Web search. "
          "Lightwork uses a connected search service when available, with a public-search "
          "fallback; whether a search succeeds is checked when it runs.",
          "toggle", "Integrations", False, "maverick.agent",
          subgroup="Web research", restart=True, weaker=True,
          warning="Agents and specialists will be allowed to send search terms to the web search service."),
        S("limits", "file_write_quota_mb", "Most a task may write to files",
          "The most data one task may write to the work area. Leave empty for no limit.",
          "number", "Spending & limits", None, "maverick.file_quota", minimum=1,
          maximum=1000000, integer=True, unit="MB", weaker="higher",
          warning="A single task will be able to write more data, or any amount."),
        S("attachments", "embed_documents", "Show attached documents to agents directly",
          "Give agents attached PDF documents as documents they can see, not only as "
          "extracted text.", "toggle", "Privacy", True, "maverick.attachments",
          subgroup="Attachments", env=("MAVERICK_ATTACH_EMBED_DOCS",)),
        S("budget", "max_input_tokens", "Words read per task",
          "The most text, in tokens, agents may send to AI services in one task. Leave empty "
          "for no limit.", "number", "Spending & limits", None, "maverick.budget",
          minimum=1000, maximum=1000000000, integer=True, unit="tokens", weaker="higher",
          warning="A single task will be able to send more text to AI services, which "
                  "costs more."),
        S("attachments", "extra_mime_prefixes", "Extra kinds of attachment to accept",
          "Accept these file kinds too, written as their standard type name or its start. "
          "Programs and archives are always refused.", "list", "Privacy", [],
          "maverick.attachments", subgroup="Attachments", item_label="File kind",
          item_hint="application/vnd.visio", pattern=r"[a-z0-9]{1,40}/[a-z0-9.+-]{0,120}",
          item_error="a file kind such as application/vnd.visio", max_items=50,
          env=("MAVERICK_ATTACH_EXTRA_MIME",),
          weaker="grow", warning="More kinds of files will be accepted as attachments."),
        S("attachments", "s3_bucket", "Copy attachments to storage bucket",
          "Also keep a copy of every attachment in this Amazon S3 bucket, using the server's "
          "AWS sign-in. Leave empty to keep them on this server only.", "text", "Privacy", "",
          "maverick.attachments", subgroup="Attachments",
          pattern=r"([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])?", max_length=63, weaker="change",
          env=("MAVERICK_ATTACH_S3_BUCKET",),
          warning="Copies of every attachment will be stored in a different place."),
        S("attachments", "s3_prefix", "Folder inside the bucket",
          "The folder in the bucket where copies are kept.", "text", "Privacy", "",
          "maverick.attachments", subgroup="Attachments", pattern=r"[A-Za-z0-9!_.*'()/-]{0,200}",
          max_length=200, env=("MAVERICK_ATTACH_S3_PREFIX",)),
        S("lsp", "servers", "Code language helpers",
          "The program, and its options, agents use to understand code in each language. "
          "Leave a language out to use the standard helper.", "table", "Integrations", {},
          "maverick.tools.lsp_bridge", subgroup="Code language helpers", row_kind="grid",
          choices=(("python", "Python"), ("go", "Go"), ("rust", "Rust"),
                   ("typescript", "TypeScript"), ("javascript", "JavaScript"), ("c", "C"),
                   ("cpp", "C++")),
          scalar=True,
          columns=(C("command", "Program and options", "words", required=True,
                     pattern=r"[A-Za-z0-9._/=:+-]{1,200}", max_items=20, max_length=200,
                     item_error="a program name or option without spaces"),),
          row_label="Language", item_label="Language", add_label="Choose a helper",
          empty_text="Every language uses its standard helper.", weaker="change",
          warning="A different program will run on the server when agents read code."),
    )


def _memory(S) -> tuple:
    group = "Memory & learning"
    return (
        S("memory", "backend", "Recall related past work",
          "Find past tasks similar to a new one by meaning, using the store chosen here.",
          "select", group, "", "maverick.semantic_recall", subgroup="Recall of past work",
          choices=(("", "Off (default)"), ("chroma", "A store on this server"),
                   ("qdrant", "A Qdrant store"), ("weaviate", "A Weaviate store"),
                   ("pgvector", "Your company database")),
          env=("MAVERICK_VECTOR_STORE",), weaker="change",
          warning="Summaries of past tasks will be stored in a different place."),
        S("session_tree", "max_depth", "Longest chain of copied tasks",
          "How many times a task may be copied from a copy.", "number", group, 10,
          "maverick.config", subgroup="Recall of past work", minimum=1, maximum=100,
          integer=True, unit="copies"),
        S("skills", "embed_threshold", "How closely a skill must match by meaning",
          "Skills are recalled only when they match the task at least this closely, from 0 "
          "(anything) to 1 (exact).", "number", group, 0.35, "maverick.config",
          subgroup="Recalling skills", minimum=0, maximum=1, step=0.05, unit="score"),
        S("skills", "lexical_min_relevance", "How many words a skill must share",
          "When matching by meaning is not available, a skill must share at least this "
          "much wording with the task.", "number", group, 4.0, "maverick.config",
          subgroup="Recalling skills", minimum=0, maximum=50, step=0.5, unit="score"),
        S("knowledge", "dsn", "Company database for document search",
          "The connection to your company database, when that is where searchable passages "
          "are kept. It is stored sealed and never shown again.", "secret", group, "",
          "maverick.config", subgroup="Document search", max_length=1000),
        S("knowledge", "api_key", "Indexing service key",
          "The key for the hosted indexing service. It is stored sealed and never shown "
          "again.", "secret", group, "", "maverick.config", subgroup="Document search",
          max_length=500),
        S("knowledge", "store_api_key", "Qdrant index key",
          "The key for your Qdrant index. It is separate from the indexing service "
          "key, stored sealed and never shown again.", "secret", group, "",
          "maverick.config", subgroup="Document search", max_length=500),
        S("knowledge", "path", "File for the search index",
          "Where on the server the search index is kept when it is a file here. Leave empty "
          "to keep it in each workspace's own folder.", "text", group, "", "maverick.config",
          subgroup="Document search", pattern=_SERVER_PATH, max_length=500, weaker="change",
          warning="Searchable passages will be read from and written to a different file."),
        S("knowledge", "revision", "Indexing model version",
          "A fixed version of the indexing model, so indexing stays the same. Leave empty "
          "for the current version.", "text", group, "", "maverick.config",
          subgroup="Document search", pattern=r"[A-Za-z0-9._-]{0,64}", max_length=64),
    )


def _diagnostics(S, C) -> tuple:  # noqa: ARG001 -- same signature as the others
    return (
        S("observability", "sentry_dsn", "Error reporting address",
          "Send error reports to your Sentry project. Paste the project's address from "
          "Sentry. It is stored sealed.", "secret", "Performance", "",
          "maverick.observability", subgroup="Error reporting",
          env=("MAVERICK_SENTRY_DSN",), restart=True, max_length=500, weaker="change",
          warning="Error reports, which can include parts of tasks, will be sent to this "
                  "error-reporting service."),
        S("tui", "mouse", "Clickable plan in the terminal view",
          "Let people click the plan shown in the terminal view of a running task.",
          "toggle", "Performance", False, "maverick.tui_mouse", subgroup="Terminal view",
          env=("MAVERICK_TUI_MOUSE",)),
        S("screening", "sdn_path", "Sanctions list file",
          "Where on the server the sanctions list used to screen names is kept.", "text",
          "Finance", "", "maverick.tools.sanctions_screen", subgroup="Sanctions screening",
          pattern=_SERVER_PATH, max_length=500, weaker="change",
          warning="Names will be screened against a different list."),
        S("env_hunt", "poll_limit", "Events gathered from each source per run",
          "The most security events the environment hunter reads from one source each "
          "time it runs.", "number", "Security suite", 1000,
          "maverick_dashboard.security_api", subgroup="Hunting schedule", minimum=1,
          maximum=1000, integer=True, unit="events", weaker="lower",
          warning="Fewer events will be checked, so threats may be missed."),
        S("ekko", "poll_interval_seconds", "How often Ekko checks the active app",
          "How often Ekko notes which app is in use on an enrolled device.", "number",
          "Privacy", 5, "maverick.config", subgroup="Work pattern discovery (Ekko)",
          minimum=1, maximum=300, integer=True, unit="seconds", weaker="lower",
          warning="Ekko will note the active app more often."),
    )


def _switches(S) -> tuple:
    """Settings that are also server environment variables. The
    variable named in ``env`` still wins when it is set."""
    return (
        # --------------------------------------------------- how agents work
        S("agent", "max_steps", "Most steps an agent may take",
          "Stop an agent after this many steps on one task. Leave empty for no step limit; "
          "the spending and time limits still apply.", "number", "AI models", None,
          # Read by maverick.config.get_agent_max_steps, which every agent calls.
          "maverick.config", subgroup="How agents work", minimum=1, maximum=10000,
          integer=True, unit="steps", none_text="No step limit", env=("MAVERICK_MAX_STEPS",),
          weaker="higher", warning="Agents will be able to take more steps on one task."),
        S("agent", "parallel_tools", "Run independent actions at the same time",
          "When an agent asks for several independent actions at once, run them together.",
          "toggle", "AI models", True, "maverick.agent", subgroup="How agents work",
          env=("MAVERICK_PARALLEL_TOOLS",)),
        S("agent", "temperature", "How varied Claude's wording is",
          "From 0 (most predictable) to 1 (most varied). Leave empty to use the model's own "
          "setting. Not used while a model is thinking.", "number", "AI models", None,
          "maverick.providers.anthropic_provider", subgroup="How agents work", minimum=0,
          maximum=1, step=0.05, unit="", none_text="The model's own",
          env=("MAVERICK_TEMPERATURE",)),
        S("thinking", "adaptive_floor", "Reply room when thinking is automatic",
          "The reply length, in tokens, allowed when a model decides for itself how much to "
          "think. Thinking is billed like written text.", "number", "AI models", 8192,
          "maverick.providers.anthropic_limits", subgroup="How agents work", minimum=2048,
          maximum=128000, integer=True, unit="tokens",
          env=("MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR",)),
        S("voice", "only_mode", "Talk to agents by voice only",
          "Read every finished answer aloud as soon as it is shown, with code, tables and "
          "links described instead of spelled out.", "toggle", "AI models", False,
          "maverick.voice_only", subgroup="How agents work"),
        S("voice", "biometric_unlock", "Check spoken requests against people's voices",
          "People who recorded their voice on the Voice unlock page can give spoken requests "
          "only in their own voice, as a second check on top of signing in. Needs the "
          "voice-unlock add-on and a speaker-recognition model on this server.", "toggle",
          "AI models", False, "maverick.voice_unlock", subgroup="Voice unlock",
          env=("MAVERICK_VOICE_UNLOCK",), weaker=False,
          warning="Spoken requests will no longer be checked against people's recorded "
                  "voices."),
        S("voice", "speaker_model_path", "Speaker-recognition model",
          "The folder on this server that holds the speaker-recognition model "
          "(speechbrain/spkrec-ecapa-voxceleb). It is never downloaded while Lightwork runs.",
          "path", "AI models", "", "maverick.voice_unlock", subgroup="Voice unlock",
          path_kind="folder", max_length=400),
        S("voice", "unlock_threshold", "How closely a voice must match",
          "How similar a spoken request must sound to the recorded voice. Higher refuses "
          "more near matches; lower accepts more.", "number", "AI models", 0.6,
          "maverick.voice_unlock", subgroup="Voice unlock", minimum=30, maximum=99,
          scale=0.01, unit="percent", weaker="lower",
          warning="Voices less like the recorded one will be accepted."),
        S("context", "auto_recall", "Remind agents of related past tasks",
          "Before a task starts, give agents the results of the most similar finished "
          "tasks.", "toggle", "AI models", False, "maverick.orchestrator",
          subgroup="How agents work", env=("MAVERICK_AUTO_RECALL",)),
        S("context", "auto_recall_k", "Past tasks to recall",
          "How many similar past tasks are recalled when the option above is on.", "number",
          "AI models", 3, "maverick.orchestrator", subgroup="How agents work", minimum=1,
          maximum=20, integer=True, unit="tasks", env=("MAVERICK_AUTO_RECALL_K",)),
        S("context", "brief_facts_max", "Known facts given to the lead agent",
          "The newest facts, at most this many, go into the lead agent's opening brief.",
          "number", "AI models", 50, "maverick.orchestrator", subgroup="How agents work",
          minimum=1, maximum=1000, integer=True, unit="facts",
          env=("MAVERICK_BRIEF_FACTS_MAX",)),
        S("context", "brief_fact_value_chars", "Longest fact in the brief",
          "Each fact in the brief is cut to this many characters.", "number", "AI models",
          300, "maverick.orchestrator", subgroup="How agents work", minimum=40,
          maximum=10000, integer=True, unit="characters",
          env=("MAVERICK_BRIEF_FACT_VALUE_CHARS",)),
        S("context", "blackboard_entry_chars", "Longest shared note shown to helpers",
          "Notes agents share on a task are cut to this many characters when shown to "
          "other agents.", "number", "AI models", 800, "maverick.blackboard",
          subgroup="How agents work", minimum=80, maximum=20000, integer=True,
          unit="characters", env=("MAVERICK_BB_RENDER_ENTRY_CHARS",)),
        S("context", "compact_tiktoken", "Count text exactly when shortening",
          "Use an exact word-piece count when shortening conversations, when one is "
          "installed, instead of an estimate.", "toggle", "AI models", True,
          "maverick.context_compactor", subgroup="How agents work",
          env=("MAVERICK_COMPACT_TIKTOKEN",)),
        S("swarm", "child_result_chars", "Longest answer from each helper",
          "Each helper agent's answer is cut to this many characters when handed back.",
          "number", "AI models", 4000, "maverick.tools.spawn", subgroup="How agents work",
          minimum=200, maximum=100000, integer=True, unit="characters",
          env=("MAVERICK_SWARM_CHILD_RESULT_CHARS",)),
        S("swarm", "results_total_chars", "Longest combined answer from helpers",
          "All helpers' answers together are cut to this many characters.", "number",
          "AI models", 24000, "maverick.tools.spawn", subgroup="How agents work",
          minimum=200, maximum=1000000, integer=True, unit="characters",
          env=("MAVERICK_SWARM_RESULTS_TOTAL_CHARS",)),
        S("search", "early_exit", "Stop at the first answer that passes every test",
          "When several code answers are tried, stop once one passes all its tests.",
          "toggle", "AI models", True, "maverick.orchestrator", subgroup="How agents work",
          env=("MAVERICK_BON_EARLY_EXIT",)),
        S("search", "ladder", "Models tried for code answers",
          "The models, in order, tried when several code answers are compared. Write each "
          "as the service name, the model name and how varied its wording is, separated by "
          "colons.", "list", "AI models", [], "maverick.orchestrator",
          subgroup="How agents work", item_label="Model",
          item_hint="anthropic:claude-opus-4-8:0.3",
          pattern=r"[a-z0-9_]{1,32}:[A-Za-z0-9._/@-]{1,160}:(0|1|0?\.[0-9]{1,3}|1\.0)",
          item_error="a service, a model and a number from 0 to 1, separated by colons",
          max_items=10, empty_unset=True, env=("MAVERICK_BON_LADDER",)),
        S("verification", "cross_family_model", "Checker from a different model family",
          "Check answers with this model, from a different family than the one that wrote "
          "them, so both do not share the same blind spots.", "select", "AI models", "",
          "maverick.verifier", subgroup="How agents work", choices_from="models",
          env=("MAVERICK_CROSS_FAMILY_VERIFIER",)),
        S("models", "vision", "Model for looking at images and video",
          "The model agents use to look at pictures and video.", "select", "AI models", "",
          "maverick.tools.view_image", subgroup="Model choices", choices_from="models",
          env=("MAVERICK_VISION_MODEL",)),
        S("skills", "decay", "Let old skill results count for less",
          "How useful a skill was counts for less as time passes, so recent results "
          "matter most.", "toggle", "Memory & learning", True, "maverick.skill.stats",
          subgroup="Recalling skills", env=("MAVERICK_SKILL_DECAY",)),
        S("skills", "render_max_chars", "Longest recalled skill",
          "Each recalled skill is cut to this many characters. Zero keeps it whole.",
          "number", "Memory & learning", 4000, "maverick.skills",
          subgroup="Recalling skills", minimum=0, maximum=100000, integer=True,
          unit="characters", env=("MAVERICK_SKILL_RENDER_MAX_CHARS",)),
        S("skills", "render_total_chars", "Most skill text per request",
          "All recalled skills together are cut to this many characters. Zero keeps them "
          "whole.", "number", "Memory & learning", 10000, "maverick.skills",
          subgroup="Recalling skills", minimum=0, maximum=500000, integer=True,
          unit="characters", env=("MAVERICK_SKILL_RENDER_TOTAL_CHARS",)),
        S("skills", "allow_url_install", "Install skills from a typed web address",
          "Let administrators install a skill from any web address, not only from the "
          "catalogs.", "toggle", "Safety", False, "maverick.skills",
          subgroup="Skill publishers", env=("MAVERICK_ALLOW_SKILL_INSTALL",), weaker=True,
          warning="Skills from any web address, which may not have been reviewed, can be "
                  "installed."),
        # ------------------------------------------------------------ caching
        S("cache", "messages", "Cache conversation history with Claude",
          "Ask Claude's service to keep the stable part of long conversations, which makes "
          "follow-up turns cheaper.", "toggle", "Performance", True,
          "maverick.providers.anthropic_provider", subgroup="Caching",
          env=("MAVERICK_CACHE_MESSAGES",)),
        S("cache", "anthropic_ttl", "How long Claude keeps instructions cached",
          "Longer costs a little more to store but helps long tasks.", "select",
          "Performance", "", "maverick.providers.anthropic_provider", subgroup="Caching",
          choices=(("", "Automatic (default)"), ("5m", "5 minutes"), ("1h", "1 hour")),
          env=("MAVERICK_ANTHROPIC_CACHE_TTL",)),
        S("cache", "anthropic_message_ttl", "How long Claude keeps history cached",
          "How long the cached part of a conversation is kept.", "select", "Performance", "",
          "maverick.providers.anthropic_provider", subgroup="Caching",
          choices=(("", "5 minutes, unless set above (default)"), ("5m", "5 minutes"),
                   ("1h", "1 hour")),
          env=("MAVERICK_ANTHROPIC_MSG_CACHE_TTL",)),
        S("latency", "read_timeout", "Wait for an AI reply for up to",
          "How long to wait for an AI service to finish replying. Leave empty for 2 "
          "minutes.", "number", "Performance", None, "maverick.llm", subgroup="Caching",
          minimum=5, maximum=3600, unit="seconds", none_text="2 minutes",
          env=("MAVERICK_LLM_READ_TIMEOUT",)),
        S("latency", "connect_timeout", "Wait to reach an AI service for up to",
          "How long to wait to connect to an AI service. Leave empty for 15 seconds.",
          "number", "Performance", None, "maverick.llm", subgroup="Caching", minimum=1,
          maximum=300, unit="seconds", none_text="15 seconds",
          env=("MAVERICK_LLM_CONNECT_TIMEOUT",)),
        # -------------------------------------------------------------- tools
        S("tools", "browser_headed", "Show the browser window",
          "Show the web browser agents use on this computer's screen instead of running it "
          "hidden.", "toggle", "Integrations", False, "maverick.tools.browser",
          subgroup="Computer control", env=("MAVERICK_BROWSER_HEADED",)),
        S("computer_use", "allow_host", "Let agents control this computer's own screen",
          "Allow computer control on the screen people use, not only on a separate screen "
          "set aside for agents.", "toggle", "Integrations", False,
          "maverick.tools.computer", subgroup="Computer control",
          env=("MAVERICK_COMPUTER_ALLOW_HOST",), weaker=True,
          warning="Agents will be able to click and type on the screen people are using."),
        S("computer_use", "require_sandbox", "Only control a screen inside the work area",
          "Refuse computer control unless it happens inside the protected work area.",
          "toggle", "Integrations", False, "maverick.tools.computer",
          subgroup="Computer control", env=("MAVERICK_COMPUTER_REQUIRE_SANDBOX",),
          weaker=False, warning="Computer control will be allowed outside the work area."),
        S("computer_use", "ocr", "Read text on screenshots",
          "Turn text on the screen into words agents can read, alongside each screenshot.",
          "toggle", "Integrations", False, "maverick.tools.computer",
          subgroup="Computer control", env=("MAVERICK_COMPUTER_OCR",)),
        S("tools", "fetch_allow_private", "Let agents read addresses inside your network",
          "Agents may read web pages at private, local or cloud-internal addresses.",
          "toggle", "Security", False, "maverick.tools._ssrf", subgroup="Tool access",
          env=("MAVERICK_FETCH_ALLOW_PRIVATE",), weaker=True,
          warning="Agents will be able to reach services inside your network, including "
                  "ones that hold credentials. Cloud metadata and link-local addresses "
                  "stay blocked. When approvals are set up, this change waits for them."),
        S("tools", "fetch_skip_scan", "Skip the safety check on web pages",
          "Give agents web pages without checking them for hidden instructions first.",
          "toggle", "Security", False, "maverick.tools.http_fetch", subgroup="Tool access",
          env=("MAVERICK_FETCH_NO_SCAN",), weaker=True,
          warning="Web pages will reach agents without being checked for hidden "
                  "instructions."),
        S("tools", "fetch_respect_robots", "Follow websites' crawling rules",
          "Do not read pages a website asks automated readers to avoid.", "toggle",
          "Security", False, "maverick.tools.http_fetch", subgroup="Tool access",
          env=("MAVERICK_FETCH_RESPECT_ROBOTS",)),
        S("tools", "search_backend", "Web search service",
          "Which service web searches use. Automatic uses the first one with a key.",
          "select", "Integrations", "", "maverick.tools.web_search",
          subgroup="Computer control",
          choices=(("", "Automatic (default)"), ("tavily", "Tavily"), ("brave", "Brave"),
                   ("serpapi", "SerpApi"), ("ddg", "DuckDuckGo")),
          env=("MAVERICK_SEARCH_BACKEND",)),
        S("tools", "raw_media_args", "Pass media options to tools unchecked",
          "Give audio and video tools the exact options agents write, without removing "
          "unsafe ones.", "toggle", "Security", False, "maverick.tools",
          subgroup="Tool access", env=("MAVERICK_ALLOW_RAW_MEDIA_ARGS",), weaker=True,
          warning="Agents will be able to make media tools read files or run programs."),
        S("tools", "credential_connectors", "Connectors that use this server's sign-ins",
          "Offer connectors (such as cloud storage and databases) that sign in with the "
          "credentials already on this server.", "toggle", "Security", False,
          "maverick.tools", subgroup="Tool access", env=("MAVERICK_ENABLE_CRED_TOOLS",),
          weaker=True,
          warning="Agents will be able to act with the sign-ins stored on this server."),
        S("tools", "database_max_rows", "Most database rows per look-up",
          "The most rows one database look-up may return.", "number", "Performance", 1000,
          "maverick.tools.database_tool", subgroup="Connected services", minimum=1,
          maximum=1000000, integer=True, unit="rows", env=("MAVERICK_DATABASE_MAX_ROWS",)),
        S("tools", "net_host_concurrency", "Requests at once to one website",
          "The most requests agents may have open to the same website at the same time.",
          "number", "Performance", 4, "maverick.net_concurrency",
          subgroup="Connected services", minimum=1, maximum=64, integer=True,
          unit="requests", env=("MAVERICK_NET_HOST_CONCURRENCY",)),
        S("sandbox", "long_command_timeout", "Time limit for long commands",
          "How long builds, installs and test runs may take, instead of the normal command "
          "time limit.", "number", "Protected work area", 600, "maverick.tools.shell",
          subgroup="Work area", minimum=30, maximum=86400, integer=True, unit="seconds",
          env=("MAVERICK_LONG_CMD_TIMEOUT",)),
        S("sandbox", "firecracker_strict", "Refuse to fall back from micro-machines",
          "When a micro-machine can't start, stop instead of using a weaker work area.",
          "toggle", "Protected work area", True, "maverick.sandbox.firecracker",
          subgroup="Cloud work areas", env=("MAVERICK_FIRECRACKER_STRICT",), weaker=False,
          warning="Commands may run in a weaker work area when a micro-machine can't start."),
        S("capabilities", "per_call_token_ttl", "A tool pass lasts",
          "How long a pass for one tool use stays valid.", "number", "Safety", 30,
          "maverick.tool_token", subgroup="Agent permissions", minimum=1, maximum=3600,
          integer=True, unit="seconds", env=("MAVERICK_TOOL_TOKEN_TTL",), weaker="higher",
          warning="A tool pass will stay usable for longer if it is leaked."),
        S("budget", "receipts", "Sign a spending receipt for every task",
          "Record each finished task's tokens and cost in a signed, tamper-evident ledger. "
          "Needs the receipt key.", "toggle", "Security", False, "maverick.budget_receipts",
          subgroup="Signing keys", env=("MAVERICK_BUDGET_RECEIPTS",)),
        S("chat", "max_inbound_chars", "Longest message accepted from a chat app",
          "Longer messages from chat apps are cut to this many characters before agents see "
          "them.", "number", "Chat channels", 30000, "maverick_channels.base",
          subgroup="Message size", minimum=1000, maximum=1000000, integer=True,
          unit="characters", env=("MAVERICK_MAX_INBOUND_CHARS",), weaker="higher",
          warning="Very long messages will be passed to agents, which costs more."),
        S("safety", "max_scan_chars", "Longest text the safety check reads",
          "Text longer than this is treated as unsafe instead of being checked in part.",
          "number", "Safety", 262144, "maverick_shield.builtin_rules",
          subgroup="Destructive actions", minimum=1000, maximum=10000000, integer=True,
          unit="characters", env=("MAVERICK_SHIELD_MAX_SCAN_CHARS",)),
        S("safety", "decode_hidden", "Look inside encoded text",
          "Decode text hidden with common encodings before checking it for threats.",
          "toggle", "Safety", True, "maverick_shield.guard", subgroup="Destructive actions",
          env=("MAVERICK_SHIELD_NO_DECODE",), weaker=False,
          warning="Threats hidden inside encoded text will no longer be found."),
        # ------------------------------------------------ outside back ends
        S("memory", "qdrant_url", "Qdrant store address",
          "The address of your Qdrant server, when recall uses a Qdrant store.", "text",
          "Memory & learning", "", "maverick.vector_store.qdrant_store",
          subgroup="Recall of past work", pattern=_ADDRESS, max_length=320,
          env=("MAVERICK_QDRANT_URL",), weaker="change",
          warning="Summaries of past tasks will be sent to a different server."),
        S("memory", "qdrant_api_key", "Qdrant store key",
          "The key for your Qdrant server. It is stored sealed and never shown again.",
          "secret", "Memory & learning", "", "maverick.vector_store.qdrant_store",
          subgroup="Recall of past work", max_length=500, env=("MAVERICK_QDRANT_API_KEY",)),
        S("memory", "weaviate_url", "Weaviate store address",
          "The address of your Weaviate server, when recall uses a Weaviate store.", "text",
          "Memory & learning", "", "maverick.vector_store.weaviate_store",
          subgroup="Recall of past work", pattern=_ADDRESS, max_length=320,
          env=("MAVERICK_WEAVIATE_URL",), weaker="change",
          warning="Summaries of past tasks will be sent to a different server."),
        S("memory", "weaviate_api_key", "Weaviate store key",
          "The key for your Weaviate server. It is stored sealed and never shown again.",
          "secret", "Memory & learning", "", "maverick.vector_store.weaviate_store",
          subgroup="Recall of past work", max_length=500,
          env=("MAVERICK_WEAVIATE_API_KEY",)),
        S("knowledge", "max_doc_bytes", "Largest document to index",
          "Bigger documents are not indexed.", "number", "Memory & learning", 26214400,
          "maverick_knowledge.parse", subgroup="Document search", minimum=1, maximum=1024,
          integer=True, scale=1048576, unit="MB",
          env=("MAVERICK_KNOWLEDGE_MAX_DOC_BYTES",)),
        S("knowledge", "max_docx_uncompressed_bytes", "Largest unpacked Word document",
          "Word documents that unpack to more than this are refused.", "number",
          "Memory & learning", 209715200, "maverick_knowledge.parse",
          subgroup="Document search", minimum=1, maximum=4096, integer=True,
          scale=1048576, unit="MB", env=("MAVERICK_KNOWLEDGE_MAX_DOCX_UNCOMPRESSED_BYTES",)),
        S("knowledge", "max_pdf_pages", "Most pages in a PDF to index",
          "PDFs with more pages are refused.", "number", "Memory & learning", 5000,
          "maverick_knowledge.parse", subgroup="Document search", minimum=1,
          maximum=100000, integer=True, unit="pages",
          env=("MAVERICK_KNOWLEDGE_MAX_PDF_PAGES",)),
        S("knowledge_sources", "max_items", "Most items in one saved company folder or space",
          "A refresh stops when the selected folder or space lists more items than this. Each refresh must also finish within the time limit in Longest time one saved company refresh may run.",
          "number", "Memory & learning", 64, "maverick.config", subgroup="Saved company sources",
          minimum=1, maximum=1000, integer=True, unit="items"),
        S("knowledge_sources", "max_pages", "Most listing pages for one saved company folder or space",
          "A refresh stops when the provider needs more pages than this to list every item. Each page holds up to 64 items.",
          "number", "Memory & learning", 16, "maverick.config", subgroup="Saved company sources",
          minimum=1, maximum=200, integer=True, unit="pages"),
        S("knowledge_sources", "max_download_mib", "Largest saved company document to import",
          "Bigger SharePoint, OneDrive and Google Drive files are not imported. Confluence pages keep a fixed 2 MiB read limit.",
          "number", "Memory & learning", 4, "maverick.config",
          subgroup="Saved company sources", minimum=1, maximum=32, integer=True, unit="MiB"),
        S("knowledge_sources", "max_text_kib", "Most source text kept for one saved company refresh",
          "A refresh stops when the text read from its documents would exceed this.", "number",
          "Memory & learning", 256, "maverick.config", subgroup="Saved company sources",
          minimum=1, maximum=8192, integer=True, unit="KiB"),
        S("knowledge_sources", "max_refresh_minutes", "Longest time one saved company refresh may run",
          "A refresh that runs past this time fails and publishes no new snapshot.",
          "number", "Memory & learning", 5, "maverick.config", subgroup="Saved company sources",
          minimum=1, maximum=60, integer=True, unit="minutes"),
        S("knowledge_sources", "permission_filter", "Who sees each saved company file",
          "Off keeps the current rule: anyone the connection is shared with can use the cached content. "
          "Email matching reads each file's sharing permissions at refresh and shows a file only to people "
          "it is shared with by email or email domain, or to anyone with its link. Group-shared files are "
          "withheld, because group members are not read. Sources refreshed before this setting was turned on "
          "must be refreshed again.",
          "select", "Memory & learning", "off", "maverick.config", subgroup="Saved company sources",
          choices=(("off", "Off: connection sharing decides (default)"),
                   ("by_email", "Match each file's sharing permissions by email"))),
        # ------------------------------------------------------- diagnostics
        S("logging", "level", "How much the server records in its log",
          "More detail helps find problems; less keeps the log small.", "select",
          "Performance", "INFO", "maverick.logging_config", subgroup="Error reporting",
          choices=(("DEBUG", "Everything"), ("INFO", "Normal (default)"),
                   ("WARNING", "Warnings and errors"), ("ERROR", "Errors only")),
          restart=True, env=("MAVERICK_LOG_LEVEL",)),
        S("logging", "format", "Log layout",
          "Plain lines for people, or one structured record per line for log collectors.",
          "select", "Performance", "text", "maverick.logging_config",
          subgroup="Error reporting",
          choices=(("text", "Plain lines (default)"), ("json", "Structured records")),
          restart=True, env=("MAVERICK_LOG_FORMAT",)),
        S("observability", "sentry_traces_sample_rate", "Share of tasks timed for error reporting",
          "From 0 to 1: the share of work whose timing is sent with error reports.",
          "number", "Performance", 0.1, "maverick.observability",
          subgroup="Error reporting", minimum=0, maximum=1, step=0.05, unit="share",
          restart=True, env=("MAVERICK_SENTRY_TRACES_SAMPLE_RATE",)),
        S("observability", "otel_exporter", "Send timing traces to a collector",
          "Send a trace of each task's steps to an OpenTelemetry collector.", "select",
          "Performance", "", "maverick.observability", subgroup="Error reporting",
          choices=(("", "Off (default)"), ("otlp", "On")), restart=True,
          env=("MAVERICK_OTEL_EXPORTER",), weaker="change",
          warning="Timing traces, which name tasks and tools, will be sent to the collector."),
        S("observability", "otel_endpoint", "Trace collector address",
          "Where traces are sent. Leave empty for a collector on this computer.", "text",
          "Performance", TEXT_SETTINGS["observability.otel_endpoint"].default, "maverick.observability",
          subgroup="Error reporting", pattern=TEXT_SETTINGS["observability.otel_endpoint"].pattern,
          max_length=TEXT_SETTINGS["observability.otel_endpoint"].dashboard_max_length,
          restart=True, env=TEXT_SETTINGS["observability.otel_endpoint"].dashboard_env,
          weaker="change", warning="Traces will be sent to a different address."),
        S("observability", "otel_headers", "Trace collector sign-in",
          "The sign-in details the collector asks for, written as name=value pairs "
          "separated by commas. They are stored sealed and never shown again.", "secret",
          "Performance", "", "maverick.observability", subgroup="Error reporting",
          max_length=2000, restart=True, env=("MAVERICK_OTEL_HEADERS",)),
        S("observability", "otlp_metrics", "Send measurements to the collector",
          "Also send the server's measurements (counts, timings and spending) to the same "
          "collector as the timing traces.", "toggle", "Performance", False,
          "maverick.observability", subgroup="Error reporting", restart=True,
          env=("MAVERICK_OTEL_METRICS",), weaker=True,
          warning="Measurements, which name tools and models, will be sent to the collector."),
        S("observability", "prometheus_port", "Share server measurements on port",
          "Publish the server's measurements on this port for a monitoring system. Leave "
          "empty to not publish them.", "number", "Performance", None,
          "maverick.observability", subgroup="Error reporting", minimum=1024, maximum=65535,
          integer=True, unit="port", none_text="Not published", restart=True,
          env=("MAVERICK_PROMETHEUS_PORT",)),
        S("observability", "prometheus_addr", "Who may read the measurements",
          "Only this computer, or every network the server is on.", "select", "Performance",
          "127.0.0.1", "maverick.observability", subgroup="Error reporting",
          choices=(("127.0.0.1", "Only this computer (default)"),
                   ("0.0.0.0", "Every network the server is on")),
          weaker=True, order=("127.0.0.1", "0.0.0.0"), restart=True,
          env=("MAVERICK_PROMETHEUS_ADDR",),
          warning="Anyone who can reach the server will be able to read its measurements."),
    )


_KEY = r"[!-~]|[Ff]([1-9]|1[0-2])|up|down|left|right|tab|enter|esc"
_MODEL_NAME = r"([A-Za-z0-9][A-Za-z0-9_.-]{0,95}/)?[A-Za-z0-9][A-Za-z0-9_.-]{0,95}"
_ORIGIN = r"https?://[A-Za-z0-9.\[\]:-]{1,253}(:[0-9]{1,5})?"
_CONSENT = (("ask", "Ask a person each time"), ("dashboard", "Wait on the Approvals page"),
            ("auto-deny", "Refuse them all"), ("auto-approve", "Allow them all"))


def _wired(S, C) -> tuple:
    """Settings that switch on code paths which are otherwise unused."""
    return (
        S("memory", "learning_cache", "Reuse checked answers to repeated tasks",
          "When the same person gives exactly the same task again, start from the answer an "
          "earlier run produced and the answer checker accepted, instead of searching again. "
          "Answers holding a password or key are never kept.", "toggle", "Memory & learning",
          False, "maverick.cache.learning", subgroup="Recall of past work",
          env=("MAVERICK_LEARNING_CACHE",)),
        S("tools", "speculative", "Look up repeated reads ahead of time",
          "While an agent thinks, repeat the look-ups it keeps making, such as reading a file it "
          "just changed, so the answer is ready when it asks. Only reads, never changes, and "
          "only with reusing tool results turned on.", "toggle", "Performance", False,
          "maverick.speculative_tools", subgroup="Reusing tool results",
          env=("MAVERICK_SPECULATIVE_TOOLS",)),
        S("energy", "wh_per_1k_tokens", "Electricity per 1,000 words of AI text",
          "Used by energy estimates, in watt-hours for every 1,000 tokens. Leave the standard "
          "figure unless you know your AI service's own.", "number", "Performance", 0.3,
          "maverick.energy_accounting", subgroup="Energy estimates", minimum=0.001,
          maximum=100, step=0.01, unit="watt-hours", env=("MAVERICK_ENERGY_WH_PER_1K_TOKENS",)),
        S("energy", "grid_co2_g_per_kwh", "Carbon per unit of electricity",
          "Used by energy estimates: grams of carbon dioxide for each kilowatt-hour where your "
          "AI service runs. The standard figure is a world average.", "number", "Performance",
          400.0, "maverick.energy_accounting", subgroup="Energy estimates", minimum=1,
          maximum=2000, step=1, unit="grams", env=("MAVERICK_ENERGY_GRID_CO2_G_PER_KWH",)),
        S("logging", "crash_log", "Keep a crash-safe copy of warnings and errors",
          "Also write every warning and error, one line at a time, to a file that survives the "
          "server stopping suddenly, so the reason for a crash is not lost.", "toggle",
          "Performance", False, "maverick.logging_config", subgroup="Error reporting",
          restart=True, env=("MAVERICK_CRASH_LOG",)),
        S("logging", "crash_only_fsync", "Save the crash-safe copy",
          "How each line of the crash-safe copy reaches the disk.", "select", "Performance",
          "always", "maverick.crash_only_log", subgroup="Error reporting",
          choices=(("always", "At once, line by line (default)"),
                   ("never", "When the computer gets round to it (faster)")),
          restart=True, env=("MAVERICK_CRASH_ONLY_FSYNC",), weaker=True,
          order=("always", "never"),
          warning="The last lines written before a crash may be lost."),
        S("tui", "keys", "Keys in the terminal view",
          "Change the keys the terminal view of a running task answers to. Use one letter, "
          "number or sign, or up, down, left, right, tab, enter, esc or f1 to f12. Ctrl-C always "
          "quits.", "table", "Performance", {}, "maverick.keymap", subgroup="Terminal view",
          row_kind="grid",
          choices=(("quit", "Quit"), ("refresh", "Refresh now"),
                   ("expand", "Open the chosen step"), ("collapse", "Close the chosen step"),
                   ("focus_next", "Next step"), ("focus_prev", "Previous step"),
                   ("toggle_follow", "Pause or follow the task")),
          scalar=True, columns=(C("key", "Key", "text", required=True, pattern=_KEY,
                                  max_length=5, item_error="one key such as q, up or f5"),),
          row_label="Action", item_label="Action", add_label="Change a key",
          empty_text="Every action uses its standard key.", restart=True,
          env=("MAVERICK_TUI_KEYS",)),
        S("security", "network_policy", "Internet for agents' web tools and commands",
          "Open lets the other rules decide. Only approved websites limits the web tools to the "
          "addresses listed as allowed and gives commands no internet. Blocked removes the web "
          "tools and gives commands no internet.", "select", "Security", "",
          "maverick.sandbox.network_policy", subgroup="Outbound connections",
          choices=(("", "Open (default)"), ("allowlist", "Only approved websites"),
                   ("deny-all", "Blocked")),
          weaker=True, order=("deny-all", "allowlist", ""),
          warning="Agents' web tools and commands will be able to reach more of the internet.",
          aliases="network policy egress internet offline"),
        S("sandbox", "network_policy", "Never give commands internet",
          "Keep the work area offline whatever else is chosen. A cluster work area checks its "
          "no-internet rule before every command and refuses to run without it.", "select",
          "Protected work area", "", "maverick.sandbox.network_policy", subgroup="Work area",
          choices=(("", "Use the work area's own setting (default)"),
                   ("deny-all", "Never, checked before each command")),
          weaker=True, order=("deny-all", ""),
          warning="Commands may be able to reach the internet again."),
        S("ekko", "provider_egress", "Send Ekko's findings to an AI service",
          "Not available yet: Ekko has no reviewed way to send what it notices off this "
          "computer, so this stays off and turning it on is refused.", "toggle", "Privacy",
          False, "maverick.config", subgroup="Work pattern discovery (Ekko)", weaker=True,
          warning="What Ekko notices would be sent to an AI service."),
        S("env_hunt", "enrichment_sources", "Lookup services for security findings",
          "Turn on the lookup services, such as a threat information feed, that your server has "
          "added, by the name it added them under. The Security page shows which ones are "
          "ready.", "table", "Security suite", {}, "maverick_dashboard.security_api",
          subgroup="Lookup services", row_kind="named",
          columns=(C("enable", "Use it", "switch", default=True),),
          pattern=r"[a-z0-9][a-z0-9_.-]{0,119}",
          item_error="lowercase letters, numbers, dots, dashes and underscores",
          row_label="Service name", item_label="Service", add_label="Add a lookup service",
          empty_text="No lookup services are turned on.", weaker="grow",
          warning="Details of security findings will be sent to the lookup services you turn on."),
        S("memory", "weaviate_grpc_host", "Weaviate fast-connection address",
          "The address of your Weaviate server's fast connection, when it differs from the "
          "address above. Leave empty to use the same one.", "text", "Memory & learning", "",
          "maverick.vector_store.weaviate_store", subgroup="Recall of past work",
          pattern=r"([A-Za-z0-9.-]{1,253})?", max_length=253,
          env=("MAVERICK_WEAVIATE_GRPC_HOST",), weaker="change",
          warning="Summaries of past tasks will be sent to a different address."),
        S("memory", "weaviate_grpc_port", "Weaviate fast-connection port",
          "Leave empty for the standard port.", "number", "Memory & learning", None,
          "maverick.vector_store.weaviate_store", subgroup="Recall of past work", minimum=1,
          maximum=65535, integer=True, unit="port", none_text="Standard port",
          env=("MAVERICK_WEAVIATE_GRPC_PORT",)),
        S("memory", "weaviate_vectorizer", "How Weaviate reads summaries",
          "The service your Weaviate server uses to turn summaries into searchable meaning. It "
          "must be turned on in your Weaviate server.", "select", "Memory & learning", "",
          "maverick.vector_store.weaviate_store", subgroup="Recall of past work",
          choices=(("", "Weaviate's own text model (default)"),
                   ("text2vec-openai", "OpenAI"), ("text2vec-ollama", "Ollama"),
                   ("text2vec-cohere", "Cohere"), ("text2vec-huggingface", "Hugging Face"),
                   ("none", "None, Lightwork supplies them")),
          env=("MAVERICK_WEAVIATE_VECTORIZER",), weaker="change",
          warning="Summaries of past tasks may be sent to a different service to be read."),
        S("models", "embed", "Model for comparing text by meaning",
          "The local model the text-comparison tool downloads and uses. Leave empty for the "
          "standard small English model.", "text", "AI models", "", "maverick.tools.embeddings",
          subgroup="Model choices", pattern=r"(" + _MODEL_NAME + r")?", max_length=193,
          env=("MAVERICK_EMBED_MODEL",), weaker="change",
          warning="A different model will be downloaded and run on this server."),
        S("models", "clap", "Model for recognising sounds",
          "The local model the sound-recognition tool downloads and uses. Leave empty for the "
          "standard one.", "text", "AI models", "", "maverick.tools.audio_understanding",
          subgroup="Model choices", pattern=r"(" + _MODEL_NAME + r")?", max_length=193,
          env=("MAVERICK_CLAP_MODEL",), weaker="change",
          warning="A different model will be downloaded and run on this server."),
        S("replay", "record", "Record every task step by step",
          "Keep a tamper-evident record of each task's steps so it can be replayed later. The "
          "records can hold parts of the tasks.", "toggle", "Performance", False,
          "maverick.replay.trace", subgroup="Task recordings", env=("MAVERICK_TRACE_DIR",),
          weaker=True, warning="A record of every task's steps, which can hold parts of the "
                               "tasks, will be kept on this server."),
        S("replay", "trace_dir", "Folder for task recordings",
          "Where the recordings are kept. Leave empty to keep them in Lightwork's own folder.",
          "path", "Performance", "", "maverick.replay.trace", subgroup="Task recordings",
          path_kind="folder", path_writable=True, max_length=400, env=("MAVERICK_TRACE_DIR",)),
        S("analytics", "task_questions", "Answer questions about past tasks",
          "Offer the questions about spending, tasks and tokens on the Insights page. They need "
          "the DuckDB add-on installed on the server.", "toggle", "Performance", True,
          "maverick_dashboard.insight_ops_api", subgroup="Insights"),
        S("director", "profiles", "Director mode autonomy levels",
          "What each autonomy level means when a task is started in director mode from the "
          "command line: how actions that can't be undone are handled, when a person reviews "
          "the work, and what share of the spending limit it may use. It never goes above the "
          "spending limit.", "table", "Safety", {}, "maverick.director_mode",
          subgroup="Director mode", row_kind="grid",
          choices=(("supervised", "Supervised"), ("semi", "Partly on its own"),
                   ("autonomous", "On its own")),
          columns=(
              C("consent_mode", "Actions that can't be undone", "select", choices=_CONSENT,
                required=True),
              C("budget_multiplier", "Share of the spending limit", "number", minimum=0.1,
                maximum=10, unit="times", required=True),
              C("dollars", "Review after spending", "number", minimum=0.01, maximum=100000,
                unit="dollars", required=True),
              C("tool_calls", "Review after actions", "number", minimum=1, maximum=100000,
                integer=True, unit="actions", required=True),
          ),
          row_label="Autonomy level", item_label="Autonomy level", add_label="Change a level",
          empty_text="Every level uses its standard meaning.", weaker="change",
          warning="Director runs at this level may ask for fewer approvals or be reviewed less "
                  "often."),
    )


def _background(S) -> tuple:
    """Programs the dashboard starts, and stops, with itself when they are on."""
    grp, programs, proxy = "Server & deployment", "Background programs", "Model proxy"
    return (
        S("perf.profiling", "enabled", "Record where the server spends its time",
          "Start a sampling program with the dashboard that regularly records where this "
          "server's time goes and saves the results in Lightwork's folder. It needs the py-spy "
          "program installed.", "toggle", grp, False, "maverick.profiling_daemon",
          subgroup=programs, restart=True, env=("MAVERICK_PROFILING",)),
        S("perf.profiling", "interval_seconds", "Record every",
          "How long to wait between recordings.", "number", grp, 300.0,
          "maverick.profiling_daemon", subgroup=programs, minimum=10, maximum=86400,
          integer=True, unit="seconds", restart=True, env=("MAVERICK_PROFILING_INTERVAL",)),
        S("perf.profiling", "duration_seconds", "Length of each recording",
          "How long each recording lasts.", "number", grp, 30.0, "maverick.profiling_daemon",
          subgroup=programs, minimum=1, maximum=600, integer=True, unit="seconds",
          restart=True, env=("MAVERICK_PROFILING_DURATION",)),
        S("perf.profiling", "format", "Recording format",
          "The kind of file each recording is saved as.", "select", grp, "speedscope",
          "maverick.profiling_daemon", subgroup=programs,
          choices=(("speedscope", "Speedscope file (default)"), ("flamegraph", "Flame picture"),
                   ("raw", "Plain text")), restart=True, env=("MAVERICK_PROFILING_FORMAT",)),
        S("ebpf_monitor", "enable", "Watch the programs agents start",
          "Start a monitor with the dashboard that follows every program Lightwork starts and "
          "warns about risky system requests. It needs the server's administrator account and "
          "the bpftrace program; without them it stops at once and says why.", "toggle", grp,
          False, "maverick.ebpf_monitor", subgroup=programs, restart=True),
        S("model_proxy", "enable", "Run the model proxy",
          "Start the model proxy with the dashboard. It holds the AI service key in a separate "
          "program, so agents never see it. The key itself is set on the server, not here.",
          "toggle", grp, False, "maverick_dashboard.background_programs", subgroup=proxy,
          restart=True, weaker=True,
          warning="A program that forwards AI requests will listen on this server."),
        S("model_proxy", "upstream", "AI service the proxy forwards to",
          "The secure address of the AI service, such as https://api.anthropic.com.", "text",
          grp, "", "maverick.model_proxy", subgroup=proxy, pattern=_ADDRESS, max_length=320,
          restart=True, env=("MAVERICK_PROXY_UPSTREAM",), weaker="change",
          warning="AI requests sent through the proxy will go to a different service."),
        S("model_proxy", "listen", "Where the proxy listens",
          "The address and port, such as 127.0.0.1:8765. Leave empty for this computer only, "
          "port 8765.", "text", grp, "", "maverick.model_proxy", subgroup=proxy,
          pattern=r"([A-Za-z0-9.\[\]:-]{1,253}:[0-9]{1,5})?", max_length=260, restart=True,
          env=("MAVERICK_PROXY_LISTEN",), weaker="change",
          warning="Other computers may be able to reach the proxy."),
        S("model_proxy", "auth_style", "How the proxy sends the key",
          "Use the style the AI service expects.", "select", grp, "bearer",
          "maverick.model_proxy", subgroup=proxy,
          choices=(("bearer", "Bearer sign-in (default)"), ("x-api-key", "Key header (Claude)")),
          restart=True, env=("MAVERICK_PROXY_AUTH_STYLE",)),
        S("model_proxy", "client_token", "Password agents give the proxy",
          "Agents must send this password to use the proxy. It is stored sealed and never shown "
          "again.", "secret", grp, "", "maverick.model_proxy", subgroup=proxy, max_length=500,
          restart=True, env=("MAVERICK_PROXY_CLIENT_TOKEN",)),
        S("model_proxy", "allowed_routes", "Requests the proxy passes on",
          "Leave all unticked for the standard AI requests.", "multiselect", grp, [],
          "maverick.model_proxy", subgroup=proxy,
          choices=(("POST /v1/messages", "Claude messages"),
                   ("POST /v1/messages/count_tokens", "Claude token counts"),
                   ("POST /v1/chat/completions", "Chat answers"),
                   ("POST /v1/responses", "Responses"),
                   ("POST /v1/completions", "Text completions"),
                   ("POST /v1/embeddings", "Text comparison")),
          restart=True, env=("MAVERICK_PROXY_ALLOWED_ROUTES",), weaker="change",
          warning="The proxy will pass on a different set of requests."),
    )


def _startup_limits(S) -> tuple:
    """Limits the kernel reads once when it starts (the environment still wins)."""
    how, length = "How agents work", "Conversation length"
    return (
        S("agent", "synthesis_reserve", "Budget kept for the final answer",
          "Helper agents stop before using this share of a task's dollar limit, leaving the lead "
          "agent room to write its answer. 0.25 keeps one quarter; zero keeps no reserve. This "
          "applies only when the task has a dollar limit. Restart the service after saving.",
          "number", "AI models", 0.25, "maverick.agent", subgroup=how, minimum=0,
          maximum=1, step=0.05, unit="share", restart=True,
          env=("MAVERICK_SYNTHESIS_RESERVE",)),
        S("agent", "spend_mirror_interval", "Refresh recorded running spending every",
          "How often the lead agent updates the recorded spending of a running task. This "
          "does not change spending limits or how charges are counted. Zero updates at every "
          "step. Restart the service after saving.", "number", "Performance", 5.0,
          "maverick.agent", subgroup="Running tasks", minimum=0, maximum=300, step=0.5,
          unit="seconds", restart=True, env=("MAVERICK_SPEND_MIRROR_INTERVAL",)),
        S("agent", "loop_guard", "Stop agents repeating the same action",
          "When an agent keeps making exactly the same request and getting the same result, "
          "tell it to change course, and in the end refuse the repeat.", "toggle", "AI models",
          True, "maverick.agent", subgroup=how, restart=True, env=("MAVERICK_LOOP_GUARD",),
          weaker=False, warning="Agents that repeat the same action will no longer be stopped, "
                                "which can waste money."),
        S("agent", "loop_guard_threshold", "Repeats before an agent is told to change course",
          "How many identical requests in a row an agent may make before it is told to try "
          "something else.", "number", "AI models", 3, "maverick.agent", subgroup=how,
          minimum=2, maximum=50, integer=True, unit="repeats", restart=True,
          env=("MAVERICK_LOOP_GUARD_THRESHOLD",)),
        S("agent", "loop_guard_block", "Repeats before the request is refused",
          "After this many identical requests with the same result, the next one is refused. "
          "Zero only tells the agent and never refuses.", "number", "AI models", 6,
          "maverick.agent", subgroup=how, minimum=0, maximum=100, integer=True,
          unit="repeats", restart=True, env=("MAVERICK_LOOP_GUARD_BLOCK",)),
        S("agent", "step_budget_warning", "Warn an agent this many steps before its limit",
          "Tell an agent to give its answer when only this many steps are left. Zero never "
          "warns.", "number", "AI models", 3, "maverick.agent", subgroup=how, minimum=0,
          maximum=100, integer=True, unit="steps", restart=True,
          env=("MAVERICK_STEP_BUDGET_WARNING",)),
        S("agent", "max_concurrent_goals", "Tasks running at once on this server",
          "The most tasks this server runs at the same time. More wait their turn.", "number",
          "Performance", 16, "maverick.runner", subgroup="Running tasks", minimum=1,
          maximum=1000, integer=True, unit="tasks", restart=True,
          env=("MAVERICK_MAX_CONCURRENT_GOALS",)),
        S("agent", "max_concurrent_goals_per_principal", "Tasks running at once for one person",
          "The most tasks one person can have running at the same time, so nobody holds up "
          "everyone else.", "number", "Performance", 3, "maverick.runner",
          subgroup="Running tasks", minimum=1, maximum=100, integer=True, unit="tasks",
          restart=True, env=("MAVERICK_MAX_CONCURRENT_GOALS_PER_PRINCIPAL",)),
        S("latency", "retry_attempts", "Tries for each AI request",
          "How many times a failed request to an AI service is tried in all. Every try is "
          "billed.", "number", "Performance", 3, "maverick.retry", subgroup="AI service requests",
          minimum=1, maximum=10, integer=True, unit="tries", restart=True,
          env=("MAVERICK_LLM_RETRY_ATTEMPTS",), weaker="higher",
          warning="Failed AI requests will be tried more times, and each try is billed."),
        S("latency", "retry_base_delay", "First wait before trying again",
          "The wait before the first retry; later waits grow from it.", "number", "Performance",
          1.0, "maverick.retry", subgroup="AI service requests", minimum=0, maximum=60,
          step=0.5, unit="seconds", restart=True, env=("MAVERICK_LLM_RETRY_BASE_DELAY",)),
        S("latency", "retry_max_delay", "Longest wait before trying again", "The longest wait "
          "between two tries.", "number", "Performance", 30.0, "maverick.retry",
          subgroup="AI service requests", minimum=1, maximum=600, unit="seconds", restart=True,
          env=("MAVERICK_LLM_RETRY_MAX_DELAY",)),
        S("swarm", "max_fanout", "Helpers one agent may start at once",
          "The most helper agents a single request can start together.", "number", "AI models",
          8, "maverick.tools.spawn", subgroup=how, minimum=1, maximum=64, integer=True,
          unit="helpers", restart=True, env=("MAVERICK_MAX_SWARM_FANOUT",), weaker="higher",
          warning="One agent will be able to start more helpers at once, which costs more."),
        S("swarm", "default_max_depth", "Levels of helpers under a task",
          "How many levels of helpers under helpers a task may use when none is chosen.",
          "number", "AI models", 3, "maverick.runner", subgroup=how, minimum=1, maximum=10,
          integer=True, unit="levels", restart=True, env=("MAVERICK_DEFAULT_MAX_DEPTH",)),
        S("verification", "confidence_accept", "How sure the checker must be to accept",
          "The answer checker accepts an answer when it is at least this sure, from 0 to 1.",
          "number", "AI models", 0.75, "maverick.verifier", subgroup="Checking answers",
          minimum=0, maximum=1, step=0.05, unit="score", restart=True,
          env=("MAVERICK_VERIFIER_CONFIDENCE",), weaker="lower",
          warning="The answer checker will accept answers it is less sure about."),
        S("verification", "disagreement_high", "Disagreement that brings in more checkers",
          "When the first answers disagree at least this much, from 0 to 1, more are compared.",
          "number", "AI models", 0.5, "maverick.verifier", subgroup="Checking answers",
          minimum=0, maximum=1, step=0.05, unit="score", restart=True,
          env=("MAVERICK_DISAGREEMENT_HIGH",)),
        S("compaction", "keep_recent", "Recent turns never shortened",
          "The newest turns of a conversation are always kept whole.", "number", "AI models", 4,
          "maverick.compaction", subgroup=length, minimum=1, maximum=100, integer=True,
          unit="turns", restart=True, env=("MAVERICK_COMPACT_KEEP_RECENT",)),
        S("compaction", "digest_every", "Summarise older turns every",
          "How often older turns are folded into a summary.", "number", "AI models", 10,
          "maverick.compaction", subgroup=length, minimum=1, maximum=1000, integer=True,
          unit="turns", restart=True, env=("MAVERICK_COMPACT_DIGEST_EVERY",)),
        S("compaction", "max_tool_bytes", "Longest older tool result kept",
          "Older tool results are cut to this many characters when a conversation is "
          "shortened.", "number", "AI models", 2048, "maverick.compaction", subgroup=length,
          minimum=256, maximum=1048576, integer=True, unit="characters", restart=True,
          env=("MAVERICK_COMPACT_MAX_TOOL_BYTES",)),
        S("compaction", "max_total_bytes", "Most text kept in a conversation",
          "When a conversation grows past this many characters, older results are shortened "
          "too. Zero never shortens for size.", "number", "AI models", 200000,
          "maverick.compaction", subgroup=length, minimum=0, maximum=10000000, integer=True,
          unit="characters", restart=True, env=("MAVERICK_COMPACT_MAX_TOTAL_BYTES",)),
        S("attachments", "max_file_bytes", "Largest attachment",
          "Bigger files are refused.", "number", "Privacy", 104857600, "maverick.attachments",
          subgroup="Attachments", minimum=1, maximum=10240, integer=True, scale=1048576,
          unit="MB", restart=True, env=("MAVERICK_ATTACH_MAX_FILE_BYTES",)),
        S("attachments", "max_goal_bytes", "Most attachments for one task",
          "All of one task's attachments together may not be bigger than this.", "number",
          "Privacy", 524288000, "maverick.attachments", subgroup="Attachments", minimum=1,
          maximum=102400, integer=True, scale=1048576, unit="MB", restart=True,
          env=("MAVERICK_ATTACH_MAX_GOAL_BYTES",)),
        S("tools", "openapi_spec_max_bytes", "Largest service description read",
          "Descriptions of outside services bigger than this are refused.", "number",
          "Performance", 10000000, "maverick.tools.openapi_runner",
          subgroup="Connected services", minimum=1, maximum=500, integer=True,
          scale=1000000, unit="MB", restart=True, env=("MAVERICK_OPENAPI_SPEC_MAX_BYTES",)),
        S("tools", "openapi_call_max_bytes", "Largest reply from an outside service",
          "Replies bigger than this are cut off.", "number", "Performance", 1000000,
          "maverick.tools.openapi_runner", subgroup="Connected services", minimum=1,
          maximum=100, integer=True, scale=1000000, unit="MB", restart=True,
          env=("MAVERICK_OPENAPI_CALL_MAX_BYTES",)),
        S("models", "openai_max_tools", "Most tools offered to OpenAI-style models",
          "OpenAI-style services refuse requests offering more tools than this. Lightwork "
          "keeps key actions available and lets agents find the rest. Change this only "
          "when your AI service supports a different limit.", "number",
          "AI models", 128, "maverick.providers.openai_provider", subgroup="Model choices",
          minimum=1, maximum=1024, integer=True, unit="tools", restart=True,
          env=("MAVERICK_OPENAI_MAX_TOOLS",)),
    )


def _tool_server(S) -> tuple:
    """The tool server for outside apps (``maverick mcp``): the ``[mcp]`` section."""
    grp, sub = "Integrations", "Tool server for outside apps"
    common = {"subgroup": sub, "aliases": "mcp tool server"}
    return (
        S("mcp", "token", "Password for outside apps",
          "The shared password outside apps send to use Lightwork's tools over the network. It "
          "is stored sealed and never shown again.", "secret", grp, "", "maverick_mcp.settings",
          max_length=500, env=("MAVERICK_MCP_TOKEN",), weaker="change",
          warning="Apps using the old password will be refused, and anyone with the new one "
                  "can use Lightwork's tools.", **common),
        S("mcp", "allowed_origins", "Web pages that may call the tool server",
          "Web page addresses, besides this computer, allowed to call the tool server from a "
          "browser.", "list", grp, [], "maverick_mcp.settings", item_label="Web address",
          item_hint="https://gateway.example.com", pattern=_ORIGIN,
          item_error="a web address such as https://gateway.example.com", max_items=50,
          env=("MAVERICK_MCP_ALLOWED_ORIGINS",), weaker="grow",
          warning="Web pages at these addresses will be able to call the tool server.",
          **common),
        S("mcp", "http_tasks", "Let outside apps start long tasks over the network",
          "Outside apps connected over the network may start tasks that keep running and "
          "collect the result later.", "toggle", grp, False, "maverick_mcp.settings",
          restart=True, env=("MAVERICK_MCP_HTTP_TASKS",), **common),
        S("mcp", "rate_limit", "Requests each app may make per minute",
          "Zero means no limit.", "number", grp, 600, "maverick_mcp.settings", minimum=0,
          maximum=100000, integer=True, unit="requests", env=("MAVERICK_MCP_RATE_LIMIT",),
          weaker="higher", warning="Outside apps will be able to send more requests.",
          **common),
        S("mcp", "max_body_bytes", "Largest request from an app",
          "Bigger requests are refused.", "number", grp, 2097152, "maverick_mcp.settings",
          minimum=1, maximum=65536, integer=True, scale=1024, unit="KB",
          env=("MAVERICK_MCP_MAX_BODY",), **common),
        S("mcp", "max_resource_sessions", "Apps watching for changes at once",
          "The most connections that may watch Lightwork's records for changes at once.",
          "number", grp, 1024, "maverick_mcp.settings", minimum=1, maximum=100000,
          integer=True, unit="connections", env=("MAVERICK_MCP_MAX_RESOURCE_SESSIONS",),
          **common),
        S("mcp", "sse_heartbeat", "Progress message every",
          "How often a long request tells the app it is still working.", "number", grp, 15.0,
          "maverick_mcp.settings", minimum=1, maximum=300, unit="seconds",
          env=("MAVERICK_MCP_SSE_HEARTBEAT",), **common),
        S("mcp", "sse_max_progress_events", "Progress messages per request",
          "The most progress messages one request sends.", "number", grp, 240,
          "maverick_mcp.settings", minimum=0, maximum=100000, integer=True, unit="messages",
          env=("MAVERICK_MCP_SSE_MAX_PROGRESS_EVENTS",), **common),
        S("mcp", "max_dollars", "Most one app task may spend",
          "Tasks started by outside apps stop at this amount. Leave empty to use the normal "
          "spending limit.", "number", grp, None, "maverick_mcp.settings", minimum=0.01,
          maximum=100000, step=0.01, unit="dollars", none_text="The normal spending limit",
          env=("MAVERICK_MCP_MAX_DOLLARS",), weaker="higher",
          warning="Tasks started by outside apps will be able to spend more.", **common),
        S("mcp", "max_wall_seconds", "Longest one app task may run",
          "Tasks started by outside apps stop after this long. Leave empty to use the normal "
          "time limit.", "number", grp, None, "maverick_mcp.settings", minimum=1,
          maximum=86400, integer=True, unit="seconds", none_text="The normal time limit",
          env=("MAVERICK_MCP_MAX_WALL_SECONDS",), weaker="higher",
          warning="Tasks started by outside apps will be able to run for longer.", **common),
        S("mcp", "max_depth", "Levels of helpers in an app task",
          "The most levels of helpers a task started by an outside app may use.", "number",
          grp, 3, "maverick_mcp.settings", minimum=1, maximum=10, integer=True,
          unit="levels", env=("MAVERICK_MCP_MAX_DEPTH",), **common),
        S("mcp", "elicitation_timeout", "Wait for a person's answer for",
          "How long an app task waits for a person to answer a question before leaving it to "
          "be answered later.", "number", grp, 300.0, "maverick_mcp.settings", minimum=1,
          maximum=86400, unit="seconds", env=("MAVERICK_MCP_ELICITATION_TIMEOUT",), **common),
        S("mcp", "max_elicit_rounds", "Questions one app task may ask",
          "The most questions a task started by an outside app may ask a person.", "number",
          grp, 8, "maverick_mcp.settings", minimum=1, maximum=64, integer=True,
          unit="questions", env=("MAVERICK_MCP_MAX_ELICIT_ROUNDS",), **common),
        S("mcp", "elicit_allowed_hosts", "Websites an app task may send a person to",
          "When a task asks a person to sign in somewhere, only these websites may be used. "
          "Leave empty to allow any secure website.", "list", grp, [], "maverick_mcp.server",
          item_label="Website", item_hint="accounts.google.com", pattern=_HOST,
          item_error="a website such as accounts.google.com", max_items=100,
          env=("MAVERICK_MCP_ELICIT_ALLOWED_HOSTS",), weaker="shrink",
          warning="Tasks will be able to send people to more websites.", **common),
        S("mcp", "max_tasks", "Long tasks kept at once",
          "The most long tasks the tool server keeps at once.", "number", grp, 256,
          "maverick_mcp.settings", minimum=1, maximum=100000, integer=True, unit="tasks",
          restart=True, env=("MAVERICK_MCP_MAX_TASKS",), **common),
        S("mcp", "max_tasks_per_owner", "Long tasks kept for one app",
          "The most long tasks one app may have at once. It can't be more than the number "
          "above.", "number", grp, 32, "maverick_mcp.settings", minimum=1, maximum=100000,
          integer=True, unit="tasks", restart=True, env=("MAVERICK_MCP_MAX_TASKS_PER_OWNER",),
          **common),
        S("mcp", "task_ttl_ms", "Keep a finished long task for",
          "How long a long task's result is kept when the app does not say.", "number", grp,
          3600000, "maverick_mcp.settings", minimum=1, maximum=604800, integer=True,
          scale=1000, unit="seconds", restart=True, env=("MAVERICK_MCP_TASK_TTL_MS",),
          **common),
        S("mcp", "task_max_ttl_ms", "Longest an app may keep a long task",
          "The longest an app may ask for a long task's result to be kept.", "number", grp,
          86400000, "maverick_mcp.settings", minimum=1, maximum=604800, integer=True,
          scale=1000, unit="seconds", restart=True, env=("MAVERICK_MCP_TASK_MAX_TTL_MS",),
          **common),
        S("mcp", "task_poll_ms", "Suggested wait between checks",
          "How often apps are told to check a long task.", "number", grp, 1000,
          "maverick_mcp.settings", minimum=50, maximum=3600000, integer=True,
          unit="milliseconds", restart=True, env=("MAVERICK_MCP_TASK_POLL_MS",), **common),
        S("mcp", "task_result_block_ms", "Longest wait for a long task's result",
          "How long one request for a result may wait before answering that it is not ready.",
          "number", grp, 60000, "maverick_mcp.settings", minimum=1, maximum=600,
          integer=True, scale=1000, unit="seconds", restart=True,
          env=("MAVERICK_MCP_TASK_RESULT_BLOCK_MS",), **common),
        S("mcp", "task_workers", "Long tasks worked on at once",
          "How many long tasks the tool server works on at the same time.", "number", grp, 4,
          "maverick_mcp.settings", minimum=1, maximum=64, integer=True, unit="tasks",
          restart=True, env=("MAVERICK_MCP_TASK_WORKERS",), **common),
    )
