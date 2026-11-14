# Configuration

Lightwork reads `~/.maverick/config.toml`. The installer wizard writes it; you can also edit by hand.

## Full schema

```toml
[deployment]
type = "desktop"       # desktop | docker | vps | phone
# Break-glass only. Exactly one control plane may write a data root: flows,
# A2A claims, and the audit, budget-receipt, fleet-memory and learning ledgers
# are hash-chained and assume a single author. Two writers do not tear a
# record -- they interleave valid ones, so the result verifies clean and is
# unreconstructable. Startup takes an exclusive lock on the data root and a
# second process refuses to serve. Set this only if you have guaranteed
# exclusivity another way; authenticated probe details report `replica_safety: unenforced`.
# allow_multiple_control_planes = false   # env: MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES

[governance]
# The business-shaped governance level picked at onboarding. Every level gets
# the self-learning/self-improvement lifecycle; the level sets the governance
# posture around it:
#   essentials  small business (a gym, a studio) — learning, no ceremony
#   standard    growing company — + signed audit trail (no spending caps)
#   regulated   bank/clinic/government — + human sign-off (Ed25519) for
#               code/weights promotions, WORM audit export, long retention
# A label for humans + dashboards: the wizard expands it into the concrete
# knobs ([audit], [quotas], [self_improvement], [retention], ...) below, so
# hand-edits keep working. A later `maverick init` protects saved settings and
# will not switch levels. Review supported changes in Lightwork Settings;
# advanced deployment-managed changes require an installation administrator.
# The advanced first-run wizard writes
# "custom": the operator hand-picked every knob, no preset applies.
profile = "essentials"   # essentials | standard | regulated | custom

[providers]
# Per-tenant BYOK (bring-your-own-key). Default OFF: the whole install shares
# the deployment-global provider key below. When true, an active tenant that
# opted in (its `byok` flag, e.g. via `maverick`) runs on ITS OWN provider key,
# resolved from the secret provider under a tenant-scoped name
# (`MAVERICK_TENANT_<digest>_<PROVIDER>_API_KEY`); a tenant with no key falls
# back to the global key. The key bytes are NEVER stored here or on the tenant
# record. `MAVERICK_PER_TENANT_KEYS` overrides this. (Distinct from per-tenant
# [kms] BYOK, which is envelope-encryption key custody, not the LLM API key.)
# NOTE: a bare [providers] scalar must appear BEFORE the [providers.<name>]
# subtables — TOML rejects a scalar added to a table after a subtable opened it.
per_tenant_keys = false

[providers.anthropic]
api_key = "${ANTHROPIC_API_KEY}"   # env var interpolation

[providers.openai]
api_key = "${OPENAI_API_KEY}"

[providers.openrouter]
api_key = "${OPENROUTER_API_KEY}"

[providers.ollama]
base_url = "http://localhost:11434"

[providers.bedrock]
# Claude on AWS Bedrock through the native Anthropic Messages API (prompt
# caching, thinking, tool_choice all work). auth_mode "iam" signs with your AWS
# credentials or role (needs the `bedrock` extra: boto3); "api_key" sends a
# Bedrock bearer token from BEDROCK_API_KEY. endpoint "mantle" is Claude in
# Amazon Bedrock (Opus 4.7 and later; ids like anthropic.claude-opus-5);
# "legacy" is Opus 4.6 and earlier (ids like global.anthropic.claude-opus-4-6-v1).
# AWS_REGION is required; BEDROCK_MODEL_ID sets the default model.
# Billing: Bedrock is invoiced by AWS at its own rates, which are not in
# Lightwork's verified rate card. Planning estimates use the Claude API list
# rate for the model behind the id; set [budget] strict_pricing=false to
# account live usage at that estimate.
auth_mode = "iam"
# endpoint = "mantle"

[providers.vertex]
# Claude on Google Cloud Vertex AI through the Anthropic SDK's Vertex client
# (prompt caching, thinking, tool_choice all work). There is no key: sign-in is
# Google Application Default Credentials (a service-account file named by
# GOOGLE_APPLICATION_CREDENTIALS, `gcloud auth application-default login`, or
# workload identity). Needs the `vertex` extra: google-auth.
# project_id falls back to ANTHROPIC_VERTEX_PROJECT_ID, then GOOGLE_CLOUD_PROJECT;
# region falls back to CLOUD_ML_REGION; model_id falls back to VERTEX_MODEL_ID;
# base_url (optional) falls back to ANTHROPIC_VERTEX_BASE_URL. The table wins
# over the environment. The model_id is the id shown in the Vertex AI Model
# Garden (name@version form, for example claude-haiku-4-5@20251001); Lightwork
# ships no Vertex model id.
# Billing: Google Cloud invoices Vertex AI at its own rates, which are not in
# Lightwork's verified rate card. Like Bedrock, planning estimates use the Claude
# API list rate for the model behind the id; set [budget] strict_pricing=false to
# account live usage at that estimate.
project_id = "my-gcp-project"
region = "us-east5"
model_id = "claude-haiku-4-5@20251001"   # copy the exact id from Model Garden

[models]
# Settings > Models offers every model a saved provider key can reach: each
# configured provider's own model-list endpoint is read (one bounded request,
# cached for discovery_ttl_minutes) on top of the shipped catalog. Off means
# the shipped catalog only; any model id can still be typed. The
# MAVERICK_MODEL_DISCOVERY=0|1 environment variable overrides the setting.
# discovery = true
# discovery_ttl_minutes = 60
# Extra picker entries, any "provider:model-id":
# catalog = ["openai:gpt-6"]
# Per-role model picks. Format: "provider:model-id".
# Any role omitted falls back to maverick.llm.ROLE_MODELS defaults.
orchestrator    = "anthropic:claude-opus-4-8"
researcher      = "anthropic:claude-sonnet-4-6"
coder           = "anthropic:claude-sonnet-4-6"
writer          = "anthropic:claude-sonnet-4-6"
analyst         = "anthropic:claude-sonnet-4-6"
revisor         = "anthropic:claude-opus-4-8"
verifier        = "anthropic:claude-sonnet-4-6"
summarizer      = "anthropic:claude-haiku-4-5"
skill_distiller = "anthropic:claude-sonnet-4-6"
# Work that names no role (background runs started from the dashboard, MCP,
# the GitHub app, agent-to-agent tasks) uses "default". Unset, it follows the
# dashboard's default-model choice, then claude-sonnet-4-6.
# default       = "anthropic:claude-sonnet-4-6"

[budget]
# New installs save $2 / 1800 seconds; existing configs with omitted limits
# retain their prior no-limit behavior. These are explicit override examples.
task_limits_enabled = true
# max_dollars       = 25.0
# max_wall_seconds  = 3600
# max_tool_calls    = 500
# max_input_tokens  = 1000000
# max_output_tokens = 200000
strict_pricing      = true

[contact_centre]
# Where a human handoff goes outside Lightwork when a person takes over a
# conversation. Off by default: nothing is sent and no outbox is kept.
# provider = "off"                 # "off" | "zendesk" | "webhook"
# zendesk_subdomain = "acme-support"   # the part before .zendesk.com
# zendesk_email = "agent@acme.example" # agent whose API token is used
# webhook_url = "https://hooks.acme.example/lightwork"
# dashboard_url = "https://lightwork.acme.example"  # links back to conversations
# max_messages = 20                # 1-50 recent messages, each 2,000 characters
# The Zendesk API token and the webhook signing secret are never set here. Enter
# them in Settings > Integrations > Contact centre (stored sealed), or set
# MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN / MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET.
# See contact-centre-handoff.md.

[safety]
profile         = "balanced"   # strict | balanced | permissive | off
block_threshold = "high"       # low | medium | high | critical
scan_input      = true
scan_tool_calls = true
scan_output     = true
# Task-start check (off by default). Lightwork reads each task's wording
# (pay, delete, deploy, passwords, all customers, production ...) before it
# starts. When set, tasks at or above this level wait on the dashboard's
# Approvals page until a person approves them, and do not start if nobody
# does within [approval] dashboard_wait_seconds (1800 s). It reads only the
# words: every action is still checked on its own once the task runs.
# goal_risk_require_human = "high"   # never (default) | high | medium
# goal_risk_floor         = "low"    # low (default) | medium | high

[approval]
# The Approvals page. A risky step waits this long for a decision (30
# minutes; MAVERICK_CONSENT_DASHBOARD_TIMEOUT wins); after 10 minutes the
# people who can decide get one in-app reminder, and with no decision in
# time the step is refused. A request's card stays approvable for the wait
# plus the undo window below, at most an hour.
dashboard_wait_seconds  = 1800
# A decision can be undone for this long; the agent
# only acts on an approval once the window has passed (0 = act at once,
# no Undo). High and critical risk approvals need an explicit confirmation
# (a ticked box; typing APPROVE for critical) unless switched off.
undo_grace_seconds      = 30
require_acknowledgement = true
# Who approves a high or critical risk action someone asked for:
# "when_available" (default) = someone else whenever another approver could
# decide it, else the requester (recorded as a self-approval); "always" =
# always someone else; "never" = the requester may approve it.
separate_approver       = "when_available"
# One row per approval check: when, workspace, risk, kind of action, agent or
# specialist, and whether it was allowed, sent to a person or refused. Never
# the content, arguments or command. For previewing a threshold change later;
# rows older than check_retention_days are pruned a few hundred at a time.
record_checks           = true
check_retention_days    = 90

[sandbox]
backend = "local"                   # local | docker | ssh | podman | gvisor | devcontainer | firecracker | kubernetes | modal
workdir = "~/maverick-workspace"
timeout = 60
# devcontainer defaults to the invoking non-root UID:GID, ignoring the repo's
# remoteUser. Run Lightwork as a non-root user on a platform with UID/GID
# support. An operator can explicitly set allow_root = true to trust that
# repository user setting, including its ability to run as root.

[features]
# Toggle agent-facing behaviors that are otherwise always on. All default true.
skills      = true   # inject distilled/installed skills into agent prompts
                     #   (the MAVERICK_USE_SKILLS env var overrides this when set)
world_model = true   # inject persisted facts (cross-run memory) into runs;
                     #   false = run without prior stored facts. The goal/event/
                     #   checkpoint store (world.db) still works regardless.
streaming   = true   # stream live progress to the terminal during `maverick start`
                     #   (MAVERICK_NO_PROGRESS or non-TTY output still suppress it)
pack_editing = true  # allow editing/overriding agents (domain packs) from the
                     #   dashboard editor at /agents; false = the editor is
                     #   read-only and the mutating /api/v1/agents endpoints 403,
                     #   locking the roster (host-side override TOML still works).
role_editing = true  # allow editing the core roles (orchestrator, coder, ...)
                     #   from the dashboard editor at /roles -- a per-tenant
                     #   system-prompt addendum + model/effort override per role
                     #   (winning over [models]/[effort]); false = read-only and
                     #   /api/v1/roles mutations 403.
scheduling  = true   # allow arming recurring schedules (cron) from the dashboard;
                     #   false = the scheduler editor + /api/v1 schedule routes 403.
triggers    = true   # allow binding a saved template to an inbound webhook;
                     #   false = the /api/v1/triggers editor + /webhook/run 404/403.

[durable]
# Crash-resume: checkpoint a goal's loop state each step so `maverick resume`
# continues from where a crash left off instead of starting over. Off by
# default (a small write per step). keep_last bounds retained checkpoints.
enabled   = false
keep_last = 5

[analytics]
# Consent-gated, OFF by default. When true, the MCP server tallies a coarse
# language bucket from each client's User-Agent (typescript/go/rust/c#/java/
# python) into a local counts file — no request content, no identifiers,
# nothing uploaded. It shows you which languages your MCP clients use.
# The wizard asks for consent in its Analytics step (`maverick init`).
mcp_client_language = false

[channels.telegram]
enabled   = false
bot_token = "${TELEGRAM_BOT_TOKEN}"

[dashboard]
# Optional bearer token. Required for VPS deploys reachable from the open
# internet; harmless to leave unset on a desktop install (localhost-only).
token = "${MAVERICK_DASHBOARD_TOKEN}"

# Externally-reachable base URL. Used to build links a CLI can't derive from a
# request — the first-admin invite link printed by `maverick tenant onboard`
# and flow-approval links. MAVERICK_PUBLIC_URL overrides.
# public_url = "https://dashboard.example.com"

# Gzip responses over 1 KB (pages, JSON, the shell CSS/JS). On by default so a
# dashboard behind a bare uvicorn or a default ingress does not ship ~160 KB
# of uncompressed shell assets per cold load; set false when a proxy in front
# already compresses. MAVERICK_DASHBOARD_COMPRESS=0|1 overrides. Shell assets
# are also served with a content hash in the URL and a one-year cache, so an
# upgrade restyles on the next page load without a hard refresh.
# compress = true

# Glass effects for everyone: "off" (the default) keeps panels, rows, controls
# and dialogs solid, so clicks and typing repaint quickly; "on" brings back the
# see-through, blurred look until people choose their own in Display
# preferences (on this device or on their account). The top bar and sidebar
# stay translucent either way. Settings > All settings and the setup wizard's
# advanced step set it too.
# glass = "off"

# The sidebar: "classic" (the default) keeps today's groups; "areas" puts
# every page in one of nine job-named areas (Home, Work, Agents, Rules &
# safety, Privacy, Risk & compliance, Evidence & audit, Costs & value,
# Settings) with local tabs and an "Area › Section" breadcrumb, and starts
# each role from its own layout. Who may open a page never changes. In areas
# mode merged pages' old addresses forward to their new homes, each still
# checked as the old page was: /today, /me and /overview to Home's views,
# /action-center to Approvals' "All decisions", /my-work to Tasks with
# background work, /project-workspaces to Projects (one project's to its Plan
# tab), /goal-builder to Chat's form, /run-tree and /walkthroughs to Task
# replay's Branches and Video tabs, /plan-tree-3d to the task map's 3D view,
# /trust, /discovery, /autonomous-compliance and /cortex to tabs of Outside
# agents, Permissions, Compliance and Knowledge access, and /flows/designer to
# the workflow builder's Steps mode. Anyone the new address would not admit,
# and classic mode, keeps the old address. Run the tree test in
# docs/tree-test/ before switching everyone.
# navigation_personal = true lets each person choose for themselves in Your
# preferences. Settings > All settings and the setup wizard set both.
# navigation = "classic"
# navigation_personal = false

# Department (suite) access for authenticated users with NO explicit grant on
# the Users page (job-function scoping: a finance analyst sees and runs only
# Finance specialists). Unset = unrestricted — scoping is opt-in per user.
# Set a list for deny-by-default: new sign-ins may then use only these
# departments until an admin grants more. Admins are never scoped.
# default_suites = ["finance"]

# SCIM-group mapping: when your IdP (Okta/Entra) pushes Groups via SCIM,
# these tables turn team membership into access — no per-user assignment.
# An explicit Users-page assignment always beats the group-derived value.
# [dashboard.group_roles]
# "Finance Team" = "operator"
# [dashboard.group_suites]
# "Finance Team" = ["finance", "tax"]

[release]
# Publisher PUBLIC keys whose signed update bundles `python -m
# maverick.release_update verify-bundle|apply|rollback` accepts (also
# MAVERICK_RELEASE_PUBKEYS). With none set, every bundle is refused unless the
# command's --pubkey names a key.
# publisher_pubkeys = ["<publisher public key hex>"]

[rehearsal]
# Predict outcomes for high-impact actions. Predictions are observed by default;
# they do not stop tool calls or replace Shield, capability, or consent checks.
# The observation switch and mode are also available under Settings > Safety.
enable = true
mode = "observe"       # observe (default) | hold (experimental)
# "hold" can refuse unfamiliar or poor predicted actions and has no in-product
# approval path. Do not use it as a customer approval workflow.

[flows]
# The visual flow-automation engine (a deterministic graph of agent/action/
# branch/switch/foreach/while/parallel/approval/delay/wait_event/scope/subflow/
# setvar nodes) + the dashboard designer and triggers. OFF by default.
enable      = false      # or MAVERICK_FLOWS=1
# Autonomous self-correction of live flows. OFF by default and also
# toggleable from the dashboard Learning page.
auto_evolve = false      # revert a node rewrite the loop measures as a regression
                         # (the safety net; or MAVERICK_FLOWS_AUTO=1)
# auto_apply is retired: workflow suggestions always need a person's review,
# so nothing is applied forward automatically and the dashboard refuses true.

[governed_records]
# Shared CAS record authority used by assurance products. "auto" keeps
# single-replica installs local and selects configured Postgres when required.
# Postgres requires application encryption plus MAVERICK_ENCRYPTION_KEY and a
# matching MAVERICK_ENCRYPTION_KEY_DIGEST="sha256:..." on every replica.
backend = "auto"          # auto | local | postgres

[evidence_graph]
# Review-gated evidence metadata and cryptographic bindings. Required by the
# Model Risk & AI Assurance Officer.
enable = false

[model_risk_assurance]
# Governed AI inventory, evidence, findings, incidents, decisions, deployment
# lineage, and signed assurance packs. Both switches must be true for the
# fail-closed DGM promotion gate.
enable = false
gate_promotions = false

[evidence_gateway]
# AI delivery disclosures, hash-only interaction receipts, cited regulatory
# impacts, and signed assurance packets. Enabling through the installer also
# enables the companion evidence graph and Model Risk Officer controls. Runtime
# use also requires an explicit authenticated tenant/client binding.
enable = false

[model_improvement]
# Specialist-model tasksets, qualification, training receipts, and optional
# external-backend exports. Inert until enabled. Hosted execution is a second
# opt-in. Cross-tenant training remains structurally refused in v1 even though
# the reserved key is explicit.
enable = false
allow_hosted = false
allow_cross_tenant = false
require_signed_receipt = true
minimum_train_families = 20
minimum_holdout_families = 20
# Signed receipts are mandatory whenever enable = true. With an active tenant,
# global enable/allow_hosted are ceilings and the tenant must opt in separately.
# Family floors combine by maximum. Mutation boundaries reject malformed or
# unknown keys instead of silently falling back.

[finance]
# Regime policies combine strictest-wins. Existing `pci` configurations now
# identify PCI DSS 4.0.1; the key remains backward compatible.
regimes = ["sox", "gaap", "dora", "basel_iii", "ifrs_17", "pci"]
# Finance Operating Profile (docs/FINANCE_OPERATIONS.md). Every key below is
# read only while [finance_operations] enable = true; unset keeps today's
# behaviour.
# framework = "us_gaap"      # us_gaap | ifrs: adds that framework's policy pack
#                            # (strictest-wins with regimes)
# materiality = 50000        # anomaly findings totalling this or more need a
#                            # second reviewer; auto_threshold never acts alone
#                            # above it

# [finance.automation]
# Automation level of the finance actions: draft (agent prepares, a person
# acts; the agent's call is refused) | approve (a person approves each call) |
# auto_threshold (acts alone only under the approval limit) | straight_through.
# Payments, postings, payroll, bank-detail/supplier changes, period close,
# chart of accounts, tax and filings never go below approve.
# default = "draft"
# "ap.approve_expense" = "approve"   # one action class (department.action or action)

# [finance.sod]
# mode = "enforce"   # enforce: block a separation-of-duties conflict when the
#                    # action runs | warn: record a finding and ask a person

# [finance.approvals]
# timeout = "fail_closed"   # the only value: an unanswered finance approval
#                           # is refused and withdrawn, never auto-approved

[finance_operations]
# Deterministic regulatory, anomaly, AML/KYC/sanctions, and GRC control-testing
# operations. Off unless explicitly enabled here or through `maverick init`.
enable = false
federal_register_enable = true
# Safe opt-in built-in. The official RSS is issue-level, so every current Texas
# Register issue is routed to the finance review queue with source provenance.
texas_register_enable = false
regulatory_poll_seconds = 3600       # 0 disables polling; otherwise 300..604800
regulatory_domains = ["finance", "money_transmitter", "insurance_producer"]
anomaly_enable = true
sanctions_max_age_hours = 72
control_test_interval_seconds = 86400 # 0 disables; otherwise 300..2678400
evidence_due_days = 7
control_owner = "Finance Control Owner"
# Add up to 50 explicit HTTPS state feeds. Supported formats: json, rss, atom.
# Keep the safe empty default until you have verified the issuing state's URL.
state_feeds = []
# Shape of a domain-specific entry (replace every placeholder with the official source).
# `default_domains` declares that EVERY item in that feed belongs to the domain;
# omit it for a general-purpose state register and rely on item text or field_map.
# state_feeds = [{ key = "state-money-transmitter", name = "Official state money-transmitter notices", jurisdiction = "US-XX", url = "https://<official-state-host>/<domain-specific-feed>", format = "rss", default_domains = ["money_transmitter"] }]

[persona]
# Appended to every agent's system prompt. Optional.
name      = "Lightwork"
style     = "concise"   # concise | thorough | friendly | formal | playful
addendum  = ""           # free-form extra instruction

[mcp_servers.filesystem]
# External MCP servers Lightwork consumes as tools. Each one is spawned as
# a subprocess; their tools appear in the agent's catalog as
# `mcp_<name>__<tool>` and still pass through Shield.
command       = "npx"
args          = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
inherit_env   = false    # default; opt-in to pass the full process env

[mcp_servers.github]
command = "npx"
args    = ["-y", "@modelcontextprotocol/server-github"]
# Pass-through env values must be listed explicitly; secrets live in
# ~/.maverick/.env so they aren't committed by accident.
env     = { GITHUB_PERSONAL_ACCESS_TOKEN = "${GITHUB_TOKEN}" }
```

`strict_pricing = true` is the default: a missing or unverified model rate
stops the call before dispatch rather than turning an estimate into billable
accounting. Set it to `false` only for a legacy or custom OpenAI-compatible
gateway whose exact rate is unavailable. That explicit opt-out emits warnings
and records the unverified source, date, confidence, pricing basis, and
applicability in `Budget.pricing_evidence`; those totals are not suitable for
invoices or chargebacks. `MAVERICK_BILLING_STRICT=true|false` overrides the
file setting.

`backend = "local"` runs tools in the same runtime environment as
Lightwork. For untrusted skills, avoid mounting secret-bearing paths into
that runtime and prefer sandbox isolation that does not expose host
state.

## Data residency & zero-data-retention (cloud providers)

When a role is routed to a cloud provider, two `[providers.<name>]` knobs
control where the request goes and what data-handling it asserts:

- **`base_url`** — pin the endpoint. Point it at a regional/EU endpoint or at a
  compliance gateway/proxy you operate, so prompts never leave the chosen
  region. Honored by `anthropic`, `openai`, and the self-hosted/OpenAI-compatible
  clients.
- **`default_headers`** — a `key = value` table of HTTP headers attached to every
  request to that provider, so a gateway can enforce **region pinning** or
  **zero-data-retention** at the edge. Threaded into the two primary cloud
  clients (`anthropic`, `openai`) today. Empty by default.

```toml
[providers.anthropic]
api_key = "${ANTHROPIC_API_KEY}"
base_url = "https://anthropic-eu.gateway.internal"   # region-pinned gateway
[providers.anthropic.default_headers]
anthropic-region = "eu"
x-no-retention = "1"
```

For application-layer default-deny model egress, use the enterprise egress lock
(`[enterprise] mode = true`), which pins every governed role to a self-hosted
provider — see `docs/security-hardening.md`. A hard no-egress boundary also
requires sandbox network isolation and host/OS/VPC egress policy. Outbound PII
can also be stripped before any cloud call with
`[privacy] redact_egress = true`.

## Learning & workforce sections

Governed, in-process learning defaults **on**. Operators can opt out globally
from the dashboard Learning page or disable individual sections below. This
default does not grant higher-authority actuation: generated executable tools,
third-party MCP acquisition, live workflow auto-apply, model-weight adoption,
and DGM code self-modification retain separate controls. If an active config
source is invalid, the learning defaults fail closed instead of enabling.

```toml
[telemetry]                # trajectory donation -> the training corpus (default off)
donate_trajectories = true # write scrubbed run records to ~/.maverick/outbox/
donate_text = false        # ALSO keep raw draft/candidate text -- DPO needs it,
                           #   but it's an egress decision (off => metadata only)
donate_min_entropy = 0.5   # swarm-disagreement floor; a single-agent run has
                           #   entropy 0, so set 0 to capture EVERY successful run
donate_min_confidence = 0.75  # verifier-confidence floor to donate a run
# Feeds `maverick.training.ingest` / `export_texts` -> PRM/DPO. Full recipe
# (incl. best-of-N pair mining) in docs/self-learning-runbook.md.

[dreaming]                 # offline experience consolidation (default on)
enable = true
# min_cluster / insight_ttl_days / retire_skills / rehearse / prune_facts /
# snapshots / promote_shared -- see FEATURES.md "Dreaming".
user_notes = false         # separate privacy opt-in: verbatim cross-chat preferences
trusted_insight_pubkeys = []   # peers for `maverick insights-import`

[data_engine]              # Cognitive Data Engine flywheel (default on)
enable = true              # causal failure triage -> guardrails -> habits
# Reads the trajectory store; mutates nothing until enabled. `maverick flywheel`.

[operations_scientist]     # discover + prove a better process (default on)
enable = true              # propose a swap, validate it in the world-model first

[consequence]              # reality is the reward (default on)
enable = true              # a recorded outcome overrides the verifier proxy
# Feed outcomes via `maverick record-outcome` or POST /api/v1/outcomes.

[emergent_protocol]        # auditable coordination shorthand (default off)
enable = true              # learn short codes for repeated boilerplate; every
                           # code decodes EXACTLY back to English. `maverick codebook`.

[emergent_codec]           # token-aware codec, live measurement (default off)
enable = true              # measure (never apply) the codec's token savings on
                           # the real coordination stream; GET /api/v1/codec.

[reflexion]                # cross-run failure lessons (default on)
enable = true

[self_harness]             # conservative harness learning (default on)
enable = true              # mine failures -> propose -> regression-validate ->
                           #   gate. Promotion ALSO needs [self_improvement]
                           #   enable. Operator commands: `maverick self-harness
                           #   show` (what was learned), `preview` (dry-run of
                           #   what it would propose), `log` (audit trail), and
                           #   `forget` (roll a learned line back).
# A clean install uses the conservative unattended profile below. Existing
# partial [self_harness] tables retain their explicitly configured lifecycle
# settings during upgrade. Details: docs/self-learning.md.
risk_limited = true              # require >=8 held-out
#                                cases, 2% effect floor, two-arm 95% confidence
#                                floor, sealed best-of-3, 3 judge votes, recent
#                                calibration, metamorphic checks, one promotion,
#                                operational caps, and canary staging. Requires
#                                an explicitly provisioned holdout ledger and the
#                                exact deployed system prompt. Constituent knobs
#                                may only tighten; fixed search/query
#                                multiplicities cannot be raised. Does NOT turn
#                                either `enable` flag on.
#   holdout_ledger = "/protected/self-harness-holdout.db"
#                                durable cross-cycle query/alpha accounting;
#                                provision with `maverick self-harness holdout
#                                provision --path <path>` before risk-limited use
#   eval_corpus = "/path.json"   {model|domain: [{goal, expected}]} — enables
#                                the auto-built live A/B on scheduled runs
#   eval_budget_dollars = 5.0    spend cap per auto-evaluated cycle (fail-closed)
# Environment: MAVERICK_SELF_HARNESS_EVALUATOR_IMAGE selects a reviewed local
# Linux image (never pulled; default request `python:3.12-slim`).
# MAVERICK_SELF_HARNESS_REQUIRE_INDEPENDENT_CUSTODY=1 requests confirmatory
# custody and currently fails closed on local/Windows deployments because the
# controller account also administers the ledger and Docker daemon.
auto_run = true                  # run the fleet cycle on the dashboard's overnight
#                                schedule, or as part of `maverick dream`.
#                                Learning shows the last review receipt. The
#                                dashboard starts this schedule even if dreaming
#                                is off; UI changes apply without a restart.
#                                One evaluation allowance is shared across the
#                                fleet and an eligible transfer sweep. Reviews
#                                remain inspection-only without evaluation cases
#                                or authority for additional model calls. The
#                                careful profile holds changes back without the
#                                exact deployed prompt and independent checks.
#   promote_as_canary = true     stage every promotion on probation
#   relapse_failure_share = 0.5  re-probate a line whose recent outcomes turn bad
#   metamorphic = true           reject lines overfit to exact goal wording
#   judge_samples = 3            self-consistency majority vote for the judge
#   calibrate_judge = true       feed judge verdicts into the drift freeze
#   transfer_auto = true         nightly cross-model transfer of proven lines
#   corpus_harvest = "propose"   bootstrap eval cases from hindsight pairs
#                                ("propose" = human-gated review; "auto" = direct)
#   mine_bucket_by = ["domain"]  scope mining/recall per domain / role / tool
#   store = "world"              learning stores AND the eval-corpus family in the
#                                shared world database so a multi-host fleet learns
#                                as one (default "files"; import a host's files with
#                                `maverick self-harness migrate-store`; hand-edit via
#                                `corpus export` / `corpus import`)

[self_learning]            # governed local learning (default on)
enable = true
create_tools = false       # generated executable code remains a separate opt-in
allow_mcp_acquisition = false # legacy setting; catalog MCP acquisition is unavailable
allow_provider_egress = false # extra learning-only model calls may cross providers
preflight = true           # default uses a local redacted catalog match; the
                           # LLM needs-analysis call requires provider egress above
distill_local = true       # stages a suggestion; review and add it from Skills
auto_distill = false       # a model writes a recallable skill straight from each
                           #   finished run (untrusted run text: keep off unless
                           #   reviewed). MAVERICK_AUTO_DISTILL, when set, decides.
                           #   Existing saved and built-in skills are never replaced.
provision_packs = true     # equip a freshly-approved pack with the skills + tools
                           #   its workflow needs at creation time (capability
                           #   provisioning at pack-birth). Default on once
                           #   self-learning is enabled; the wizard sets it.
                           #   Read-only analysis is always safe; applying it is
                           #   gated on the same human approval `save_profile`
                           #   requires and never widens the clamped envelope.
                           #   Wired into `maverick onboard`. See FEATURES.md.

[ekko]                     # client-controlled work discovery (default OFF)
enable = false             # independent of self-learning and DGM
retention_days = 14        # raw local events; runtime clamps to 2..30
enrollment_days = 30       # device consent expiry; runtime clamps 1..90
min_occurrences = 3        # repeated sequences required; runtime clamps 2..100
min_distinct_days = 2      # avoid one-off bursts; 2..retention_days
poll_interval_seconds = 5  # injected collector cadence; runtime clamps 1..300
capture_level = "application_metadata" # or "guided" action labels
allowed_apps = []          # positive allowlist; empty means observe nothing
blocked_apps = ["email", "outlook", "gmail", "chat", "teams", "slack",
                "crm", "salesforce", "erp", "sap", "database"]
provider_egress = false    # reserved/unsupported; true fails closed
# Enabling policy does not enroll a device, start a service, request OS
# monitoring permissions, save a generated flow, or activate automation.
# See ekko-work-discovery.md and `maverick ekko --help`.

[self_improvement]         # promotion ladder for learned guidance (default on)
enable = true
factory_learning = true    # close the loop onto generation quality: attribute
                           #   provisioning/approval gaps to a pack's suite/signal,
                           #   mine them into proposer corrections, promote on the
                           #   `prompt` rung, and fold into future pack generation.
                           #   Default on once self-improvement is enabled; the
                           #   wizard sets it. Force-enable via MAVERICK_FACTORY_LEARNING.
                           #   `maverick factory-learn [--dry-run]`. See FEATURES.md.
evaluator_evolution = true  # promote a BETTER judge instead of only freezing when
                           #   the evaluator drifts: a challenger evaluator replaces
                           #   the incumbent only when its agreement with a fixed,
                           #   checksum-locked ground-truth ANCHOR (by the eps-best-
                           #   belief lower bound) beats it, on a dedicated `evaluator`
                           #   rung. The anchor is immutable (governed by `python -m
                           #   maverick.evaluator_evolution --ci`) so a weak judge
                           #   can't launder drift. An evaluator swap still needs
                           #   human approval until max_auto_rung = "evaluator".
                           #   Override via MAVERICK_EVALUATOR_EVOLUTION. See FEATURES.md.
evaluator_eps = 0.05       # confidence level of the eps-best-belief lower bound used
                           #   for evaluator promotion (lower = more conservative).
prm_backend = "null"       # step scorer: null | heuristic | remote | learned | linear
prm_endpoint = ""          # remote scorer address (https, or http on loopback)
prm_api_key = ""           # remote scorer key (sealed when set from the dashboard)
prm_path = ""              # learned-model folder or linear artifact file
                           #   Each MAVERICK_PRM* variable, when set, wins over its key.

[self_modify]              # research-only code DGM (default off)
enable = false             # dashboard/API arming changes only this gate
editable_paths = []        # readiness needs a narrow reviewed allowlist
eval_tests = []            # readiness needs at least two discriminating tests
# Arming does not start a cycle and never authorizes code adoption or deployment.
# Readiness additionally requires [self_improvement] enable, a clean learning
# HALT state, a Git snapshot/budget preflight, and an external sandbox SDK
# backend (`[sandbox] backend = "ep:<name>"`) that enforces no egress/non-root,
# bounded output, and the controller-owned `maverick.test-evidence.v1` protocol.
# Bundled sandboxes are deliberately not DGM-attested; stdout/JUnit files do not
# satisfy this boundary. See `docs/security/dgm-evaluator-evidence.md`.

[domains]                  # specialist-pack behavior (defaults shown)
discipline = true          # suite operating-discipline appended at spawn
memory = true              # department lessons injected at spawn

[workforce]                # treat each agent like a hire (defaults shown)
levels = false             # per-agent autonomy levels (observe/suggest/request/
                           #   auto). OFF -> every agent stages actions for human
                           #   execution. Per-agent overrides: [workforce.agents].
                           #   Env: MAVERICK_WORKFORCE_LEVELS.
data_grounding = true      # auto-grant each analyst pack its suite's primary-
                           #   source data connectors (SEC EDGAR, FRED, openFDA,
                           #   USAspending, weather, ...). GET-only, low-risk,
                           #   deferred (no context cost), inert without each
                           #   source's API key. Set false to withhold them.
                           #   Env: MAVERICK_WORKFORCE_DATA_GROUNDING.

[fleet_memory]             # external agents read/write governed memory
enable = false             # explicit trust decision; per-agent data_scopes
                           # apply even when global trust enforcement is off

[cortex]                   # Cortex, the company brain (default on)
enable = true              # one governed recall/deposit surface over knowledge
                           #   (cited), skills, self-harness lessons, the
                           #   Operating Record and fleet memory: tenant-exact,
                           #   one audit row per read and per write. Each
                           #   source's own toggle still applies. Operator
                           #   External callers can use only scoped fleet memory;
                           #   other Cortex sources remain internal.
                           #   commands: `maverick cortex status|recall|deposit`.
                           #   Env: MAVERICK_CORTEX.

[knowledge_access]         # current-rights Knowledge page and API (default on)
enable = true              # exact registry versions only; every display/cache/
                           #   export rechecks purpose, requested action, source
                           #   checksum, approval, freshness, consent, lineage,
                           #   and current named-user authority. Explicit false
                           #   disables the page and API. Env override:
                           #   MAVERICK_KNOWLEDGE_ACCESS.

[commerce]                 # Commerce suite tools (com_shop_* / com_merch_* packs)
enable = false             # explicit opt-in; env: MAVERICK_COMMERCE
backend = "demo"           # in-memory reference backend; a real storefront/
                           #   merchant system registers via
                           #   maverick.commerce.register_backend(name, factory)
max_session_spend = 500.0  # cart subtotal cap per session (store currency)
max_line_quantity = 10     # per-line quantity cap
max_cart_lines = 25        # distinct lines per cart
# The caps, the provenance gate, staged writes (only a human approval token
# applies a price/inventory/listing/campaign/order change) and the opaque
# checkout handoff are enforced in maverick.commerce, not in prompts. The
# agent never sees payment, address, or checkout-page details.
[shoring]                  # Autonomous Shoring engagement tooling (dashboard
                           #   /shoring: book of work, measured SLAs, exception
                           #   desk). ON by default — a kill switch, not a gate.
enable = true              # set false to hide the surface. Env: MAVERICK_SHORING.

[billing.stripe]           # Platform billing collection (maverick.billing_stripe):
                           #   turn metered-usage invoices into real Stripe charges.
enable = false             # explicit opt-in; env: MAVERICK_STRIPE_ENABLE
bill_metered_usage = false # false bills only the
                           #   recurring platform fee; true also pushes the metered
                           #   model-usage line items (no markup is set here — the
                           #   amounts come from whatever RateCard rated the invoice).
                           #   Env: MAVERICK_STRIPE_BILL_METERED
currency = "usd"
# The secret key and webhook signing secret are NEVER read from config — they
# come from the environment (via the secret provider):
#   MAVERICK_STRIPE_SECRET_KEY, MAVERICK_STRIPE_WEBHOOK_SECRET
[billing.stripe.prices]    # plan id -> Stripe recurring price id (the platform fee)
# pro = "price_..."        # a plan with no price here is billed no platform fee
# enterprise = "price_..."
# Operator surface: `maverick billing stripe-status`, `stripe-preview <tenant>`
# (dry-run), `stripe-sync <tenant>`. A failed-payment webhook downgrades a tenant
# to the base entitlement tier; a recovered payment restores it. The `stripe` SDK
# is an OPTIONAL extra: `python -m pip install -e './packages/maverick-core[stripe]'`
# from the repository root (or add `stripe` to `--core-extra` when running
# `scripts/install_release_cohort.py`).

[suites]                   # disable whole suites (all on by default)
# healthcare = false
```

## Per-role model choice

This is the *fully control every aspect* knob. Heavy roles benefit from a smart model; cheap roles can use a small one. Mix providers freely — the orchestrator can be a cloud Opus while the summarizer is a local Llama.

Roles available:

| Role | Used for |
|---|---|
| `orchestrator` | Plans, decomposes, verifies. Wants the smartest model. |
| `researcher`   | Searches, gathers info. Workhorse. |
| `coder`        | Writes and tests code. |
| `writer`       | Drafts long prose. |
| `analyst`      | Synthesizes findings. |
| `revisor`      | Second-pass review when verify fails. |
| `verifier`     | Independent final-answer check. |
| `summarizer`   | Cheap distillation. |
| `skill_distiller` | Turns trajectories into reusable skills. |

## Env vars vs config

- **Secrets** (API keys, bot tokens) live in `~/.maverick/.env` (chmod 600) and are referenced via `${VAR}` interpolation in operator-owned `config.toml`. Dashboard and tenant configuration values are literal and do not expand process environment variables; move any existing references into an operator-owned configuration layer.
- **Everything else** lives in `config.toml` and is safe to commit (e.g. to a personal dotfiles repo).

The installer keeps these separated automatically.

> **Config typos are caught, not silently ignored.** `maverick config-lint`
> (also surfaced as advisory `config-lint` rows by `maverick doctor`, and emitted
> as a one-line warning at process startup) walks the loaded config against a
> known-section/key schema
> and flags a mistyped section or an unknown key in a fixed-key section (with
> `difflib` "did you mean" suggestions), plus a few obvious type errors. This
> catches the classic footgun where a typo like `[budget] max_dollarss` would
> otherwise be silently ignored and the run go **uncapped**. The check is
> advisory; configured policy gates refuse work when their configuration
> cannot be read, so after editing
> `config.toml` by hand, run `maverick config-lint` (or `maverick doctor`) and
> confirm the security/cost-critical values (`[budget]`, `[enterprise]`,
> `[encryption]`, `[audit]`, `[safety]`) read back as you intend.

## Overriding the config path

```bash
MAVERICK_CONFIG=/etc/maverick/config.toml maverick start "..."
```

Useful for VPS deployments where you want the config under `/etc/`.

## Document conversion

The Pandoc tool accepts a restricted set of built-in formats and basic options;
PDF output is currently unavailable; it requires an isolated document worker.
Rich document conversion can read referenced files or fetch resources. Run it
only in an isolated workspace without secrets and with network access disabled.
The ImageMagick tool similarly accepts only bounded basic conversion options;
untrusted image formats can invoke decoders or refer to external resources, so
use the same isolation for image processing. FFmpeg accepts a restricted set
of conversion options and permits only file, crypto and data input protocols,
but media files can still reference other local files; use an isolated workspace
for those too.

## WebSocket connections

The WebSocket tool connects directly to its validated, pinned destination and
does not follow redirects or use implicit proxy settings. Use the final URL;
deployments that require a proxy need a separately configured safe egress path.

## Incoming email authentication

Configure a trusted receiving mail server that removes inbound
`Authentication-Results` headers and adds its own. Email-driven work requires
that server's topmost result to contain one aligned DMARC pass. The parser
fails closed on quoted `header.from` values and DMARC method versions; verify
the format emitted by your mail server before enabling email-driven work.

## Dashboard authentication

For desktop installs the dashboard binds to `127.0.0.1:8765` and bearer
auth is optional. For VPS deploys (reachable from the open internet)
set `MAVERICK_DASHBOARD_TOKEN` — every request to `/api/v1/*` and every
HTML page is then gated. The probe paths `/healthz`, `/livez`, `/readyz` and
the agent-card well-knowns are exempt. Public probes return status only;
authenticated administrators can inspect `/api/v1/admin/system/probe-details`.
The OpenAPI schema and reference pages require authentication. In static-token
mode, use an authenticated API client for the schema; interactive reference
pages require a browser session that authenticates their assets and requests. The
inbound webhook routes (`/webhook/start`, `/webhook/run`, issue webhooks)
and the `/share/`, `/scim/`, `/saml/` prefixes authenticate by their own
mechanism (HMAC signature / share token / SSO) rather than the bearer.

API clients authenticate with `Authorization: Bearer <token>`. Dashboard
tokens in URL query strings are not accepted. Use a named browser session for
interactive access.

Token comparison is constant-time (`hmac.compare_digest`).

A shared dashboard token has no named owner whose access can be rechecked
later. Creating or changing a webhook or event trigger, or creating an executive
report schedule, therefore requires a named account or genuine local auth-off mode.
Existing triggers can still be inspected or removed; older token-owned records
may need to be recreated under a named account before they can run.

Authenticated accounts without an explicit role or verified group mapping
default to `viewer`. Assign `operator` or `admin` deliberately before granting
the ability to run work or decide approvals. If no workspace-role roster has
been initialized, installations may explicitly set `[dashboard] default_role =
"operator"` to restore the previous fallback. Once workspace roles are in use,
unassigned users need an explicit global assignment or workspace membership.
The viewer role still grants read access where `view` permission is sufficient.

## External MCP servers

Lightwork can consume any MCP server (filesystem, GitHub, Postgres,
browser, etc.) as tools. Add entries under `[mcp_servers.<name>]`:

```toml
# stdio: spawn a local subprocess
[mcp_servers.filesystem]
command = "npx"
args    = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

# remote: connect to a server over Streamable HTTP (set `url` instead of `command`)
[mcp_servers.remote]
url        = "https://mcp.example.com/mcp"
auth_token = "..."                      # optional; sent as `Authorization: Bearer …`
# headers  = { X-Org = "acme" }         # optional extra request headers
```

Behavior:

- A `command` server is spawned as a stdio subprocess on swarm start and
  torn down on goal completion. A `url` server is reached over HTTP
  (Streamable HTTP, spec 2025-11-25) — `tools/list` + `tools/call` over
  JSON or SSE, with session-id continuity; no subprocess. OAuth 2.1 isn't
  wired yet, but a static bearer (`auth_token`) is.
- Every tool it exposes is registered as `mcp_<name>__<tool>` in the
  agent's catalog and passes through `Shield.scan_tool_call` like any
  other tool.
- By default the child inherits only the allowlisted environment variables:
  `PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`, `TZ`, `TMPDIR`, `TEMP`, `TMP`,
  `NODE_PATH`, `NVM_DIR`, `NPM_CONFIG_PREFIX`, `SHELL` and `PWD` (see
  `mcp_client.DEFAULT_ENV_ALLOWLIST`). Pass secrets explicitly via the
  `env = { ... }` table or set `inherit_env = true` to pass the full
  environment (only do this for fully-trusted servers).
- A background reader drains stderr to prevent pipe-buffer deadlocks
  when a server logs verbosely.

## Concurrency cap

The dashboard, REST API, and MCP server all share a process-wide
semaphore that bounds the number of swarms running in background
threads simultaneously. Override with:

```bash
MAVERICK_MAX_CONCURRENT_GOALS=4 maverick dashboard
```

Default is 16. Raise on a beefy machine; lower on a Raspberry Pi. (A
separate per-principal cap also limits concurrent goals from any one caller.)

## Swarm size

One goal may create up to 64 agents by default. To run larger swarms, raise
the cap and bound the goal's model calls so the swarm queues for the provider
instead of tripping its rate limits (the installer asks both):

```toml
[swarm]
max_total_spawns = 256          # agents one goal may create (default 64)
max_concurrent_model_calls = 16 # model calls in flight per goal (0 = unbounded, the default)
finding_post_max_chars = 1500   # how much of a helper's final answer is posted to the shared board (min 200)
```

`MAVERICK_MAX_TOTAL_SPAWNS`, `MAVERICK_MAX_CONCURRENT_MODEL_CALLS` and
`MAVERICK_FINDING_POST_MAX_CHARS` override these. The per-call fan-out cap and the goal's budget still apply at any size.

## Runtime settings on Settings > All settings

These keys were environment variables only, or were read by code nothing
called. Each is now used by the running product and can be changed on
Settings > All settings; the environment variable in the comment, when set,
still wins, and an unset key keeps the behaviour shown as the default.

```toml
[memory]
learning_cache = false        # MAVERICK_LEARNING_CACHE: start a repeated task from its checked answer
weaviate_grpc_host = ""       # MAVERICK_WEAVIATE_GRPC_HOST (default: the weaviate_url host)
weaviate_grpc_port = 50051    # MAVERICK_WEAVIATE_GRPC_PORT (443 for a standard HTTPS address)
weaviate_vectorizer = ""      # MAVERICK_WEAVIATE_VECTORIZER (default text2vec-transformers)

[tools]
exposure = "core"             # MAVERICK_TOOL_EXPOSURE: "core" describes a short role-aware tool list on each
                              # request (a specialist pack sees its own allow_tools) and agents look the rest
                              # up with find_tools; "full" offers more up front, up to the model's tool limit
core_extra = []               # tool names always described as well as the short list
speculative = false           # MAVERICK_SPECULATIVE_TOOLS: read ahead for repeated look-ups (needs output_cache)
openapi_spec_max_bytes = 10000000   # MAVERICK_OPENAPI_SPEC_MAX_BYTES (read at startup)
openapi_call_max_bytes = 1000000    # MAVERICK_OPENAPI_CALL_MAX_BYTES (read at startup)

[models]
embed = ""                    # MAVERICK_EMBED_MODEL (default BAAI/bge-small-en-v1.5)
clap = ""                     # MAVERICK_CLAP_MODEL (default laion/clap-htsat-unfused)
openai_max_tools = 128        # MAVERICK_OPENAI_MAX_TOOLS (read at startup); overflow remains discoverable through find_tools

[energy]                      # used by the energy_accounting tool's estimates
wh_per_1k_tokens = 0.3        # MAVERICK_ENERGY_WH_PER_1K_TOKENS
grid_co2_g_per_kwh = 400      # MAVERICK_ENERGY_GRID_CO2_G_PER_KWH

[logging]
crash_log = false             # MAVERICK_CRASH_LOG: fsync'd copy of warnings/errors in logs/crash-only.jsonl
crash_only_fsync = "always"   # MAVERICK_CRASH_ONLY_FSYNC: or "never" (faster, may lose the last lines)

[replay]
record = false                # MAVERICK_TRACE_DIR (set = on, in that folder): record each task's steps
trace_dir = ""                # default: Lightwork's own traces folder

[security]
network_policy = "open"       # "allowlist" or "deny-all"; enforced (web tools + work area), see below

[sandbox]
network_policy = ""           # "deny-all": the work area never gets internet (Kubernetes verifies it)

[perf.profiling]              # started with the dashboard when enabled (needs py-spy)
enabled = false               # MAVERICK_PROFILING
interval_seconds = 300        # MAVERICK_PROFILING_INTERVAL
duration_seconds = 30         # MAVERICK_PROFILING_DURATION
format = "speedscope"         # MAVERICK_PROFILING_FORMAT: or "flamegraph", "raw"

[ebpf_monitor]
enable = false                # started with the dashboard (needs root and bpftrace)

[model_proxy]
enable = false                # started with the dashboard; the key stays in MAVERICK_PROXY_KEY
upstream = ""                 # MAVERICK_PROXY_UPSTREAM
listen = ""                   # MAVERICK_PROXY_LISTEN (default 127.0.0.1:8765)
auth_style = "bearer"         # MAVERICK_PROXY_AUTH_STYLE: or "x-api-key"
client_token = ""             # MAVERICK_PROXY_CLIENT_TOKEN (sealed when set on the page)

[tui.keys]                    # MAVERICK_TUI_KEYS ("quit=x,refresh=g"); keys of `maverick monitor`
# quit = "q"

[director.profiles.supervised] # `maverick start --director supervised "<outcome>"`
# consent_mode = "ask"
# budget_multiplier = 0.5      # clamped to the configured spending cap
# dollars = 2.0                # review checkpoint
# tool_calls = 25

[agent_factory]
jd_hiring = true              # Agent Factory: draft or match agents from a job description
require_passing_tests = true  # changed instructions publish only after every saved test passes (or with a recorded reason)

[agent_tests]
# Saved answer checks that gate publishing (maverick.agent_tests_policy). The defaults keep today's behaviour.
max_cases_per_specialist = 20          # 1 to 200: saved checks one specialist can keep; one run checks at most this many.
                                       # Lowering it keeps saved checks, but a set larger than the limit cannot pass a full run.
require_for_new_specialists = false    # true: a specialist never published before needs a saved check and a passing full
                                       # run of every check on its exact draft. A reason does not skip this. Business setup,
                                       # customization bundles and the CLI (onboard, learn-demo) cannot add a new specialist
                                       # while it is on; add it in Agent Factory instead.
bypass_requires_second_person = false  # true: publishing changed instructions without a passing run (with a reason) needs
                                       # another administrator's approval on the Approvals page or in chat. The requester cannot approve it
                                       # on either. Rejecting is never refused.
tool_checks = false                    # true: a saved check may say which tools the specialist must call, must not call, and
                                       # what the call must include. Tools run as recording stubs with fixed answers; nothing real runs.
                                       # While false, such checks cannot be created and any existing ones are skipped (never counted as passing).
canary_percent = 0                     # 0 (off): publishing changed instructions replaces the current version, as before.
                                       # 1 to 50: the changed version is a trial on that share of NEW goals (chosen by goal id);
                                       # the rest keep the current version. Goals already running are not changed. Each goal
                                       # records which version it used. Promote or roll back the trial in Workforce. Only one
                                       # trial per specialist; a second change is refused until then. A new specialist publishes normally.
                                       # Goals that ran before or after a trial record no version. Work a trial goal hands to other
                                       # specialists, and public chat, use the current version. Unreadable settings publish nothing.
canary_auto_rollback = false           # true: roll the trial back on its own once at least 10 of its goals have finished and its
                                       # failed share is more than 20 percentage points above the current version's. Recorded in the
                                       # activity log. It needs a finished goal on the current version to compare with, and it is
                                       # checked at most once a minute. Unreadable settings or a value other than true leave it off.

[autonomy]
confirm_plan = false          # show the plan in Approvals and wait before a task's first action that reaches outside Lightwork

[practice]
enable = true                 # offer practice mode: a separate practice workspace where nothing is sent, paid or changed
daily_spend_cap = 1.0         # dollars per person per day for AI in practice: real provider cost, counted apart
                              # from real spending limits and never above one that applies

[analytics]
task_questions = true         # Insights page questions (need the dashboard's "duckdb" extra)
usability_survey = false      # optional ease-of-use survey (SUS + one question after top tasks); answers stay local
web_vitals = false            # optional page speed for real visitors (LCP, INP, CLS, p75 per page); counts stay local
web_vitals_sample_rate = 0.5  # share of visits measured when web_vitals is on (0 to 1)
usage_measures = false        # optional name-free counts: first result in the first session, AI suggestions used or dismissed

[collaboration]
comments = true               # comments and @mentions on tasks, runs, approvals and policies; mentions reach personal notifications
suggestions = true            # agents and colleagues suggest edits to AI use rules, data use rules and privacy notices; accepting creates a draft that keeps its own approval
ai_suggestions = true         # the AI assistant drafts a suggested edit when a person asks (within the per-task spending cap)

[env_hunt.enrichment_sources.intel_feed]  # a lookup service your server registered
enable = true

[mcp]                         # tool server for outside apps: every MAVERICK_MCP_* variable
token = ""                    # MAVERICK_MCP_TOKEN (sealed when set on the page)
http_tasks = false            # MAVERICK_MCP_HTTP_TASKS
rate_limit = 600              # MAVERICK_MCP_RATE_LIMIT (per minute; 0 = none)
# also: max_body_bytes, max_resource_sessions, allowed_origins, sse_heartbeat,
# sse_max_progress_events, max_dollars, max_wall_seconds, elicitation_timeout,
# elicit_allowed_hosts, max_depth, max_elicit_rounds, max_tasks,
# max_tasks_per_owner, task_ttl_ms, task_max_ttl_ms, task_poll_ms,
# task_result_block_ms, task_workers
```

Read once when the process starts (the environment still wins):
`[agent] loop_guard`, `loop_guard_threshold`, `loop_guard_block`,
`step_budget_warning`, `max_concurrent_goals`,
`max_concurrent_goals_per_principal`; `[latency] retry_attempts` (3),
`retry_base_delay` (1.0), `retry_max_delay` (30.0); `[swarm] max_fanout` (8),
`default_max_depth` (3); `[verification] confidence_accept` (0.75),
`disagreement_high` (0.5); `[compaction] keep_recent`, `digest_every`,
`max_tool_bytes`, `max_total_bytes`; `[attachments] max_file_bytes` (100 MiB),
`max_goal_bytes` (500 MiB).

`[security] network_policy` is enforced, never only displayed: `deny-all`
removes the web tools (http_fetch, web_search, browser, websocket, webrtc) and
keeps the work area offline (container backends start without a network, the
`local` backend must become a container or is refused, and `ssh` is refused);
`allowlist` lets the web tools reach only hosts on a tool's `allow_egress` or
`[egress] allow` list, removes web_search and webrtc, and keeps the work area
offline. A value it does not know blocks everything.

`[ekko] provider_egress` stays off: Ekko has no reviewed network path, so the
setting page refuses to turn it on.

## Upload size

The dashboard refuses any request larger than 600 MB (above the largest batch
of task attachments one request may carry) before reading it, with a plain
"That upload is too large" message:

```toml
[dashboard]
max_request_mb = 600   # MAVERICK_DASHBOARD_MAX_REQUEST_MB overrides
```

## Spending limits

There is no spending limit by default. An administrator sets limits in the
dashboard under **Admin > Spending limits**, for the workspace they are in:

- **Whole workspace:** the most everyone together may spend per day or month.
- **Everyone:** a limit each person gets on their own, per task, day or month.
- **A named person:** replaces the limit for everyone for that person.

When a limit is reached, new work is refused and running work stops before its
next paid step, with a plain message naming the limit. Every change is recorded
in the audit trail (`spending_limits_changed`). The installer's advanced step
can seed starting limits; what an administrator saves in the dashboard wins:

```toml
[spending_limits]
workspace_dollars = 500.0       # 0 or unset = no workspace limit
workspace_period = "month"      # "day" or "month"
default_user_dollars = 50.0     # 0 or unset = no limit for each person
default_user_period = "month"   # "task", "day" or "month"
typical_cost_min_runs = 10      # finished tasks needed before a typical cost shows
```

Beside the task form on **Teams** and in a specialist's or agent's **Check
access** panel, Lightwork shows what that agent's or specialist's past runs
usually cost: the middle half (25th to 75th percentile) and the median of its
most recent finished tasks in this workspace. It is recorded history, never a
prediction. With fewer finished tasks than `typical_cost_min_runs` (2 to 1000,
default 10) it says there are not enough past runs yet.

Spend is counted from the usage ledger plus runs still going in the dashboard
process. Runs in separate worker processes are counted once they settle, so
several of them running at once can pass a limit by what they spend before
settling. A workspace provisioned on **Workspaces** can also carry a daily cap;
whichever limit is reached first applies. New workspaces have no daily cap.

## Go-live check

`maverick launch-check` verifies the deliberate production switches are on and
exits non-zero if any is off, so a deploy pipeline can gate on it. It is
distinct from `maverick doctor` (which checks whether the install *works*). Each
row reads real config/env:

- a workspace or everyone limit in **Admin > Spending limits**, or
  `[quotas] enforce = true` with at least one non-zero cap (cost governance);
- `[tenancy] by_user = true` (per-user tenant isolation);
- at-rest encryption on (`[encryption] at_rest` / `MAVERICK_ENCRYPT_AT_REST`);
- a provider credential resolvable (an API key or a `[providers.<name>]` table).

Onboard a tenant and mint its first admin in one step with
`maverick tenant onboard <id> --admin-email <email> --plan <plan>`.

## Environment variables

Most settings live in this file, but many can be overridden (or only set) via
`MAVERICK_*` environment variables — see **[Environment variables](env-vars.md)**
for the full reference.
