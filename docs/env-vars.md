# Environment variables

Lightwork's primary configuration is `~/.maverick/config.toml` (see
[configuration.md](configuration.md)). The `MAVERICK_*` environment variables
below are a complement: they override the equivalent config keys when set, and
expose a handful of knobs that have no config equivalent. **Env vars win over
config.** Most users never need to set any of these — the defaults are the
out-of-the-box behavior. They're documented here for operators tuning a
deployment.

Boolean vars accept `1`/`true`/`yes`/`on` for true and `0`/`false`/`no`/`off`
for false unless noted otherwise.

## Core / run

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_CONFIG` | `~/.maverick/config.toml` | Path to an alternate config file. |
| `MAVERICK_CODING_MODE` | unset | When `1`/`true`/`yes`, switches the agent into coding mode (set by `maverick start --coding-mode`); affects prompts, fs/shell tool defaults, and cache TTL. |
| `MAVERICK_LANGUAGE` | unset | Primary project language hint (e.g. `python`, `go`). Feeds sandbox/toolchain selection and coding mode. |
| `MAVERICK_MAX_STEPS` | unset | Optional explicit cap on agent loop steps per goal. Ordinary goals have no generated step cap. |
| `MAVERICK_STEP_BUDGET_WARNING` | `3` | When this many tool-using turns remain before `MAVERICK_MAX_STEPS`, the loop nudges the agent to give its FINAL answer (so a long run isn't cut off mid-work). `0` disables. Also `[agent] step_budget_warning` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MAX_SWARM_FANOUT` | `8` | Max child agents a single spawn call may branch into. Also `[swarm] max_fanout` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MAX_TOTAL_SPAWNS` | `64` | Cap on the agents one goal may create (overrides `[swarm] max_total_spawns`). |
| `MAVERICK_MAX_CONCURRENT_MODEL_CALLS` | `0` (unbounded) | Model calls in flight at once across one goal's swarm (overrides `[swarm] max_concurrent_model_calls`). |
| `MAVERICK_MAX_CONCURRENT_GOALS` | `16` | Global ceiling on goals running in parallel — a host-overload backstop, sized so normal multi-user load never reaches it. Also `[agent] max_concurrent_goals` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MAX_CONCURRENT_GOALS_PER_PRINCIPAL` | `3` | Per-user concurrency lane: one principal can run this many goals at once without blocking other users (fair scheduling). Also `[agent] max_concurrent_goals_per_principal` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_GOAL_ACQUIRE_TIMEOUT` | `300` | Seconds to wait for a goal-execution slot (per-user lane, then global) before giving up. |
| `MAVERICK_PARALLEL_TOOLS` | `1` (on) | Set `0` to run tool calls within a turn serially instead of in parallel. |
| `MAVERICK_LOOP_GUARD` | `1` (on) | Set `0` to disable the repeated-failure loop guard (nudges the agent when it re-issues the same failing tool call). Also `[agent] loop_guard` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_LOOP_GUARD_THRESHOLD` | `3` | Consecutive identical tool-call failures before the loop guard nudges (min 2). Also `[agent] loop_guard_threshold` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_HALT_FILE` | `~/.maverick/HALT` | Killswitch path; the run aborts if this file exists. |
| `MAVERICK_NO_CLI` | unset | `1` marks embedded mode: skips third-party plugin auto-discovery and CLI-only paths. |
| `MAVERICK_NO_PROGRESS` | unset | Set to suppress the live progress display. |
| `MAVERICK_DEBUG` | unset | `1` re-raises original exceptions and prints full tracebacks instead of friendly errors. |
| `MAVERICK_NO_WIZARD` | unset | `1` runs the installer non-interactively (used by the unattended install scripts). |

## Budget & limits

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_BUDGET_DOLLARS` | config `[budget]` | Override the dollar budget cap for a run. |
| `MAVERICK_BILLING_STRICT` | `true` | Require verified pricing for live accounting. `false` explicitly enables warning-labelled estimate-only accounting for legacy/custom gateways. |
| `MAVERICK_DEFAULT_MAX_DOLLARS` | unset | Optional deployment goal default; Settings and `[budget] max_dollars` take precedence. Without a config file, omitted goals use $2. Existing config files with no task cap keep that choice. The task-limits switch can disable defaults. |
| `MAVERICK_DEFAULT_MAX_WALL_SECONDS` | unset | Optional deployment goal wall-clock default, in seconds. Without a config file, omitted goals use 1800 seconds. Existing config files with no time cap keep that choice. |
| `MAVERICK_DEFAULT_MAX_DEPTH` | `3` | Default max recursion depth for spawned sub-goals. Also `[swarm] default_max_depth` (Settings > All settings; read at startup, this variable wins). |

Task limits and organization allowances are separate. See
[task limits and spend accounting](task-limits.md) for existing-install migration,
explicit limits, retry behavior and unknown provider charges.

## Models & routing

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_MODEL_OVERRIDE` | unset | Global run-wide model override (`provider:model-id`); set by `maverick --model`. Beats config for every role. |
| `MAVERICK_MODEL_OVERRIDE_<ROLE>` | unset | Per-role override, e.g. `MAVERICK_MODEL_OVERRIDE_CODER`. Beats the global override for that role. |
| `MAVERICK_TEMPERATURE` | provider default | Sampling temperature for LLM calls. |
| `MAVERICK_VISION_MODEL` | `anthropic:claude-sonnet-4-6` | Model used by the image/video viewing tools (`provider:model-id`). |
| `MAVERICK_EMBED_MODEL` | `BAAI/bge-small-en-v1.5` | Local embedding model id. Also `[models] embed` (Settings > All settings; this variable wins). |
| `MAVERICK_COST_ROUTING` | config `[routing] cost_aware` (off) | Enable cost-aware model routing. |
| `MAVERICK_CASCADE_ROUTING` | config `[models] cascade` (off) | Enable cascaded routing (cheap model first, escalate on need). |
| `MAVERICK_ESCALATE_BELOW` | `0.6` | Verifier-confidence threshold below which a cascade escalates to a stronger model. |
| `MAVERICK_ESCALATE_TOOL_DEPTH` | `3` | Tool-call depth at which a cascade escalates. |
| `MAVERICK_ANTHROPIC_CACHE_TTL` | `1h` (coding mode: `5m`) | Anthropic prompt-cache TTL; an explicit value always wins. |
| `MAVERICK_CACHE_MESSAGES` | `1` (on) | Set `0` to disable prompt caching of message history. |
| `MAVERICK_LLM_CACHE` | unset (off) | Enable the on-disk LLM response cache. |
| `MAVERICK_LLM_RETRY_ATTEMPTS` | `3` | Max retry attempts for failed LLM calls. Also `[latency] retry_attempts` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_LLM_RETRY_BASE_DELAY` | `1.0` | Base backoff delay (seconds) between LLM retries. Also `[latency] retry_base_delay` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_LLM_RETRY_MAX_DELAY` | `30.0` | Max backoff delay (seconds) between LLM retries. Also `[latency] retry_max_delay` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_LLM_CONNECT_TIMEOUT` | `15.0` | LLM connect timeout (seconds). |
| `MAVERICK_LLM_READ_TIMEOUT` | `120.0` | LLM read timeout (seconds). |

## Reasoning & verification

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_BEST_OF_N` | `1` | Generate N candidate solutions and pick the best. |
| `MAVERICK_BON_LADDER` | built-in ladder | Comma-separated best-of-N sample ladder for adaptive escalation. |
| `MAVERICK_BON_EARLY_EXIT` | `1` (on) | Best-of-N stops the ladder after the first candidate whose tests all pass. Set `0` to run all N attempts, so a *failing* candidate is also captured — needed to mine a DPO preference pair (pass vs fail) from one coding task. |
| `MAVERICK_TREE_OF_THOUGHT` | unset (off) | Enable tree-of-thought planning: fork candidate plans, critic selects. |
| `MAVERICK_TOT_CANDIDATES` | built-in | Number of candidate plans tree-of-thought forks. |
| `MAVERICK_REFLEXION` | config `[reflexion] enable` (on) | Override the default-on reflexion self-critique loop; set `0` to opt out. |
| `MAVERICK_DREAMING` | config `[dreaming] enable` (on) | Override default-on offline experience consolidation (`maverick dream`); set `0` to opt out. |
| `MAVERICK_SELF_HARNESS` | config `[self_harness] enable` (on) | Override the default-on conservative self-harness loop (`maverick self-harness`; promotion also needs `[self_improvement] enable`). |
| `MAVERICK_FACTORY_LEARNING` | config `[self_improvement] factory_learning` (on when the master is on) | Override the factory loop directly: `0` disables it and `1` force-enables it even if the self-improvement master is off. |
| `MAVERICK_DATA_ENGINE` | config `[data_engine] enable` (on) | Override the default-on Cognitive Data Engine flywheel: causal failure triage → guardrails → habits (`maverick flywheel`). |
| `MAVERICK_OPERATIONS_SCIENTIST` | config `[operations_scientist] enable` (on) | Override the default-on Operations Scientist: propose + simulate a better process before a real experiment. |
| `MAVERICK_CONSEQUENCE` | config `[consequence] enable` (on) | Override default-on grounding in real downstream outcomes (`maverick record-outcome`). |
| `MAVERICK_SELF_MODIFY` | config `[self_modify] enable` (off) | Arm/disarm the research-only DGM gate. Setting this env var makes the deployment environment authoritative, so the dashboard control is read-only. Arming never starts a cycle or permits live code adoption. |
| `MAVERICK_FLOWS` | config `[flows] enable` (off) | Enable the visual flow-automation engine (deterministic graph of agent/action/branch/… nodes; the dashboard designer + triggers). |
| `MAVERICK_FLOWS_AUTO` | config `[flows] auto_evolve` (off) | Let the flow self-rewrite loop act autonomously: revert a node rewrite it measures as a regression. Also toggleable from the dashboard Learning page. Improvements are never applied forward automatically; workflow suggestions always need review. |
| `MAVERICK_EMERGENT_PROTOCOL` | config `[emergent_protocol] enable` (off) | Enable the auditable coordination codec (sentinel form; `maverick codebook`). |
| `MAVERICK_EMERGENT_CODEC` | config `[emergent_codec] enable` (off) | Measure the token-aware codec on the live coordination stream (telemetry only; `maverick codec-learn`). |
| `MAVERICK_DOMAIN_DISCIPLINE` | config `[domains] discipline` (on) | Append suite operating discipline to specialist personas at spawn. |
| `MAVERICK_FLEET_MEMORY` | config `[fleet_memory] enable` (off) | Allow registered external agents to use the governed memory plane. |
| `MAVERICK_CORTEX` | config `[cortex] enable` (on) | Override the default-on Cortex surface (`maverick cortex`): one governed recall/deposit over knowledge, skills, lessons, the Operating Record and fleet memory. `0` refuses every recall and deposit (still audited); each source's own toggle applies underneath. |
| `MAVERICK_COMMERCE` | config `[commerce] enable` (off) | Register the Commerce suite tools (storefront search/compare/cart/product Q&A/orders for the `com_shop_*` packs; catalog/inventory/pricing/orders/analytics/campaign reads and staged store changes for the `com_merch_*` packs). Caps, provenance gate, staged writes, and the opaque checkout handoff are enforced in `maverick.commerce`. |
| `MAVERICK_SHORING` | config `[shoring] enable` (on) | Autonomous Shoring tooling (dashboard `/shoring`: book of work, measured SLAs, exception desk). Set `0` to hide the surface. |
| `MAVERICK_PRM` | `null` | Process reward model: `null`, `heuristic`, `remote`, `learned`, or `linear`. A linear backend reconciles durable verifier-promotion authority before serving and falls back to the heuristic for an in-doubt, unrecognized, or out-of-band artifact. |
| `MAVERICK_PRM_PATH` | unset | Learned-model directory (`learned`) or stable serving artifact (`linear`). Relative linear paths are pinned to an absolute startup path before recovery and serving. |
| `MAVERICK_PRM_BOOTSTRAP_SHA256` | unset | Explicit SHA-256 trust root for an initially provisioned `linear` artifact. Required when `MAVERICK_PRM_PATH` already exists but has no committed promotion chain; later hot reloads must match the durable ledger exactly. |
| `MAVERICK_PRM_ENDPOINT` | unset | Endpoint URL when `MAVERICK_PRM=remote`. |
| `MAVERICK_PRM_API_KEY` | unset | API key for the remote PRM endpoint. |
| `MAVERICK_VERIFY_ENSEMBLE` | config `[routing] verify_ensemble` (off) | Run the multi-model verifier panel (stronger, ~Nx cost). |
| `MAVERICK_VERIFIER_CONFIDENCE` | `0.75` | Confidence threshold at which the verifier accepts a result. Also `[verification] confidence_accept` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_DISAGREEMENT_HIGH` | `0.5` | Verifier disagreement level treated as high. Also `[verification] disagreement_high` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_CROSS_FAMILY_VERIFIER` | config-driven | Force the verifier to use a different model family than the generator. |
| `MAVERICK_SPECULATIVE_FINALIZE` | `1` (on) | Set `0` to disable speculative finalization in the orchestrator. |

## Memory & recall

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_MEMORY_DIR` | `~/.maverick/memory` | Root directory for the cross-session `memory` tool (the agent's model-curated long-term notes). |
| `MAVERICK_AUTO_RECALL` | unset (off) | Auto-recall related prior goals/facts into a run. |
| `MAVERICK_AUTO_RECALL_K` | `3` | Number of prior items to recall when auto-recall is on. |
| `MAVERICK_AUTO_DISTILL` | unset (off) | Auto-distill skills from completed runs. |
| `MAVERICK_SELF_LEARNING` | config `[self_learning] enable` (on) | Override governed self-learning; set `0` to opt out. Generated tools and MCP acquisition keep their separate off-by-default controls. |
| `MAVERICK_EKKO` | config `[ekko] enable` (off) | Controls only Ekko's master policy switch. It never enrolls a device, grants an application, starts a collector, or enables provider egress. Invalid values fail closed. |
| `MAVERICK_SKILL_DECAY` | `1` (on) | Set `0` to disable time-decay of skill usefulness stats. |
| `MAVERICK_ALLOW_SKILL_INSTALL` | unset (off) | Opt in to installing skills from free-text URLs. |
| `MAVERICK_VECTOR_STORE` | config `[memory] backend` | Semantic-recall backend: `chroma`, `qdrant`, `weaviate`, `pgvector`, or unset/`none` to disable. |
| `MAVERICK_CHROMA_PATH` | `~/.maverick/...` default | On-disk path for the Chroma vector store. |
| `MAVERICK_QDRANT_URL` | unset | Qdrant server URL (remote mode). |
| `MAVERICK_QDRANT_PATH` | default path | Qdrant local on-disk path (embedded mode). |
| `MAVERICK_QDRANT_API_KEY` | unset | API key for a remote Qdrant server. |
| `MAVERICK_WORLD_BACKEND` | config-driven | Set `postgres` to use the Postgres world-model backend. |
| `MAVERICK_PG_DSN` | unset | Postgres DSN for the Postgres world model (e.g. `postgres://user@host:5432/maverick`; prefer `PGSERVICE`, `~/.pgpass`, peer auth, or a secret manager over embedding passwords). |
| `MAVERICK_PG_CONNECT_TIMEOUT_SECONDS` | `10` | Maximum connection wait per host for the Postgres world model (including reconnects and pool workers) and the SQLAlchemy `database` tool's libpq drivers. Integer from `2` to `300`; invalid values use `10`. A shorter positive DSN `connect_timeout` or `PGCONNECT_TIMEOUT` is retained, with a two-second minimum. Omitted, invalid or nonpositive driver timeouts use this finite cap. This does not set a SQL statement deadline or change other database drivers. |
| `MAVERICK_ORPHAN_RECLAIM_SECONDS` | code default | Seconds before orphaned world-model goal locks are reclaimed. |
| `MAVERICK_BLACKBOARD_MAX_ENTRIES` | `5000` (min 100) | Max entries retained in the shared blackboard. |

## Hosted control plane & multi-tenancy

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_STRICT_TENANT_ISOLATION` | config `[world_model] strict_tenant_isolation`; **auto-on under enterprise mode** | Postgres reads return ONLY the active tenant's rows (drop NULL-legacy tolerance). Enable after backfilling `tenant_id`. Env wins over config wins over enterprise default. |
| `MAVERICK_PER_TENANT_KEYS` | config `[providers] per_tenant_keys` (off) | Master switch for per-tenant **BYOK** provider keys (bring-your-own-key for LLM credentials — distinct from `[kms]` BYOK). Off = the whole install shares the deployment-global provider key (unchanged behavior). On = an active tenant that opted in (its `byok` flag) runs on its own key, resolved through the secret provider under a tenant-scoped name (`MAVERICK_TENANT_<digest>_<PROVIDER>_API_KEY`, where `<digest>` derives from the tenant's collision-safe namespace key; obtain the exact name from `maverick.config.tenant_provider_key_env`). A tenant with the flag on but no key configured falls back to the global key (never crashes). The key bytes are resolved via the secret provider (env or a mounted vault/secret file) and are **never** stored in config, on the tenant record, or logged; the name ends in `_API_KEY` so the GitHub Action sanitizer redacts it. This env var is a boolean policy switch, not a credential. |
| `MAVERICK_PG_RLS` | config `[world_model] rls`; **auto-on under enterprise mode** | DB-native Postgres Row-Level Security on the tenant tables (defense-in-depth over the app predicate). When auto-enabled by enterprise mode, a boot preflight refuses to start on legacy `tenant_id IS NULL` rows (run `maverick tenant backfill`); explicit `=1` keeps the fail-closed opt-in path. |
| `MAVERICK_KMS_KEK` | derived from the at-rest key | The per-tenant-DEK Key Encryption Key (32 bytes, hex/base64) for `tenant/kms.py`. |
| `MAVERICK_KMS_DEK_CACHE_TTL` | config `[kms] dek_cache_ttl` (`0` = process lifetime) | Seconds a tenant DEK stays cached before it must be re-unwrapped by the KMS. A positive TTL bounds how long a *revoked* cloud-KMS key keeps opening data (the next access re-hits the KMS and fails closed). Per-tenant **BYOK** is configured in each tenant's own `tenants/<id>/config.toml` `[kms]` section (provider/key_id/region), resolved deterministically by `get_kms(tenant_id)`. A workspace's own `key_id` always outranks the server-wide `MAVERICK_KMS_KEY_ID`, which applies only to workspaces that pinned no key of their own, so a customer's key is never silently replaced by the operator's. Data keys that were locked under the server-wide key while a workspace's own key was configured (the earlier behaviour) must be re-wrapped to the workspace's key, or they will not open: run `tenant.kms.rotate_kek_fleet` with `old_kms_for=lambda t: build_cloud_kms(provider, key_id=<server-wide key>)` and `new_kms_for=get_kms`. **Rolling the local KEK** across the fleet: `maverick tenant kms-rotate --old-kek-file /run/secrets/old-kek --new-kek-file /run/secrets/new-kek` (re-wrap only, idempotent/resumable, `--dry-run` to preview; omit file options to use hidden prompts). Avoid passing KEKs in command-line arguments; set `MAVERICK_KMS_KEK` to the new value live only after rotation reports 0 failed. Cloud/BYOK rotation uses `tenant.kms.rotate_kek_fleet` with per-tenant resolvers. |
| `MAVERICK_MCP_ANALYTICS` | config `[analytics] mcp_client_language` (off) | Opt-in, consent-gated local tally of the languages your MCP clients use. |
| `MAVERICK_RELEASE_PUBKEYS` | config `[release] publisher_pubkeys` | Comma-separated Ed25519 public key hex of the publishers whose signed update bundles `python -m maverick.release_update` accepts (added to the config keys). With no key set, every bundle is refused as `no_trust_anchor` unless `--pubkey` names one. |
| `MAVERICK_PUBLIC_URL` | config `[dashboard] public_url` / `[flows] public_url` | Externally-reachable dashboard base URL. `maverick tenant onboard` uses it to build the printed first-admin invite link (also used for flow-approval links). Unset → the command prints the relative `/auth/invite/<token>` path and tells you to prepend your host. |
| `IRC_ALLOWED_ACCOUNTS` | — | Comma-separated allowlist of authenticated IRC account names that may drive the agent over the IRC channel. Requires an IRC server that provides the IRCv3 `account-tag` capability. |
| `IRC_SERVER` / `IRC_PASSWORD` | config `[channels.irc]` | IRC server host / password. |

### Platform billing (Stripe)

Turn the metered-usage invoices (`maverick.billing`) into real charges
(`maverick.billing_stripe`). Off by default; the `stripe` SDK is an optional
extra (`python -m pip install -e './packages/maverick-core[stripe]'` from the
repository root, or add `stripe` to `--core-extra` in
`scripts/install_release_cohort.py`). Distinct from the agent-facing
`stripe` **tool** (which uses `STRIPE_SECRET_KEY` to read a customer's account) —
these drive the *platform's own* Stripe account to bill tenants.

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_STRIPE_ENABLE` | config `[billing.stripe] enable` (off) | Master switch for platform billing collection. Even on, nothing charges until a secret key is present. |
| `MAVERICK_STRIPE_SECRET_KEY` | — | The platform Stripe secret key (`sk_...`). Resolved through the secret provider; NEVER read from config or logged. Required to create customers/subscriptions and push usage. |
| `MAVERICK_STRIPE_WEBHOOK_SECRET` | — | Webhook signing secret (`whsec_...`) used to verify inbound Stripe events (stdlib HMAC; no SDK needed). A verified `invoice.payment_failed` / past-due subscription downgrades the tenant to the base entitlement tier; a recovered payment restores it. |
| `MAVERICK_CONTACT_CENTRE_ZENDESK_TOKEN` | — | Zendesk API token for contact-centre handoffs (see `docs/contact-centre-handoff.md` in the repository). Resolved through the secret provider; overrides the sealed value saved in Settings. Never logged. |
| `MAVERICK_CONTACT_CENTRE_WEBHOOK_SECRET` | — | Signing secret for contact-centre webhook handoffs. Resolved through the secret provider; overrides the sealed value saved in Settings. Without it nothing is sent to the webhook. |
| `MAVERICK_STRIPE_BILL_METERED` | config `[billing.stripe] bill_metered_usage` (off) | Off bills only the recurring platform-fee subscription; on also pushes the metered model-usage line items. No markup is set here — amounts come from whatever `RateCard` rated the invoice. |

### Fleet queue

`[queue] backend = "arq"` selects authenticated out-of-process goal execution.
Run only the matching hardened worker entry point:

```bash
arq maverick.arq_worker.WorkerSettings
```

| Env var | Config equivalent | Description |
| --- | --- | --- |
| `MAVERICK_QUEUE_SIGNING_KEY` | `[queue] signing_key` | Required shared HMAC key of at least 32 UTF-8 bytes. Supply through a secret manager, not source control. |
| `MAVERICK_QUEUE_NAMESPACE` | `[queue] namespace` | Required non-secret deployment id (1-64 safe characters). Producer and workers must match; distinct fleets must not share it. |
| `MAVERICK_QUEUE_REDIS_DSN` | `[queue] redis_dsn` | Shared `redis://`, `rediss://`, or `unix://` endpoint. Non-loopback TCP requires `rediss://`; hostname and certificate validation are forced on. |
| `MAVERICK_QUEUE_REDIS_CA_CERTS` | `[queue] redis_ca_certs` | Optional private-CA bundle for `rediss://`. |
| `MAVERICK_QUEUE_REDIS_CERTFILE` / `MAVERICK_QUEUE_REDIS_KEYFILE` | `[queue] redis_certfile` / `redis_keyfile` | Optional client mTLS pair; both are required together. |
| `MAVERICK_QUEUE_WORKER_MAX_DOLLARS` | `[queue] worker_max_dollars` | Worker-local per-goal spend ceiling; signed producer requests can only narrow it. |
| `MAVERICK_QUEUE_WORKER_MAX_WALL_SECONDS` | `[queue] worker_max_wall_seconds` | Worker-local wall-time ceiling. |
| `MAVERICK_QUEUE_WORKER_MAX_DEPTH` | `[queue] worker_max_depth` | Worker-local recursion-depth ceiling (1-64). |

Use a dedicated Redis database and ACL identity per Lightwork deployment. ARQ
stores job bodies under global Redis key prefixes even when its ready queue is
namespaced, so a dedicated database/ACL is defense in depth against accidental
cross-fleet access. Network workers also require the same Postgres world-model
backend for durable, tenant-aware replay claims. The worker refuses to poll if
the HMAC key or shared claim store is unavailable. The unsafe
`MAVERICK_ALLOW_INSECURE_QUEUE_REDIS=1` escape hatch is only for isolated local
development networks.

For a codec or signing-key rollout, pause producers, drain (or deliberately
purge) the old deployment queue, deploy workers and producers together, then
resume. Old pickle records and envelopes signed by a retired key are rejected;
there is intentionally no silent compatibility fallback. Generate and rotate
the HMAC value in your secret manager, and keep it out of process arguments,
logs, and repository configuration.

Other config-only knobs: `[billing.plans]` (override plan entitlements), `[egress]` /
`[tenancy.egress.<t>]` (per-tenant egress plane). Tenants are managed with
`maverick tenant …`; invoices/entitlements with `maverick billing …`.

**Operator lifecycle:** `maverick tenant onboard <id> --admin-email <email>`
provisions a tenant and mints its first-admin invite in one step;
`maverick launch-check` prints PASS/FAIL for each go-live switch (cost-cap
enforcement, per-user tenancy, at-rest encryption, and a resolvable provider
key) and exits non-zero if any is off, so a deploy pipeline can gate on it.

## LLM cost & latency

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_EFFORT_ENABLED` | config `[effort] enabled` (off) | Turn on the built-in per-role reasoning-effort profile (`output_config.effort`): orchestrator/coder/revisor stay `high`, bulk roles (researcher/verifier/writer) drop to `medium`, reflector/distiller to `low`. The biggest cost/latency lever on Opus 4.7/4.8. Model-gated (Opus 4.5+/Sonnet 4.6) so it never 400s. |
| `MAVERICK_EFFORT` | unset | Global effort for **all** roles (`low`/`medium`/`high`/`xhigh`/`max`). Wins over config. |
| `MAVERICK_EFFORT_<ROLE>` | unset | Per-role override, e.g. `MAVERICK_EFFORT_CODER=xhigh`. Highest precedence. |
| `MAVERICK_CACHE_PREWARM` | config `[cache] prewarm` (off) | Pre-warm the prompt cache at orchestrator start (`max_tokens=0` prefill) so the first turn's time-to-first-token doesn't pay the cold cache write. Best for interactive surfaces. |
| `MAVERICK_CACHE_MESSAGES` | `1` | Cache the stable message-history prefix (set `0` to disable). |
| `MAVERICK_LOG_TURNS` | unset | Print per-turn `in/out/cache_read/cache_write` token stats to stderr. The Prometheus `maverick_llm_cache_tokens_total` counter (kind=`read`/`creation`/`uncached`) is the metric form — a hit-rate panel surfaces a silent cache invalidator. |

Config equivalents live under `[effort]` (`enabled`, `default`, `<role>`) and
`[cache]` (`prewarm`).

## Compaction & context

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_COMPACT_HISTORY` | config `[context] compact` (off) | Enable history compaction. |
| `MAVERICK_COMPACT_TIKTOKEN` | `1` | Use a real local BPE tokenizer (tiktoken) for compaction token counts when installed; `0` forces the `len/4` heuristic. Fails open to the heuristic if tiktoken is absent. |
| `MAVERICK_HISTORY_WINDOW` | config `[context]` | Max number of recent turns kept verbatim. |
| `MAVERICK_HISTORY_TOKENS` | config `[context]` | Max history tokens before compaction triggers. |
| `MAVERICK_COMPACT_KEEP_RECENT` | `4` | Recent turns always kept uncompacted. Also `[compaction] keep_recent` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_COMPACT_DIGEST_EVERY` | `10` | Digest older turns every N turns. Also `[compaction] digest_every` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_COMPACT_MAX_TOOL_BYTES` | `2048` | Max bytes of tool output retained before truncation during compaction (applies to results behind the recent window). Also `[compaction] max_tool_bytes` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_COMPACT_MAX_TOTAL_BYTES` | `200000` | Ceiling on the whole live message window. When a few results at the per-result cap push the window over it, compaction shrinks into the recent window oldest-first (the brief and the newest message are always spared). `0` disables. Also `[compaction] max_total_bytes` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MAX_TOOL_RESULT_BYTES` | `100000` | Hard cap on a single tool result (head+tail kept) before it enters the context window, so one runaway `shell`/query output can't blow tokens/budget in a turn. |
| `MAVERICK_ADAPTIVE_MAX_TOKENS_FLOOR` | `8192` | `max_tokens` headroom floor when Opus 4.7/4.8 auto-injects adaptive thinking for a role with no explicit thinking budget. Thinking bills at the output rate, so this is the worst-case output spend of every non-thinking-role turn on the default model (min 2048). Config `[thinking] budget` sets the orchestrator/revisor base (default 8000). |
| `MAVERICK_SKILL_RENDER_MAX_CHARS` | `4000` | Per-skill body cap when recalled skills are rendered into a system prompt (`0` disables). |
| `MAVERICK_SKILL_RENDER_TOTAL_CHARS` | `10000` | Combined budget across rendered skills; the relevance-ranked tail is dropped once spent (`0` disables). |
| `MAVERICK_FINDING_POST_MAX_CHARS` | `1500` | Excerpt size for a FINAL posted to the blackboard (the full answer still reaches the parent and the run record). Overrides `[swarm] finding_post_max_chars`. |
| `MAVERICK_BB_RENDER_ENTRY_CHARS` | `800` | Per-entry bound when blackboard activity is rendered into a worker's brief. |
| `MAVERICK_SWARM_CHILD_RESULT_CHARS` | `4000` | Per-child answer cap in the `spawn_swarm` result returned to the parent. |
| `MAVERICK_SWARM_RESULTS_TOTAL_CHARS` | `24000` | Total budget for the joined swarm result; trailing children's answers are elided (identity line kept). |
| `MAVERICK_BRIEF_FACTS_MAX` | `50` | Newest facts included in the orchestrator brief's facts block. |
| `MAVERICK_BRIEF_FACT_VALUE_CHARS` | `300` | Per-fact value cap in the brief's facts block (truncation runs after secret redaction). |
| `MAVERICK_ANTHROPIC_MSG_CACHE_TTL` | `5m` | TTL for the message-tier cache breakpoints (re-anchored every turn, so the write surcharge is paid per turn); system/tools keep `MAVERICK_ANTHROPIC_CACHE_TTL` semantics. |
| `MAVERICK_BUDGET_RECEIPTS` | off | Mint a signed budget receipt (tokens, cache buckets, cost) per finished goal into the hash-chained ledger. |
| `MAVERICK_RETRIEVAL_ROUTER` | config `[context] retrieval_router` (off) | Enable the long-context retrieval router: when a single payload (e.g. a pasted document in the goal description) exceeds the token threshold, shard it and keep only the shards relevant to the goal, instead of overflowing the model window. |
| `MAVERICK_ROUTER_THRESHOLD_TOKENS` | config `[context]` (`200000`) | Payload size (approx tokens) above which the retrieval router activates. |
| `MAVERICK_ROUTER_TOP_K` | config `[context]` (`12`) | Number of shards the retrieval router retains. |

## Sandbox & tools

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_SUPPRESS_SANDBOX_WARNING` | unset | `1` silences the "running without an isolated sandbox" warning. |
| `MAVERICK_DEFERRED_TOOLS` | unset (on) | `0` disables deferred tool loading, putting every SaaS-connector schema back in the model's per-turn catalog (~600 tools). On by default: the model sees the core toolset + `find_tools` and activates connectors on demand. Also settable via `[capabilities] deferred_tools`. |
| `MAVERICK_TOOL_EXPOSURE` | unset (`core`) | `core` describes a short, role-aware tool list on each request (about 30-40 tools; a specialist pack sees its permitted tools) and the model looks the rest up with `find_tools`; `full` offers more tools up front, up to the model's tool limit, and leaves overflow discoverable. Also settable via `[tools] exposure`; `[tools] core_extra` pins extra tools into the short list. |
| `MAVERICK_CODE_EXEC` | unset (off) | `1` enables the `code_exec` tool (programmatic tool calling: a sandboxed Python script that orchestrates declared tool calls, keeping raw outputs out of context). Also settable via `[capabilities] code_exec`. |
| `MAVERICK_FIRECRACKER_STRICT` | `1` (on) | Set `0` to allow Firecracker to fall back to a Docker/hardened sandbox instead of failing. |
| `MAVERICK_LONG_CMD_TIMEOUT` | `600` | Timeout (seconds) for long-running shell commands. |
| `MAVERICK_PARALLEL_TOOLS` | `1` (on) | See Core / run. |
| `MAVERICK_BROWSER_DISABLE` | unset | `1` disables the browser tool. |
| `MAVERICK_BROWSER_STATE` | unset | Path to a per-task browser storage-state file; setting it enables persistence. |
| `MAVERICK_BROWSER_NO_PERSIST` | unset | `1` disables browser-state persistence even when a state file is set. |
| `MAVERICK_BROWSER_HEADED` | `0` (headless) | `1` runs the browser headed (visible). |
| `MAVERICK_COMPUTER_DISABLE` | unset | `1` disables the computer-use tool. |
| `MAVERICK_COMPUTER_OCR` | unset (off) | Enable OCR of computer-use screenshots. |
| `MAVERICK_CLIPBOARD_DISABLE` | unset | `1` disables the clipboard tool. |
| `MAVERICK_EMAIL_DISABLE` | unset | `1` blocks the email tool from sending. |
| `MAVERICK_WHISPER_MODEL` | `small` | Whisper model size for the voice tool. |
| `MAVERICK_WHISPER_OPENAI_MODEL` | `whisper-1` | OpenAI speech-to-text model used by the voice tool. |
| `MAVERICK_WHISPER_GROQ_MODEL` | `whisper-large-v3-turbo` | Groq speech-to-text model used by the voice tool. |
| `MAVERICK_TTS_OPENAI_MODEL` | `tts-1` | OpenAI text-to-speech model used by the voice tool. |
| `MAVERICK_TTS_ELEVENLABS_MODEL` | `eleven_turbo_v2_5` | ElevenLabs text-to-speech model used by the voice tool. |
| `MAVERICK_SEARCH_BACKEND` | auto (preference order) | Force a web-search backend: `tavily`, `brave`, `serpapi`, or `ddg`. |
| `MAVERICK_FETCH_ALLOW_PRIVATE` | unset | `1` allows supported fetch tools and A2A push-notification webhooks to reach private/loopback/reserved IPs (SSRF escape hatch). Event pollers always require public addresses, including when this is enabled. |
| `MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK` | unset | Explicit operator opt-in for exact-IP loopback partner test-estate enrollment and probes; each API action also requires global-admin authority. |
| `MAVERICK_FETCH_RESPECT_ROBOTS` | unset | `1` makes the fetch tool honor `robots.txt`. |
| `MAVERICK_FETCH_NO_SCAN` | unset | `1` skips safety scanning of fetched remote content. |
| `MAVERICK_NET_HOST_CONCURRENCY` | `4` | Max concurrent network requests per host. |
| `MAVERICK_ATTACH_MAX_FILE_BYTES` | `104857600` (100 MiB) | Max size of a single attachment file. Also `[attachments] max_file_bytes` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_ATTACH_MAX_GOAL_BYTES` | `524288000` (500 MiB) | Max total attachment bytes per goal. Also `[attachments] max_goal_bytes` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_ALLOW_RAW_MEDIA_ARGS` | unset | Legacy helper override for extensions that use it. Built-in Pandoc, ImageMagick and FFmpeg always enforce their restricted option sets. |
| `MAVERICK_ENABLE_CRED_TOOLS` | unset (off) | Enable credential-handling tools. |
| `MAVERICK_USE_SKILLS` | config `[features] skills` | Override skill injection; `0` disables (e.g. for benchmark runs). |

## Safety & consent

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_CONSENT_MODE` | `ask` in enterprise mode; otherwise `ask` for high/critical risk under secure defaults, `auto-approve` for low/medium risk | Gating for destructive actions: `auto-approve`, `auto-deny`, `ask`, or `dashboard`. |
| `MAVERICK_CONSENT_DASHBOARD_TIMEOUT` | `1800` | Seconds to wait for a dashboard approval before treating as denied (overrides `[approval] dashboard_wait_seconds`). |
| `MAVERICK_APPROVAL_UNDO_GRACE_SECONDS` | `30` | Seconds a decision on the Approvals page can be undone. The agent waits this long before acting on an approval; `0` acts at once and removes Undo. Also `[approval] undo_grace_seconds` (Settings > All settings; this variable wins). |
| `MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT` | `1` | Approving a high or critical risk request needs an explicit confirmation (a ticked box; typing APPROVE for critical). `0` makes those approvals one click. Also `[approval] require_acknowledgement`. |
| `MAVERICK_SEPARATE_APPROVER` | `when_available` | Who approves a high or critical risk action someone asked for: `when_available` (someone else whenever another approver could decide it, else the requester, recorded as a self-approval), `always` (always someone else) or `never` (the requester may approve it). Also `[approval] separate_approver` (Settings > All settings; this variable wins). |
| `MAVERICK_MCP_ELICITATION` | `decline` | How the MCP client answers an external server's `elicitation/create`: `decline` (continue without the value), `cancel` (abort the server's op), or `prompt` (collect typed input from an interactive operator, gated through consent). The prompt is shield-scanned either way. |
| `MAVERICK_MCP_ELICITATION_TIMEOUT` | `300` | Seconds the MCP *server* waits for an elicitation response from a stdio client before giving up and leaving the question parked for the async `maverick_answer` flow. Also `[mcp] elicitation_timeout` (Settings > All settings; this variable wins). |
| `MAVERICK_MCP_MAX_ELICIT_ROUNDS` | `8` | Max elicit→answer→resume rounds the MCP server runs per `maverick_start`/`maverick_resume` call before returning (bounds runaway question loops). Also `[mcp] max_elicit_rounds` (Settings > All settings; this variable wins). |
| `MAVERICK_MCP_TASK_WORKERS` | `4` | Background worker threads for MCP async tasks (concurrent task-augmented tool calls over stdio). Also `[mcp] task_workers` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MCP_MAX_TASKS` | `256` | Max MCP tasks retained in the in-memory registry; the oldest are evicted past this cap. Also `[mcp] max_tasks` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MCP_TASK_TTL_MS` | `3600000` | Default task lifetime (ms) when the client doesn't request a `ttl`; the task may be purged after it elapses. Also `[mcp] task_ttl_ms` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MCP_TASK_MAX_TTL_MS` | `86400000` | Ceiling (ms) a client-requested task `ttl` is clamped to. Also `[mcp] task_max_ttl_ms` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_MCP_TASK_POLL_MS` | `1000` | `pollInterval` (ms) the server suggests to clients in task responses. Also `[mcp] task_poll_ms` (Settings > All settings; read at startup, this variable wins). |
| `MAVERICK_PREFLIGHT` | `warn` | Request preflight mode: `warn` (log only), `strict` (hard-refuse), or `off`. |
| `MAVERICK_AUDIT_SIGN` | config `[audit] sign` (off) | Sign audit-log rows. |
| `MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS` | unset | Comma-separated hex Ed25519 public keys trusted for audit verification, supplied by an independently protected startup environment. The value is captured at startup. Pin retired external keys before rotation. Without an external signer, the list is exclusive and must include the active local public key. |
| `MAVERICK_ANON` | config `[privacy] anonymous` (off) | Enable anonymous mode (scrubs home paths and identifying data). |
| `MAVERICK_AI_DISCLOSURE` | config `[compliance] disclosure_text` | AI-disclosure text appended to outputs; empty string opts out. |
| `MAVERICK_STRIPE_ENABLE_REFUNDS` | unset (off) | Required to allow the Stripe tool to issue real refunds. |

## Secrets, residency & audit forwarding

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_SECRETS_BACKEND` | config `[secrets] backend` (`env`) | Where deployment secrets are read from. `env` = process environment (default, unchanged). `file` = mounted secret files (Vault Agent / Secrets Store CSI / Docker/podman secrets), one secret per file, with env fallback. Applies to OIDC client/session secrets, the inbound webhook secret, and the SCIM bearer. |
| `MAVERICK_SECRETS_DIR` | config `[secrets] dir` | Directory the `file` backend reads (`<dir>/MAVERICK_OIDC_CLIENT_SECRET`, etc.; trailing newline trimmed). |
| `MAVERICK_RESIDENCY_STRICT` | config `[residency] strict` (off) | Refuse to boot when the declared data region is missing or outside the allowed set (`require_residency_or_die`). Off = informational only. |
| `MAVERICK_DATA_REGION` | config `[residency] region` | The deployment's declared data region (ISO code or group, e.g. `DE`, `EU`). |
| `MAVERICK_RESIDENCY_ALLOWED` | config `[residency] allowed_regions` | Comma-separated permitted storage regions; `EU`/`EEA` groups expand to members. Empty = region unconstrained. |
| `MAVERICK_SIEM_DEST` | config `[audit] siem_dest` | Destination for `maverick audit forward`: `tcp://host:port` / `udp://host:port` (syslog), `http(s)://host/path` (Splunk HEC `/raw`, etc.), `datadog://<site>` (Datadog Logs intake for a documented site such as `datadoghq.com` or `datadoghq.eu`), or `sentinel://<dce-host>/<dcr-immutable-id>/Custom-<stream>` (Microsoft Sentinel through the Azure Monitor Logs Ingestion API; the host must end in `.monitor.azure.com`). The Sentinel DCR stream must declare `TimeGenerated` (datetime) and `RawData` (string). Each line becomes one row with the event time from its `ts` field, or now. A Datadog log over 1,000,000 bytes or a Sentinel line over 64,000 bytes is refused instead of truncated (the vendors do not define MB or KB, so the smaller decimal reading is used; the Sentinel call is capped at 1,000,000 bytes). |
| `MAVERICK_SIEM_TOKEN` | — | Bearer sent on HTTP(S) audit forwarding (read via the secret provider). |
| `MAVERICK_DATADOG_API_KEY` | config `[audit] datadog_api_key` | Datadog API key for `datadog://` forwarding, sent in the `DD-API-KEY` header (read via the secret provider; never logged or put in the URI). |
| `MAVERICK_SENTINEL_TENANT_ID` | config `[audit] sentinel_tenant_id` | Microsoft Entra directory (tenant) ID for `sentinel://` forwarding. |
| `MAVERICK_SENTINEL_CLIENT_ID` | config `[audit] sentinel_client_id` | Application (client) ID of the Entra app registration that has the Monitoring Metrics Publisher role on the data collection rule. |
| `MAVERICK_SENTINEL_CLIENT_SECRET` | config `[audit] sentinel_client_secret` | Client secret of that app registration (read via the secret provider; never logged). |

## Observability

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_LOG_LEVEL` | `INFO` | Logging level. |
| `MAVERICK_LOG_FORMAT` | `text` | Log format: `text` or `json`. |
| `MAVERICK_LOG_TURNS` | unset | Set to log full LLM turns (verbose). |
| `MAVERICK_OTEL_EXPORTER` | unset (off) | Set to `otlp` to enable the OpenTelemetry trace exporter. `false`, `0`, `off`, `no` or blank keep it off, in the environment and in `[observability] otel_exporter` alike. |
| `MAVERICK_OTEL_ENDPOINT` | `http://localhost:4318/v1/traces` | OTLP collector endpoint. |
| `MAVERICK_OTEL_METRICS` | config `[observability] otlp_metrics` (off) | Also send the Prometheus series over OTLP to the same collector, under the same names. Needs `MAVERICK_OTEL_EXPORTER=otlp`; the metrics URL is the endpoint with `/v1/traces` replaced by `/v1/metrics`, so the endpoint must end in `/v1/traces`. |
| `MAVERICK_RESIDENCY_REGION` | config `[residency] region` (unset) | Declare a data-residency requirement (e.g. `eu`). `maverick doctor` then warns about any residency-sensitive feature still defaulting to a US region (`AWS_REGION`→us-east-1, `VERTEX_LOCATION`→us-central1). No effect unset. |
| `MAVERICK_PROMETHEUS_PORT` | unset (off) | Set a port to expose Prometheus metrics. `false`, `0`, `off`, `no` or blank keep it off. |
| `MAVERICK_PROMETHEUS_ADDR` | `127.0.0.1` | Bind address for the Prometheus metrics server. |
| `MAVERICK_ALERTS` | config `[alerts] enabled` (off) | Enable OPERATIONAL alerts — page the operator (via the configured notification backends) on infrastructure events like a killswitch trip or a deployment-wide provider cost-cap exhaustion. Distinct from agent-task notifications. |

## Plugins

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_PLUGINS_ALLOW` | config `[plugins] enabled` | Comma-separated plugin allowlist; `*` enables all. |
| `MAVERICK_PLUGINS_ENFORCE` | config `[plugins] enforce_permissions` (on) | Reject plugins whose declared permissions are not granted. This checks declarations at load time; it does not sandbox plugin code or enforce its actual access. |

## Channels & integrations

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_WEBHOOK_SECRET` | unset | Outbound webhook signing secret; takes precedence over the legacy outbound configuration. Do not reuse it for inbound control or approval links. |
| `MAVERICK_PUBLIC_POLICY_GLOBAL_RATE` | `20000` | Maximum public policy-link requests per process per minute, clamped to 1–100,000. Client limits also apply and trusted proxy configuration controls forwarded client addresses. |
| `MAVERICK_INBOUND_WEBHOOK_SECRET` | unset | Dedicated HMAC secret for `/webhook/start` and `/webhook/run`. These control endpoints fail closed without it or if it duplicates another configured webhook credential. Configure callers with the new key when upgrading. |
| `MAVERICK_LINEAR_WEBHOOK_SECRET`, `MAVERICK_JIRA_WEBHOOK_SECRET` | unset | Separate HMAC secrets for the Linear and Jira issue receivers. Each must differ from the control webhook, GitLab and approval-link secrets. Existing integrations must configure and update their provider's secret. |
| `MAVERICK_FLOW_APPROVAL_SECRET` | unset | Dedicated signing secret for actionable flow approval links. It must differ from the control webhook and issue-tracker credentials. Existing links stop working when this key changes; mint new links after configuring it. |
| `MAVERICK_WEBHOOK_WORKERS` | config `[webhooks] workers` (4) | Outbound webhook dispatch thread-pool size. |
| `MAVERICK_WEBHOOK_MAX_INFLIGHT` | config `[webhooks] max_inflight` (16×workers) | Cap on queued+running dispatches; excess is dropped + logged (bounds memory under a burst against a slow receiver). |
| `MAVERICK_GRPC_MAX_WORKERS` | config `[grpc] max_workers` (8) | gRPC goal-API server thread-pool size. |
| `MAVERICK_GRPC_MAX_CONCURRENT` | config `[grpc] max_concurrent_rpcs` (worker count) | Max in-flight gRPC RPCs (RESOURCE_EXHAUSTED backpressure past the cap). |
| `MAVERICK_GRPC_MAX_DEPTH` | config `[grpc] max_depth` (runner default, hard max 64) | Worker-owned recursion ceiling for remote `RunGoal` calls. |
| `MAVERICK_GRPC_STREAM_MAX_SECONDS` | config `[grpc] stream_max_seconds` (300, hard max 3600) | Per-call episode-stream deadline; clients resume with `since_id`. |
| `MAVERICK_ALLOW_INSECURE_GRPC` | unset (off) | Explicitly permit non-loopback plaintext gRPC binds and client dials. Keep unset in production; configure `[grpc]` / `[federation]` TLS instead. |
| `MAVERICK_FEDERATION_MAX_WORKERS` | config `[federation] max_workers` (8) | Federation server thread-pool size. |
| `MAVERICK_FEDERATION_MAX_CONCURRENT` | config `[federation] max_concurrent_rpcs` (worker count) | Max in-flight federation RPCs. |
| `MAVERICK_GH_APP_WEBHOOK_SECRET` | unset | Webhook secret for the GitHub App; requests are rejected if unset. |
| `MAVERICK_TRIGGER_LABELS` / `MAVERICK_GH_TRIGGER_LABELS` | built-in default | Comma-separated issue labels that trigger a GitHub-App run. |
| `MAVERICK_BOT_LINEAR_ID` | unset | Linear user id identifying "the bot" for issue webhooks. |
| `MAVERICK_BOT_JIRA_ACCOUNT_ID` | unset | Jira accountId (or bot email) identifying "the bot" for issue webhooks. |
| `MAVERICK_NTFY_TOPIC` | config `[notifications]` | ntfy topic for push notifications. |

## Connectors

Each enterprise connector reads its own credentials from named environment
variables — by convention `<SYSTEM>_BASE_URL` + `<SYSTEM>_TOKEN`, with a few
system-specific shapes (e.g. `SERVICENOW_INSTANCE_URL`, `SNOWFLAKE_ACCOUNT`,
`DATABASE_URL`). The full list of connectors and their exact variables lives in
[connectors.md](connectors.md); `maverick init` can collect them for you.

| Env var | Default | Description |
| --- | --- | --- |
| `<SYSTEM>_BASE_URL` / `<SYSTEM>_TOKEN` | unset | Per-connector endpoint + credential; see [connectors.md](connectors.md). Writes stay confirm-gated regardless. |
| `DATABASE_URL` | unset | SQLAlchemy URL for the `database` tool (Postgres / MySQL / SQL Server / Oracle / Redshift / ...). |
| `MAVERICK_ENABLE_CRED_TOOLS` | unset (off) | `1`/`true` registers connectors that can use ambient host credentials (AWS Lambda/DynamoDB, Google Drive, Airtable, Asana, ClickUp, Vercel). Off by default. |
| `MAVERICK_WORKFORCE_DATA_GROUNDING` | config `[workforce] data_grounding` (on) | Kill-switch for primary-source data grounding. When on, each analyst pack is granted its suite's read-only public-data connectors (37 in total across suites: SEC EDGAR, FRED, openFDA, USAspending, NWS/NOAA weather, ...) — GET-only, low-risk, deferred. Set `off`/`0` to withhold them. See [connectors.md](connectors.md). |
| `MAVERICK_WORKFORCE_LEVELS` | config `[workforce] levels` (off) | Enable per-agent autonomy levels (observe/suggest/request/auto). Off = every agent stages actions for human execution. |

## Agent-to-agent (A2A)

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_A2A_ENABLED` | config `[a2a] enabled` (off) | Enable the outward-facing A2A surface. |
| `MAVERICK_A2A_BASE_URL` | code default | Base URL advertised for A2A. |
| `MAVERICK_A2A_TOKEN` | unset | Bearer token required from A2A clients. |
| `MAVERICK_A2A_ALLOW_UNAUTHENTICATED` | unset (off) | `1` allows unauthenticated A2A requests (trusted networks only). |
| `MAVERICK_A2A_MAX_DOLLARS` | `5.0` | Dollar ceiling for an A2A-initiated task. |
| `MAVERICK_A2A_MAX_WALL_SECONDS` | `3600` | Wall-clock ceiling (seconds) for an A2A task. |
| `MAVERICK_A2A_MAX_DEPTH` | `3` | Max recursion depth for an A2A task. |
| `MAVERICK_A2A_MAX_TASKS` | `1000` (min 16) | Max concurrently-tracked A2A tasks. |

## Durable execution

| Env var | Default | Description |
| --- | --- | --- |
| `MAVERICK_DURABLE` | config `[durable] enabled` (off) | Enable durable execution (checkpoint/resume). |
| `MAVERICK_WORLD_SYNCHRONOUS` | config `[world_model] synchronous` (NORMAL) | World-DB PRAGMA synchronous level. `FULL`/`EXTRA` make every commit durable on OS crash/power loss (no acked-row loss) at a write-latency cost — for deployments treating the world DB as the billed Operating Record. |

## Also settable in the dashboard

Each of these environment variables also has a config key that a global
administrator can set on **Settings > All settings** (secrets are stored sealed
and never shown again). The environment variable wins over the config key; with
neither set, the default applies.

| Env var | Config key |
| --- | --- |
| `MAVERICK_DASHBOARD_TOKEN` | `[dashboard] token` |
| `MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN` | `[dashboard] max_goals_per_min` |
| `MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN` | `[dashboard] max_goals_global_per_min` |
| `MAVERICK_DASHBOARD_MAX_SSE` | `[dashboard] max_sse` |
| `MAVERICK_SHUTDOWN_TIMEOUT` / `MAVERICK_DRAIN_TIMEOUT` | `[dashboard] shutdown_timeout_seconds` |
| `MAVERICK_SCIM_TOKEN` | `[dashboard] scim_token` |
| `MAVERICK_A2A_TOKEN` | `[a2a] token` |
| `MAVERICK_A2A_ALLOW_UNAUTHENTICATED` | `[a2a] allow_unauthenticated` |
| `MAVERICK_A2A_ALLOWED_ORIGINS` | `[a2a] allowed_origins` |
| `MAVERICK_A2A_BASE_URL` | `[a2a] base_url` |
| `MAVERICK_A2A_MAX_DOLLARS` / `_MAX_WALL_SECONDS` / `_MAX_DEPTH` | `[a2a] max_dollars` / `max_wall_seconds` / `max_depth` |
| `MAVERICK_A2A_MAX_CONCURRENCY` / `MAVERICK_A2A_MAX_TASKS` | `[a2a] max_concurrency` / `max_tasks` |
| `MAVERICK_PG_CONNECT_TIMEOUT_SECONDS` | `[world_model] connect_timeout_seconds` |
| `MAVERICK_PG_IO_TIMEOUT_SECONDS` | `[world_model] io_timeout_seconds` |
| `MAVERICK_PG_STATEMENT_TIMEOUT_MS` | `[world_model] statement_timeout_ms` |
| `MAVERICK_PG_IDLE_TX_TIMEOUT_MS` | `[world_model] idle_tx_timeout_ms` |
| `MAVERICK_ORPHAN_RECLAIM_SECONDS` | `[world_model] orphan_reclaim_seconds` |
| `MAVERICK_PG_DSN` | `[world_model] dsn` (also read by the Postgres record store) |
| `MAVERICK_QUEUE_GOAL_ACQUIRE_TIMEOUT` | `[queue] goal_acquire_timeout_seconds` |
| `MAVERICK_GRPC_BEARER_TOKEN` | `[grpc] token` |
| `MAVERICK_GRPC_RATE_LIMIT` | `[grpc] rate_limit` |
| `MAVERICK_FEDERATION_RATE_LIMIT` | `[federation] rate_limit` |
| `MAVERICK_SIEM_TOKEN` | `[audit] siem_token` |
| `MAVERICK_SIEM_ALLOW_INSECURE` | `[audit] siem_allow_insecure` |
| `MAVERICK_DATADOG_API_KEY` | `[audit] datadog_api_key` |
| `MAVERICK_SENTINEL_TENANT_ID` | `[audit] sentinel_tenant_id` |
| `MAVERICK_SENTINEL_CLIENT_ID` | `[audit] sentinel_client_id` |
| `MAVERICK_SENTINEL_CLIENT_SECRET` | `[audit] sentinel_client_secret` |
| `MAVERICK_PUBLIC_BASE_URL` | `[channels] public_base_url` |

`MAVERICK_SETTINGS_PATH_ROOTS` (deployment only) replaces the list of places a
server location chosen on that page may point into (locations separated by the
system path separator). By default: Lightwork's own folders, the folder of its
config file, the home folder of the account it runs as, and on Linux and macOS
`/etc`, `/run/secrets`, `/var/lib`, `/srv` and `/opt`. A program Lightwork
runs (a plugin program) may also be in `/usr/bin`, `/usr/local/bin` or `/bin`
unless this variable is set.
