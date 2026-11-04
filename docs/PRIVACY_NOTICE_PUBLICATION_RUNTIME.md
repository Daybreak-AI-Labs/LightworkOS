# Privacy notice publication runtime

The privacy notice publication runtime is the repository-owned background
composition for `PrivacyNoticePublicationBridge`. It is explicit opt-in and
local-only: it consumes approved notice publication intents and mutates only
Lightwork's tenant-private Consent Publishing SQLite authority.

It does **not** update a customer site, tag manager, consent provider, web or
mobile SDK, app store artifact, or browser. A locally applied result is not a
claim of production deployment, customer/browser behavior, legal sufficiency,
or live provider acceptance.

## Closed configuration

The notice authority and Consent Publishing must already be enabled. Every
eligible tenant and every release target must be named exactly. A binding is
selected by exact tenant, notice ID, consent-publication reference, and
property ID; its rule-group and notice-resource versions are immutable
configuration inputs for that release.

```toml
[consent_preferences]
enable = true

[consent_preferences.publishing]
enable = true

[privacy_automation]
enable = true

[privacy_automation.notice_governance]
enable = true

[privacy_automation.notice_governance.publication_runtime]
enable = true
scheduler_enable = true
active_tenants = ["tenant-a"]
poll_seconds = 30
retry_max_seconds = 300
tenant_limit = 100
lease_seconds = 60
retry_delay_seconds = 60

[privacy_automation.notice_governance.publication_runtime.bindings.primary]
tenant_id = "tenant-a"
notice_id = "privacy-main"
consent_publication_ref = "consent-binding:7"
property_id = "property-main"
rule_group_id = "production-rules"
rule_group_version = 7
notice_resource_id = "privacy-notice"
notice_resource_version = 4
```

Unknown runtime keys, incomplete binding tables, duplicate tenant/reference
pairs, bindings outside the active-tenant allowlist, or an active tenant with
no binding fail closed. A global administrator can also add, change and remove
bindings on the Privacy notices page ("Where approved notices are published"),
which checks the whole resulting table with this same parser before saving and
keeps `active_tenants` in step. The installer can emit one real first binding; add a
new named binding for each additional exact release target rather than reusing
an existing consent-publication reference.

## Authority and CAS resolution

For each leased intent, the production resolver:

1. Matches one server-owned binding. The API accepts no tenant, property,
   consent reference, resource ID, resource version, or CAS revision.
2. Re-reads the exact notice release and rejects any definition or state drift.
3. Builds the exact Consent Publishing preview twice and requires stable,
   matching property, rule group, rule digest, notice resource, document
   digest, and bundle digest authority.
4. Derives the property CAS revision and current publication-head revision
   from that authority.
5. For rollback, searches bounded verified publication history for the exact
   selected release bundle digest and uses the oldest matching non-withdrawal
   publication ID. Absence or incomplete bounded custody fails closed.
6. Lets the core bridge repeat all digest checks and execute the local CAS
   mutation with its deterministic idempotency key.

The notice and consent stores are distinct SQLite authorities and cannot share
one atomic transaction. A completed consent mutation followed by an uncertain
notice acknowledgement remains `ambiguous`; after lease expiry, the same
managed path recovers through exact history and deterministic idempotency.

## Scheduler and operator endpoints

The dashboard lifespan installs and starts the scheduler only when both runtime
and scheduler gates are true. It intersects the explicit allowlist with the
deployment's active-tenant authority, caps tenants per cycle, processes at most
one intent per tenant per cycle, and records only content-free aggregate state.
One process-local mutex and the repository cross-process lock serialize cycles.
The integrity-bound state records interrupted-cycle recovery, consecutive
failures, bounded exponential retry timing, last aggregate cycle, and next run.
It never stores tenant IDs, release content, evidence bodies, or lease tokens.

Authenticated operators use:

- `GET /api/v1/privacy/notices/publication-runtime/status` for configuration-only
  tenant readiness plus content-free scheduler health. It opens no tenant store.
- `POST /api/v1/privacy/notices/publication-runtime/run-once` with an exact empty
  JSON object (`{}`). The tenant comes from authenticated context, and target
  authority comes only from configuration and local stores. Unknown body fields
  are rejected.

The `/privacy/notice-governance` page exposes the same bounded controls in the
shared liquid-glass material system and supplies a server-owned page context to
Copilot. Copilot is guidance-only and cannot authorize or execute a cycle.

## Operational acceptance still required

Repository tests cover closed configuration, source rotation, binding rekey,
exact rollback digest selection, in-process overlap, cross-instance exclusion,
interrupted-cycle recovery, request target rejection, and UI/Copilot wiring.
Deployment owners must still run fresh-tenant, recovery, concurrency, scale,
backup/restore, privacy, accessibility, and audit-export acceptance on their
own estate. External site/SDK/provider publication needs a separately designed,
authorized, and accepted mutation plane; it is intentionally absent here.
