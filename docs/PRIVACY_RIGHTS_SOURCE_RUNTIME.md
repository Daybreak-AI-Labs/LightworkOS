# Privacy-rights source runtime

The privacy-rights source runtime is the opt-in provider execution plane for
the provider-neutral rights orchestrator. It does not make the enrolled source
list a claim of whole-estate coverage, and local contract tests are not live
provider, customer, legal, or scale acceptance.

## Safety contract

- A source task is pinned at planning and destructive approval to its source
  revision and integrity digest, adapter reference, credential reference, case,
  phase, identity status, legal-hold state and retention gate. Any source
  rotation after approval makes the old task ineligible for claim and requires
  source re-enrollment and replanning. No provider request is made for that old
  task.
- The worker leases only the source IDs present in its server-owned provider
  manifest. It cannot lease, retry or dead-letter callbacks owned by an
  external adapter runtime in the same tenant database.
- A delete is prepared with a read-only exact-subject lookup. Exactly one
  immutable provider ID must be returned. The raw ID is sealed in a
  tenant/case/source/operation/provider-bound deployment custody database; only
  an opaque custody reference and binding digest enter orchestration state.
- Immediately before the delete request, the store opens `BEGIN IMMEDIATE`,
  rechecks the live lease, case, task, legal hold, retention gate, predecessor
  phases and source pins, records adapter authority/configuration and exact
  target provenance, and changes the callback to `ambiguous`. The lease and raw
  lease token are cleared before network I/O. Concurrent workers, process exit,
  lease expiry and retry cannot issue the mutation again.
- Provider success does not directly close a mutation. An exact-target,
  read-only reconciliation must prove `purged` or `hard_deleted`. A soft-deleted
  or recycle-bin item remains ambiguous. An active-record 404 alone is never
  treated as proof of erasure. Google Workspace and ServiceNow active 404s
  remain `retention_unknown` because their stock contracts do not prove purge.
- A read-only lookup that proves the target was already absent completes as
  `not_found` with `provider_operation_performed = false`; no DELETE is sent.
- Provider evidence and case exports retain the provider operation ID/digest,
  source revision/integrity, adapter and credential references, adapter
  authority digest, provider contract, target binding, operation truth and
  provider retention state. The export-level
  `provider_operations_performed` value is derived from evidence, not a static
  claim.
- Retrieval bytes can flow only to a tenant-bound, encrypted,
  retention-enforced artifact sink. The stock governed-vault bridge is
  idempotent by tenant/case/source/operation. It can recover the one prior vault
  artifact when ingest committed but receipt/index persistence failed, and it
  rejects changed content under the same operation.
- Claim history contains callback/revision/token-digest bindings rather than a
  callback payload or raw token. Empty polls do not create durable operation or
  batch rows. Old batches and their idempotency bindings are garbage-collected
  under the configured retention bound.

## Configuration

The parent Privacy Automation and rights-orchestration gates must both be on.
The source runtime is off unless its own gate is explicitly enabled.

```toml
[privacy_automation]
enable = true

[privacy_automation.rights_orchestration]
enable = true

[privacy_automation.rights_orchestration.source_adapters]
enable = true
timeout_seconds = 15
max_response_bytes = 1048576
max_retrieval_bytes = 8388608
max_records = 200
batch_size = 10
lease_seconds = 60
retry_delay_seconds = 30
claim_history_retention_seconds = 86400
target_custody_retention_seconds = 2592000

[privacy_automation.rights_orchestration.source_adapters.providers.microsoft_graph_users]
enable = true
source_id = "directory-graph"
origin = "https://graph.microsoft.com"
credential_ref = "env:GRAPH_RIGHTS_TOKEN"
capabilities = ["discover", "retrieve", "delete", "verify_delete"]
```

The provider table is closed to `microsoft_graph_users`,
`google_workspace_users`, `salesforce_contacts`, and `servicenow_users`.
Origins are exact public HTTPS origins; secret values are never valid in the
configuration, only `env:`, `vault:` or `secret:` references. Provider source
IDs must be unique. Retrieval size must be at least the ordinary response size.
Each stock adapter reference includes the full canonical source-manifest digest;
changing any provider or operational binding therefore requires source
re-enrollment and task replanning before provider I/O can resume.
The lease must cover the bounded lookup and mutation I/O window:
`ceil(timeout_seconds * 2) + 5` seconds or more. The runtime uses the configured
values as server-owned defaults and rejects caller overrides outside those
caps.

The installer exposes the stock source runtime only after rights orchestration
is selected, writes the complete bounded manifest above, and emits a config
that is exercised through the real configuration linter in tests.

## Readiness and operation

The status endpoint is intentionally side-effect free. It does not open the
rights store, resolve a credential, call a provider, or claim that live
acceptance passed. `configuration_preflight_ready` means the closed provider
manifest, subject-authority seam, artifact sink and target-custody composition
are structurally available. `executable_ready` remains false until an explicit
execution path performs credential and authority checks; status never performs
that check merely to display green.

Before enabling a tenant:

1. Enroll each configured source with the exact adapter and credential
   references exposed by readiness.
2. Install a tenant-bound subject resolver whose authority digest matches the
   case subject digest, and use short-lived provider credentials with only the
   selected capabilities.
3. Confirm the governed document vault and deployment encryption key custody,
   backup and rotation procedures. If custom sink or target-custody factories
   are injected, both required protocols must be present; invalid configured
   factories fail closed.
4. Run a consenting provider sandbox pilot for lookup, already-absent,
   mutation, ambiguous response, exact-target reconciliation, soft-delete,
   purge, credential rotation, outage and recovery behavior.
5. Retain the limitation that the configured source manifest is not proof that
   every system containing the subject was enrolled.

## Local acceptance evidence

The focused repository slice exercises same-run concurrent duplicate claims,
process exit after provider success, lease expiry during preparation, a legal
hold introduced before dispatch, post-approval source rotation, mixed owned and
external source callbacks, already-absent deletion, immutable provenance,
exact-target identifier reuse/rekey, Graph soft-delete retention, claim-history
garbage collection, encrypted production custody and recovery of one prior
retrieval artifact after a simulated post-ingest database failure. These are
local/synthetic contract tests. Fresh-tenant usability, cross-tenant
adversarial operation, live-provider sandboxes, multi-node scale and customer
acceptance remain separate deployment work.
