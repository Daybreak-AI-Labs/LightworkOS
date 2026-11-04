# Platform contracts v1

- Module: `maverick.platform_contracts`
- Scope: additive transport projections over existing Lightwork authorities
- Consumer: governed vendor onboarding

## Design

Lightwork uses a small versioned contract layer for records that cross product,
worker, evidence, and research boundaries. The layer is implemented in
`maverick.platform_contracts`. It validates projections and exports; it does not
own a database, grant authority, dispatch work, or replace a domain model.

Every contract carries one common envelope: schema and version, immutable
logical ID, server-resolved tenant and owner, purpose, UTC timestamps, monotonic
revision, provenance, policy snapshot, authority and credential versions,
idempotency state, budget, exact or explicitly unknown cost, freshness, human
intervention, uncertainty, and causal status. Unknown values are structured
states with a reason. Producers must exclude secret values from defined domain
fields. Export applies the separate boundary below; it does not detect secrets
embedded in arbitrary customer prose.

The v1 schemas are:

| Contract | Existing authority and persistence | v1 role |
|---|---|---|
| WorkItem | `VendorOnboardingService` plus tenant-scoped `GovernedRecordStore` | Customer-facing projection of objective, journey, deployment boundary, lifecycle, next action, technical verification and business acceptance. |
| ActionIntent | `vendor_onboarding.operation` plus `governed_operations` bindings | Portable intent and approval metadata. The original operation record remains authoritative. |
| Observation | provider adapter readback, evidence records and evidence graph | Independent, source-versioned facts and artifact references. It never grants execution authority. |
| OutcomeRecord | onboarding outcome and `outcomes`/operating-record consumers | Versioned business verdict distinct from an API response or verified technical effect. |
| ExperienceRecord | outcome/evidence sources and existing governed learning consumers | Rights- and retention-bound reference to learning material. It is not a second experience database. |
| ExperimentSpec | immutable `consent_experiments.ExperimentSpec` | Cross-program protocol envelope. The specialized experiment service keeps enforcing its domain constraints. |
| CandidateManifest | `self_modify_archive.CodeCandidate` plus promotion/evaluation records | Hash- and lineage-bound candidate metadata. It does not make a candidate releasable. |

Action receipts, cost events and run attempts remain domain records. The v1
contracts can reference them; they have no general-purpose table.

## Compatibility and mutation rules

The reader accepts only the declared v1 schema names. It supplies documented
defaults for additive optional fields such as `schema_version`, `updated_at`,
and empty authority or credential-version maps. Identity and domain fields have
no guessed default. Reading then reserializing a supported legacy v1 projection
therefore preserves its logical ID and meaning.

Inputs must have string object keys and JSON values, with at most 64 levels of
nesting and 65,536 value nodes within the 1 MiB serialized transport limit.
Tuples, bytes, sets, cycles and other Python objects are rejected before copying
or exporting. Before copying or rendering JSON, traversal also sums aggregate
encoded size, counting repeated references each time they occur, object keys,
container punctuation, scalars, and JSON's ASCII escapes for controls and Unicode.
The normalized serialized record then passes a final exact UTF-8 byte-limit check.
Native `Decimal` values are permitted only for budget limit/spent
and exact cost amount; readers convert those to decimal strings. Fixed-point
money representations are limited to 64 characters, with magnitude and scale
checked before exponent expansion. Negative zero is normalized to `0`.
Native Decimal coefficients are bounded before string or tuple conversion:
exact quantization uses a fixed 64-digit context and traps any inexact result.
Oversized fractional coefficients are rejected even when their magnitude is
small; arbitrarily many redundant trailing zeros may be removed because their
removal preserves the exact monetary value. Ambient decimal precision cannot
silently change the result.

Unknown schemas, cross-tenant reads, non-finite or overspent budgets, invalid
timestamps, stale revisions, and invalid transitions raise
`PlatformContractError` with a stable machine code. Domain mutation services
must validate their own persisted schema and contract binding before writing or
calling a queue/provider. Storage remains responsible for compare-and-swap;
the contract revision is its visible token.

The generic WorkItem transition validator supports these policy-level edges:

| From | Allowed next states |
|---|---|
| Draft | Ready, Failed, Cancelled |
| Ready | Awaiting approval, Running, Failed, Cancelled |
| Awaiting approval | Ready, Running, Failed, Cancelled |
| Running | Awaiting observation, Needs reconciliation, Failed, Cancelled |
| Awaiting observation | Verified, Needs reconciliation, Failed, Cancelled |
| Needs reconciliation | Ready, Verified, Failed, Cancelled |
| Verified | Accepted, Failed, Cancelled |
| Cancelled | Needs reconciliation |
| Accepted, Failed | none |

The vendor-onboarding service projects its more detailed stages onto this
lifecycle. Its existing durable `executing`, `reconciliation_required`, and
`verified` operation states remain the execution authority.

Cancellation records a local decision and preserves the current technical effect.
It cannot relabel a verified external effect as absent or grant customer acceptance.
A cancelled WorkItem can return to Needs reconciliation for new readback; that
edge alone grants no execution permission. The domain retains the cancellation
decision and must continue rejecting new dispatch and acceptance after cancellation,
even if subsequent observations change the projected lifecycle.

A WorkItem in Verified or Accepted must have `technical_effect=verified`.
Accepted and `business_outcome=accepted` must occur together. In particular,
Verified does not imply business acceptance: a transition to Accepted must
explicitly supply the accepted business verdict. These checks enforce projection
consistency; the owning domain service still validates the human decision,
evidence and authority that justify it.

## Export boundary

`read_contract` preserves bounded JSON extensions for additive compatibility.
`export_contract` exports defined envelope and record fields (including the
WorkItem's optional `objective` and `contract_binding`). Other top-level
extensions become `[redacted]`. The optional `diagnostic` extension retains its
object/list structure and managed credential references, but every other leaf
value is redacted, including unknown provider fields and free-form messages.

Defined domain maps are scrubbed recursively for credential-bearing field names,
including snake/camel/acronym variants of API keys, access keys, tokens, secrets,
passwords, credentials, Authorization, Proxy-Authorization, Cookie and Set-Cookie.
Matching is case-insensitive after removing separators, so compact uppercase
forms such as `APIKEY` and `ACCESSKEY` follow the same rule as `api_key`. Credential
reference suffixes use that identical normalization.
A credential-like name ending in `ref` or `reference` does not by itself exempt
its value. Supported references are a closed `{kind: managed_connection, id: ...}`
object with an opaque bounded identifier, or a legacy `vault://tenant/path`
locator without embedded authentication, query parameters or fragments. Plural
reference lists apply the same check to every entry; unsupported values are
redacted. These are reference-shape checks, not proof that a connection exists or
that the caller may access it.

Defined customer text and domain observations remain customer data. The exporter
does not infer whether a secret was placed in a purpose, fact, arbitrary domain
field or syntactically valid managed identifier. The producing service must keep
raw credentials out of those fields and authorize the tenant, resource and
recipient before exporting. This helper is neither an authorization service nor
a general free-text secret scanner.

## Vendor onboarding

Vendor onboarding pins the exact supplier-evidence journey contract at intake.
The API returns a WorkItem projection generated by the shared validator. A Jira
readback can set `technical_effect=verified`, while `business_outcome` remains
`pending` until an authorized human accepts or rejects the result. The dashboard
shows the technical promise, business completion rule, supported topology, and
explicit exclusions.

Vendor onboarding uses `lightwork.error.v1` with stable `code`,
customer-readable `message`, `retryable`, and `next_action` fields for
composition, authority, record, contract, revision, workflow, and provider
failures. Provider payloads, credential values, stack traces, and storage paths
are excluded. The v1 error envelope carries no request ID, retry timing or
current revision.

## Route map

| Logical operation | Authenticated route |
|---|---|
| Create/list/read work | `POST /vendor-onboarding/cases`, `GET /vendor-onboarding/cases`, `GET /vendor-onboarding/cases/{case_id}` |
| Update evidence/work | `POST /vendor-onboarding/cases/{case_id}/documents`, `/upload`, `/upload-preview`, `/upload-reviewed`, `/collect-evidence`, `/assess` |
| Prepare intent | `POST /vendor-onboarding/cases/{case_id}/prepare-action` |
| Approve intent | `POST /vendor-onboarding/cases/{case_id}/approve-action` |
| Execute | `POST /vendor-onboarding/cases/{case_id}/execute` |
| Observe/reconcile | Provider verification inside execute; `POST /vendor-onboarding/cases/{case_id}/reconcile` |
| Accept/reject result | `POST /vendor-onboarding/cases/{case_id}/accept` with explicit boolean |
| Renew/check freshness | `POST /vendor-onboarding/cases/{case_id}/check-renewal`; new intake links `renewal_of` |
| Correct review | `POST /vendor-onboarding/cases/{case_id}/review` with corrections |
| Cancel the request | `POST /vendor-onboarding/cases/{case_id}/cancel` (see [supplier request cancellation](./supplier-cancellation-v1.md)) |
| Export evidence | `POST /vendor-onboarding/cases/{case_id}/evidence-export-preview`, `/evidence-export` |

Experiments, run inspection and candidate promotion or restore use their own
specialized services; the v1 contracts define no shared route for them.

No route accepts a client-supplied tenant or owner as authority. Existing
authentication, role checks, service context, operation bindings, and governed
stores remain the enforcement points.

## Conformance tests

`test_platform_contracts.py` covers every declared schema, additive v1
compatibility, non-finite budgets, unknown schemas, tenant mismatch, transition
guards, revision conflicts, technical/business separation, and redacted export.
The vendor-onboarding tests cover single-winner revision checks on the governed
store, journey bindings, and the absence of provider effects on stale or
unsupported records. Dashboard API and JavaScript tests cover the error envelope
and customer-facing scope.
