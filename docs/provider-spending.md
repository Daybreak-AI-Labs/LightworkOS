# Provider spending and reviewed accounting recovery

The existing `[budget.provider_caps]` setting enables a provider cap, with
`[budget] provider_caps_period = "day"` or `"month"` selecting UTC periods.
This remains separate from a run's Budget and a principal's quota. No configured
cap leaves provider admission unchanged. No provider cap is enabled by
default.

Local provider spending is shared across the deployment rather than separated
by tenant, and earlier per-tenant ledgers are folded in once; review configured
caps against the deployment's combined spending after upgrading.

Every physical synchronous, asynchronous, or hedged LLM dispatch reserves its
projected cost under the accounting lock before calling a provider. Outstanding
reservations are included in the numeric total. The call's own response usage
replaces its reservation with actual cost. A cancellation, ambiguous failure,
or missing usage leaves an unresolved charge; a crashed process leaves its
reservation charged. Neither is automatically refunded or retried. Unknown
final charges block further admission for that provider and period.

Projection uses known pricing and estimated tokens. Providers can report a final
cost above the projection; that full cost is recorded and subsequent admission
is blocked at the cap. This is not a guarantee about the provider's external
invoice. Local accounting follows the existing workspace data scope. Configured
shared PostgreSQL accounting uses row-locked counters and reservation receipts;
it never substitutes a local ledger if the shared authority is unavailable.

An established local ledger has a `provider_spend.json.required` marker. Missing,
unreadable, oversized, or invalid accounting blocks capped calls and preserves
the failed bytes. Compatible existing numeric ledgers migrate when first written.
Settlement failure retains the prior charge instead of making an already-incurred
successful call look safely retryable.

## In-app review

Open **Workspace recovery → Provider spending** as a global administrator.
Inspect current or previous UTC periods, search a previously configured provider,
and page through unresolved reservations. Counts show when more reservations
exist beyond the displayed page. A provider's currently configured cap is shown
for comparison, including on historical periods.

For a reservation whose final cost is unknown, enter its final invoice or receipt
reference and verified cost. Review the exact provider, period, reservation,
amount, and evidence, then explicitly confirm. The change is bound to the current
account, workspace, exact accounting revision, and a ten-minute review. It
preserves all other reservations and retains a governed audit receipt. A known
reservation that may still be running requires actual isolated desktop recovery,
not a checkbox. A retained correction interrupted after its ledger write can
finish the exact receipt without applying it twice. This browser session retains
only the review ID for that account/workspace, so Refresh can reopen its review.

## Unreadable local accounting

Download a verified complete accounting copy while accounting is healthy. It is
authenticated with the workspace recovery key; create and separately retain that
key through Workspace recovery. The copy includes confirmed totals, reservations,
and settlement identities. Metadata-only diagnostics can be downloaded even when
accounting cannot be read; they do not include damaged file contents.

Repair requires the desktop's existing isolated recovery mode and enforced
single-control-plane lease. Independently managed workers and external storage
block this local procedure. Select a verified complete accounting copy bound to
this workspace, then enter complete confirmed spending totals for every exported
provider/period and any later provider/period. Exported confirmed amounts cannot
be reduced; exported unresolved identities remain reserved separately. A separate
confirmation requires final provider receipts for every call since the export.
If later costs remain unknown, do not apply repair from that copy. Lightwork
does not contact providers or establish invoice completeness automatically.

The final review binds the failed file's SHA-256 and preserves those bytes before
replacing accounting. Readable accounting cannot be replaced from an older copy.
Changes after review refuse the repair. Shared database corruption requires its
administrator's coordinated recovery; there is no local override, automatic zero,
or old-schema merge. Losing both trustworthy accounting and complete final cost
evidence remains a reconciliation boundary, not proof of zero spending.

## Validation

The focused core tests use actual local ledgers, SQLite transactions, process-crash
fixtures, and synthetic LLM clients. They cover concurrent admission, per-hedge
reservations, unknown costs, idempotent settlement, preserved invalid bytes,
review binding, receipt coverage, pagination, and interrupted completion. Dashboard
API tests use temporary workspaces; DOM tests execute the actual template and
controller with synthetic HTTP responses. The dedicated PostgreSQL two-connection
test requires the existing PostgreSQL test DSN and does not claim local live
database acceptance without that fixture. No test calls a live provider.
