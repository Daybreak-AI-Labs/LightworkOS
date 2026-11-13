# Finance regulatory operations and assurance

Lightwork's finance operations layer is deterministic decision-support plumbing
for regulated finance teams. It gathers cited facts, creates review work, and
preserves human authority. It does not use an LLM to interpret a rule, declare a
license requirement, clear a sanctions match, decide a SAR, or issue an audit
opinion.

Enable it with:

```toml
[finance]
regimes = ["sox", "dora", "basel_iii", "ifrs_17", "pci"]

[finance_operations]
enable = true
federal_register_enable = true
texas_register_enable = false
eur_lex_enable = false
edpb_enable = false
regulatory_poll_seconds = 3600
regulatory_domains = ["finance", "money_transmitter", "insurance_producer"]
state_feeds = []
anomaly_enable = true
sanctions_max_age_hours = 72
control_test_interval_seconds = 86400
evidence_due_days = 7
control_owner = "Finance Control Owner"
```

The installer exposes these controls through `maverick init`. The entire module
is off until `[finance_operations] enable = true` is present in deployment-global
configuration.

## What ships

### Regulatory-change monitoring

`maverick.finance.regulatory_change` provides bounded JSON, Federal Register
JSON, RSS, and Atom normalization. The dashboard scheduler retrieves configured
HTTPS sources through Lightwork's DNS-pinned SSRF guard, with redirect
revalidation, a 20-second timeout, and a 5 MiB per-page body ceiling. Federal
Register collection pagination follows the publisher's explicit same-host
`next_page_url`, rejects cycles, and stops at 100 pages or 50 MiB cumulative.
Every page is validated before any write and the complete bounded poll is
promoted in one transaction. A malformed later page, conflicting duplicate ID,
or cumulative limit failure therefore leaves no partial document versions.

Every normalized record retains:

- configured feed URL, actual paginated retrieval URL, and item URL;
- retrieval timestamp;
- page-payload, full canonical source-record, and normalized-content SHA-256 digests;
- the publisher's citation when supplied;
- a monotonically increasing document version; and
- a field-level before/after diff for updated records.

The canonical publisher record is retained under the same bounded payload
budget. If source bytes change without changing mapped fields, the alert still
records before/after digests and bounded changed JSON paths. Enabled-scope
changes are reconciled over every alert version in resumable keyset batches;
disabled scopes become `inactive` instead of remaining in the live queue.

Only records matching an enabled regime or domain enter the review queue. A
review transition uses revision compare-and-swap and is append-only in the alert
history. If a previously accepted or dismissed document later gains a newly
enabled regime or domain, it reopens with a system scope-change event. The initial official
source is the [Federal Register API](https://www.federalregister.gov/developers/documentation/api/v1).
An opt-in built-in uses the official [Texas Register RSS](https://www.sos.state.tx.us/texreg/texreg.xml).
That feed is issue-level, so its HTML/PDF/archive items route to human review;
Lightwork does not pretend they are notice-level rule records. Up to 50 other
state sources may be configured explicitly, with no invented or silently
substituted URL. The built-in EUR-Lex legislation and EDPB news feeds are
also opt-in, through `eur_lex_enable` and `edpb_enable` respectively.

### State-licensing source packs

Two immutable `1.0.0` packs cover all 50 states exactly once:

- money transmitter / money services business; and
- insurance producer.

Each pack has a semantic version, as-of date, deterministic content digest,
renewal workflow metadata, a named state authority, citations, and 50 stable
register projections. The scheduler persists those projections as cited,
versioned documents in the regulatory register; a later pack digest creates a
field diff and reopens review. The money-transmitter pack routes each state
through its official NMLS resource plus the common NMLS company-renewal window.
The insurance pack routes each state through its jurisdiction-specific
[NIPR state requirements](https://nipr.com/licensing-center/state-requirements)
and [NIPR renewal](https://nipr.com/licensing-center/apply-for-a-license/renew-your-license).

The v1 boundary is deliberate: all 100 rows are `source_check_required`. They
do not claim state-law applicability, exemptions, fees, filing deadlines,
continuing-education requirements, or reinstatement rules. The validator refuses
to promote a row to `required`, `not_required`, or `conditional` unless a later
pack includes a dated, jurisdiction-specific primary citation and verification
date. The NIPR/NMLS operational routes are deliberately not sufficient primary
legal authority for that promotion. A lending pack is not included yet.

### Finance anomaly engine

`maverick.finance.anomaly_engine` evaluates normalized transactions with five
transparent rule families:

| Rule | Evidence and guardrail |
|---|---|
| Duplicate payment | Exact/heuristic duplicate groups within a bounded window |
| Benford first digit | Separate currency populations; explicit eligibility attestation; minimum sample and magnitude-order floors |
| Just under approval limit | Caller-supplied threshold and policy citation |
| Split payment / threshold straddling | Same counterparty, bounded time window, cited threshold |
| Off-hours posting | Explicit business timezone, days, and hours |

Findings have stable IDs, a rule version, deterministic score, explanation,
caveats, exact normalized transaction evidence, source-system identifiers, and
content digests. Scans retain a deterministic top set, report exact candidate
and omitted counts, and reject approval-threshold workloads above a fixed CPU
budget before running detectors. Each report includes the canonical rule
configuration, its SHA-256, the normalized-input SHA-256, and a combined scan
SHA-256 so even a clear result is reproducible against its thresholds/calendar.
The API can enqueue findings into the governed
CAS case queue, whose cursor can traverse beyond the first 5,000 records.
The `scan_finance_anomalies` agent tool is wired into the existing
`finance_anomaly` pack and projects both finance findings and
`cross_run_anomaly` output through a small common signal envelope. The
tenant-effective `anomaly_enable` switch stops new API and agent scans.
High-severity closure requires a second human distinct from the disposition
actor.

Benford output is a screening signal, not evidence of fraud. The rule is
ineligible unless the caller explicitly attests that the population is suitable.

### AML, KYC, and sanctions screening

`maverick.finance.aml_screening` ingests bounded text, JSON, CSV, and XML list
versions. It records source, version, publication/retrieval timestamps, parser
version, record count, and SHA-256. The loader rejects XML declarations capable
of entity expansion and refuses missing HTTPS/URN provenance. A source URL,
list kind, and declared version are immutably bound to one payload digest, so a
same-version mutation or concurrent conflicting ingest fails closed.

The matching ladder is explainable: normalized exact, prefix, substring, token
Jaccard, then a bounded character-similarity fallback. Every plausible fuzzy
candidate is evaluated or the screen fails closed; list-head, comparison, and
hit limits never produce a silent clean result. Successful responses explicitly
state the selected scope and whether all latest active sources were covered. Possible
ambiguities are retained as candidates rather than guessed away. Every hit cites
the exact list ID, revision, source URL, version, content digest, entry ID,
matched alias/name, method, score, and rule version.

A possible match opens an idempotent governed case. The screening submitter
cannot review their own case. Final `clear` or `escalate` status requires two
distinct reviewers to agree. If the first two disagree, two additional,
independent adjudicators must agree with each other; after the first adjudicator
the case is `pending_adjudication_review`. Stable list and case IDs make
concurrent identical submissions converge. No code
path automatically blocks a payment, closes an account, or files a report.
When finance operations are enabled, the existing `screen_sanctions` payment
and vendor hook uses this governed path and never falls back to the legacy local
matcher after a governed failure.

OFAC's [Sanctions List Service](https://ofac.treasury.gov/sanctions-list-service)
is the primary public-list source. OFAC also publishes [file hashes for content
assurance](https://ofac.treasury.gov/specially-designated-nationals-list-sdn-list/hash-values-for-ofac-sanctions-list-files).
Production programs remain responsible for list selection, update cadence,
identifiers beyond names, ownership rules, tuning, and qualified disposition.

### Regime expansion

Finance regime policies now include:

- [DORA, Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng);
- [Basel III final reforms and consolidated framework](https://www.bis.org/basel_framework/);
- [IFRS 17 Insurance Contracts](https://www.ifrs.org/issued-standards/list-of-standards/ifrs-17-insurance-contracts/); and
- [PCI DSS 4.0.1](https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss).

The existing `pci` key remains backward compatible. Selecting several regimes
unions policy controls strictest-wins: deny wins over human approval, and the
lowest risk/dollar threshold wins. `[finance].regimes` is compiled into the live
governance policy; malformed or unknown configured keys fail closed. Regime
metadata is a control mapping, not an automatic legal-scope determination.

### Finance operating profile

`maverick.finance.profile` compiles five keys into live controls (the Finance
Operating Profile of the finance-agent-suite proposal, §3.8). Each takes effect
only while `[finance_operations] enable = true` is set in deployment-global
configuration; with the layer off or a key unset, behaviour is exactly as
before. The installer asks for them in its finance step and Settings > All
settings > Finance edits them, with the same values.

```toml
[finance]
framework = "us_gaap"        # us_gaap | ifrs
materiality = 50000          # positive amount in the reporting currency

[finance.automation]
default = "draft"            # draft | approve | auto_threshold | straight_through
"ar.send_invoice" = "approve" # optional per-class override (department.action or action)

[finance.sod]
mode = "enforce"             # enforce | warn

[finance.approvals]
timeout = "fail_closed"      # the only value
```

| Key | Effect |
|---|---|
| `[finance] framework` | Adds that framework's policy pack, unioned strictest-wins with `[finance] regimes`. Both packs require a person to post, close a period, or change an accounting policy. US GAAP refuses `reverse_impairment_loss` (ASC 360-10-35-20, ASC 350-20-35) and `revalue_fixed_asset` (historical cost). IFRS requires a person for both (IAS 16.31, IAS 36.114) and refuses `apply_lifo_inventory` (IAS 2.25). |
| `[finance] materiality` | Review scope. A duplicate, just-under-limit, split-payment or off-hours anomaly finding whose transactions total at least this amount is raised to high severity, so closing its case needs a second, independent person. The amount is recorded in the finding's metrics and in the scan's configuration digest. Benford is a population screen and is unchanged. Materiality also caps `auto_threshold`: an action with an amount above it always waits for a person. |
| `[finance.automation] default` | The automation ladder (§3.1) for the committing finance actions (`maverick.finance.profile.FINANCE_ACTIONS`: payments, postings, payroll, master-data changes, approvals of expenses/POs/suppliers, invoices, credit limits, write-offs, disposals, trades, tax and filings). `draft` refuses the agent's call, because an agent prepares and a person carries the action out. `approve` requires a person for every call. `auto_threshold` runs only when the call carries an amount within the lower of `[governance] require_human_above` and materiality; otherwise it requires a person. `straight_through` adds no gate. Other keys in the table set one action class's level. |

Dollar thresholds also apply to governed flow actions. Direct flow and library
workflow actions are unavailable when capability enforcement is enabled or an
active agent grant is inherited; the library workflow otherwise requires its
caller to provide appropriate authorization. When a relevant
transaction's amount cannot be verified, a configured deny ceiling refuses the
call and an approval threshold requires a person. Refunds for the full balance,
non-USD amounts without a trusted conversion, and Stripe refunds whose charge
currency is unknown cannot be compared to a dollar ceiling. A configured ceiling
therefore blocks those calls or sends them for approval; do not supply a guessed
currency to bypass that decision.
Generic tools whose transaction amount cannot be established from a known
operation are also refused or require approval when a threshold applies, even
when they carry an `amount` field. Wildcard thresholds can therefore restrict
unrelated generic actions; use explicit action thresholds when appropriate.
Direct callers of `governance.evaluate` also treat an omitted amount as
unverifiable when a threshold applies. Only a trusted caller that knows an
operation is non-transactional should explicitly set `amount_unavailable=False`.
For example, a wildcard threshold also applies to federation delegation, which
has no transaction amount and is refused if it needs approval. Use narrowly
scoped action thresholds if delegation should remain available.
| `[finance.sod] mode` | An action-time separation-of-duties check on the agent path and on flow/workflow dispatch. When a duty-bearing tool (record, authorize, custody, reconcile) is about to run, the acting agent's grant is linted together with every pack sharing its compartment. An agent with no allow-list holds every duty. `enforce` refuses a conflict. `warn` writes a `finance_sod_finding` audit row as the compensating control's evidence and requires a person's approval (§3.6); if the row cannot be written, the action is refused. A conflict on a hard-floored action is refused in both modes. A flow step holds no agent grant, so a conflict there is always refused. |
| `[finance.approvals] timeout` | `fail_closed` sends a finance action that needs approval to a person through `require_person`. The automatic consent mode and earlier "remember this" grants never answer it. A request nobody decides within `[approval] dashboard_wait_seconds` is refused and withdrawn from the Approvals page. No value can make an unanswered finance approval proceed, so none is offered. Unset, finance approvals follow the general rule, which also requires a fresh human decision. |

**Hard floors.** While the ladder is in use, these actions stay at `approve` or
stricter whatever the default: `release_payment`, `send_payment`,
`wire_transfer`, `ach_send`, `release_payroll_payment`, `run_payroll`,
`edit_employee_bank_details`, `vendor_master_change`, `post_journal_entry`,
`close_period`, `edit_chart_of_accounts`, `remit_tax`, `file_return`,
`file_tax_return` and `file_with_sec`. An explicit entry that lowers one below
`approve` is refused. The governance policy fails closed, and the dashboard
refuses the save. Levels, like regimes, only ever add gates: a
`straight_through` level never loosens `[governance]`, a regime, or a
framework pack.

### Finance↔GRC control-testing loop

The scheduled control cycle gathers deterministic finance posture observations,
opens a normal Security/GRC audit engagement, records each control test as
`needs_review`, and creates the corresponding evidence request. Pass/fail still
requires human-approved evidence under the existing GRC integrity rules.

A bounded scheduled readback follows a rotating governed cursor. It accepts
only terminal human tests backed by approved evidence and an accepted/closed
generated evidence request, then records per-control results as
`human_review_passed` or `human_review_failed` on the finance cycle. Later GRC
reversals reopen or revise that finance result; the API also exposes an explicit
single-cycle reconcile action.

Cycle records use tenant-scoped governed storage, stable period IDs, revision
compare-and-swap, execution leases/generations, and the durable audit outbox.
After a process loss or provider failure, the next cycle reconciles the marked
engagement, tests, and evidence requests before resuming, avoiding orphaned or
duplicate GRC work. Replaying a completed schedule period returns its existing
cycle.

## Product surfaces

The `/finance` workspace shows queue counts, cited regulatory alerts, pack
versions/digests, anomaly case metadata, privacy-minimized AML case metadata,
and the GRC engagement link. Detailed workflows live under 24 endpoints at
`/api/v1/finance-operations`:

- `/summary` is viewer-safe aggregate data only; regulatory counts are exact,
  while anomaly and control-cycle scans read at most 50 records one at a time,
  AML case counts use a 25-record first-page cap, and every bounded count
  discloses its cap and truncation state;
- regulatory alerts, anomaly cases, and control cycles use metadata-only cursor
  pages capped at 25 records so detail evidence is loaded only by ID;
- AML list pages contain metadata only and are capped at 500 versions. AML case
  lists are privacy-minimized, capped at 25 records, and explicitly identify
  themselves as a bounded first page until a durable case index is available;
- regulatory and case details require `operate`;
- list metadata never returns the full names/aliases payload; and
- feed/list ingestion and manual control-cycle triggers require global `admin`.

The workspace and all 24 routes also require the `finance` suite grant. POST
bodies are capped before JSON/Pydantic parsing (256 KiB normally, with bounded
larger envelopes for regulatory feeds, screening lists, and transaction scans).
Tenant-scoped success receipts make regulatory and GRC posture report `active`
only after a recent successful scheduled operation.

Mutations return revision conflicts as HTTP 409, validation failures as 422,
missing records as 404, and unexpected failures as a redacted 503. Dashboard
mutations require the same-origin header enforced across Lightwork.

## Demonstration walkthrough

1. Enable the module and the desired finance regimes.
2. Ingest a bounded Federal Register fixture (or let the scheduler poll the
   official endpoint), then show the cited alert and field diff in `/finance`.
3. Show both licensing pack digests and their 100 persisted state-register
   documents while calling out the `source_check_required` boundary.
4. Submit a small transaction set containing one duplicate, one just-under-
   threshold payment, and one off-hours posting; show the exact evidence that
   produced each stable finding.
5. Ingest a small cited sanctions fixture, screen a typo/alias, and demonstrate
   that the submitter cannot clear it and one reviewer cannot finalize it.
6. Trigger a finance control cycle and open the resulting Security/GRC
   engagement, where every machine test is still `needs_review` with an evidence
   request. Record evidence-backed human results, then reconcile them back into
   the finance cycle.

This walkthrough exercises the product loop. It does not provide legal advice,
a production sanctions determination, evidence of fraud-detection efficacy, or
an audit opinion.

## Known v1 boundaries and next work

- Add counsel-reviewed, jurisdiction-specific licensing pack versions and the
  lending vertical.
- Certify notice-level state-register endpoints one state at a time; the shipped
  Texas source is an issue-level starting point.
- Add commercial sanctions/PEP providers and structured identifiers (DOB,
  address, nationality, ownership) behind the same governed case contract.
- Add reconciliation feedback and labeled-case precision/recall measurement for
  anomaly tuning; do not tune against synthetic demos alone.
- Move the regulatory document/alert register to the shared governed Postgres
  authority before claiming active-active multi-replica operation. The current
  SQLite register is concurrency-safe on one shared filesystem but is not a
  cross-region database.
- Keep finance control-cycle and Security/GRC engagement storage on the same
  governed filesystem/replica until both authorities share a cross-replica
  persistence and correlation contract.
- Complete legal, security, privacy, and model-risk review before production use.
