# In-house legal workspace

Open **Legal** to manage legal requests, contracts, outside counsel, digital
assignments and the general counsel's review queue. Enable **Legal workspace**
in Settings → All settings first. The advanced installer offers the same choice.
The configuration equivalent is `[legal_workspace] enable = true`; it is off by
default. Sign in, select a workspace and use an account with the `operate`
permission and access to the legal suite.

## Your digital staff

Four AI paralegals support intake and matters, contracts and obligations,
outside counsel and spend, and corporate records and knowledge. Five AI
associates cover commercial contracts, corporate transactions, employment,
product/privacy/regulatory work, and disputes/investigations.

Each assignment names one worker, a requested deliverable and completion
criteria, selected evidence, a target date and supervising counsel. The matter
creator is its supervisor. Digital workers do not approve their own work.
Assignments and their results survive page reloads and application restarts.
The workforce view shows assignments, accepted work and requested corrections
within the matters the signed-in person can access.

## First complete journey

1. Choose **Open a legal request**. Record the business objective, department,
   business owner, jurisdiction, priority and target date.
2. Open **Evidence** and add the relevant source text with its origin and
   status. Text and Markdown files can be imported in the browser. Original
   documents remain in the company's existing document system.
3. Register the contract and assign a worker. Select the evidence explicitly;
   an agreement and its approved playbook can be selected together.
4. Review the worker run. The review shows the exact evidence, configured
   model and maximum cost/time before calling the provider.
5. Review the resulting draft, supporting quotations, unanswered questions
   and citation exceptions. Accept it, request changes with feedback, or cancel.
6. When outside counsel is needed, prepare an engagement with scope,
   deliverables, currency, budget and rate ceiling. Record conflict clearance
   and approval before progressing the engagement.
7. Prepare a counsel packet from explicitly selected evidence. Download it
   for controlled delivery through the company's existing communication system.
   Preparation and download do not claim that the packet was sent or received.
8. Add counsel advice as evidence, assign follow-up analysis, and record the
   business/legal decisions and obligations. Track invoice exceptions and the
   engagement's progress through receipt of advice and closure.

## Operating boundaries

- Every matter has an explicit member list. Sharing a workspace, being an
  administrator, or having the legal suite alone does not grant matter access.
  The supervisor can grant access to current operating workspace members and
  revoke it. Membership changes, views, exports and mutations are audited.
- Native controls and Copilot use the same operation handlers. Copilot mutations
  additionally require the existing Copilot actions switch and `tasks` family.
- Confirmations bind the signed-in account, workspace, permissions, budget
  authority and exact matter revision. A stale review cannot overwrite current
  work. The same confirmation returns its original result rather than duplicating
  a matter or calling the provider again.
- Sources are immutable entries. Add a new source for a new agreement version.
  Contract decisions bind the selected source version. Recording execution
  requires an executed source plus separate legal, commercial and signing
  approvals for that version. This records human approvals; it does not obtain
  an electronic signature.
- Obligations require a supporting quotation that matches the selected source.
  A person confirms the proposed date and its basis before marking completion.
  This release does not calculate court deadlines or maintain jurisdictional
  calendars.
- Changes to an engagement's scope or budget return it to proposed status for
  renewed clearance and approval. Invoice checks detect duplicate references,
  budget overruns, excessive rates and missing rate information. Acceptance does
  not release payment. Spend totals remain separated by currency.
- A worker receives only the reviewed evidence packet, assignment and feedback.
  It has no tools, external retrieval, cross-matter memory or permission to send,
  sign, file, pay, clear conflicts or certify compliance. The existing configurable
  model routing and `Budget` controls apply. There is one admitted provider
  attempt per confirmed run, with no automatic failover or retry.
- Worker citations are checked for source membership and exact quotation
  matching. Unmatched quotations prevent acceptance. These checks do not prove
  authenticity, legal correctness, completeness or subsequent treatment of law.
  Research requires supplied authorities; a live research database or citator is
  not integrated by this module.
- Cancelled work cannot publish a late result. If the process stops during a
  provider call, its saved assignment remains running with its deadline and
  original attempt. Refresh or recover the original result; cancel interrupted
  work before starting a separately reviewed replacement. An uncertain attempt
  may have incurred cost and is never silently repeated.
- These operational matters are distinct from the existing eDiscovery hold
  ledger. Creating a matter does not impose a legal hold on external records or
  extend the eDiscovery subsystem's documented preservation coverage.

## Supported storage and limits

Matter aggregates use the shared `GovernedRecordStore`: tenant-scoped local
storage or the platform's configured Postgres backend, CAS revisions and durable
audit outbox. There are no new dependencies or separate storage credentials.
Local behavior is covered by the module tests; deployment-specific Postgres
acceptance remains required before relying on a shared deployment.

The bounded inventory supports 1,000 matters, 200 records of each kind per
matter, 500,000 source-text characters per matter and 2,000 operations per
matter. A worker packet contains at most 20 sources and 120,000 characters.
Each assignment supports ten explicitly reviewed attempts. Exceeding a limit
produces a refusal; records are not silently discarded or archived. Matter and
packet exports remain available for review and migration.

## Coverage and validation

| Customer job | Direct UI / Copilot operation | Observable result and recovery |
|---|---|---|
| Intake and lifecycle | Legal / `legal.create_matter`, `legal.edit_matter` | Saved scoped matter; closure refuses unresolved work |
| Matter access | Matter operations / `legal.access` | Current member list; rechecked on confirmation and reads |
| Evidence | Evidence / `legal.source` | Immutable text, origin, digest and status |
| Contracts | Contracts / `legal.contract`, `legal.edit_contract` | Version history and separate decisions tied to source version |
| Obligations | Obligations / `legal.obligation`, `legal.review_obligation` | Proposed, confirmed, disputed or completed record with source passage |
| Counsel engagements | Outside counsel / `legal.engagement`, `legal.edit_engagement`, `legal.review_engagement` | Scope, budget, progress and renewed approval after changes |
| Counsel packets | Counsel packets / `legal.packet` | Exact selected evidence; authenticated audited download |
| Invoice review | Invoices / `legal.invoice`, `legal.review_invoice` | Deterministic exceptions and recorded human review |
| Digital work | Assignments / `legal.assignment`, `legal.run`, `legal.review_assignment` | Saved attempts, source-linked draft, feedback and acceptance |
| Business/legal decisions | Decisions / `legal.decision`, `legal.review_decision` | Responsible owner, options and recorded rationale |
| GC oversight | Department overview / `legal.status` | Current authorized attention queue, currency-separated spend and worker activity |
| Export | Matter / counsel packet download, `legal.export` | Authenticated audited export; current access rechecked at download |
| Interrupted confirmation | Review dialog / shared original-result recovery | Original record found without repeating provider work |

Core and HTTP tests are in `test_legal_workspace.py` and
`test_legal_workspace_api.py`. `tests/browser/legal_workspace_server.py` and
`legal_workspace_smoke.cjs` exercise the native dashboard, durable operations,
lost-response recovery, restricted matter access and responsive layout. That
browser fixture supplies a synthetic identity and synthetic provider response;
it does not validate live model quality, a real identity provider, external
counsel delivery, e-signature, payment or licensed legal research integrations.
