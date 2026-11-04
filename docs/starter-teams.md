# Autonomous Shoring starter teams

The starter-team catalog provides 37 bounded workflows for approved structured
exports. Each team has a small roster of existing specialist packs, a named
business owner, a setup review, synthetic sample inputs, deterministic checks,
an evidence-linked exception worklist, and persistent cases and handoffs.

There are two execution paths. **Check the evidence** runs the declared
deterministic rules without an AI provider. **Run the specialists** uses the
native goal runner and configured AI provider to produce successive intake,
analysis, and review drafts over an exact, human-approved evidence package.
Both paths prepare work for an accountable owner. Neither can make external
business changes.

A roster, saved setup, or passing deterministic sample does not certify that
the provider connection or specialist output meets customer requirements.
Provider-backed execution requires separate review and finite spending and
time limits. Sample-mode cases cannot launch provider-backed specialist goals.

## Use the starter-team workbench

Open **Workforce**, then **Starter teams**. Choose a team and review its inputs,
connection checklist, acceptance criteria, restrictions, and sample goal.
Assign a business owner and a precise scope. Review and confirm the setup
before running its sample. The same operations are available through Copilot
under the same account, workspace, permissions, and review requirements.

Results contain the supplied source references, row digests, check outcomes,
proposed follow-up work, and handoff records. A source reference is an
identifier supplied with the export: the engine does not open it or verify
that the upstream document is authoritative. Review the worklist against the
original evidence before relying on it.

Customer inputs must follow the team's declared table columns. Extract and
approve facts such as notice dates, contractual limits, policy decisions,
currency-normalized totals, or lead-time demand before import. The engine
checks those values; it does not independently establish them. To request
specialist analysis of a supplied-export case, review the exact evidence,
roster, deliverable, permitted tools, and total dollar and wall-time limits,
then approve that specific runtime plan. The native runner preserves each
specialist's domain and effective capabilities. Each next specialist receives
the actual prior result and its digest. The final draft remains subject to
human business acceptance.

After you confirm and start a direct specialist workflow, Lightwork continues
through its reviewed roster automatically while the application is running.
You do not need to approve each handoff or keep its page open. The local worker
uses the original review, owner, evidence, and total limits, and rechecks current
authority before advancing. A review that has only been prepared or approved
does not start in the background. Paused, blocked, and uncertain work does not
silently restart.

The runtime permits only authorized knowledge retrieval and local control
lookup. Caller and specialist capabilities further restrict those tools. It
does not grant file writes, shell, arbitrary connectors, spawning, messaging,
payments, publishing, access changes, or deployment. Each run uses an explicit
**supplied-evidence workflow** over the existing specialist's persona and
policy. It replaces that pack's broader fetch/action playbook with bounded
intake, analysis, or review of the approved packet. The review binds both the
original pack and this effective workflow; the native worker verifies that
binding before constructing the agent. Original terminal approval gates remain
release gates.

The effective workflow must pass its readiness check, and the configured
provider must remain available. The original pack's full-workflow diagnostics
are retained separately. In the repository's offline qualification environment,
all 37 teams' actual effective profiles pass native readiness and tool
compatibility checks. Broader pack readiness depends on the enabled tools and
configured executors and may still be blocked. An effective evidence workflow
does not establish that disabled web search or missing financial, CRM, lease,
or other connector executors in the original pack have been implemented. Pausing prevents later
stages from starting; it does not claim to cancel a goal already admitted to
the native runner.

## Reviewed schedules

The setup's cadence preference is descriptive. Actual recurring work requires
a separate schedule review with a UTC start and end, an interval of at least
one hour, a run-count limit, a per-run dollar and time cap, and an aggregate
dollar cap. Each immutable evidence package placed in the schedule's inbox
also needs its own human approval of the exact specialist runtime plan. A
schedule cannot approve future inputs, fetch fresh exports, or replay an old
export as if it were current.

While Lightwork is running, its local schedule worker checks due work every
30 seconds. It reconstructs the saved owner's current role, policy, budget,
workspace, and department access before dispatch. It admits an approved
package only at or after its due time and advances successive stages under
that same occurrence. Without approved inputs, it waits. The bounded worker
advances at most five schedules per tenant in a cycle and rotates through
active tenants; it does not promise exact-second execution.

The same worker separately advances at most five already-started direct
workflows per tenant in a cycle. Dispatch ownership is bound to the runtime
review: direct continuation cannot advance a schedule-owned workflow around
its schedule's pause, due-time, or approval controls. Schedule-owned work stays
under its exact approved schedule item.

Approval must still be fresh when the first specialist starts: the reviewed
runtime's dispatch window lasts 24 hours. For a later weekly or monthly
schedule, approve that occurrence's evidence close to its due time. Pausing a
team or schedule blocks new dispatch. Blocked or uncertain runtime outcomes
hold the schedule for review. Reservations count the approved per-run maximum
against the aggregate cap; they are not a statement of actual provider spend.
The worker needs a running persistent application and its original current
authority. Closing Lightwork stops background progress.

## What qualification means

| Level | Meaning | Evidence needed |
| --- | --- | --- |
| Sample | The bundled synthetic input produces the expected findings and provenance under offline tests. | Exact sample inputs, expected findings, output, and test result. |
| Structured customer input | The checks can process an authorized export that meets the declared schema. | Source-owner review of every normalized field, current scope and owner, correct permissions, and acceptance of the resulting worklist. |
| Specialist runtime wiring | The native runner receives the bound domain, attenuated capabilities, approved evidence, budgets, and prior-stage result; durable recovery reads the same goal. | Offline tests with a fake submission/provider boundary. This proves plumbing, not live provider output quality. |
| Provider qualification | The configured model provider executes the reviewed evidence workflow and returns useful, bounded results. | Separate provider identity, budget, error, recovery, and representative output tests. No live provider was exercised by this qualification. |
| Source connection qualification | The intended upstream source can supply authorized, current evidence reliably. | Separate connection, identity, scope, freshness, error, and recovery tests. The starter workflow does not fetch upstream exports. |
| Customer qualification | The workflow satisfies the customer's actual business requirements and operating controls. | Representative customer cases, acceptance criteria, source checks, approval boundaries, operational support, and explicit owner sign-off. Not inferred from sample tests. |

Bundled sample-mode results remain outside the real Operating Record and
Shoring SLA measurements: the sample path creates no native specialist goal,
and the provider-backed path refuses sample-mode cases. A passing sample is
not a completed customer engagement, a compliance attestation, or live
integration readiness. Do not upload synthetic sample content as a customer
export to represent it as real work.

Native specialist stages remain available with their original goals, execution
costs, and results. They are excluded from Work value request discovery and
economic estimates, including Ekko's repeated-work suggestions. Intake,
analysis, and review are contributions to one team occurrence; they are not
three independent customer requests. A team-occurrence adapter for those
surfaces is not implemented. This limitation applies to direct runs and each
separately approved scheduled occurrence, and does not change native cost
records or claim whole-team Shoring SLA aggregation.

## Authority, durability, and recovery

Setup review binds the team definition, owner, scope, limits, authenticated
authority, and expiry. Changed review material or authority requires a fresh
review. A replay returns the original saved setup when its binding matches.

Cases are isolated by tenant, resource owner, and workspace authority. Each
run binds its idempotency key to its exact inputs, date, and setup. Repeating
the same request retrieves its existing case; changing inputs under the same
key is refused. Restarting the service does not erase those receipts.

Backup restore has an additional limit. The recovery inventory retains all nine
starter-team stores as authority-bearing state. Restoring any of those stores
blocks normal application startup, reconciliation completion, and automatic
dispatch. Their bytes remain intact for investigation. A starter-team restore
adapter that safely reconciles pending work and invalidates old approvals is
not implemented; supplying a generic readback reference cannot clear this hold.
Normal restart using the intact original stores and original-result recovery
remain supported by the workflows described here.

The shared governed-record store supplies revision checks and a durable audit
outbox. The starter-team service supports one persistent application replica;
it refuses unsupported shared execution rather than assuming a local lock
coordinates independent hosts. The specialist path invokes the existing native runner under a
strict prepare-only capability envelope. An approval to save a setup,
prepare a worklist, run specialists, or save a schedule cannot release a
payment, send a message, grant access, sign an agreement, publish, or deploy.

If a response is lost, use the original-result recovery control before
submitting a new request. When inputs are invalid or the bounded processing
budget is exhausted, correct the input or reviewed limit and start a new
request. Do not treat an incomplete or failed case as a cleared exception.

For specialist work, the runtime persists the reservation and exact goal
identity before submitting it. An uncertain submission is not automatically
resubmitted. Reconciliation reads that original goal and checks its owner,
domain, execution principal, and prompt binding before accepting its result.
An empty, oversized, failed, or unconfirmed result cannot silently advance the
next specialist. The schedule follows the same runtime recovery path.

This first local implementation has finite per-tenant stores: 500 team setups,
500 schedules, 5,000 cases, 5,000 runtimes, and 5,000 schedule input packages.
There is no retirement interface for those records yet. Reaching a cap refuses
new records while existing records remain available. Confirmed schedule tick
receipts and setup review previews use the governed store's archive path;
archived receipts remain recoverable by their original identifiers. Unresolved
tick receipts are retained for investigation.

## Catalog coverage

The team's connection checklist and acceptance criteria are the authoritative
per-team setup details. All 37 teams have offline-qualified deterministic
samples, persistent cases, and the shared reviewed specialist path. All 37
remain unqualified for live provider output and customer business acceptance.
The matrix describes the supplied-evidence work and the facts an authorized
source owner must supply; it does not certify the original packs' broader
connector workflows.

| Team | Prepared work and checks | Upstream facts and review required |
| --- | --- | --- |
| Compliance Operations | Control evidence register, gaps, and follow-up list. | Approved control mapping, evidence state and dates; compliance interpretation and attestation. |
| Vendor Assurance | Supplier evidence gaps and review exceptions. | Authoritative supplier, risk, contract, and approval facts; onboarding decision. |
| AP & Purchasing Exceptions | Invoice, purchase-order, and receipt exceptions. | Normalized amounts, quantities, currencies, and references; payment or purchase authorization. |
| Support Operations | Ticket routing and knowledge-review worklist. | Approved routing, ticket state, ownership, and knowledge evidence; customer communications. |
| Security Questionnaire Desk | Missing or unsupported questionnaire answers. | Approved answer and evidence references; security assertions and delivery approval. |
| Privacy Operations | Request evidence and deadline worklist. | Verified intake, jurisdictional deadlines, identity state, and source map; disclosure or deletion authority. |
| Contract Obligations & Renewals | Obligation and notice-date action packet. | Reviewed contract extraction, owners, and dates; legal interpretation or execution. |
| Audit Readiness | Evidence freshness and missing-input index. | Approved audit requirements, evidence dates, and provenance; auditor acceptance. |
| Employee Onboarding & Offboarding | Checklist gaps and completion evidence. | Authorized employee-event and task records; access and employment decisions. |
| Revenue Operations | CRM completeness and stalled-work exceptions. | Approved account and opportunity exports; outreach and sales decisions. |
| Billing & Collections Preparation | Billing disputes and collection-preparation worklist. | Reconciled contract and invoice data; collection communications and money movement. |
| Software Release Operations | Release evidence and unresolved-item worklist. | Authoritative test, approval, and issue results; deployment authorization. |
| Management Reporting | Reporting completeness and decisions needed. | Approved metric definitions, values, dates, owners, and decisions. |
| RFP & Proposal Operations | Requirement coverage and submission exceptions. | Approved requirements, answers, evidence, and deadlines; bid commitments and submission. |
| Customer Onboarding | Setup, training, and handoff readiness worklist. | Approved milestones and completion evidence; configuration and customer communication. |
| Customer Success & Renewal Preparation | Renewal commitments and account-review exceptions. | Approved usage, support, contract, and commitment facts; renewal negotiation. |
| Insurance Certificate Desk | Coverage-limit and expiration exceptions. | Reviewed certificate extraction and contractual requirements; licensed coverage review. |
| License & Permit Operations | Renewal and missing-material worklist. | Official obligations, dates, and required materials; authorized filing or certification. |
| Data Quality Operations | Missing, inconsistent, or duplicate-record findings. | Approved data definitions and source records; corrections and validation of applied changes. |
| Procurement Sourcing | Quote and requirement comparison worklist. | Comparable normalized quotes, requirements, and terms; supplier selection and purchasing. |
| Expense Review | Policy, duplicate, and documentation exceptions. | Approved policy parameters, receipt facts, and amounts; reimbursement decision. |
| IT Service Desk | Ticket ownership, approved-runbook, and diagnostic gaps. | Approved runbooks and diagnostics; authorized configuration or access changes. |
| Incident Coordination | Timeline, owner, evidence, and follow-up gaps. | Authoritative incident events and assignments; incident command and containment decisions. |
| Research & Competitive Intelligence | Source-date and evidence-review worklist. | Selected public-source observations and approved comparisons; independent verification. |
| Board & Committee Operations | Packet, agenda, decision, and action gaps. | Approved governance records and owner assignments; notices, decisions, and external follow-up. |
| Order Management | Order, inventory, and fulfillment exceptions. | Authoritative order and fulfillment quantities/status; customer updates or order changes. |
| Inventory Planning | Stock-risk and replenishment-review worklist. | Approved demand, lead time, stock, and policy assumptions; purchasing or stock movements. |
| Logistics Exceptions | Shipment, document, and delivery-discrepancy worklist. | Carrier and delivery facts; resolution decisions and communications. |
| Quality Operations | Defect, complaint, and corrective-action exceptions. | Approved classification and quality evidence; quality disposition and corrective action. |
| Maintenance Planning | Due maintenance and inspection follow-up. | Approved asset schedules and qualified inspection findings; safety-critical decisions. |
| Construction Project Controls | RFI, submittal, and change-control worklist. | Approved commitments, dates, and cost/scope facts; change approval and field decisions. |
| Property Operations | Maintenance, lease, and vendor-document follow-up. | Approved property obligations and inspection facts; no tenant eligibility or adverse decisions. |
| Grant Operations | Eligibility-evidence, application, and reporting worklist. | Published criteria and reviewed program facts; application representations and submission. |
| Training & Certification Operations | Completion and expiration exceptions. | Approved role requirements and verified completions; qualification or personnel decisions. |
| Product Feedback Operations | Evidence and priority-review worklist. | Source-owner theme classification and impact inputs; product prioritization and commitments. |
| Content Production Operations | Brief, evidence, and approval-completeness worklist. | Approved briefs, factual sources, and asset status; editorial approval and publishing. |
| Business Continuity Operations | Recovery, dependency, exercise, and preparedness gaps. | Approved recovery requirements and exercise evidence; activation and operational decisions. |

## Configuration and developer verification

The feature follows the existing Shoring enable setting (`[shoring] enable`,
or `MAVERICK_SHORING`). Turning it off removes the operational surface and
blocks service access; it does not destroy stored work.

The versioned catalog data ships with `maverick-core` under
`maverick/starter_team_data/`. Adding a team requires a declared input schema,
existing specialist IDs, review restrictions, deterministic rules, synthetic
pass and exception cases, and exact expected finding identifiers. Do not add
an unsupported operator or claim live readiness through catalog metadata.

Run focused qualification from the repository root with the repository's
configured Python environment:

```text
python -m pytest -q packages/maverick-core/tests/test_starter_teams.py
python -m pytest -q packages/maverick-core/tests/test_starter_team_runtime.py
python -m pytest -q packages/maverick-core/tests/test_starter_team_schedule.py
python -m pytest -q packages/maverick-dashboard/tests/test_starter_team_scheduler.py
python -m pytest -q packages/maverick-dashboard/tests/test_starter_teams_api.py
python -m pytest -q packages/maverick-dashboard/tests/test_starter_team_schedule_api.py
python -m pytest -q packages/maverick-core/tests/test_starter_templates.py
```

Repeat the affected tests with `MAVERICK_TEST_SECURE_DEFAULT=1`. Dashboard
qualification separately covers the direct UI/API and Copilot adapters. The
eight existing [starter goals](starter-goals.md) retain their current behavior
and sample files; those provider-backed specialist samples are a separate
journey from these deterministic team checks.

The loopback-only browser fixture is
`packages/maverick-dashboard/tests/browser/starter_teams_server.py --port 8909`.
With that fixture running and Playwright/Chromium installed, run
`node packages/maverick-dashboard/tests/browser/starter_teams_smoke.cjs`.
It exercises reviewed setup, sample and supplied records, response-loss
recovery, pause/resume, schedules, deep links, and desktop/mobile rendering.
The fixture blocks outbound traffic and does not run the background worker.
