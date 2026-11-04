# Intent, work value and customer-controlled opportunities

Open **Work value & opportunities** at `/work-value` (also linked from Savings).
The page and Copilot use the same authorized report service. No model call or
provider credential is needed to classify supported requests, read reports,
correct intent, evaluate opportunities or create a workflow draft.

## Customer journey

1. Choose a UTC period, **My work** or permitted **Company totals**, business
   activity and contributor. Open a headline metric to see its exact contributing
   work population; open a work item for evidence, assumptions and history.
2. Review an opportunity. Its explanation separates the original baseline,
   unexecuted potential, current supporting records and incremental forecast.
3. **Use existing** records the choice and opens the existing capability.
   Chat receives a prefilled, editable task and an opportunity reference. The
   normal task submission binds the exact goal before dispatch. Nothing starts
   on selection. Existing workflow reuse binds the exact owned definition,
   child-workflow bundle, publication and selection time; later matching runs
   are associated, not causal proof.
4. If repeatability, supported completed examples and provisional net benefit
   support a draft, choose **Build reviewable workflow draft**. Input selection
   and final review remain manual; preparation can also stay manual. The native
   workflow designer receives a saved, editable definition with no schedule.
5. Inspect the definition and connection/provider readiness. Use the existing
   explicit **Publish** and **Run** controls. Draft creation neither publishes,
   executes, schedules, adds credentials nor grants permissions.
6. Return to the opportunity to inspect linked outcomes and cost feedback. Ask
   Copilot what the selected process delivered, then “What about last month?”,
   “Why?”, “Show me what contributed to that”, or “What could we improve?”
   Metric replies include their scope, UTC period, cost limitations and evidence
   link. Ambiguous entity names require clarification.

Defer and keep-current decisions persist. Unchanged declined/deferred proposals
are hidden unless **Include deferred and declined suggestions** is selected.
Reopening is explicit. None of these decisions deletes an existing process.

Turning off **Suggest reusable work** stops recommendation discovery and blocks
previously opened use, build, decision and linked Chat actions. The page and
Copilot explain that recommendations are off. Work-value metrics remain
available and stored recommendation history is retained; turning suggestions
back on restores the normal review journey.

Workflow outcomes require the selected definition and its actual publication.
An older active release cannot adopt newer saved edits or contribute their
outcomes. Mixed-release retry groups and earlier selections without exact
workflow evidence remain outside recommendation comparisons; their underlying
work and costs remain in platform totals. Review and select the current workflow
again to bind future outcomes. A newly built draft remains editable: its first
observed explicit publication in the same owned creation generation binds the
customer's final definition and child-workflow bundle. Later publications do
not replace that outcome binding; select the workflow again to adopt new work.
Selecting an existing unpublished workflow binds its current saved content.
If the designer saves another version before publishing, return to the
opportunity and select the published workflow again to bind future outcomes.
Pending publication is bound when it is observed. If a matching release was
published and replaced before the first refresh, the comparison stays unbound
rather than inferring that historical activation. Once observed, the stored
publication evidence survives later publication changes.

## Integration map

| Existing mechanism | Integration |
| --- | --- |
| WorldModel goals, parent IDs, conversations/turns, goal origins | `intent_value.sources` reads native authorized tenant stores; related goals share a work identity; unexecuted channel requests are observations only |
| Signed/strict audit reader and native `goal_start` / `goal_end` | Successful orchestrator/source-analysis receipts establish performed work; available run-start requests establish the executed intent despite later title edits; status fields or user assertions alone do not |
| Flow execution, immutable snapshots and run generations | `flow.execution` records content-free terminal/progress receipts with completed work-step identifiers and binds agent goals to their native run; retries share a work identity |
| Episodes, `episode_reporting`, provider receipt catalogue | Failure/rework spend is retained; exact linked provider receipts replace overlapping runtime amounts, with separate measured/estimated coverage |
| Existing Savings, `workforce_value`, `[value]` rates | Same source episodes and department rate configuration; numeric bridge explains alternative effort/count/cost assumptions |
| `GovernedRecordStore` | Tenant-scoped work, settings, benchmark and recommendation namespaces reuse private local/shared Postgres storage, CAS, revision history and audit-outbox recovery |
| Recovery authority and persistence inventories | Derived analytics/assumptions restore as data and are rechecked against current sources; recommendation draft/adoption receipts retain the native restore hold until reconciled |
| Domain profiles and owned native flows | Accessible capability matching prefers an existing process; reuse does not create a duplicate builder |
| `flow.evolve`, node outcomes/tool traces | Existing supported evolution signals are shown in reuse explanations; linked execution costs update the next-review reference without overwriting forecasts |
| Ekko `governed_candidate_projection` | Live owner/device/consent-bound patterns appear with native evidence/draft links; no raw event content is copied, no business intent or executed benefit is fabricated. A read excludes expired events and never deletes them; expired ciphertext is removed by the store's own write and maintenance paths |
| Copilot sealed conversation context, product operations | Provider-free metric answers call `read_report`; scoped follow-ups are sealed to tenant/account/current permissions. Reviewed correction, recalculation, optional confirmation, company assumptions, benchmark override, decision, use and draft operations call the native endpoints |
| Dashboard route catalogue, Jinja shell, shared style tokens | `/work-value`, native explanation dialog, responsive report, opportunities, benchmark/rate controls, error and retry states |
| Installer and All settings | `[intent_value] enabled` and `recommendations` controls; optional completion confirmation defaults off |

There is no new world-schema migration or queue. Derived work is refreshed on
demand from complete native reads, including page/Copilot requests. A bad source
read returns unavailable rather than a zero report. Read endpoints do not record
work or suggestions: `GET` reports the recorded ledger, and the page records newly
observed work through `POST /api/v1/intent-value/sync` before it reads. A read
never retries a pending audit receipt; the sync, saves and prepared actions do.
A read withholds a work item whose recorded flow run, task or conversation turn
has since been deleted, until the sync retires or re-derives it; the item's
explanation answers not found. `recorded_as_of` in a report is the newest
recorded change, not the time of the read. `checked_at` in a report is a
deprecated alias with the same value; use `recorded_as_of`. It is removed in
0.3.0. The sync takes `device_id`, the enrolled Ekko device it reviews, and
deletes that device's expired Ekko observations; a name that is not a device name
deletes none, and the sync still records. Another enrolled device's expired
observations are deleted when that device is reviewed in Ekko. Each newly observed item keeps the
estimate assumptions in force when it was first recorded. Saving company
assumptions or a benchmark first records observed work. If that work cannot be
read completely, the save is refused (503 or 422) and nothing changes, so an
administrator cannot change the rate during a source outage. The guarantee
covers work recorded before the save: work that finishes while a save runs is
recorded afterwards under the new assumptions. Native governed stores support
both existing storage backends; this feature does not change deployment, API
authentication, billing, connection or activation policy.

## Economic and grouping contract

`taxonomy.py` composes stable business-object/action identifiers across nine
families (sales, finance, procurement, operations, support, marketing,
engineering/product, HR/communications, research/compliance). Each definition
includes description, examples, dimensions, component scope and benchmark
mapping. Draft, review, summary and extraction are distinct components.

Classification is a deterministic, local, English instruction parser with
explicit abstention. It removes bounded quoted/source blocks, associates
actions within clauses, records multiple supported activities and exposes
`supported`, `contextual`, `ambiguous`, `unknown` or `corrected` confidence.
These are evidence labels, not calibrated probabilities. It never executes
instructions from analyzed content and cannot mint an execution receipt.
Guidance questions such as “Explain how to draft an RFP” and quoted task names
do not receive the deliverable benchmark. Unsupported wording/languages stay
unknown and may be corrected by an authorized owner. Audited explicit intent
changes in continuing work append a new estimate;
an unexecuted follow-up does not revalue already performed work. User corrections
take precedence over subsequent inference.

Workflow estimates use the agent components identified by the audited completed
steps and matching definition revision. An unexecuted drafting branch cannot
inflate the value of a reviewing branch. A receipt with only an older step count
can identify a sole work step; ambiguous older routes remain performed but
unvalued. Direct tool actions remain execution facts, but a workflow's name does
not by itself establish their business effort. Linked agent receipts still show
partial performed work when the parent flow lacks a sufficient completion receipt.
An entirely manual workflow records its human approvals without creating executed
Lightwork labor credit.

Ten related prompts or retries are one work item, not ten task credits. Parent
links and native flow retry/origin IDs take precedence over text similarity.
An explicit separate/new deliverable request or a separate root task creates
another item across every supported business object, including invoices. Explicit
bounded quantities are retained per object and can be corrected in the work
explanation. More than 50 deliverables or documents over ten pages require scope
review. Uncertain grouping is stated in the drilldown. Distinct tasks are
not inferred from conversation elapsed time or model latency.

For each distinct business object, the largest applicable component is used;
overlapping draft/review/extraction components are not added. Different business
objects can contribute separate components. This avoids awarding the same
document's full benchmark several times. Two independently requested documents
count as two deliverable components in one business work item; drafting and
reviewing those same two documents still use the largest component twice.

```
attributable avoided minutes = deliverable count × max(0, component minutes × Lightwork share − retained review minutes)
gross estimated labor value = attributable avoided minutes × applicable hourly rate / 60
estimated net benefit = gross estimated labor value − same-scope, same-period known execution costs
```

The benchmark concerns a bounded component, not an entire business project.
Known large/complex scope is left unvalued until reviewed. Only completed root
work or a completed native workflow qualifies for the full component. Audited
partial child/flow work is visible as performed but unvalued; costs remain.
A later revision does not award a second full benefit.
Renaming completed work in the task map does not change the credited activity or
deliverable count. Available audited run-start requests supply the original
classification, without copying prompt text into the ledger. For older successes
without that snapshot, the explanation identifies the initial classification's
reliance on current task fields; subsequent metadata edits preserve credited
intent until new execution evidence or an explicit authorized correction.

For the specification's synthetic fixture, 30 avoided minutes at USD 60/hour
with USD 2 known cost gives USD 30 gross and USD 28 estimated net. Coverage still
states excluded/unverified costs. No cost record, an unknown receipt, an unvalued
performed item or incompatible currencies makes the total net unavailable.
Known subtotal costs remain visible. No foreign-exchange conversion is invented.

Episode amounts are runtime estimates, not provider invoices. Settled, verified
observed/reconciled provider amounts are shown separately as measured. The exact
native receipt reference, pricing basis and coverage remain in the explanation
response. Native receipts have month precision; their day is allocated to the
latest linked runtime event in that month, or month start if none exists, and
labelled as such. The reporting method does not pretend this is an exact incurred
day. A positive unmatched runtime residual remains estimated rather than being
dropped. Parent flow totals are not added to child costs. No linked agent cost
and a zero default flow reservation means missing cost, not free execution.

Full credit occurs once, at the first qualifying completion. Costs use their
own event period even after the work was first credited. Specialist, named
agent and process views are overlapping **contributions**, not additional
platform benefit. Human execution principals are not labelled as agents.
Every customer total counts the underlying work once.

The legacy bridge uses the existing completed-episode predicate and configured
whole-task hours/rates on the same contributing goals/window. It reports old
attempt counts and labor values beside unique audited work and numeric
differences. Savings dates finished episodes by start; this feature dates runtime
cost at completion (or start while running), and provider costs as above. The
two labor estimates are alternatives, never summed.

Original opportunities and forecasts survive conversion. An observed item is
allocated to a linked adopted execution once; remaining potential excludes that
item. Neither its original potential nor an incremental automation forecast is
added to executed labor value. The assignment is inspectable from the original
work explanation.

## Benchmarks and research qualification

Default version: `2026-10-08.1`, effective 2026-10-08. All default task-minute
ranges, action factors, attributable shares and retained-review assumptions are
explicitly **provisional Lightwork planning assumptions**. They are not validated
industry averages. No mandatory benchmark-design onboarding is required.

Related research:

- Noy & Zhang, *Experimental evidence on the productivity effects of generative
  artificial intelligence*, Science 381 (2023), 187–192,
  [DOI 10.1126/science.adh2586](https://doi.org/10.1126/science.adh2586),
  [indexed abstract](https://pubmed.ncbi.nlm.nih.gov/37440646/).
  This concerns bounded professional writing tasks; it does not validate full
  RFP drafting, review or finance-analysis minute baselines.
- Brynjolfsson, Li & Raymond, *Generative AI at Work*,
  [NBER Working Paper 31161](https://www.nber.org/papers/w31161).
  Customer-support productivity varies with experience and workflow. Its results
  do not establish a universal effort-reduction multiplier for other tasks.

Those studies support task-sensitive evaluation, not transferring a published
percentage to every Lightwork activity. Accordingly the product does not cite
them as the source of the provisional minute values. Companies should calibrate
component scopes, effort ranges, attributable share, retained review and labor
rates using their own work before relying on financial claims.

An admin can edit a tenant benchmark and record its basis. New estimates use the
new version. Historical estimates retain full benchmark/rate/method and cost
snapshots. **Recalculate with current benchmarks** deliberately appends a new
version, leaving original estimates and audit evidence intact. The company's
dedicated labor-rate override takes precedence over department defaults; a
deployment labor-rate override remains authoritative. No tenant edit changes
another tenant's records. Completion confirmation is off by default and records
only the user's opinion about the present result; it neither creates execution
evidence nor prevents reopening.

## Recommendation method and controls

The evaluator requires at least three distinct work items, two audit-backed
valued examples, a supported business component and a positive provisional
incremental planning net to offer a new reusable draft. These are conservative,
testable product rules, not learned confidence probabilities. Existing matching
workflows are preferred. Observed tool names are evidence of past use, never
permission grants or proof of replayable arguments.

The supported draft is a supplied-material preparation step between mandatory
input selection and result review. It does not invent external API bindings.
The customer can keep the preparation step manual too. Provider/connection
readiness and native permissions remain necessary to run agent steps.

The provisional incremental labor forecast is 20% of the assisted component's
avoided-effort estimate, capped at ten minutes per run. For a conservative
planning net, the entire observed known execution-cost mean is subtracted.
This is a disclosed planning scenario: marginal cost, external fees and retained
manual effort still require qualification. Forecast and baseline snapshots are
versioned; explicit decisions freeze their original proposal. New audited
results update a separate next-review cost reference and existing workflow
learning signals. They do not retroactively validate a labor forecast or prove
causality.

After adoption, the explanation compares the original forecast with a separate
before/after estimate. It compares mean benchmark labor values and includes costs
from every linked attempt, including failures, per audit-backed work item. A
positive forecast can therefore be followed by zero or negative estimated
improvement. Missing baseline, valuation or cost inputs leave that comparison
unavailable; known cost subtotals remain visible. Task mix and changed assumptions
can affect this estimate. It is never added again to platform value.

Draft ID reservation occurs before native save; retries recover that same
definition, including interruption after save and before linkage. A conflicting
definition or changed generation fails closed. After creation, edit manual steps
in the native builder. Publication, revocation, run admission, approvals, budget,
connection and learning controls remain the existing ones.

## Privacy, access and operational limits

- APIs use the pinned tenant and native view/operate/admin authority. Company
  totals additionally require unscoped analytics authority. Private content
  access is checked for owned work; administrative analytics do not grant chat
  access. Company explanations omit source links, employee correction reasons
  and actors. No prompt/result text is copied to the value stores or explanations.
- Copilot queries the identical API service and binds follow-up context to
  tenant, account, permissions and expiry. It does not send metric records to a
  model. Leaving a metric conversation starts a fresh guide context.
- Consent-bound Ekko patterns are owner/device reads, not company aggregates.
  Device IDs are selected explicitly; hashed stores do not provide an account-wide
  device-name catalogue. Application metadata alone is insufficient for defensible
  business intent or effort, so those patterns remain unvalued with native action
  links. Revoked/expired consent cannot release prior patterns.
- Refresh is bounded to 10,000 goals, user turns, native flow runs and work
  records. Exceeding a source bound or encountering unreadable audit/store data
  makes reporting unavailable; it does not silently publish a partial total.
  Large-tenant indexing/archival needs qualification before raising that bound.
- Source deletion retires derived current value and clears source/evidence
  references. Non-content assumption/history receipts remain for explainability.
  Policy/access changes are rechecked on detail and effect boundaries.
  The shared request helper closes open explanations and hides stale reporting
  when access or account/workspace context changes; an authorized retry reloads
  the current report. Restored recommendation decisions and draft reservations
  use the existing recovery hold, preserving their bytes without replaying a
  build or adoption. Analytics snapshots and benchmark/preferences cannot admit
  execution and restore as data; fresh source checks still determine totals.
- Work recorded by earlier versions may lack a workflow completion receipt or
  agent/run correlation. Such evidence is not fabricated or inferred solely from
  `completed` status. Legacy gaps are unvalued/missing, with the alternative
  Savings bridge available. Historical goal receipts remain usable when the
  native evidence is present.
- Complete invoice/subscription/external-tool coverage, causal time savings,
  calibrated inference probabilities, inferred external data bindings, live
  provider output quality, measured employee labor reduction and
  deployment-scale/load qualification are not claimed.

## Requirement and verification map

The focused automated suites are `test_intent_value.py`,
`test_intent_value_api.py`, `test_wizard_value.py` and
`tests/browser/intent_value.spec.js`. Existing flow execution, Copilot,
configuration, privacy and reporting regressions are also checked.

| Acceptance scenario | Working implementation and focused evidence |
| --- | --- |
| 1: ten RFP prompts / separate work | Native parent/new-work grouping; `test_ten_prompts_retries_reopen_and_separate_work` |
| 2: draft corrected to review | CAS correction + snapshot/rollup recalculation; core/API correction tests and browser correction |
| 3: observation without execution | Observations create potential, never executed credit; confirmation test and exact handoff conversion test |
| 4: audited execution | Strict native receipts and flow driver seam; `test_goal_status_without_audit_does_not_award_value`, native driver test |
| 5: optional confirmation | Default off, separate opinion receipt, revisions preserved; core/API/browser checks |
| 6: tenant-specific benchmark | Governed override/version + deliberate recalculation; tenant override arithmetic test |
| 7: unknown inputs | Abstention for guidance/quoted task names, uncertain later execution, size review, missing cost, mixed currency; guidance/unknown/receipt/currency tests |
| 8: rework/failure | One business credit, all attempt costs, partial unvalued, only the actually executed branch, native workflow residual above linked agent spend; duplicate/failure/partial/driver, branch and completed-task rename tests |
| 9: reconciled rollups | Unique work totals, overlapping attribution, native Savings numeric bridge; parent/agent and driver tests |
| 10: dashboard explanation | Clickable population and source/assumption/history detail; browser desktop and narrow checks |
| 11: Copilot parity | Shared `read_report`, current dashboard filters, sealed period/entity clarification, business-name resolution and ambiguity rejection; API and native execution browser checks |
| 12: access boundaries | Tenant/account/content, pending audit and reviewed-operation boundaries; company metadata, cross-tenant and least-privilege PostgreSQL tests |
| 13: opportunity conversion | Explicit handoff, exact task link, separate remaining potential; handoff/conversion test |
| 14: recommendation quality | Distinct-work and cost support, existing capability preference, versioned maturing proposal; recommendation tests |
| 15: retained control | Manual preparation, required reviews, persistent defer/decline; core/API/browser checks |
| 16: draft versus activation | Native save only, no run/schedule/publication; API/browser checks; explicit publish outcome test and fully manual execution without labor credit |
| 17: duplicate/interrupted flows | Deterministic reservation, native CAS, recover same saved draft; repeat/interruption API tests |
| 18: post-adoption feedback | Native generation/selection linkage, separate before/after cost reference; outcome/driver/handoff tests |
| 19: historical explainability | Original snapshots survive corrections, override and proposal maturation; history tests |
| 20: intuitive complete journey | Chromium drives the native opportunity → draft → explicit publish → cancelled/confirmed start → input approval → queued agent execution → result approval → outcomes → identical Copilot/dashboard totals; the agent runner supplies synthetic output, cost and a completion receipt |

## Operation coverage

Every entry requires the feature to be enabled. Copilot writes additionally use
the existing enabled operation family, sealed review and explicit confirmation.
Dates and entity names are selected by the user; revisions and review references
are obtained from current authorized records.

| Customer job | Direct UI / Copilot | Shared authority and current-state contract | Result and recovery |
| --- | --- | --- | --- |
| Read scoped value, costs and evidence | Work value filters, metric cards and explanations / live questions and `work_value_read` | `read_report`, view, current tenant and source access; company scope requires unscoped analytics | Identical scoped numbers, coverage and assumptions; unreadable/pending sources show unavailable/incomplete, with refresh |
| Correct activity, size or deliverable count | Work explanation / reviewed `work_value_correct` | Owned accessible work, operate, CAS, validated taxonomy/counts, audited mutation | Appended estimate/correction history; execution receipts unchanged; stale version requires fresh review |
| Apply current assumptions to earlier work | Recalculate in explanation / `work_value_recalculate` | Same owned-work CAS and current tenant assumptions | Original and new estimates remain inspectable; audit-pending is not treated as success |
| Record optional completion opinion | Optional explanation button / `work_value_confirm` | Setting enabled, owned accessible work, operate, CAS | Deduplicated opinion bound to current source state; never execution evidence; later revisions allowed |
| Set labor rate/currency and optional confirmation | Company assumptions form / `work_value_settings` | Admin, CAS, deployment rate override remains authoritative | Versioned tenant setting; historical work unchanged until deliberate recalculation; stale replay rejected |
| Override an effort benchmark | Named benchmark editor / `work_value_benchmark` | Admin, selected stable activity, validated interval/share/review, CAS | Versioned company provenance and prior assumptions; other tenants unchanged |
| Retain manual steps, defer, decline or reopen | Opportunity explanation / `work_value_decision` | Own recommendation, operate, current evidence, CAS | Persistent decision history; unchanged declined suggestions hidden; created drafts edited through native builder |
| Use an existing capability | Opportunity action / `work_value_use` | Current accessible specialist/process; current source and ownership checks | Native chat or builder handoff; subsequent actual work linked; selection starts no execution |
| Create a populated draft | Opportunity build action / `work_value_build` | Current supported evidence, operate, native flow enablement, reservation and CAS | Same saved draft on duplicate/recovered clicks; changed/deleted generation refuses replacement; no activation |
| Publish, run, approve and inspect adopted work | Existing workflow designer/run views / existing native workflow operations | Existing publication, release, connection, budget, queue and human approval controls | Audit-backed outcomes and separate before/after estimates; partial/failed costs retained; no additional platform credit |
