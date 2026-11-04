# Workflow pilots

Enable **Outcome measurement** in Settings or the installer wizard, then open
**Savings → Measure a workflow pilot**. The feature is off by default
(`features.outcome_measurement`). Operators can manage only pilots created in
their current account/workspace context. Every source is reauthorized when
the pilot is read or an observation is recorded.

The page also reads a bounded tenant-scoped outcome-accounting page. It
summarizes admitted work shown in that page, including failed, cancelled and
unresolved records, known cost by currency, failed-attempt cost and the count of
records with unknown amounts. It explicitly labels when more cursor pages
exist, and Previous/Next controls let the operator inspect them in the app.
A successful transport response does not verify a technical outcome,
and technical verification does not create customer acceptance. Corrections
and expired evidence invalidate the current projection without deleting the
earlier observation or human verdict. Record detail responses project the
shared versioned outcome contract for other platform consumers.

## In-app path

1. Name the customer/team, workflow and acceptance criteria. Choose at least
   four different unstarted tasks or vendor intake cases. The task preparation
   form selects an enabled specialist with a review gate, saves its exact brief
   and holds it without a provider call. Existing vendor intake runs through
   the normal document and connection permissions.
2. Freeze the plan before starting work. The server randomly assigns half the
   cases to an evaluation group. Inputs, criteria and assignments are immutable;
   a different request cannot reuse the same creation reference. Task and pilot
   stores are separate: source state is checked twice and actual episode start
   times are checked on reporting, rather than claiming an atomic cross-store
   execution embargo.
3. Open each prepared task and choose **Start this task**, with an optional
   spending limit. This uses the existing governed run path. Vendor cases use
   their existing collection, review, approved write, external confirmation
   and customer-acceptance actions. The pilot never approves those records.
4. Record the paired baseline, non-overlapping preparation/review/rework
   minutes, correction count, elapsed time, evidence references and method.
   Unknown values stay blank. Record full costs, including failed attempts and
   human effort, with their currency and evidence references if available.
   Optional human preparation/review and rework costs remain separate fields;
   they are not automatically added to the already all-in reported total.
5. Refresh the report and download its current JSON projection in the app.
   The export includes plan version, observations, correction history,
   current source status, missing cases, separate group results and limits.

## Interpretation and limits

The source's current human sign-off or verified vendor acceptance is distinct
from a recorder's assertion that the frozen pilot criteria were met. Both are
shown. A completed run is not automatically accepted; sample vendor results
do not count as live acceptance or enter paired comparisons.

All planned cases remain in the acceptance denominator. Current, complete
pairs, including rejected results, enter reported effort comparisons. Changed
inputs, stale observation versions, pre-plan execution and unavailable sources
remain explicit and do not enter paired comparisons. Cost per accepted outcome
requires costs for **every planned case**, one currency and at least one
accepted result; it includes the costs of rejected cases. Missing pairs can
bias the paired comparison and are reported alongside it.

Time and cost observations are attributed operator reports. Evidence references
are retained as text; the page does not fetch arbitrary URLs or independently
verify invoices. Recorded runtime prices remain separate from reported total
cost. A representative customer baseline, independently validated provider
cost attribution, and actual customer acceptance of a pilot remain external
evidence requirements.

## Admitted provider cost allocation

With AI cost and ROI enabled in a named workspace, a global administrator who
owns the pilot can find completed provider billing admissions directly in the
pilot report. Review the original provider line, its corrections, immutable
receipt bindings and source citations, then allocate a percentage to each case.
The server derives amounts from the admitted decimal values; the form never
accepts a replacement provider amount. Shares use basis points and cannot
exceed 100% of a line. The remainder stays visibly unallocated.

Saving replaces that provider line's shares within this pilot and retains the
prior attribution, actor, method and source versions. An empty allocation
withdraws the shares without deleting history. Concurrent updates use the
pilot revision, and exact uncertain retries keep their operation identity.
New billing corrections, changed case inputs or source versions invalidate the
allocation until it is reviewed again. Revoked access hides source details and
their allocation history. Unavailable or changed allocations are excluded
with an explicit partial status; their missing costs are never treated as zero.

Provider amounts remain separate from operator-reported workflow, human and
rework costs. Each currency has its own total. Completed admission receipts
establish the recorded source binding, not independent invoice authenticity;
case attribution is an operator decision. Deduplication applies within one
pilot. Reusing a billing line across different pilots is not a consolidated
enterprise cost ledger. A pilot supports at most 100 provider lines and 1,000
cost-allocation operations, subject to governed record size limits.

The separate **Review complete cost coverage** action requires a current
allocation for every planned case, finished eligible sources and one common
currency. The operator must explicitly confirm that all attempts and rejected
results are represented and record the method. The review is bound to the
plan, current outcomes, allocations and complete admitted billing catalogue;
changed receipts or outcomes require another review. The report computes
allocated provider cost per accepted outcome only while this review is current
and at least one outcome is accepted. Its numerator includes rejected cases.
A genuinely admitted zero-cost line can cover a case; a missing line cannot.
The metric is labelled as operator-reviewed allocation and rounded to nine
decimal places. Unknown or incomplete coverage leaves the metric absent.

Provider reports reuse successful source reads only within that one report to
bound repeated history lookups. The next request reauthorizes and refreshes
every case. Coverage reviews retain actor, time, method and prior review
history, with at most 1,000 review operations per pilot.

## Evaluation evidence boundary

Plans default to **Observe results only**. A named account can instead choose
**Exclude evaluation tasks from local learning** before freezing a goal-only
plan and record what is known about prior exposure. This selection is part of
the immutable plan. Vendor intake cases do not support this exclusion mode.
The existing Outcome measurement setting and installer step still control
access to the feature; the exclusion is an explicit per-plan choice.

Each selected holdout receives a durable, tenant-bound exclusion receipt tied
to its goal, frozen inputs and plan version. Automatic goal-bound trajectory
capture, donation, training ingest, local distillation, semantic indexing,
dream replay, goal-derived user notes and guarded learning writes consult this
policy. Canonical child goals inherit their parent's exclusion. Existing
business records remain readable; legacy learning corpus rows retaining their
goal identity are filtered on the supported ingestion paths. Unreadable policy
blocks optional learning rather than permitting capture. A partially prepared
plan retains its assignments and exclusion markers; its report does not claim
that exclusion is established until publication finishes and sources are
rechecked. Retry the same creation reference to finish an interrupted plan.

The report distinguishes an enforced local exclusion from the author's prior
exposure statement. A different named global administrator can open the pilot
reference in **Independent learning review**, reauthorize all source tasks,
review the exact current evidence and record a decision with explicit
confirmation. That review retains its actor, evidence version and history;
changed inputs or policy evidence make it stale. This is an attributed review,
not an independent measurement of what a model previously saw.

The local policy does not erase prior learning, control provider training,
inspect external datasets or cover manually copied/relabelled material that
has lost its goal identity. It is not a general information-flow guarantee.
The report therefore continues to set `holdout_exposure_verified` and
`provider_invoice_verified` to false. A controlled held-out customer experiment
still requires evidence for those separate conditions.

Limits: 100 cases per plan, 1,000 pilots per workspace store, 5,000 observation
operations per pilot (also subject to governed record size limits), 2,000
episodes per measured task, and 200 recent source candidates per source kind.
Unavailable/partial source discovery is explicit. No provider invocation,
external publication, or live goal mutation occurs when saving observations.
Concurrent saves use record revisions; exact uncertain retries retain their
identity and changed requests are rejected. Authentication or source access
changes invalidate old page context and hide unavailable source observations.
