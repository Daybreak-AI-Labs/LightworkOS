# Customer workflows

This page describes customer workflow surfaces and recovery behavior. Live
provider behavior and customer acceptance are not qualified.

## Personal Action Center

`/action-center` collects pending approvals, deliverable sign-offs, and open or
overdue assessments. It applies the existing operate permission, goal ownership,
department suites, and assignment rules. Claimed approvals belonging to another
reviewer, self-requested approvals, and approvals already voted on are excluded.
Unclaimed work is explicitly labeled available to review.

Read and snooze preferences use a tenant-scoped governed store and an
account-specific identifier. A preference is bound to the source version;
changed content becomes unread and unsnoozed. Concurrent updates use the store's
revision check, and an exact retry of the latest operation is idempotent.
Snoozing never changes a deadline; overdue work remains in the active view.
Actions open the existing authoritative review screens rather than bypassing
their approval or publication rules.

The list is paginated. Approval and completed-goal sources are bounded to 2,000
records and show partial coverage when that bound is reached. An unavailable
source is visibly unavailable; the page does not infer that its queue is clear.
The feature can be disabled through `[features] action_center`, the installer
wizard, or Settings. The default is enabled.

## Guided reviewed outcomes

`/start` offers permitted paths for a deliverable, vendor onboarding, or privacy
assessment. Each path links to prerequisites, work, and review inside the app.
The caller's role remains authoritative; selecting a path does not grant access.
`[features] guided_onboarding` controls the path panel through Settings and the
installer wizard. The default is enabled.

The general checklist includes an explicit reviewed-result step. Choosing
and using an existing agent or specialist satisfies the workflow-choice step; authoring
a new agent is optional. Merely creating a task or schedule cannot satisfy the
reviewed-result step. Deliverables require a current human approval. Privacy
assessments must be complete, approved, not due for review, and assigned to or
reviewed by the caller. Vendor cases require a recorded verified external result
and human customer acceptance; sample cases do not qualify. Unreadable evidence
remains incomplete. Recorded acceptance does not substantiate general accuracy,
customer ROI, or a later provider state.

## Usage and held deliveries

Billing contains owner-filtered cumulative usage receipts and retained daily
increments. See [runtime accounting](runtime-accounting-recovery.md) for the
supported crash and resume boundary, legacy migration, and retention limits.

The Governance workspace lets a named global administrator compare a held GRC
delivery with its external record. Confirmation requires a unique exact match,
the same reviewer, a fresh second read, and the current ledger revision. The
recorded attempted payload survives later source edits. A mismatched, changed,
unreadable, or duplicate record remains held. Neither comparison nor resolution
resends content. Existing records without a stored attempt require unchanged
source hashes and cannot establish their original endpoint retrospectively.
