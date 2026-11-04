# Supported supplier evidence journey v1

The normative retained outcome contract is
`vendor_onboarding._JOURNEY_CONTRACT_V1`; its ID, version and content digest are
recorded at intake. The mapping below documents the existing service and WorkItem
contract without replacing either authority.

## Promised result and admission

The supported result is a human-reviewed supplier evidence assessment, one Jira
Task matching the exact approved proposal, fresh authoritative ticket readback,
and a separate authorized customer's acceptance or rejection. A ticket alone is
not customer acceptance. Procurement approval, payment, contracts, ERP changes,
vendor production approval and model release are outside this outcome.

Admission records the active workspace, named requester, fixed review owner,
vendor name, intended use, Jira project, evidence validity period (1–730 days),
and optional prior request for renewal. Required owner and connection setup is
visible in the app. An administrator chooses the owner from active permitted
workspace members; saving setup does not grant membership or credential access.
Approval uses the current actor, workspace, role, budget policy and exact
credential generation. Collection, review, approval, execution and acceptance
remain separate operations with revision checks.

Evidence may come from Google Drive or reviewed uploads. Drive supports Google
Docs export, UTF-8 text and supported digital PDFs; uploads support `.txt`,
`.pdf`, `.docx` and `.xlsx`. Parsing, document count and bytes are bounded by the
existing evidence adapters. Unsupported or incomplete extraction requires an
explicit review or transcription path; it is not silently treated as complete.
Drive setup is optional for upload-only requests. Jira task delivery still
requires a current named connection and approved project access.

Evidence freshness produces the renewal deadline. Version 1 does not promise a
separate task completion due date or service-level agreement. Provider work uses
the existing Budget and authority checks; the projected per-case budget and
unmeasured provider billing remain explicitly unknown. Unknown cost is not zero.

## Lifecycle and outcome mapping

| Service state | WorkItem lifecycle | Next action | Outcome treatment |
|---|---|---|---|
| `intake` | Draft | Obtain evidence | Admitted, pending |
| `evidence_collected` | Ready | Build assessment | Admitted, pending |
| `pending_review` | Awaiting approval | Human assessment review | Admitted, pending |
| `review_approved` | Ready | Prepare exact task proposal | Admitted, pending |
| `review_rejected` | Failed | Correct evidence or close | Rejection retained; not customer acceptance |
| `action_pending_approval` | Awaiting approval | Approve exact task | Admitted, pending |
| `action_approved` | Ready | Execute approved action | Admitted, pending |
| `executing` | Running | Wait or reconcile | Effect indeterminate; pending |
| `reconciliation_required` | Needs reconciliation | Read-only provider comparison | Effect indeterminate; pending |
| `execution_completed` | Verified | Customer accepts or rejects | Technical effect verified; business pending |
| `accepted` | Accepted | Check freshness and renewal | Explicit accepted business outcome |
| `customer_rejected` | Failed | Closed | Explicit rejected business outcome |
| `cancelled` | Cancelled | Closed; retain any external effect | No fabricated acceptance or reversal |

Every admitted case retains its admission identity through rejection, cancellation
and uncertainty; these states must not disappear from an admitted cohort.
Cancelling an uncertain attempted action keeps Needs reconciliation until its
effect is checked. A verified cancelled action remains an external effect and
cannot be accepted or dispatched again. See
[supplier request cancellation](./supplier-cancellation-v1.md) for cancellation
semantics.

Changing the default process contract does not migrate existing cases. Reopening
uses each recorded contract reference and digest. Historical v1 records without
an explicit reference use the documented v1 legacy default without rewriting
their revision. Unknown versions and mismatched digests are rejected. A new
business rubric requires a new contract version and explicit readmission or a
separately implemented, reviewed migration.

## Supported installation and readiness

One persistent application instance with single-instance protection is supported.
Workers in that installation share the same local saga locks and tenant storage;
different hosts do not share those locks. A shared Postgres record backend does
not establish distributed saga safety. The service checks the canonical
`MAVERICK_REPLICA_COUNT`, deployment-global multiple-control-plane policy and
its existing override, without acquiring a lease or opening a record store.
Multiple instances, disabled single-instance protection and unavailable or
malformed deployment policy block service entry before storage and provider work.
Sensitive save/authority boundaries recheck the policy.

These checks validate declared configuration. They do not discover unreported
replicas, certify disk durability or prove runtime isolation. Operators must keep
the supported installation and its protected local state intact.

The page and setup API share this profile result. A fresh workspace shows the
missing enablement, owner, Jira and save steps. A saved setup means configuration
was saved, not that private provider access or customer acceptance was verified.
Readiness reads do not contact providers. Existing role, origin, workspace,
configuration and record-revision checks still govern setup mutations.

Workspace snapshots cover supported local state and validated references under
the [restore reference validation](./restore-reference-validation-v1.md)
contract. Recovery requires application quiescence and does not reverse Drive or
Jira changes. Unsupported sealed or additive governed store restores remain
refused. This contract does not establish live provider access, native
installation behavior or acceptance by representative users.
