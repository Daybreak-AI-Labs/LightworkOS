# Supplier request cancellation v1

- Applies to: the supplier evidence workflow
- Scope: local cancellation intent, retained provider state, customer API and controls
- Supported deployment: single persistent application replica

## Design

Cancellation is a human decision to stop work on a supplier request. It does not
delete a Jira task, authorize compensation, erase an approval or verify an
unknown provider outcome. The existing vendor-workflow configuration and setup
control this behavior; cancellation adds no independently enabled integration.

The application accepts a current revision, an explicit confirmation in the
customer API, and a nonempty reason. The service rechecks current read authority,
tenant and owner scope, and authenticated human `action.cancel` authority before
writing the decision. Stock composition requires the current active workspace
membership and `operate` permission. Request fields cannot supply authority or
claim that the provider effect was reversed.

The additive `cancellation` field records actor, time, rationale, reviewed case
revision, current authority binding, original operation identifier, local-only
scope, dispatch and technical effect at processing time, and
`effect_reversal=not_requested`. Older records without this field remain active
under their existing stages. No released storage migration or journey contract
is rewritten.

## State handling

| State when cancellation is processed | Durable result | Customer next step |
|---|---|---|
| No execution claim | Archive any unused prepared/approved intent; case Cancelled; technical effect not verified; record not dispatched | Local request closed |
| Executing or uncertain attempted action | Keep original operation, payload, approval and credential binding; case Needs reconciliation; technical effect indeterminate | Read-only ticket lookup and verification |
| Verified external action | Keep verified operation and confirmation; case Cancelled; technical effect verified | Ticket remains; optionally recheck its current state |
| Existing customer acceptance/rejection | Reject cancellation without altering the recorded decision | Retain original decision |

An execution claim is conservatively possibly dispatched even if a later
authority check stopped before the adapter call. A zero-result lookup does not
prove absence and does not permit another create. Reconciliation under current
observer authority preserves the original effect scope and credential generation.
Successful readback of a cancelled request records the effect while retaining
the cancellation; failed readback leaves Needs reconciliation and retains any
previous confirmation as historical evidence.

Cancellation blocks further evidence changes, assessment review, preparation,
approval, create execution and customer acceptance on that request. It creates
no artificial rejected or accepted business outcome. Repeating cancellation on
the same current revision returns the original decision without another write.
The governed-record audit outbox retains `vendor_onboarding_cancelled`, actor,
tenant, revision and record digest even if audit delivery is unavailable.

## Concurrency and UI

The existing saga lock covers the provider request and serializes cancellation
with it. This is not an asynchronous provider interrupt. A cancellation submitted
against a revision overtaken by dispatch returns a revision conflict; the app
asks the customer to refresh and review the actual result before submitting
again. No automatic retry of cancellation or creation follows that conflict.

The app labels the decision as cancellation of local work, asks for a reason
and explicit confirmation, and retains the uncertain-result or verified-ticket
readback control. Changing the selected request or revision clears the draft
reason and confirmation. It shows retained ticket effects separately from the
absence of a customer acceptance decision.

## Boundaries

Cancellation covers the supplier service and its customer API and UI. It does not add
provider deletion, compensation, asynchronous queue cancellation, or multi-replica
preemption. The generic platform-contract transition API remains separate from
the supplier saga, which enforces the actual authority and side-effect boundaries.
Any generic cancellation transition must preserve the current technical effect;
rechecking a cancelled request must not grant a new dispatch or acceptance.
