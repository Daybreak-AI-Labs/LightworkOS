# Effective permission review

Account links to **Explain or request permissions**. Named employees can inspect their current `operate`, `audit` or `admin` permission, or a named tool. Tool explanations use the same current dashboard root capability resolver as execution and identify organization/workspace, dashboard-channel, exact-user, runtime-block and assigned-role restrictions. Effective regulatory/expiry/secure-default attenuation remains visible as a final ceiling. No private paths, resources or another employee's configuration are disclosed. Task-specific resource/consent/provider restrictions remain separate use-time checks; a root allowance is never presented as permission to every task action.

Enable `features.permission_access_requests` in Settings or the installer for saved requests. An employee explicitly shares a bounded business reason with the policy owner. A workspace administrator can review requests governed by current workspace membership; installation tool/global-policy requests require installation authority. The requester cannot review their own request. Records are scoped to the current tenant and visible only to their owner or an authorized policy reviewer.

Reviewers change real policy through existing People/Settings controls. Marking a request effective rechecks the current resolver and fails while the requested permission is still blocked. Cases store the actual explanation and reviewed result with durable activity receipts. No request, review note or Copilot instruction changes roles or tool ACLs automatically.

Browser and live-provider behavior are not qualified.

The shared Copilot registry uses the same native service for explanation, request and reviewed decision. Its sealed preparation is bound to current account/workspace/policy revisions and requires explicit confirmation; models never choose execution arguments or grant access. Exact operation receipts support safe readback after interrupted responses.
