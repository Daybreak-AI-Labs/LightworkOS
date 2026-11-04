# Workbench access loss and recovery

Vendor onboarding, account connections, workspace members and knowledge access
share `lightwork-access-state.js` for HTTP response meaning and request epochs.
Each workbench keeps its rendering, schema validation, capability decisions,
approval bindings and revision checks.

A 401 clears the affected workbench's private results before any body is parsed.
This also covers an HTML sign-in/error response. A changed account/workspace
context invalidates outstanding requests, clears private state and requires a
new authenticated page load. The final busy-state cleanup cannot unlock it.
An old successful response cannot repaint after a changed local context.

A 403 has a scoped meaning. Denial of a workbench's read authority clears that
workbench. Workspace member reads and mutations all require the same global
administrator authority, so its 403 closes the entire members editor. A vendor
action, connection registration, knowledge export, or rights action denial
instead disables that capability and preserves still-authorized views. Repeated
clicks cannot resend the denied operation. A reload rechecks permission.

The workspace members picker deliberately advances its epoch when selecting
another workspace. Previous requests become obsolete; they cannot replace the
new selection or prove that the newly selected workspace is unauthorized.
The original page's expected-tenant header remains unchanged.

A 409 retains existing domain-specific revision/approval recovery. Vendor
mutations remain locked until the current case is read and validated. A new
revision or approval is reviewed by the user; no failed write is replayed.
Temporary service failure preserves unsent non-secret drafts. An unreadable or
interrupted response never authorizes automatic replay of an external action.

These are client state controls. Server authentication, tenant binding, source
eligibility, immutable approval digests and mutation authorization remain the
authority. Local Node/DOM and API tests do not qualify production identity
providers, deployed proxies, or a real customer browser session.
