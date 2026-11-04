# Review restored connections

Workspace recovery keeps old connected-service work on hold. An administrator
can review an item in the recovery list or open the same review in Recovery
Copilot. Changing between those views preserves one form and one set of entries.
This local helper does not contact an AI provider or start ordinary work.

For messages, record whether the requested action happened, whether the message
was delivered, and the findings for each reply part. Previously confirmed
deliveries and their receipts must be retained. For collection, the form shows
the position or time required by that connection. For iMessage and Mastodon,
select **Look up source checkpoints** to read dates and evidence from the exact
configured source, then select a checkpoint. Lookup fills the observation time
and evidence reference for your review; it does not confirm the review. Other
connections already use human dates or retained delivery receipts. You can still
review the original service and record an explicit manual attestation. Unknown
outcomes remain unresolved; no choice is silently treated as “did not happen.”

Review the details and explicitly confirm to record them. These are your
findings, not independent verification by Lightwork. New observations must be
within 15 minutes and no earlier than restoration. Recording a review never
repeats the old work. Returning to ordinary use is a separate decision after
all held items have been reviewed.

If recording was interrupted, refresh the review. When its findings were
already saved, Lightwork shows those saved findings and offers to finish
recording the same review. It does not change the observation time or send
the old action again. A lost response is not success: refresh status before
taking another action.

Entries remain in memory during same-account refreshes when the reviewed item
has not changed. Confirmation is cleared. A different recovery, changed item,
changed account or lost permission invalidates the earlier review. There is no
browser-storage copy of these entries.

## Current product boundary

The structured forms include read-only checkpoint lookup for the two built-in
sources that use numeric collection positions: iMessage and Mastodon. Their
existing adapter identity must match the restored record exactly; disabled,
changed or unavailable sources are never substituted. iMessage reads only row
identity/date metadata from the configured local Messages database in SQLite
read-only mode. Mastodon reads a bounded page of notification metadata using the
configured account. The result exposes dates and evidence digests, not message
bodies, sender identities or credentials. Older pages remain explicit.

Selecting a checkpoint means collection resumes after that item; it can skip
older uncollected work and therefore requires the administrator's separate
confirmation. Lookup does not start a channel, run its polling loop, change a
checkpoint, confirm delivery or rewrite prior receipts. Empty, unavailable and
unknown states are distinct. If lookup fails, keep the item unresolved, check
source access and retry; a manual advanced source-position review remains
available. Normal work still requires the separate final recovery decision.

The workspace-recovery setting, global administrator permission, current
recovery context, configured channel enablement and exact account binding govern
lookup. Lookup uses no additional provider credentials or broader source access.
Lookup against installed sources and the authenticated installed application
are not qualified.

## Implementation and qualification

The existing `features.workspace_recovery` setting, installer step and global
administrator admission remain in force. The typed operation is confined to
the recovery route family and uses the existing locked reconciliation service.
Ordinary Copilot/model routes remain unavailable in recovery mode.

The service binds a form to the original authenticated recovery and item. It
derives record identities internally, checks the current source and preserves
the native no-replay validator. Interrupted publication uses the exact retained
readback and digest, including older readbacks with timestamps that a date
control cannot reproduce exactly. Signed bootstrap disposition and retained
readback evidence are not a claim of a new independent external audit receipt.

Relevant implementation:
[form adapter](../packages/maverick-core/maverick/channel_recovery_controls.py),
[locked service](../packages/maverick-core/maverick/workspace_recovery.py),
[typed API](../packages/maverick-dashboard/maverick_dashboard/recovery_api.py),
[shared form](../packages/maverick-dashboard/maverick_dashboard/static/lightwork-workspace-recovery.js),
and [local helper](../packages/maverick-dashboard/maverick_dashboard/static/lightwork-recovery-copilot.js).
