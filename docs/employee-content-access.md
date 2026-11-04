# Employee content and administrator authority

Installed and distributed deployments of this feature are not qualified.

Named administrators do not inherit employee task content through the task
authorization helper. Lists remain owner scoped. Existing task ownership is
preserved; the migration does not guess owners for unowned legacy work. An
unowned task needs explicit reviewed access. Existing explicitly shared result
packets keep their assigned reviewer authority.

The Content access page is available from Account and Users. The installation
feature `employee_content_access_requests` controls exceptional requests and is
off by default. The installer and Settings expose it. Turning it off prevents
use of existing approvals while keeping ordinary owner access available.

A request binds a named requester, current workspace, one task or one exact
channel/user export or approval card, a closed purpose and a duration of 5-60 minutes. A different
installation administrator or the exact content owner must approve. Requests,
decisions and revocations use the governed record store with compare-and-swap
revisions and its audit outbox. Pending audit does not grant access. Every
exceptional read requires another acknowledged audit receipt. A current feature,
scope, ownership, requester role, reviewer authority and expiry check is made
when evaluating a read. A task read does not grant a whole conversation, mutation,
external publication, or an employee companion conversation. Expired approvals
must be requested again. Revocation and audit-retry controls stay available.

Approval cards have a separate exact-record content grant available to a named
operator. Its fingerprint includes the card, action, target, task and owner;
changed content invalidates the grant. Every exceptional card read is recorded.
The read grant adds no voting authority. Existing operate/reviewer authority,
claim, current-card binding and separation-of-duties checks still determine
whether a decision can be made, independently of permission to read the card.
The queue lists readable cards and a minimized count/link for private ones.

Audit tail, literal search and download/forward projections omit prompts, tool
inputs, responses and task titles before matching and rendering. A projected
download is not the original signed byte stream. Integrity checks continue to
operate on original storage. Auth-off or shared installation credentials identify
no employee and can access only genuinely unowned local work. They cannot read
named employees' tasks. Existing named owners remain unchanged. An owner who
approves a request must retain viewing membership in that request's workspace;
removing that membership immediately invalidates the approval.

Task/chat exports, attachments, search, audit pages and model-recall paths are
covered by the integrated authorization helpers and their recorded route and
store regressions. Direct UI, API and closed Copilot operation contracts share
the same service; see the adapters described below.

Retention uses explicit indefinite values and a saved effective-policy
review. A run retains its cutoff, workspace targets and per-store receipts.
Completed stores are not repeated when retrying unresolved steps. Unknown past
effects or unconfirmed audit recording remain unresolved after a retry; the
system does not manufacture a successful history. Preservation holds in external
systems are not discovered by this retention engine, so the review explicitly
requires records-owner confirmation before deletion. This is not an assertion
of automatic legal-hold coverage.

Private workflow templates use exact ownership across catalog, suggestions, builder, execution, schedules, triggers, source outcomes and version history. Administrator policy authority does not expose another employee's drafts or input fixtures. Bundled templates are recognized only by exact configured bundled roots. Newly installed catalog templates carry a server-written publication receipt bound to their stored bytes; edits invalidate it. Unknown legacy user-template ownership is not inferred as public. Publishing one's reviewed own revision requires operate and a passed rendering fixture; it does not share the template or start scheduled work.

Native Copilot adapters share the direct content-access service for metadata status, requesting one exact resource and independent review/revocation. Prepared actions bind current resource/request revision; retries use exact operation receipts and never silently extend a grant duration or read private content.
