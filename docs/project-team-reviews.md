# Project team reviews

Enable **Project team reviews** in Settings. The capability is off by default
and requires a named signed-in human and an active workspace. An administrator
can add a colleague's workspace role from **Users → Members of this
workspace**, using the existing tenant role authority. Assigning an operator
role does not grant every department: the colleague's current department grants
still apply. Per-user isolated tenancy refuses tenant role assignments through
the existing API; use a shared workspace deployment for team collaboration.

The project owner opens **Projects → a project → Manage team reviews**, grants
review access to a current workspace colleague, selects a stopped task with a
saved result, and previews exactly what will be shared. The owner chooses a
reviewer, due date, and review note before confirming the share. Only results
owned by that project owner and filed in that project can be selected.

Reviewers use **Project team reviews** to find assigned packets. Each packet
contains the captured task title, result text, status, department, source
timestamp and version digest; it does not expose the task's conversation,
credentials, tools, or other artifacts. Comments and decisions retain their
actor and time in governed history. The reviewer may approve the captured
result, request changes, or comment. The owner may comment or withdraw a
pending request and can open their own live task to decide its next step.
An exact retry after a lost response cannot send another packet or record a
second response. A changed request reference or record version is checked.

**Packet approval is a separate review record.** It neither executes a task nor
changes its output, tool approvals, result sign-off, or general access policy.
Only the assigned independent reviewer can decide. Tasks that change after
capture make their packets visibly stale; stale packets retain the original
content and comments but refuse a new approval or request-changes decision.
Send a new packet to review the new result. A later source change also marks
an already approved packet stale instead of implying that the approval covers
the new version.

Removing a project reviewer immediately denies that person's packet reads,
comments, decisions, search hits, and counts. The owner retains history and may
withdraw the request. Workspace membership, SCIM lifecycle, current role, and
department policy are rechecked on access. Read-only roles cannot record a
decision. Packet metadata is filtered before search and counts. Browser reads
and writes reject an account/workspace context change, and responses use
`private, no-store` caching. Revocation does not erase information that someone
already read or copied.

Local project membership and review mutations share one strict cross-process
project lock. PostgreSQL packet writes use a `GovernedMutationFence` against
the exact team authority version in the write transaction. Records use the
existing governed storage and durable audit outbox. No execution permission is
added to `can_access_goal`. Raw result text is deliberately retained in the
packet, so governed-record encryption and deployment retention policy apply;
this capability does not claim to redact all sensitive material from a result.

Supported bounds are 100 review members per project, 2,000 membership history
operations, 500 comments/decisions per packet, 256 KiB result text, and 10,000
team/packet records per tenant namespace. Due dates must be within one year.
Limits refuse an operation rather than silently trimming evidence or history.
The owner retains responsibility for data minimization before sharing.

Live multi-host PostgreSQL, external identity providers and customer usability
are not qualified.
