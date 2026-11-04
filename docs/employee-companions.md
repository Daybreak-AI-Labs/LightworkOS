# Employee companions: bounded conversation preview

Employee companions are a preview feature. Installed-app and provider behavior
are not qualified; see [Limits](#limits).

## What the preview provides

An employee has a personal companion home at **My companion** (`/companion`).
They can converse, plan and write drafts while existing tasks continue. An
explicit employee policy grant enables AI replies through the installation's
configured **writer** model. A separate grant permits deterministic questions
such as "what is running?" and "what needs attention?" using the existing
conversational-supervisor grammar. Task status includes current source links,
observation times and an owner/policy decision receipt. AI replies are labeled
drafts; their task-context links identify data supplied to the model, not proof
that every generated statement is correct. Restored history does not restore
previously authorized links.

This separate companion conversation does not acquire the active chat's
single-turn admission fence, steer an active agent, start another task, or become
a replacement agent runtime. The separate
[governed conversation inbox](conversation-inbox.md) serves ordinary task chats;
its queue/guidance controls are not companion capabilities.

The existing installation provider configuration is untouched. AI turns send
the employee's message, up to six eligible retained exchanges and optional own
task title/status context to that configured provider. They use the existing
LLM facade, Budget, provider and organization admission, emergency stop,
spending limits and usage settlement. They do not start an Agent, invoke tools,
read connector credentials, search enterprise documents, learn preferences or
send audio.

## Setup and operation

1. An installation administrator enables **Employee companions** in Settings.
   The optional installer choice sets the same default-off feature switch.
2. The employee and the managing administrator must have explicit membership
   in the selected workspace and named signed-in accounts. The historical
   authenticated-user default role does not enroll anyone.
3. A workspace administrator opens **Employee companions**
   (`/companion/admin`), chooses a current workspace member, and enables their
   companion. **AI draft conversations** permits model replies. **Their own
   tasks** supplies task context; **Read task status** permits deterministic
   status questions. Prompt-only AI drafts work without a task-source grant.
   Existing policies do not acquire AI permission automatically.
4. The administrator chooses no saved history (default), or 1, 7 or 30 days.
   The employee can clear their own saved history. Disabling the employee's
   companion or selecting no history deletes its live retained history as part
   of the policy update. It does not erase task records or backups.

Policy edits compare the revision the administrator reviewed with the current
revision. A stale form refuses to overwrite newer policy. Browser requests are
also bound to the signed-in account and selected workspace, and mutation routes
require the existing same-origin check. Role, membership, offboarding, suite
access and policy are re-read under the installation's authority-effect fence.

Before enabling AI drafts, the configured writer route must be usable under the
deployment's model/provider policy. No new key, provider route or retention
contract is provisioned here. Unsupported executable routes such as the Codex
CLI are refused. The existing provider's caching, logging and retention are
separate from companion history retention.

## Conversation lifecycle

Each deliberate model request has an employee-and-tenant-bound receipt. One
model turn per employee is admitted at a time; existing task runs and task-panel
refreshes continue independently. A short local reservation is persisted before
model dispatch. Policy/store locks are released during network I/O. Current
membership, credential revocation, workspace-selection generation, source
authority, policy revision, conversation generation and model route binding are
checked again before physical dispatch and reply publication. Browser/invite
credentials are locally revalidated; verified bearer expiry is checked again.
Revocation after dispatch cannot recall data already sent to a provider; the
late result is refused if publication authority no longer holds.

The LLM facade permits only one observed physical attempt for this turn, with
no failover or hedged duplicate. Application request receipts prevent automatic
paid replays. The browser reconciles a timed-out request through a metadata-only
status endpoint and never silently resends it. With no saved history, a completed
reply lost in transit cannot be recovered; the employee must deliberately start
another request and is told the earlier call may have been billed. Unknown
provider outcomes are not an exactly-once provider guarantee.

Request IDs have a 15-minute admission window (plus 60 seconds of future clock
skew); consumed receipts are retained for 24 hours, with at most 512 per employee.
Requests above capacity are refused. Pending leases expire after five minutes.
Every policy change, history clear and actual history expiration invalidates a
pending turn. The UI can clear/cancel while a reply is pending; this prevents a
late reply from repopulating history, not cancellation of provider processing.

Per-turn budgets take the lower of deployment limits and $0.50, 16,000 input
tokens, 2,000 output tokens, 90 seconds and zero tool calls. The wall-time budget
is checked by the existing runtime, not a hard network timeout. Existing SDK
timeouts still apply, and a physical request can outlive the browser wait.

## Data and authority boundaries

- Task queries always specify the current employee owner; returned rows are
  checked again. Bootstrap administrator owner/department bypass helpers are
  deliberately not used. Current department restrictions still apply. Tasks
  attached to a project require that project to have the same employee owner.
- Task views are bounded to 50 visible nonterminal/attention records. They are
  snapshots, not an assertion that every task or event has been scanned.
- AI context includes only task IDs, bounded titles and status, never task
  results, files, connector data or arbitrary documents. Retained exchanges
  whose source access has been removed are omitted from the conversation and
  model context. Each new draft retains the union of its supplied source
  provenance, including eligible prior exchanges, so later revocation also
  suppresses derived replies. Historical provenance can include ended tasks.
- A new private companion message is never inserted into ordinary goals,
  conversations, facts, shared memory, or the general audit writer. This avoids
  giving legacy goal-content access paths a copy of the companion conversation.
- Retained messages and replies use the existing tenant-and-owner-bound
  authenticated encryption helper. Plaintext history fallback is refused.
  No-retention mode stores metadata events and request receipts, not exchange
  text. It is stateless across turns; unsaved browser text is not sent back as
  model history. Retained exchanges carry their draft/status kind and model
  route metadata inside the encrypted envelope.
- Companion admin APIs return only policy and event metadata. No companion
  administrator route accepts an employee ID to retrieve their conversation.
  The separate reviewed content-access process covers supported ordinary task,
  approval-card and subject-data resources; it does not grant companion-history
  access.
- Each policy change or completed companion reply is published atomically with
  its required local metadata receipt. Failed persistence does not return a
  successful reply. The journal records actor, owner, action, revision and time;
  it excludes prompts, replies and task titles. Refused requests are not a
  complete refusal-audit stream.
- The feature's local file authority is bound to a named tenant. Stores refuse
  tenant-context changes, corrupt records, unsupported capability expansion and
  a configured replica count other than one. A maximum of 1,000 employee
  records, 50 exchanges per employee, and 200 metadata events per employee keeps
  the preview bounded. Admin activity shows the latest 200 workspace events.

The administrator remains able to change retention policy. Applying a shorter
retention period can rewrite encrypted history internally, but no content is
returned to the administrator. Increasing retention cannot resurrect previously
expired or removed history. History expires on employee access or policy
updates; there is no scheduled purge worker. Already-rendered browser text and
backups have separate lifecycles. The browser stores no companion text in local
storage and clears its view when it detects an account/workspace change.

## Limits

The preview is **not a complete personal companion**. Cross-session learned
memory, connector/document retrieval, write approvals, active-run
steering/cancellation, notifications and live voice are not implemented. The
preview does not propagate source ACLs, so it offers no enterprise retrieval,
and its provider contracts and routing are not qualified for production
deployment.

Administrators have no automatic content access to existing employee tasks and
chats. Named accounts list their own task content; administrator policy
authority does not itself authorize reading private employee content. Supported
exceptional reads require an exact resource request, an independent current
reviewer, expiry and an acknowledged audit receipt. Each exceptional read requires its own acknowledged receipt, and
the grant does not authorize mutation or publication. Audit search and export
use metadata projections instead of raw prompts or tool payloads. This is not a
deployment-wide privacy certification.

No-egress, compliance, privileged-host confidentiality and immutable audit
retention are not promised. Operating-system/key holders remain trusted; the
companion metadata journal is bounded and mutable.
The shared runtime's usage settlement is best-effort; this feature does not
make global audit or billing failure handling fail-closed.

The authority is host-local. Shared PostgreSQL policy storage, replicated
deployment coordination, scheduled deletion, backup erasure, and retirement of
offboarded employees' retained files are not supported. A deployment that omits
its replica-count declaration is not proof of single-host operation. Keep this
preview disabled in distributed deployments.

On Your companion, Global Copilot can check the owner's saved-exchange
count, retention and pending-reply state without exposing conversation text.
It can clear saved history and cancel a pending reply only after a fresh review
and explicit confirmation. The native page uses the same history revision, and
an exact Copilot retry reads its saved clear receipt rather than clearing again.
Copilot cannot enroll an employee, change policy or converse as that person's
companion.

Source admission and durable turn reservation are separate from model I/O,
which runs outside authority locks; physical dispatch and publication keep
their current-authority checks. Real model behavior, provider retention and
billing, installed distributions and distributed deployment are not qualified
for this preview.
