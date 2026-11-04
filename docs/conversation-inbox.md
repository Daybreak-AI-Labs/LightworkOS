# Conversation messages during background work

**Keep conversation responsive during tasks** is on by default (`[conversation_inbox] enabled`, default `true`): people can send messages while a task runs. An administrator can turn it off in Settings → All settings → Chat channels or during installation; an explicit `enabled = false` in the organization or workspace settings always stays off, and the composer then says sending during a task is turned off for the workspace. Guidance, queued messages, separate tasks and the maximum pending count have independent administrator controls. Workspace settings can narrow organization ceilings. Existing execution ownership, permissions, task concurrency and spending limits still apply. The inbox needs a signed-in, named account; a dashboard without sign-in keeps the earlier behaviour (send again once the task finishes).

While a task runs, the composer says in plain words what the chosen kind of message will do: guidance is saved, checked once more, and read by the task at its next safe point without starting a new task; a queued message starts as the next task when the current one finishes; a separate task starts now, alongside the current one.

In an owned task conversation the employee chooses a boundary before sending:

- **Guidance** saves the exact text and files without creating a task. A separate review shows the original brief and previously delivered guidance. The employee explicitly adds it or replaces other unconsumed guidance. Changing that review invalidates the decision. The existing task owner inserts approved guidance at a safe root model-turn checkpoint; the durable acknowledgement names the exact delivered text, files and checkpoint. Delivery is not proof the model read attachments or complied. Conflicts require a decision, and guidance cannot undo completed effects or widen authority.
- **Queue next message** acknowledges a saved message while the current task continues. Pending text and selected files can be edited or cancelled with revision checks. Queue admission remains serialized through the existing thread fence. After a message creates a durable execution draft its content is fixed; an interrupted draft can be explicitly cancelled before a revised message is sent. Earlier blocked queue admissions cannot be silently overtaken.
- **Start separately** creates a separate task under current permissions and limits, so it can finish while the original task remains active. The employee chooses no earlier content or explicitly reviews an immutable snapshot of the current task title, brief and result. A changed snapshot must be reviewed again. Snapshot access grants no execution authority or additional tools.

Preferences supplies inherited defaults for the mode and brief/balanced/detailed message cards. Organization/workspace locks use the existing preference hierarchy. Clarification answers retain their existing native answer path. Turning this feature off preserves owned receipt reading and authorized cancellation; it does not reopen handed-off task execution.

## Save and recovery contract

The native API and four typed Copilot operations (`conversation.inbox`, `conversation.send`, `conversation.edit`, `conversation.decide`) call the same services. Each accepted operation has an immutable receipt bound to exact content, owner and workspace. Repeating the same operation does not create another message or task; changing its contents is refused. Unknown network results retain the original draft, selected files and request identity. Receipt lookup is read-only; retry requires an explicit user action.

The supervised observer dispatches at most four local inbox workers and uses the native submission store, attachment preparation and runner. Authority is rechecked before admission and again by the existing runner. An uncertain recorded runner handoff is never automatically invoked a second time. The durable task link is the recovery destination. No provider call is used merely to save, classify or acknowledge guidance.

Private pending text, snapshots and attachment bytes are sealed with owner/thread/tenant binding in the existing governed CAS store. No new database migration or credential configuration is required. Shared deployments retain that store's existing Postgres/tenant/key requirements. Limits are explicit: 10 files per message, 4 MiB pending file bytes per conversation, 1–100 pending messages (default 20), 1,000 retained item identities, 4,000 submission request identities, and 10 MiB of sealed-record plaintext. Storage exhaustion refuses the new operation and preserves existing receipts; it does not silently evict idempotency history. Message text is limited to 16,000 characters (12,000 through Copilot), and explicitly selected task snapshots to 32,000 characters. A large snapshot requires a selected summary or no prior context.

## My Data integration

`maverick.conversation_inbox` exposes exact-owner helpers for the existing reviewed data workflow:

- `owned_inventory(principal)` returns record ID, revision, owner, root task ID and whether consumption/admission is in flight.
- `export_owned(principal, record_id, expected_revision)` returns the exact reviewed private items, including pending file bytes.
- `erase_owned(principal, record_id, expected_revision, operation_id, *, actor)` accepts a separate authorized review actor, refuses in-flight consumption/admission, erases private payloads, and retains empty replay tombstones plus a new save generation. Old tabs cannot resurrect erased messages. Audit acknowledgement pending returns `unconfirmed`.

These helpers do not themselves admit a privacy reviewer; the reviewed My Data adapter owns that authority. Task artifacts already admitted to execution retain their separate task-data governance. There is no additional automatic time-based inbox retention policy in this feature.

## Limits

Multi-process failure handling on PostgreSQL, real-browser visual and
accessibility behavior, and live provider calls are not qualified.
