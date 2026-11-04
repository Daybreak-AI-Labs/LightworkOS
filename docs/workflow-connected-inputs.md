# Connected account inputs

Workflow builder's **Connected account** input lets a person choose a current,
owned account in Templates, rendering-only sample checks, schedule enrollment,
and trigger enrollment. The existing `workflows.typed_inputs` setting controls
the capability; Settings and the installer describe it. Connections must also
be enabled. This requires a current named account with permission to operate
in the selected workspace. An administrator's broader visibility is not an
account-selection grant.

The picker advertises only adapters with an exact saved-account binding:
enterprise REST/read connectors and the read-only Google Drive adapter. It
never imports environment credentials, silently chooses an account, or copies
a private account into a reusable template default. Account names remain user
content. Copilot's `templates.accounts` reviews these same current native
choices without testing a provider or starting work.

A prepared task keeps the account name in the readable brief and keeps its
exact owner, workspace, connector, name, and credential generation separately.
Chat's encrypted draft recovery retains that metadata. Converting a selected
task draft to reusable agent/flow authoring is refused with a repair path.
The native API, multipart Chat admission, event admission, and schedules all
validate and persist the exact selection. An inbound event cannot replace a
reviewed connected-account input. Scheduled occurrences keep the admitted
selection; changing or removing an account never silently rebinds them.

Task dispatch, inherited child tasks, model/tool boundaries, and credential
resolution recheck current account and permission state. A selected task gets
no new tool permissions. Unselected services and adapters that only support
ambient credentials are refused. Rotation or revocation requires a new,
explicitly reviewed selection; reconnecting another account is insufficient.
Drive selections permit its existing list/get/export operations, not writes.

## Storage and restore

Additive world-model migration **46**, in both SQLite and PostgreSQL, adds
`goals.connection_selection TEXT NOT NULL DEFAULT ''`. New selection envelopes
use the existing encrypted-field codec and are written in the same transaction
as goal admission. Legacy goals keep an empty value. No new credential store,
secret value, permission atom, or deployment credential is introduced. Released
migrations 1–45 and their lock fingerprints are unchanged.

The column follows existing task deletion and backup custody. Restoring a
database cannot reactivate an old grant: normal restored-work admission gates
and fresh identity, workspace, permission, and exact connection-generation
checks still apply. An older binary must refuse a newer database as usual;
rollback requires a reviewed pre-migration backup, not destructive SQL that
silently discards task restrictions.

## Limits

A live PostgreSQL service, live providers and provider consent flows are not
qualified.
