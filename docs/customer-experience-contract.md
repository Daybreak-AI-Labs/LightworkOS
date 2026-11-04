# Lightwork customer experience contract

This document defines the product's experience target and acceptance evidence;
it does not certify current coverage.

After installation, a customer must be able to set up, configure, operate,
supervise, improve and recover every supported Lightwork capability inside the
platform. Customers must not need a terminal, a configuration file, a code
editor, developer tools or a hand-written data structure to complete those jobs.
Administrative tasks belong in the product under the appropriate permissions.

This applies to every supported operation, including infrequent maintenance and
repair. An administrator is a permission level, not an assumption that someone
can program or operate a terminal. Moving a required technical step into an
"Advanced" panel, a support article, Copilot-generated instructions, or a
support ticket does not complete the journey. Do not narrow the advertised
capability simply to omit a missing control from the inventory.

## One deliberate visual and interaction system

Use a coherent Liquid Glass design across navigation, workspaces, cards,
dialogs, forms, menus, notifications and Copilot. Materials, typography, spacing,
depth, focus, motion and responsive behavior must come from shared components
and tokens. Verify readability on the actual backgrounds; provide high-contrast
and reduced-transparency/motion treatments. Translucency must preserve hierarchy
and legibility, including error, selected and disabled states.

Each screen must make its purpose, current state and next useful action obvious.
Every control must have a real, authorized operation and useful feedback. Cover
loading, cancellation, empty results, success, stale information, unavailable
dependencies and recoverable failure. Prevent duplicate submissions. Restore
focus after dialogs; support keyboard navigation, meaningful labels, error
association and responsive layouts. Preserve entered work where safe.

Customer copy describes the work and its consequences. Use business names,
readable dates and specific remedies. Internal identifiers, endpoint names,
configuration keys, serialized objects, hashes and stack traces do not belong
in the ordinary experience. Translate status codes into meaningful states.
Keep exact technical evidence available in an optional support/export artifact
when needed without requiring the customer to interpret or edit it.

This is a quality standard for working software, not a screen styling exercise.
Visual polish cannot compensate for a disconnected feature or missing recovery
path. Do not remove a required operation merely to make a screen look simpler.

## Complete control after installation

The coverage inventory must include the following customer jobs and their
dependencies, not just the visible navigation pages:

- Workspace and user setup, roles, access, invitations and ownership changes.
- Connections, credentials, provider/model choices, key rotation and connection
  health, with clear control of the effective setting.
- Capability enablement, prerequisites, policies, budgets and operating limits.
- Creating, importing, teaching, reviewing, saving, publishing, scheduling,
  running, pausing, cancelling and retiring supported work.
- Evidence capture, retention, review, training use, withdrawal and audit export.
- Approval, exceptions, pending work, uncertain effects and safe reconciliation.
- Backups, verification, recovery and supported installation/update management.
- Data import/export and the normal work of each business module.

Replace configuration-only ownership with a deliberate in-product
administration/migration path. Detect higher-priority deployment settings and
explain what is effective; do not show a successful save while another source
silently overrides it. Some operations require an administrator, operating-system
consent or an external service's authorization. Guide those steps inside the
experience and return to a verified result. Do not invent authority or hide a
dependency that prevents completion.

Customers select named records, dates, files and business choices. Lightwork
must obtain the current record version, generate request references, calculate
file fingerprints and serialize requests itself. Preserve those exact bindings
through review and execution; removing a technical field must not remove its
concurrency, integrity or authorization check. A genuine external attestation
must come from its authorized source, never from invented form values.

Setup and repair must remain available when ordinary work cannot start: for
example, an expired connection, unavailable AI provider or interrupted update.
Use a restricted recovery interface where necessary. A guided action that
requires the broken subsystem to operate is not a recovery path. Retain the
separate boundary for operating-system or provider consent; Lightwork must guide
the user through that consent rather than bypass it.

## Copilot is an operating interface to the whole product

Copilot must be able to explain and perform every supported product operation
that the signed-in person is authorized to perform. It must have a discoverable
operation catalog, the same business validation and permission checks as the
direct interface, and access to current authorized product state. A general chat
model, documentation retrieval or page description alone does not meet this
requirement.

Use a shared action/service contract for direct UI and Copilot operations. Each
operation needs readable intent, input collection, authority and scope,
consequence preview where appropriate, execution, status and recovery. A user
must be able to move between conversation and the relevant screen without
repeating context or losing a pending decision. Copilot must accurately report
what was saved, started, completed, refused or remains unknown.

The catalog must bind supported actions to their actual service contracts;
arbitrary shell access, configuration-file editing or simulated button clicks
are not substitutes for this integration. Credentials and authentication
challenges belong in protected controls, not conversational history. Copilot
can guide that handoff and continue from the verified connection state.

Copilot must understand the relationship between the current screen, selected
records, workspace, active jobs, outstanding approvals and relevant related work.
The context must be tenant/role scoped, freshness-aware and based on actual
state. Changes from other panels, jobs or people must invalidate stale decisions.
Retain current version checks when both a person and Copilot edit an item; do
not overwrite one with an older snapshot from the other. Show dependencies and
conflicts in business terms, and continue independent work when appropriate.

An answer about platform state needs an identifiable source and freshness. If
the evidence is missing, inaccessible or unresolved, say what is needed and
offer a real next action. Never manufacture a setting, completion state, audit
receipt or permission to satisfy the appearance of omniscience.

## Delivery and acceptance

Maintain an operation-level matrix with direct UI, Copilot, required settings,
permissions, backend behavior, pending/error/recovery states and test evidence.
Derive its inventory from implemented services/commands/configuration as well
as screens so absent UI is visible. Mark partial and unavailable operations
explicitly; a route count or successful component suite is not coverage of the
customer journey.
Each inventory entry must identify the customer job, its prerequisites, its
direct and Copilot entry points, the shared operation, current-state check,
observable result, repair path and dated evidence. Track implementation and
acceptance separately. A static form scan supplies review candidates, not proof
that a required manual step exists or that an ordinary alternative is absent.

Qualify each delivered journey through the real authenticated application using
an isolated local workspace. Test navigation, actual state changes, current
permissions, stale revisions, repeated clicks, cancellation, denied actions and
recovery. Separately inspect the rendered desktop and narrow layout, keyboard
use, focus, contrast and loading/error feedback. Synthetic UI fixtures qualify
presentation and request construction only; keep that evidence distinct from
native execution, installed-app and customer acceptance.

No unqualified promise of complete readiness or zero errors follows from this
contract. A pull request must state what was actually exercised and which gaps
remain unresolved.
